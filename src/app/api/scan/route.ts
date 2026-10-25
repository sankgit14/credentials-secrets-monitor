
import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import pool from "@/lib/mysql";
import clientPromise from "@/lib/mongodb";
import type { Collection, Document } from "mongodb";
import { getSessionUser } from "@/lib/auth";

const REPOSITORY_NAME = "demo-payment-service";
const REPOSITORY_FOLDER = path.join(process.cwd(), "sample-repo");
const SCANNER_NAME = "synthetic-demo-scanner";
const MAX_FILE_SIZE = 1024 * 1024;

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type DetectedSecret = {
  secretType: string;
  fingerprint: string;
  maskedPreview: string;
  filePath: string;
  lineNumber: number;
  severity: Severity;
};

type StoredEvidence = {
  findingId: number;
  filePath: string;
  lineNumber: number;
  secretType: string;
  maskedPreview: string;
};

type ScanSummary = {
  total: number;
  high: number;
  medium: number;
  low: number;
  critical: number;
};

function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
}

function detectType(variableName: string): string | null {
  const name = variableName.toUpperCase();

  if (name.includes("AWS_ACCESS_KEY_ID")) return "AWS_ACCESS_KEY_ID";
  if (name.includes("DATABASE_URL")) return "DATABASE_URL";
  if (name.includes("API_KEY")) return "API_KEY";
  if (name.includes("SECRET")) return "SECRET";
  if (name.includes("TOKEN")) return "TOKEN";
  if (name.includes("PASSWORD")) return "PASSWORD";

  return null;
}

function getSeverity(secretType: string): Severity {
  if (secretType === "AWS_ACCESS_KEY_ID") return "CRITICAL";

  if (secretType === "API_KEY" || secretType === "DATABASE_URL") {
    return "HIGH";
  }

  return "MEDIUM";
}

async function collectFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (entry.isSymbolicLink() || entry.name.startsWith(".")) continue;

    const absolutePath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await collectFiles(absolutePath)));
      continue;
    }

    if (!entry.isFile()) continue;

    const extension = path.extname(entry.name).toLowerCase();

    if (
      [".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env"].includes(
        extension,
      )
    ) {
      const relativePath = path.relative(REPOSITORY_FOLDER, absolutePath);

      if (
        !relativePath.startsWith("..") &&
        !path.isAbsolute(relativePath)
      ) {
        files.push(absolutePath);
      }
    }
  }

  return files;
}

async function scanFiles(): Promise<{
  filesScanned: number;
  detections: DetectedSecret[];
}> {
  const files = await collectFiles(REPOSITORY_FOLDER);
  const detections: DetectedSecret[] = [];

  for (const file of files) {
    const fileInfo = await stat(file);

    if (fileInfo.size > MAX_FILE_SIZE) continue;

    const content = await readFile(file, "utf8");
    const lines = content.split(/\r?\n/);

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];

      const match = line.match(
        /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["']([^"']{8,500})["']\s*(?:#.*)?$/,
      );

      if (!match) continue;

      const [, variableName, value] = match;
      const secretType = detectType(variableName);

      if (!secretType) continue;

      if (/^(your_|replace_me|changeme|placeholder)/i.test(value)) {
        continue;
      }

      const relativePath = path
        .relative(REPOSITORY_FOLDER, file)
        .split(path.sep)
        .join("/");

      // Store a fingerprint and masked preview, never the raw value.
      const fingerprint = createHash("sha256")
        .update(`${secretType}:${value}`)
        .digest("hex");

      detections.push({
        secretType,
        fingerprint,
        maskedPreview: maskSecret(value),
        filePath: relativePath,
        lineNumber: index + 1,
        severity: getSeverity(secretType),
      });
    }
  }

  return {
    filesScanned: files.length,
    detections,
  };
}

export async function POST() {
  // Authenticate before scanning files or accessing either database.
  const user = await getSessionUser();

  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  // Only admins can start a scan.
  if (user.role !== "ADMIN") {
    return NextResponse.json(
      { success: false, error: "Admin access required." },
      { status: 403 },
    );
  }

  let connection: Awaited<ReturnType<typeof pool.getConnection>> | undefined;
  let transactionStarted = false;

  let evidenceCollection: Collection<Document> | undefined;
  let mongoDocumentId: unknown;
  let mongoInserted = false;
  let transactionCommitted = false;

  try {
    const { filesScanned, detections } = await scanFiles();

    connection = await pool.getConnection();
    await connection.beginTransaction();
    transactionStarted = true;

    const [repositoryResult] = await connection.execute(
      "SELECT repository_id FROM repositories WHERE name = ? LIMIT 1",
      [REPOSITORY_NAME],
    );

    const repositoryRows = repositoryResult as {
      repository_id: number;
    }[];

    if (repositoryRows.length === 0) {
      await connection.rollback();
      transactionStarted = false;

      return NextResponse.json(
        {
          success: false,
          error: `Repository '${REPOSITORY_NAME}' was not found in MySQL.`,
        },
        { status: 404 },
      );
    }

    const repositoryId = repositoryRows[0].repository_id;

    // Record the ID of the authenticated user who started the scan.
    const startedBy = user.id;

    const [runResult] = await connection.execute(
      `INSERT INTO scan_runs
        (repository_id, started_by, status, started_at, total_findings)
       VALUES (?, ?, 'RUNNING', NOW(), 0)`,
      [repositoryId, startedBy],
    );

    const scanRunId = (runResult as { insertId: number }).insertId;
    const storedEvidence: StoredEvidence[] = [];

    for (const finding of detections) {
      await connection.execute(
        `INSERT INTO findings
          (repository_id, scan_run_id, secret_type, fingerprint,
           masked_preview, file_path, line_number, severity,
           first_seen, last_seen, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), NOW())
         ON DUPLICATE KEY UPDATE
           scan_run_id = VALUES(scan_run_id),
           masked_preview = VALUES(masked_preview),
           file_path = VALUES(file_path),
           line_number = VALUES(line_number),
           severity = VALUES(severity),
           last_seen = NOW(),
           updated_at = NOW()`,
        [
          repositoryId,
          scanRunId,
          finding.secretType,
          finding.fingerprint,
          finding.maskedPreview,
          finding.filePath,
          finding.lineNumber,
          finding.severity,
        ],
      );

      const [findingResult] = await connection.execute(
        `SELECT finding_id
         FROM findings
         WHERE repository_id = ? AND fingerprint = ?
         LIMIT 1`,
        [repositoryId, finding.fingerprint],
      );

      const findingRows = findingResult as { finding_id: number }[];

      if (findingRows.length > 0) {
        storedEvidence.push({
          findingId: findingRows[0].finding_id,
          filePath: finding.filePath,
          lineNumber: finding.lineNumber,
          secretType: finding.secretType,
          maskedPreview: finding.maskedPreview,
        });
      }
    }

    const summary: ScanSummary = {
      total: detections.length,
      high: detections.filter((item) => item.severity === "HIGH").length,
      medium: detections.filter((item) => item.severity === "MEDIUM").length,
      low: detections.filter((item) => item.severity === "LOW").length,
      critical: detections.filter((item) => item.severity === "CRITICAL")
        .length,
    };

    await connection.execute(
      `UPDATE scan_runs
       SET status = 'COMPLETED',
           completed_at = NOW(),
           total_findings = ?
       WHERE scan_run_id = ?`,
      [detections.length, scanRunId],
    );

    // Store scan metadata and masked evidence in MongoDB.
    const client = await clientPromise;
    const databaseName =
      process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence";

    const collection = client
      .db(databaseName)
      .collection<Document>("scan_evidence");

    evidenceCollection = collection;

    const mongoResult = await collection.insertOne({
      scanRunId,
      repositoryName: REPOSITORY_NAME,
      scanner: SCANNER_NAME,
      findingsSummary: summary,
      evidence: storedEvidence,
      createdAt: new Date(),
    });

    mongoDocumentId = mongoResult.insertedId;
    mongoInserted = true;

    await connection.commit();
    transactionStarted = false;
    transactionCommitted = true;

    return NextResponse.json({
      success: true,
      scanRunId,
      repository: REPOSITORY_NAME,
      filesScanned,
      findingsDetected: detections.length,
      summary,
      message: "Scan completed. Raw credential values were not stored.",
    });
  } catch (error) {
    if (connection && transactionStarted && !transactionCommitted) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("MySQL rollback failed:", rollbackError);
      }
    }

    if (
      mongoInserted &&
      evidenceCollection &&
      mongoDocumentId &&
      !transactionCommitted
    ) {
      try {
        await evidenceCollection.deleteOne({ _id: mongoDocumentId });
      } catch (cleanupError) {
        console.error("MongoDB evidence cleanup failed:", cleanupError);
      }
    }

    console.error("Scan failed:", error);

    return NextResponse.json(
      {
        success: false,
        error: "Scan failed. Check the server terminal for details.",
      },
      { status: 500 },
    );
  } finally {
    connection?.release();
  }
}
