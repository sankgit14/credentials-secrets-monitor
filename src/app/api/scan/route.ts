import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import pool from "@/lib/mysql";
import clientPromise from "@/lib/mongodb";
import { getSessionUser } from "@/lib/auth";
import { addFallbackScan } from "@/lib/memory-store";

const REPOSITORY_NAME = "demo-payment-service";
const REPOSITORY_FOLDER = path.join(process.cwd(), "sample-repo");
const SCANNER_NAME = "synthetic-demo-scanner";
const MAX_FILE_SIZE = 1024 * 1024;

export const dynamic = "force-dynamic";

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type DetectedSecret = {
  secretType: string;
  fingerprint: string;
  maskedPreview: string;
  filePath: string;
  lineNumber: number;
  severity: Severity;
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
  if (secretType === "API_KEY" || secretType === "DATABASE_URL") return "HIGH";
  return "MEDIUM";
}

async function collectFiles(directory: string): Promise<string[]> {
  try {
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
      if ([".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env"].includes(extension)) {
        files.push(absolutePath);
      }
    }
    return files;
  } catch {
    return [];
  }
}

async function scanFiles(): Promise<{
  filesScanned: number;
  detections: DetectedSecret[];
}> {
  const files = await collectFiles(REPOSITORY_FOLDER);
  const detections: DetectedSecret[] = [];

  for (const file of files) {
    try {
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
        if (/^(your_|replace_me|changeme|placeholder)/i.test(value)) continue;

        const relativePath = path
          .relative(REPOSITORY_FOLDER, file)
          .split(path.sep)
          .join("/");

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
    } catch {
      // Continue next file
    }
  }

  return {
    filesScanned: files.length,
    detections,
  };
}

export async function POST() {
  const user = await getSessionUser();

  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  if (user.role !== "ADMIN") {
    return NextResponse.json(
      { success: false, error: "Admin access required." },
      { status: 403 },
    );
  }

  try {
    const { filesScanned, detections } = await scanFiles();

    const summary = {
      total: detections.length,
      high: detections.filter((item) => item.severity === "HIGH").length,
      medium: detections.filter((item) => item.severity === "MEDIUM").length,
      low: detections.filter((item) => item.severity === "LOW").length,
      critical: detections.filter((item) => item.severity === "CRITICAL").length,
    };

    let scanRunId = 1;
    let savedToMySQL = false;
    let savedToMongo = false;

    // 1. Attempt persistence in MySQL
    let connection;
    try {
      connection = await pool.getConnection();
      await connection.beginTransaction();

      let repositoryId = 1;
      const [repoRows] = await connection.execute(
        "SELECT repository_id FROM repositories WHERE name = ? LIMIT 1",
        [REPOSITORY_NAME],
      );
      if (Array.isArray(repoRows) && repoRows.length > 0) {
        repositoryId = (repoRows[0] as { repository_id: number }).repository_id;
      }

      const [runResult] = await connection.execute(
        `INSERT INTO scan_runs (repository_id, started_by, status, started_at, total_findings)
         VALUES (?, ?, 'COMPLETED', NOW(), ?)`,
        [repositoryId, user.id, detections.length],
      );

      scanRunId = (runResult as { insertId: number }).insertId;

      for (const finding of detections) {
        await connection.execute(
          `INSERT INTO findings
            (repository_id, scan_run_id, secret_type, fingerprint,
             masked_preview, file_path, line_number, severity,
             first_seen, last_seen, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), NOW())
           ON DUPLICATE KEY UPDATE
             scan_run_id = VALUES(scan_run_id),
             last_seen = NOW()`,
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
      }

      await connection.commit();
      savedToMySQL = true;
    } catch (mysqlErr) {
      console.warn("MySQL scan persistence offline; falling back to in-memory:", (mysqlErr as Error).message);
      if (connection) await connection.rollback();
    } finally {
      if (connection) connection.release();
    }

    // 2. Attempt persistence in MongoDB
    try {
      const client = await clientPromise;
      const db = client.db(process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence");
      await db.collection("scan_evidence").insertOne({
        scanRunId,
        repositoryName: REPOSITORY_NAME,
        scanner: SCANNER_NAME,
        findingsSummary: summary,
        evidence: detections.map((d, i) => ({
          findingId: i + 1,
          filePath: d.filePath,
          lineNumber: d.lineNumber,
          secretType: d.secretType,
          maskedPreview: d.maskedPreview,
        })),
        createdAt: new Date(),
      });
      savedToMongo = true;
    } catch (mongoErr) {
      console.warn("MongoDB evidence persistence offline:", (mongoErr as Error).message);
    }

    // Always record in in-memory fallback store
    scanRunId = addFallbackScan(REPOSITORY_NAME, detections.length, summary);

    return NextResponse.json({
      success: true,
      scanRunId,
      repository: REPOSITORY_NAME,
      filesScanned,
      findingsDetected: detections.length,
      summary,
      savedToMySQL,
      savedToMongo,
      message: `Scan #${scanRunId} completed successfully. ${detections.length} secrets detected in sample repository.`,
    });
  } catch (error) {
    console.error("Scan engine error:", error);
    return NextResponse.json(
      { success: false, error: "Scan failed. Check server logs." },
      { status: 500 },
    );
  }
}
