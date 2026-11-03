import { NextResponse } from "next/server";
import pool from "@/lib/mysql";
import clientPromise from "@/lib/mongodb";
import { getSessionUser } from "@/lib/auth";
import { getFallbackScans } from "@/lib/memory-store";

export const dynamic = "force-dynamic";

type ScanRow = {
  scan_run_id: number;
  repository_name: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  total_findings: number;
  started_at: Date | string;
  completed_at: Date | string | null;
};

export async function GET() {
  const user = await getSessionUser();

  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  try {
    const [rows] = await pool.query(`
      SELECT
        sr.scan_run_id,
        r.name AS repository_name,
        sr.status,
        sr.total_findings,
        sr.started_at,
        sr.completed_at
      FROM scan_runs sr
      JOIN repositories r
        ON r.repository_id = sr.repository_id
      ORDER BY sr.started_at DESC
      LIMIT 100
    `);

    const scans = rows as ScanRow[];

    const client = await clientPromise;
    const databaseName = process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence";

    const evidence = await client
      .db(databaseName)
      .collection("scan_evidence")
      .find({}, { projection: { _id: 0, scanRunId: 1, findingsSummary: 1, createdAt: 1 } })
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();

    const evidenceByScanId = new Map(evidence.map((item) => [Number(item.scanRunId), item]));

    const history = scans.map((scan) => {
      const snapshot = evidenceByScanId.get(Number(scan.scan_run_id));
      const summary = snapshot?.findingsSummary ?? {};

      return {
        scanRunId: scan.scan_run_id,
        repositoryName: scan.repository_name,
        status: scan.status,
        totalFindings: scan.total_findings,
        startedAt: scan.started_at,
        completedAt: scan.completed_at,
        evidenceSummary: {
          total: Number(summary.total ?? scan.total_findings),
          critical: Number(summary.critical ?? 0),
          high: Number(summary.high ?? 0),
          medium: Number(summary.medium ?? 0),
          low: Number(summary.low ?? 0),
        },
      };
    });

    return NextResponse.json({
      success: true,
      totals: {
        totalScans: history.length,
        completed: history.filter((s) => s.status === "COMPLETED").length,
        failed: history.filter((s) => s.status === "FAILED").length,
        running: history.filter((s) => s.status === "RUNNING").length,
      },
      history,
    });
  } catch (error) {
    console.warn("MySQL/MongoDB offline; returning fallback scan history:", (error as Error).message);
    const fallbackScans = getFallbackScans();
    return NextResponse.json({
      success: true,
      totals: {
        totalScans: fallbackScans.length,
        completed: fallbackScans.filter((s) => s.status === "COMPLETED").length,
        failed: 0,
        running: 0,
      },
      history: fallbackScans,
      isFallback: true,
    });
  }
}
