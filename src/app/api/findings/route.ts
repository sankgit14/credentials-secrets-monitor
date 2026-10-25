
import { NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";

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
        f.finding_id,
        r.name AS repository_name,
        u.full_name AS repository_owner,
        f.secret_type,
        f.severity,
        f.status,
        f.file_path,
        f.line_number,
        f.first_seen
      FROM findings f
      JOIN repositories r
        ON f.repository_id = r.repository_id
      JOIN users u
        ON r.owner_id = u.user_id
      ORDER BY
        CASE f.severity
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3
          WHEN 'LOW' THEN 4
        END,
        f.first_seen DESC
      LIMIT 100
    `);

    return NextResponse.json({
      success: true,
      count: Array.isArray(rows) ? rows.length : 0,
      findings: rows,
    });
  } catch (error) {
    console.error("Failed to fetch findings:", error);

    return NextResponse.json(
      { success: false, error: "Failed to fetch findings." },
      { status: 500 },
    );
  }
}
