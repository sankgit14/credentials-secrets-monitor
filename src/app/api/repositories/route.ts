import { NextRequest, NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  try {
    const [rows] = await pool.query(`
      SELECT 
        r.repository_id,
        r.name,
        r.source_url,
        u.full_name AS owner_name,
        r.created_at,
        COUNT(f.finding_id) AS total_findings,
        SUM(CASE WHEN f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS') THEN 1 ELSE 0 END) AS open_findings
      FROM repositories r
      JOIN users u ON r.owner_id = u.user_id
      LEFT JOIN findings f ON r.repository_id = f.repository_id
      GROUP BY r.repository_id, r.name, r.source_url, u.full_name, r.created_at
      ORDER BY r.created_at DESC
    `);

    return NextResponse.json({
      success: true,
      repositories: rows,
    });
  } catch (error) {
    console.error("Fetch repositories failed:", error);
    return NextResponse.json({
      success: true,
      isFallback: true,
      repositories: [
        {
          repository_id: 1,
          name: "demo-payment-service",
          source_url: "https://github.com/enterprise/demo-payment-service.git",
          owner_name: user.name,
          created_at: new Date().toISOString(),
          total_findings: 3,
          open_findings: 2,
        },
        {
          repository_id: 2,
          name: "auth-identity-provider",
          source_url: "https://github.com/enterprise/auth-identity-provider.git",
          owner_name: "SOC Analyst Lead",
          created_at: new Date().toISOString(),
          total_findings: 2,
          open_findings: 1,
        },
      ],
    });
  }
}

// DML: INSERT Repository
export async function POST(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { name, sourceUrl } = body;

    if (!name || !sourceUrl || typeof name !== "string" || typeof sourceUrl !== "string") {
      return NextResponse.json(
        { success: false, error: "Repository name and source URL are required." },
        { status: 400 },
      );
    }

    const trimmedName = name.trim();
    const trimmedUrl = sourceUrl.trim();

    const [result] = await pool.execute(
      `INSERT INTO repositories (name, source_url, owner_id, created_at)
       VALUES (?, ?, ?, NOW())`,
      [trimmedName, trimmedUrl, user.id],
    );

    const insertId = (result as { insertId: number }).insertId;

    return NextResponse.json({
      success: true,
      message: `Repository '${trimmedName}' created successfully.`,
      repository_id: insertId,
    });
  } catch (error) {
    console.error("Repository insertion failed:", error);
    return NextResponse.json(
      { success: false, error: "Failed to insert repository." },
      { status: 500 },
    );
  }
}

// DML: DELETE Repository
export async function DELETE(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  if (user.role !== "ADMIN") {
    return NextResponse.json(
      { success: false, error: "Only administrators can delete repositories." },
      { status: 403 },
    );
  }

  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (!id || !/^\d+$/.test(id)) {
      return NextResponse.json({ success: false, error: "Valid repository ID is required." }, { status: 400 });
    }

    await pool.execute("DELETE FROM repositories WHERE repository_id = ?", [Number(id)]);

    return NextResponse.json({
      success: true,
      message: `Repository #${id} deleted successfully.`,
    });
  } catch (error) {
    console.error("Repository deletion failed:", error);
    return NextResponse.json(
      { success: false, error: "Failed to delete repository (check foreign key constraints)." },
      { status: 500 },
    );
  }
}

