import { NextRequest, NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { findingId, actionType, notes, evidenceRef } = body;

    if (!findingId || !actionType) {
      return NextResponse.json(
        { success: false, error: "findingId and actionType are required." },
        { status: 400 },
      );
    }

    // Call MySQL Stored Procedure `sp_resolve_finding`
    const connection = await pool.getConnection();
    try {
      await connection.query("SET @p_success = FALSE;");
      await connection.query("SET @p_msg = '';");
      
      await connection.execute(
        `CALL sp_resolve_finding(?, ?, ?, ?, ?, @p_success, @p_msg)`,
        [
          Number(findingId),
          user.id,
          actionType,
          notes ?? "Resolution recorded via Stored Procedure",
          evidenceRef ?? "Manual security triage",
        ],
      );

      const [outRows] = await connection.query("SELECT @p_success AS success, @p_msg AS message");
      const out = (outRows as { success: number | boolean; message: string }[])[0];

      return NextResponse.json({
        success: Boolean(out?.success),
        message: out?.message ?? "Stored procedure executed successfully.",
        findingId,
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Stored procedure execution error:", error);
    return NextResponse.json(
      { success: false, error: "Stored procedure sp_resolve_finding execution failed." },
      { status: 500 },
    );
  }
}

