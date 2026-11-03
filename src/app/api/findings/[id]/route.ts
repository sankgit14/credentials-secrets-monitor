import { NextRequest, NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";
import { updateFallbackFindingStatus } from "@/lib/memory-store";

const allowedStatuses = [
  "OPEN",
  "INVESTIGATING",
  "REMEDIATION_IN_PROGRESS",
  "RESOLVED",
  "FALSE_POSITIVE",
] as const;

type FindingStatus = (typeof allowedStatuses)[number];

export const dynamic = "force-dynamic";

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const user = await getSessionUser();

  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  if (user.role !== "ADMIN" && user.role !== "ANALYST") {
    return NextResponse.json(
      { success: false, error: "Forbidden." },
      { status: 403 },
    );
  }

  try {
    const { id } = await context.params;

    if (!/^[1-9]\d*$/.test(id)) {
      return NextResponse.json(
        { success: false, error: "Invalid finding ID." },
        { status: 400 },
      );
    }

    const findingId = Number(id);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { success: false, error: "Invalid JSON request body." },
        { status: 400 },
      );
    }

    if (
      typeof body !== "object" ||
      body === null ||
      !("status" in body) ||
      typeof body.status !== "string" ||
      !allowedStatuses.includes(body.status as FindingStatus)
    ) {
      return NextResponse.json(
        { success: false, error: "Invalid finding status." },
        { status: 400 },
      );
    }

    const status = body.status as FindingStatus;

    // Try updating MySQL
    let updatedInDb = false;
    let connection;
    try {
      connection = await pool.getConnection();
      await connection.beginTransaction();
      await connection.query("SET @app_user_id = ?", [user.id]);

      await connection.execute(
        `UPDATE findings SET status = ?, updated_at = NOW() WHERE finding_id = ?`,
        [status, findingId],
      );

      await connection.execute(
        `INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, details, created_at)
         VALUES (?, 'FINDING_STATUS_UPDATED', 'finding', ?, ?, NOW())`,
        [user.id, findingId, JSON.stringify({ newStatus: status })],
      );

      await connection.commit();
      updatedInDb = true;
    } catch (dbErr) {
      console.warn("MySQL update failed; applying to in-memory store:", (dbErr as Error).message);
      if (connection) await connection.rollback();
    } finally {
      if (connection) connection.release();
    }

    // Always update in-memory fallback
    updateFallbackFindingStatus(findingId, status);

    return NextResponse.json({
      success: true,
      finding_id: findingId,
      status,
      persistedInMySQL: updatedInDb,
      message: `Finding #${findingId} updated to ${status}.`,
    });
  } catch (error) {
    console.error("Finding status update failed:", error);
    return NextResponse.json(
      { success: false, error: "Failed to update finding status." },
      { status: 500 },
    );
  }
}
