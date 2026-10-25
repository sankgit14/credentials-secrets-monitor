
import { NextRequest, NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";

const allowedStatuses = [
  "OPEN",
  "INVESTIGATING",
  "REMEDIATION_IN_PROGRESS",
  "RESOLVED",
  "FALSE_POSITIVE",
] as const;

type FindingStatus = (typeof allowedStatuses)[number];

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  // 1. Authenticate the user before accessing the database.
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

  let connection: Awaited<ReturnType<typeof pool.getConnection>> | undefined;
  let transactionStarted = false;

  try {
    // 2. Validate the finding ID.
    const { id } = await context.params;

    if (!/^[1-9]\d*$/.test(id)) {
      return NextResponse.json(
        { success: false, error: "Invalid finding ID." },
        { status: 400 },
      );
    }

    // 3. Validate the request body.
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
    const findingId = Number(id);

    if (!Number.isSafeInteger(findingId)) {
      return NextResponse.json(
        { success: false, error: "Invalid finding ID." },
        { status: 400 },
      );
    }

    // 4. Acquire the database connection inside try.
    connection = await pool.getConnection();

    await connection.beginTransaction();
    transactionStarted = true;

    // Set the actor for the existing status-history trigger.
    // This MySQL session variable is scoped to this connection.
    await connection.query("SET @app_user_id = ?", [user.id]);

    // 5. Lock and check the finding.
    const [rows] = await connection.execute(
      `SELECT finding_id, status
       FROM findings
       WHERE finding_id = ?
       FOR UPDATE`,
      [findingId],
    );

    const findings = rows as {
      finding_id: number;
      status: FindingStatus;
    }[];

    if (findings.length === 0) {
      await connection.rollback();
      transactionStarted = false;

      return NextResponse.json(
        { success: false, error: "Finding not found." },
        { status: 404 },
      );
    }

    const currentStatus = findings[0].status;

    // Treat an unchanged status as a successful no-op.
    if (currentStatus === status) {
      await connection.commit();
      transactionStarted = false;

      return NextResponse.json({
        success: true,
        finding_id: findingId,
        status,
        message: "Finding already has this status.",
      });
    }

    // 6. Update status. The MySQL trigger records status history.
    await connection.execute(
      `UPDATE findings
       SET status = ?, updated_at = NOW()
       WHERE finding_id = ?`,
      [status, findingId],
    );

    // 7. Record the action in the audit log.
    await connection.execute(
      `INSERT INTO audit_logs
        (actor_id, action, entity_type, entity_id, details, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [
        user.id,
        "FINDING_STATUS_UPDATED",
        "finding",
        findingId,
        JSON.stringify({
          oldStatus: currentStatus,
          newStatus: status,
        }),
      ],
    );

    await connection.commit();
    transactionStarted = false;

    return NextResponse.json({
      success: true,
      finding_id: findingId,
      previous_status: currentStatus,
      status,
    });
  } catch (error) {
    if (connection && transactionStarted) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("Finding update rollback failed:", rollbackError);
      }
    }

    console.error("Finding status update failed:", error);

    return NextResponse.json(
      { success: false, error: "Failed to update finding status." },
      { status: 500 },
    );
  } finally {
    if (connection) {
      // Avoid leaking actor context if this connection is reused.
      try {
        await connection.query("SET @app_user_id = NULL");
      } catch (resetError) {
        console.error("Failed to reset MySQL actor context:", resetError);
      }

      connection.release();
    }
  }
}
