
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
    const [rows] = await pool.query(
      "SELECT DATABASE() AS database_name, VERSION() AS mysql_version",
    );

    return NextResponse.json({
      success: true,
      result: rows,
    });
  } catch (error) {
    console.error("Database connection failed:", error);

    return NextResponse.json(
      { success: false, error: "Database connection failed." },
      { status: 500 },
    );
  }
}
