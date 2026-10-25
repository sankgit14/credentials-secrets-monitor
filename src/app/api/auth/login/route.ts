
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { SignJWT } from "jose";
import pool from "@/lib/mysql";


const SESSION_DURATION = "8h";

export async function POST(request: NextRequest) {
  try {
    let body: unknown;

try {
  body = await request.json();
} catch {
  return NextResponse.json(
    { success: false, error: "Invalid JSON request body." },
    { status: 400 },
  );
}

if (typeof body !== "object" || body === null || Array.isArray(body)) {
  return NextResponse.json(
    { success: false, error: "Invalid request body." },
    { status: 400 },
  );
}

const data = body as Record<string, unknown>;
  const email =
  typeof data.email === "string" ? data.email.trim().toLowerCase() : "";

const password =
  typeof data.password === "string" ? data.password : "";

    if (
      !email ||
      !password ||
      email.length > 254 ||
      password.length > 128
    ) {
      return NextResponse.json(
        { success: false, error: "Enter a valid email and password." },
        { status: 400 },
      );
    }

    const [rows] = await pool.execute(
      `SELECT user_id, full_name, email, password_hash, role, is_active
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email],
    );

    const users = rows as {
      user_id: number;
      full_name: string;
      email: string;
      password_hash: string;
      role: "ADMIN" | "ANALYST";
      is_active: number;
    }[];

    const user = users[0];

    // Use the same response for invalid users and passwords.
    if (
      !user ||
      !user.is_active ||
      !user.password_hash.startsWith("$2") ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return NextResponse.json(
        { success: false, error: "Invalid email or password." },
        { status: 401 },
      );
    }

    const secretValue = process.env.AUTH_SECRET;

    if (!secretValue || secretValue.length < 32) {
      console.error("AUTH_SECRET is missing or too short.");
      return NextResponse.json(
        { success: false, error: "Authentication is not configured." },
        { status: 500 },
      );
    }

    const secret = new TextEncoder().encode(secretValue);

    const token = await new SignJWT({
      role: user.role,
      name: user.full_name,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(String(user.user_id))
      .setIssuedAt()
      .setExpirationTime(SESSION_DURATION)
      .sign(secret);

    const response = NextResponse.json({
      success: true,
      user: {
        id: user.user_id,
        name: user.full_name,
        email: user.email,
        role: user.role,
      },
    });

    response.cookies.set("session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 8 * 60 * 60,
    });

    return response;
  } catch (error) {
    console.error("Login failed:", error);

    return NextResponse.json(
      { success: false, error: "Unable to sign in right now." },
      { status: 500 },
    );
  }
}
