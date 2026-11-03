import { cookies } from "next/headers";
import { jwtVerify } from "jose";
import pool from "@/lib/mysql";

export type UserRole = "ADMIN" | "ANALYST";

export type SessionUser = {
  id: number;
  role: UserRole;
  name: string;
};

type UserRow = {
  user_id: number;
  full_name: string;
  role: UserRole;
  is_active: number | boolean;
};

const DEFAULT_AUTH_SECRET = "credentials-secrets-monitor-pes-university-dbms-level-3-secret-key-32chars";

export async function getSessionUser(): Promise<SessionUser | null> {
  try {
    const token = (await cookies()).get("session")?.value;
    const secretValue = process.env.AUTH_SECRET ?? DEFAULT_AUTH_SECRET;

    if (!token || !secretValue || secretValue.length < 32) {
      return null;
    }

    const secret = new TextEncoder().encode(secretValue);

    const { payload } = await jwtVerify(token, secret, {
      algorithms: ["HS256"],
    });

    const id = Number(payload.sub);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return null;
    }

    const fallbackRole = (payload.role === "ADMIN" ? "ADMIN" : "ANALYST") as UserRole;
    const fallbackName = typeof payload.name === "string" ? payload.name : "Authenticated User";

    // 1. Attempt to verify user's current status and role in MySQL
    try {
      const [rows] = await pool.execute(
        `SELECT user_id, full_name, role, is_active
         FROM users
         WHERE user_id = ?
         LIMIT 1`,
        [id],
      );

      const users = rows as UserRow[];
      const user = users[0];

      if (user) {
        if (!user.is_active || (user.role !== "ADMIN" && user.role !== "ANALYST")) {
          return null;
        }

        return {
          id: user.user_id,
          role: user.role,
          name: user.full_name,
        };
      }
    } catch {
      // MySQL server is offline; fall through to verified JWT payload claims
    }

    // 2. Return cryptographically verified JWT claims
    return {
      id,
      role: fallbackRole,
      name: fallbackName,
    };
  } catch {
    // Invalid/expired token
    return null;
  }
}
