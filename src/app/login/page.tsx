"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();

  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("Admin@123");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "same-origin",
        body: JSON.stringify({ email, password }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        setError(result.error ?? "Login failed. Check your credentials.");
        return;
      }

      router.replace("/");
      router.refresh();
    } catch {
      setError("Unable to connect to the server. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function selectDemoAccount(demoEmail: string, demoPass: string) {
    setEmail(demoEmail);
    setPassword(demoPass);
    setError("");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10 text-white">
      <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-xl">
        <div className="mb-6">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
            Security Operations Platform
          </p>

          <h1 className="mt-2 text-2xl font-bold">
            Secrets Exposure Monitor
          </h1>

          <p className="mt-2 text-xs leading-5 text-slate-400">
            Enterprise credentials exposure monitoring with Polyglot Persistence (MySQL 8.0 + MongoDB).
          </p>
        </div>

        {/* Demo Role Selector */}
        <div className="mb-6 rounded-lg border border-slate-800 bg-slate-950 p-3">
          <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Demo Credentials (RBAC)
          </p>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => selectDemoAccount("admin@example.com", "Admin@123")}
              className={`rounded border px-2.5 py-1.5 text-left text-xs transition ${
                email === "admin@example.com"
                  ? "border-cyan-400 bg-cyan-950/40 text-cyan-200"
                  : "border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-700"
              }`}
            >
              <span className="font-bold block text-purple-300">ADMIN</span>
              <span className="text-[10px] text-slate-400">admin@example.com</span>
            </button>

            <button
              type="button"
              onClick={() => selectDemoAccount("analyst@example.com", "Analyst@123")}
              className={`rounded border px-2.5 py-1.5 text-left text-xs transition ${
                email === "analyst@example.com"
                  ? "border-cyan-400 bg-cyan-950/40 text-cyan-200"
                  : "border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-700"
              }`}
            >
              <span className="font-bold block text-blue-300">ANALYST</span>
              <span className="text-[10px] text-slate-400">analyst@example.com</span>
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="email"
              className="mb-1.5 block text-xs font-medium text-slate-300"
            >
              Email address
            </label>

            <input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400"
              placeholder="you@example.com"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="mb-1.5 block text-xs font-medium text-slate-300"
            >
              Password
            </label>

            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400"
              placeholder="Enter your password"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-cyan-500 py-2.5 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:opacity-60 text-sm"
          >
            {loading ? "Signing in..." : "Sign in to Dashboard"}
          </button>
        </form>

        <p className="mt-5 text-center text-[11px] text-slate-500">
          Role-Based Access Control enforced at database and API layers.
        </p>
      </section>
    </main>
  );
}
