"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export type SessionUser = {
  id: number;
  role: "ADMIN" | "ANALYST";
  name: string;
};

type Finding = {
  finding_id: number;
  repository_name: string;
  repository_owner: string;
  secret_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status:
    | "OPEN"
    | "INVESTIGATING"
    | "REMEDIATION_IN_PROGRESS"
    | "RESOLVED"
    | "FALSE_POSITIVE";
  file_path: string;
  line_number: number | null;
  first_seen: string;
};

type ScanHistoryItem = {
  scanRunId: number;
  repositoryName: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  totalFindings: number;
  startedAt: string;
  completedAt: string | null;
  evidenceSummary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};

type RepositoryItem = {
  repository_id: number;
  name: string;
  source_url: string;
  owner_name: string;
  created_at: string;
  total_findings: number;
  open_findings: number;
};

type AnnotationItem = {
  scanRunId: number;
  findingId: number;
  annotatedBy: string;
  status: string;
  notes: string;
  tags?: string[];
  updatedAt: string;
};

type SqlQueryItem = {
  title: string;
  category: string;
  sql: string;
  isLiveDb: boolean;
  rows: Record<string, unknown>[];
};

const statuses: Finding["status"][] = [
  "OPEN",
  "INVESTIGATING",
  "REMEDIATION_IN_PROGRESS",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export default function DashboardClient({ user }: { user?: SessionUser }) {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<
    "findings" | "sql_console" | "nosql_rud" | "repositories" | "scans"
  >("findings");

  // Findings state
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(true);
  const [statusDrafts, setStatusDrafts] = useState<Record<number, Finding["status"]>>({});
  const [savingId, setSavingId] = useState<number | null>(null);
  const [filter, setFilter] = useState("ALL");

  // Advanced SQL queries state
  const [sqlQueries, setSqlQueries] = useState<Record<string, SqlQueryItem>>({});
  const [selectedQueryKey, setSelectedQueryKey] = useState<string>("multi_table_join");
  const [loadingQueries, setLoadingQueries] = useState(false);

  // NoSQL RUD state
  const [annotations, setAnnotations] = useState<AnnotationItem[]>([]);
  const [aggData, setAggData] = useState<Record<string, unknown>[]>([]);
  const [loadingMongo, setLoadingMongo] = useState(false);
  const [annotDraft, setAnnotDraft] = useState({
    scanRunId: "1",
    findingId: "1",
    status: "VERIFIED_EXPOSURE",
    notes: "Verified exposed token in environment configuration.",
  });

  // Repositories state
  const [repositories, setRepositories] = useState<RepositoryItem[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [newRepo, setNewRepo] = useState({ name: "", sourceUrl: "" });

  // Scan History state
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  // Global notifications
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  // Load findings
  useEffect(() => {
    async function fetchFindings() {
      setLoadingFindings(true);
      try {
        const res = await fetch("/api/findings");
        if (!res.ok) throw new Error("Failed to load findings");
        const data = await res.json();
        setFindings(data.findings ?? []);
        setStatusDrafts((prev) => {
          const next = { ...prev };
          for (const f of (data.findings ?? []) as Finding[]) {
            next[f.finding_id] ??= f.status;
          }
          return next;
        });
      } catch {
        setError("Unable to load findings.");
      } finally {
        setLoadingFindings(false);
      }
    }
    fetchFindings();
  }, [refreshKey]);

  // Load SQL queries console data
  useEffect(() => {
    if (activeTab !== "sql_console") return;
    async function fetchQueries() {
      setLoadingQueries(true);
      try {
        const res = await fetch("/api/analytics/queries");
        const data = await res.json();
        if (data.success && data.queries) {
          setSqlQueries(data.queries);
        }
      } catch {
        console.error("SQL queries load error");
      } finally {
        setLoadingQueries(false);
      }
    }
    fetchQueries();
  }, [activeTab, refreshKey]);

  // Load NoSQL RUD data
  useEffect(() => {
    if (activeTab !== "nosql_rud") return;
    async function fetchNoSql() {
      setLoadingMongo(true);
      try {
        const [resList, resAgg] = await Promise.all([
          fetch("/api/evidence-rud?mode=list"),
          fetch("/api/evidence-rud?mode=aggregate"),
        ]);
        const listData = await resList.json();
        const aggDataRes = await resAgg.json();
        if (listData.success) {
          setAnnotations(listData.annotations ?? []);
        }
        if (aggDataRes.success) {
          setAggData(aggDataRes.data ?? []);
        }
      } catch {
        console.error("NoSQL load error");
      } finally {
        setLoadingMongo(false);
      }
    }
    fetchNoSql();
  }, [activeTab, refreshKey]);

  // Load Repositories
  useEffect(() => {
    if (activeTab !== "repositories") return;
    async function fetchRepos() {
      setLoadingRepos(true);
      try {
        const res = await fetch("/api/repositories");
        const data = await res.json();
        if (data.success) {
          setRepositories(data.repositories ?? []);
        }
      } catch {
        console.error("Repositories load error");
      } finally {
        setLoadingRepos(false);
      }
    }
    fetchRepos();
  }, [activeTab, refreshKey]);

  // Load Scan History
  useEffect(() => {
    if (activeTab !== "scans") return;
    async function fetchScans() {
      setLoadingScans(true);
      try {
        const res = await fetch("/api/scan-history");
        const data = await res.json();
        if (data.success) {
          setScanHistory(data.history ?? []);
        }
      } catch {
        console.error("Scans load error");
      } finally {
        setLoadingScans(false);
      }
    }
    fetchScans();
  }, [activeTab, refreshKey]);

  async function updateStatus(findingId: number) {
    const status = statusDrafts[findingId];
    if (!status) return;
    setSavingId(findingId);
    setError("");
    setMessage("");

    try {
      const res = await fetch(`/api/findings/${findingId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Update failed");
      setMessage(`Finding #${findingId} updated to ${status}. Status history recorded.`);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Status update failed.");
    } finally {
      setSavingId(null);
    }
  }

  // Resolve via Stored Procedure `sp_resolve_finding`
  async function resolveViaStoredProcedure(findingId: number) {
    setSavingId(findingId);
    setError("");
    setMessage("");

    try {
      const res = await fetch("/api/findings/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findingId,
          actionType: "ROTATED",
          notes: "Resolved via MySQL Stored Procedure sp_resolve_finding",
          evidenceRef: "SOC-Live-Triage",
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || "Stored procedure execution failed");
      }
      setMessage(`Finding #${findingId} resolved via Stored Procedure sp_resolve_finding.`);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Stored Procedure failed.");
    } finally {
      setSavingId(null);
    }
  }

  // Trigger scan
  async function runScan() {
    setScanLoading(true);
    setError("");
    setMessage("");
    try {
      const res = await fetch("/api/scan", { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || "Scan failed");
      }
      setMessage(`Scan #${data.scanRunId} completed. ${data.findingsDetected} findings detected across ${data.filesScanned} files.`);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      setScanLoading(false);
    }
  }

  // Create/Update NoSQL Annotation
  async function saveNoSqlAnnotation() {
    setError("");
    setMessage("");
    try {
      const res = await fetch("/api/evidence-rud", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(annotDraft),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Save failed");
      setMessage("NoSQL Annotation updated in MongoDB.");
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "NoSQL write failed.");
    }
  }

  // Delete NoSQL Annotation
  async function deleteNoSqlAnnotation(scanRunId: number, findingId: number) {
    if (user?.role !== "ADMIN") {
      setError("Admin role required for NoSQL DELETE operations.");
      return;
    }
    setError("");
    setMessage("");
    try {
      const res = await fetch(`/api/evidence-rud?scanRunId=${scanRunId}&findingId=${findingId}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Delete failed");
      setMessage(`NoSQL document for finding #${findingId} deleted.`);
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed.");
    }
  }

  // Add Repository (DML INSERT)
  async function handleAddRepo(e: React.FormEvent) {
    e.preventDefault();
    if (!newRepo.name || !newRepo.sourceUrl) return;
    setError("");
    setMessage("");
    try {
      const res = await fetch("/api/repositories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newRepo),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Insert failed");
      setMessage(data.message);
      setNewRepo({ name: "", sourceUrl: "" });
      setRefreshKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Repository insert failed.");
    }
  }

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  const filteredFindings =
    filter === "ALL"
      ? findings
      : findings.filter((f) => f.severity === filter);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 pb-16">
      {/* Top Banner / Navigation */}
      <div className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-20">
        <div className="mx-auto max-w-7xl px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-cyan-400 animate-pulse" />
            <div>
              <h1 className="font-bold text-lg tracking-tight">Secrets Exposure Monitor</h1>
              <p className="text-xs text-slate-400">Enterprise Security Operations Platform</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {user && (
              <div className="flex items-center gap-2 rounded-lg bg-slate-800/80 px-3 py-1.5 border border-slate-700 text-xs">
                <span className="text-slate-300 font-medium">{user.name}</span>
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                    user.role === "ADMIN"
                      ? "bg-purple-900/80 text-purple-200 border border-purple-700/50"
                      : "bg-blue-900/80 text-blue-200 border border-blue-700/50"
                  }`}
                >
                  {user.role}
                </span>
              </div>
            )}

            {user?.role === "ADMIN" && (
              <button
                type="button"
                onClick={runScan}
                disabled={scanLoading}
                className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold hover:bg-cyan-500 disabled:opacity-50"
              >
                {scanLoading ? "Scanning..." : "⚡ Run Scan"}
              </button>
            )}

            <button
              type="button"
              onClick={handleLogout}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
            >
              Log out
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="mx-auto max-w-7xl px-6 flex space-x-1 overflow-x-auto text-sm border-t border-slate-800/60 pt-1">
          {[
            { id: "findings", label: "Findings & Triage (SQL)" },
            { id: "sql_console", label: "Advanced SQL Console" },
            { id: "nosql_rud", label: "NoSQL Evidence RUD (MongoDB)" },
            { id: "repositories", label: "Repositories (DML)" },
            { id: "scans", label: "Scan History & Audits" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-4 py-2.5 font-medium border-b-2 whitespace-nowrap transition ${
                activeTab === tab.id
                  ? "border-cyan-400 text-cyan-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 mt-6">
        {/* Alerts */}
        {message && (
          <div className="mb-4 rounded-lg border border-green-500/30 bg-green-950/40 p-3 text-sm text-green-300">
            ✓ {message}
          </div>
        )}
        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-950/40 p-3 text-sm text-red-300">
            ✕ {error}
          </div>
        )}

        {/* TAB 1: FINDINGS & TRIAGE */}
        {activeTab === "findings" && (
          <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard label="Total Findings" value={findings.length} />
              <MetricCard
                label="Open / Active"
                value={findings.filter((f) => ["OPEN", "INVESTIGATING", "REMEDIATION_IN_PROGRESS"].includes(f.status)).length}
              />
              <MetricCard
                label="Critical Severity"
                value={findings.filter((f) => f.severity === "CRITICAL").length}
              />
              <MetricCard
                label="Resolved Findings"
                value={findings.filter((f) => f.status === "RESOLVED").length}
              />
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold">Detected Secrets & Triage</h2>
                  <p className="text-xs text-slate-400">
                    Status transitions trigger database kernel auditing (`trg_finding_status_history`).
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Filter Severity:</span>
                  <select
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              {loadingFindings ? (
                <p className="py-8 text-center text-slate-400">Loading findings...</p>
              ) : filteredFindings.length === 0 ? (
                <p className="py-8 text-center text-slate-400">No findings matching current criteria.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 text-slate-400 text-xs uppercase">
                      <tr>
                        <th className="px-3 py-3">Finding / File</th>
                        <th className="px-3 py-3">Secret Type</th>
                        <th className="px-3 py-3">Severity</th>
                        <th className="px-3 py-3">Current Status</th>
                        <th className="px-3 py-3">Repo Owner</th>
                        <th className="px-3 py-3">Update Status (Trigger)</th>
                        <th className="px-3 py-3">Procedure Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {filteredFindings.map((finding) => (
                        <tr key={finding.finding_id} className="hover:bg-slate-800/40">
                          <td className="px-3 py-3">
                            <p className="font-semibold text-slate-200">
                              #{finding.finding_id} · {finding.repository_name}
                            </p>
                            <p className="text-xs text-cyan-400 font-mono mt-0.5">
                              {finding.file_path}:{finding.line_number ?? 1}
                            </p>
                          </td>
                          <td className="px-3 py-3 font-mono text-xs">{finding.secret_type}</td>
                          <td className="px-3 py-3">
                            <SeverityBadge severity={finding.severity} />
                          </td>
                          <td className="px-3 py-3 text-xs">
                            <span className="rounded bg-slate-800 px-2 py-1">
                              {finding.status.replaceAll("_", " ")}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-xs text-slate-300">{finding.repository_owner}</td>
                          <td className="px-3 py-3">
                            <div className="flex items-center gap-1.5">
                              <select
                                value={statusDrafts[finding.finding_id] ?? finding.status}
                                onChange={(e) =>
                                  setStatusDrafts((prev) => ({
                                    ...prev,
                                    [finding.finding_id]: e.target.value as Finding["status"],
                                  }))
                                }
                                disabled={savingId === finding.finding_id}
                                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
                              >
                                {statuses.map((st) => (
                                  <option key={st} value={st}>
                                    {st.replaceAll("_", " ")}
                                  </option>
                                ))}
                              </select>
                              <button
                                type="button"
                                onClick={() => updateStatus(finding.finding_id)}
                                disabled={savingId === finding.finding_id || statusDrafts[finding.finding_id] === finding.status}
                                className="rounded bg-cyan-600 px-2 py-1 text-xs font-semibold hover:bg-cyan-500 disabled:opacity-40"
                              >
                                Save
                              </button>
                            </div>
                          </td>
                          <td className="px-3 py-3">
                            {finding.status !== "RESOLVED" && (
                              <button
                                type="button"
                                onClick={() => resolveViaStoredProcedure(finding.finding_id)}
                                disabled={savingId === finding.finding_id}
                                className="rounded bg-emerald-700 hover:bg-emerald-600 px-2.5 py-1 text-xs font-semibold text-white disabled:opacity-40"
                                title="Executes MySQL stored procedure sp_resolve_finding"
                              >
                                ⚡ SP Resolve
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: ADVANCED SQL CONSOLE */}
        {activeTab === "sql_console" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <h2 className="text-xl font-bold">Advanced SQL Queries & Analytics Console</h2>
              <p className="text-xs text-slate-400 mt-1">
                Execute and analyze Multi-Table Joins, Nested Subqueries, Correlated Subqueries, Recursive CTEs, and Stored Procedures & Functions.
              </p>

              {/* Query selector pills */}
              <div className="mt-4 flex flex-wrap gap-2">
                {[
                  { key: "multi_table_join", label: "1. 4-Table JOIN" },
                  { key: "nested_query", label: "2. Nested Subquery" },
                  { key: "correlated_subquery", label: "3. Correlated Subquery" },
                  { key: "recursive_cte", label: "4. WITH RECURSIVE (SLA Ladder)" },
                  { key: "stored_objects", label: "5. Procedure & Function" },
                ].map((item) => (
                  <button
                    key={item.key}
                    onClick={() => setSelectedQueryKey(item.key)}
                    className={`rounded-lg px-3 py-2 text-xs font-medium border transition ${
                      selectedQueryKey === item.key
                        ? "bg-cyan-950 border-cyan-400 text-cyan-300"
                        : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {loadingQueries ? (
              <p className="py-8 text-center text-slate-400">Executing database query...</p>
            ) : sqlQueries[selectedQueryKey] ? (
              <div className="space-y-4">
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <span className="rounded bg-cyan-900/60 text-cyan-300 px-2 py-0.5 text-[11px] font-semibold border border-cyan-700/50 uppercase">
                        {sqlQueries[selectedQueryKey].category}
                      </span>
                      <h3 className="text-base font-bold text-slate-100 mt-1.5">
                        {sqlQueries[selectedQueryKey].title}
                      </h3>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">
                      Target Engine: MySQL 8.0+
                    </span>
                  </div>

                  <pre className="rounded-lg bg-slate-950 p-4 text-xs font-mono text-cyan-300 overflow-x-auto border border-slate-800/80 leading-5">
                    {sqlQueries[selectedQueryKey].sql}
                  </pre>
                </div>

                {/* Query Result Dataset */}
                <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                  <h4 className="text-sm font-semibold text-slate-200 mb-3">Query Execution Output</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono">
                        <tr>
                          {Object.keys(sqlQueries[selectedQueryKey].rows[0] ?? {}).map((col) => (
                            <th key={col} className="px-3 py-2.5">
                              {col}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 font-mono">
                        {sqlQueries[selectedQueryKey].rows.map((row, idx) => (
                          <tr key={idx} className="hover:bg-slate-800/40">
                            {Object.values(row).map((val, cIdx) => (
                              <td key={cIdx} className="px-3 py-2.5 text-slate-300">
                                {val === null ? <span className="text-slate-600">NULL</span> : String(val)}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        )}

        {/* TAB 3: NOSQL EVIDENCE RUD (MONGODB) */}
        {activeTab === "nosql_rud" && (
          <div className="space-y-6">
            <div className="grid gap-4 lg:grid-cols-3">
              {/* NoSQL Explanation & Justification */}
              <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-5">
                <div className="flex items-center justify-between mb-2">
                  <h2 className="text-xl font-bold">MongoDB Evidence RUD & Aggregation Pipeline</h2>
                  <span className="rounded bg-emerald-900/60 text-emerald-300 px-2 py-0.5 text-xs font-bold border border-emerald-700/50">
                    MongoDB Document Store
                  </span>
                </div>
                <p className="text-xs text-slate-400 mb-4">
                  Demonstrates <strong>Read</strong>, <strong>Update/Create</strong>, and <strong>Delete</strong> on semi-structured evidence collections (`scan_evidence` and `evidence_annotations`) with JSON Schema Validation and Aggregation Pipeline analytics.
                </p>

                {/* Aggregation Pipeline Results */}
                <h3 className="text-sm font-semibold text-slate-200 mb-2">
                  Aggregation Pipeline ($unwind ➔ $match ➔ $group ➔ $project)
                </h3>
                <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-slate-400 font-mono">
                      <tr>
                        <th className="px-2 py-2">Secret Type</th>
                        <th className="px-2 py-2">Total Exposures</th>
                        <th className="px-2 py-2">Unique Files</th>
                        <th className="px-2 py-2">Scans Seen In</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {aggData.map((item, idx) => (
                        <tr key={idx}>
                          <td className="px-2 py-2 text-cyan-300">{String(item.secretType)}</td>
                          <td className="px-2 py-2 font-bold">{String(item.totalExposures)}</td>
                          <td className="px-2 py-2">{String(item.fileCount)}</td>
                          <td className="px-2 py-2">{String(item.scanCount)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* NoSQL Form: Create / Update Annotation */}
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                <h3 className="text-sm font-bold text-slate-100 mb-2">NoSQL Update / Upsert Annotation</h3>
                <p className="text-xs text-slate-400 mb-4">Update analyst annotations on evidence in MongoDB.</p>

                <div className="space-y-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">Scan Run ID</label>
                    <input
                      type="number"
                      value={annotDraft.scanRunId}
                      onChange={(e) => setAnnotDraft({ ...annotDraft, scanRunId: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Finding ID</label>
                    <input
                      type="number"
                      value={annotDraft.findingId}
                      onChange={(e) => setAnnotDraft({ ...annotDraft, findingId: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Verification Status</label>
                    <select
                      value={annotDraft.status}
                      onChange={(e) => setAnnotDraft({ ...annotDraft, status: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5"
                    >
                      <option value="VERIFIED_EXPOSURE">VERIFIED_EXPOSURE</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                      <option value="NEEDS_TRIAGE">NEEDS_TRIAGE</option>
                      <option value="RESOLVED_VERIFIED">RESOLVED_VERIFIED</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Notes</label>
                    <textarea
                      rows={2}
                      value={annotDraft.notes}
                      onChange={(e) => setAnnotDraft({ ...annotDraft, notes: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-1.5"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={saveNoSqlAnnotation}
                    className="w-full rounded bg-emerald-600 hover:bg-emerald-500 py-2 font-semibold text-white"
                  >
                    Save Annotation (NoSQL Upsert)
                  </button>
                </div>
              </div>
            </div>

            {/* List of Existing MongoDB Annotations with DELETE */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <h3 className="text-base font-bold text-slate-100 mb-3">
                MongoDB Evidence Annotations (READ & DELETE)
              </h3>
              {loadingMongo ? (
                <p className="py-6 text-slate-400 text-center">Loading MongoDB documents...</p>
              ) : annotations.length === 0 ? (
                <p className="py-6 text-slate-400 text-center">No annotations currently stored.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-slate-400 font-mono uppercase">
                      <tr>
                        <th className="px-3 py-2.5">Scan / Finding</th>
                        <th className="px-3 py-2.5">Annotator</th>
                        <th className="px-3 py-2.5">Tag / Status</th>
                        <th className="px-3 py-2.5">Analyst Notes</th>
                        <th className="px-3 py-2.5">Last Updated</th>
                        <th className="px-3 py-2.5">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {annotations.map((ann, i) => (
                        <tr key={i} className="hover:bg-slate-800/40">
                          <td className="px-3 py-2.5 font-mono">
                            Scan #{ann.scanRunId} · Finding #{ann.findingId}
                          </td>
                          <td className="px-3 py-2.5">{ann.annotatedBy}</td>
                          <td className="px-3 py-2.5">
                            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                              {ann.status}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-slate-300">{ann.notes}</td>
                          <td className="px-3 py-2.5 text-slate-400">
                            {new Date(ann.updatedAt).toLocaleDateString()}
                          </td>
                          <td className="px-3 py-2.5">
                            <button
                              type="button"
                              onClick={() => deleteNoSqlAnnotation(ann.scanRunId, ann.findingId)}
                              className="rounded bg-red-900/60 hover:bg-red-800 border border-red-700/50 px-2 py-1 text-[11px] text-red-200 font-semibold"
                            >
                              Delete (D)
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: REPOSITORIES (DML OPERATIONS) */}
        {activeTab === "repositories" && (
          <div className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-3">
              {/* Repositories List */}
              <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-xl font-bold">Managed Repositories</h2>
                    <p className="text-xs text-slate-400">Relational DML: Select, Insert, Delete with Referential Integrity.</p>
                  </div>
                  <span className="rounded bg-cyan-900/60 text-cyan-300 px-2 py-0.5 text-xs font-bold border border-cyan-700/50">
                    Relational Schema
                  </span>
                </div>

                {loadingRepos ? (
                  <p className="py-8 text-center text-slate-400">Loading repositories...</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono">
                        <tr>
                          <th className="px-3 py-2.5">Repository</th>
                          <th className="px-3 py-2.5">Source URL</th>
                          <th className="px-3 py-2.5">Owner</th>
                          <th className="px-3 py-2.5">Total Findings</th>
                          <th className="px-3 py-2.5">Open</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {repositories.map((repo) => (
                          <tr key={repo.repository_id} className="hover:bg-slate-800/40">
                            <td className="px-3 py-2.5 font-semibold text-slate-200">
                              #{repo.repository_id} · {repo.name}
                            </td>
                            <td className="px-3 py-2.5 font-mono text-cyan-400 truncate max-w-[200px]">
                              {repo.source_url}
                            </td>
                            <td className="px-3 py-2.5 text-slate-300">{repo.owner_name}</td>
                            <td className="px-3 py-2.5 font-mono">{repo.total_findings ?? 0}</td>
                            <td className="px-3 py-2.5 font-mono font-bold text-amber-400">
                              {repo.open_findings ?? 0}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Add Repository Form (DML INSERT) */}
              <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
                <h3 className="text-base font-bold text-slate-100 mb-2">Register Repository (DML INSERT)</h3>
                <p className="text-xs text-slate-400 mb-4">
                  Adds a new relational record linked to the authenticated user foreign key (`owner_id`).
                </p>

                <form onSubmit={handleAddRepo} className="space-y-4 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1">Repository Name</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. auth-gateway-service"
                      value={newRepo.name}
                      onChange={(e) => setNewRepo({ ...newRepo, name: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Git Source URL</label>
                    <input
                      type="url"
                      required
                      placeholder="https://github.com/org/repo.git"
                      value={newRepo.sourceUrl}
                      onChange={(e) => setNewRepo({ ...newRepo, sourceUrl: e.target.value })}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-200"
                    />
                  </div>
                  <button
                    type="submit"
                    className="w-full rounded bg-cyan-600 hover:bg-cyan-500 py-2.5 font-semibold text-white"
                  >
                    + Insert Repository (SQL DML)
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: SCAN RUNS & HISTORY */}
        {activeTab === "scans" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-xl font-bold">Scan Executions & Evidence Summary</h2>
                  <p className="text-xs text-slate-400">
                    Dual-database persistence: Scan lifecycle logged in MySQL `scan_runs` and masked tokens in MongoDB `scan_evidence`.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setRefreshKey((k) => k + 1)}
                  className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800"
                >
                  Refresh
                </button>
              </div>

              {loadingScans ? (
                <p className="py-8 text-center text-slate-400">Loading scan history...</p>
              ) : scanHistory.length === 0 ? (
                <p className="py-8 text-center text-slate-400">No scans executed yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono">
                      <tr>
                        <th className="px-3 py-2.5">Scan Run</th>
                        <th className="px-3 py-2.5">Target Repo</th>
                        <th className="px-3 py-2.5">Status</th>
                        <th className="px-3 py-2.5">Total Findings</th>
                        <th className="px-3 py-2.5">Severity Breakdown (MongoDB)</th>
                        <th className="px-3 py-2.5">Started</th>
                        <th className="px-3 py-2.5">Completed</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {scanHistory.map((scan) => (
                        <tr key={scan.scanRunId} className="hover:bg-slate-800/40">
                          <td className="px-3 py-2.5 font-bold text-slate-200">#{scan.scanRunId}</td>
                          <td className="px-3 py-2.5">{scan.repositoryName}</td>
                          <td className="px-3 py-2.5">
                            <span
                              className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                                scan.status === "COMPLETED"
                                  ? "bg-green-950 text-green-300 border border-green-700/50"
                                  : "bg-amber-950 text-amber-300 border border-amber-700/50"
                              }`}
                            >
                              {scan.status}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 font-bold">{scan.totalFindings}</td>
                          <td className="px-3 py-2.5 text-[11px] leading-5">
                            <span className="text-red-400">Critical: {scan.evidenceSummary.critical}</span> ·{" "}
                            <span className="text-orange-400">High: {scan.evidenceSummary.high}</span> ·{" "}
                            <span className="text-blue-400">Med: {scan.evidenceSummary.medium}</span>
                          </td>
                          <td className="px-3 py-2.5 text-slate-400">
                            {new Date(scan.startedAt).toLocaleString()}
                          </td>
                          <td className="px-3 py-2.5 text-slate-400">
                            {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-bold tracking-tight text-white">{value}</p>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  const styles = {
    LOW: "bg-slate-800 text-slate-300 border-slate-700",
    MEDIUM: "bg-blue-950 text-blue-300 border-blue-800",
    HIGH: "bg-orange-950 text-orange-300 border-orange-800",
    CRITICAL: "bg-red-950 text-red-300 border-red-800",
  };

  return (
    <span className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold border ${styles[severity]}`}>
      {severity}
    </span>
  );
}
