
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

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

type ScanEvidence = {
  scanRunId: number;
  repositoryName: string;
  scanner: string;
  findingsSummary: {
    total: number;
    high: number;
    medium: number;
    low: number;
    critical?: number;
  };
  evidence: {
    findingId: number;
    filePath: string;
    lineNumber: number;
    secretType: string;
    maskedPreview: string;
  }[];
  createdAt: string;
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
  evidenceCreatedAt: string | null;
};

type ScanHistoryResponse = {
  success: boolean;
  totals: {
    totalScans: number;
    completed: number;
    failed: number;
    running: number;
  };
  history: ScanHistoryItem[];
};

const statuses: Finding["status"][] = [
  "OPEN",
  "INVESTIGATING",
  "REMEDIATION_IN_PROGRESS",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export default function Dashboard() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanEvidence, setScanEvidence] = useState<ScanEvidence[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  const [historyTotals, setHistoryTotals] =
    useState<ScanHistoryResponse["totals"]>({
      totalScans: 0,
      completed: 0,
      failed: 0,
      running: 0,
    });

  const [evidenceLoading, setEvidenceLoading] = useState(true);
  const [evidenceError, setEvidenceError] = useState("");
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState("");

  const [statusDrafts, setStatusDrafts] = useState<
    Record<number, Finding["status"]>
  >({});

  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [refreshKey, setRefreshKey] = useState(0);

  // Load findings from MySQL.
  useEffect(() => {
    let cancelled = false;

    async function loadFindings() {
      setLoading(true);
      setError("");

      try {
        const response = await fetch("/api/findings");

        if (!response.ok) {
          throw new Error("Could not load findings");
        }

        const data = await response.json();

        if (cancelled) return;

        setFindings(data.findings ?? []);

        setStatusDrafts((previous) => {
          const next = { ...previous };

          for (const finding of data.findings as Finding[]) {
            next[finding.finding_id] ??= finding.status;
          }

          return next;
        });
      } catch {
        if (!cancelled) {
          setError("Unable to load findings. Please try again.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  // Load scan evidence from MongoDB.
  useEffect(() => {
    let cancelled = false;

    async function loadScanEvidence() {
      setEvidenceLoading(true);
      setEvidenceError("");

      try {
        const response = await fetch("/api/scan-evidence");

        if (!response.ok) {
          throw new Error("Could not load scan evidence");
        }

        const data = await response.json();

        if (!cancelled) {
          setScanEvidence(data.evidence ?? []);
        }
      } catch {
        if (!cancelled) {
          setEvidenceError("Unable to load MongoDB scan evidence.");
        }
      } finally {
        if (!cancelled) {
          setEvidenceLoading(false);
        }
      }
    }

    loadScanEvidence();

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  // Load scan history from MySQL and MongoDB.
  useEffect(() => {
    let cancelled = false;

    async function loadScanHistory() {
      setHistoryLoading(true);
      setHistoryError("");

      try {
        const response = await fetch("/api/scan-history");

        if (!response.ok) {
          throw new Error("Could not load scan history");
        }

        const data: ScanHistoryResponse = await response.json();

        if (!data.success) {
          throw new Error("Scan history request failed");
        }

        if (!cancelled) {
          setScanHistory(data.history ?? []);
          setHistoryTotals(
            data.totals ?? {
              totalScans: 0,
              completed: 0,
              failed: 0,
              running: 0,
            },
          );
        }
      } catch {
        if (!cancelled) {
          setHistoryError("Unable to load scan history.");
        }
      } finally {
        if (!cancelled) {
          setHistoryLoading(false);
        }
      }
    }

    loadScanHistory();

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  async function logout() {
    setLogoutLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await fetch("/api/auth/logout", {
        method: "POST",
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Logout failed. Please try again.");
      }

      router.replace("/login");
      router.refresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to log out. Please try again.",
      );
      setLogoutLoading(false);
    }
  }

  async function runScan() {
    setScanLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Scan failed. Please try again.");
      }

      setMessage(
        `Scan #${data.scanRunId} completed successfully. ` +
          `${data.findingsDetected} findings detected across ` +
          `${data.filesScanned} files.`,
      );

      // Refresh findings, scan evidence, and scan history.
      setRefreshKey((key) => key + 1);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to run the scan. Please try again.",
      );
    } finally {
      setScanLoading(false);
    }
  }

  async function updateStatus(findingId: number) {
    const status = statusDrafts[findingId];
    if (!status) return;

    setSavingId(findingId);
    setError("");
    setMessage("");

    try {
      const response = await fetch(`/api/findings/${findingId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Status update failed");
      }

      setMessage(`Finding #${findingId} updated to ${status}.`);
      setRefreshKey((key) => key + 1);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Status update failed.",
      );
    } finally {
      setSavingId(null);
    }
  }

  const filteredFindings =
    filter === "ALL"
      ? findings
      : findings.filter((finding) => finding.severity === filter);

  const openCount = findings.filter((finding) =>
    ["OPEN", "INVESTIGATING", "REMEDIATION_IN_PROGRESS"].includes(
      finding.status,
    ),
  ).length;

  const criticalCount = findings.filter(
    (finding) => finding.severity === "CRITICAL",
  ).length;

  const resolvedCount = findings.filter(
    (finding) => finding.status === "RESOLVED",
  ).length;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-10">
        <header className="mb-10 flex flex-wrap items-center justify-between gap-5">
          <div>
            <p className="mb-2 text-sm font-medium text-cyan-400">
              SECURITY OPERATIONS
            </p>

            <h1 className="text-3xl font-bold tracking-tight">
              Secrets Exposure Monitor
            </h1>

            <p className="mt-2 text-slate-400">
              Monitor exposed credentials and track their remediation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={runScan}
              disabled={scanLoading}
              className="rounded-lg bg-cyan-600 px-5 py-3 text-sm font-semibold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scanLoading ? "Scanning..." : "Run Scan"}
            </button>

            <button
              type="button"
              onClick={logout}
              disabled={logoutLoading}
              className="rounded-lg border border-slate-700 px-5 py-3 text-sm font-semibold text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {logoutLoading ? "Logging out..." : "Log out"}
            </button>
          </div>
        </header>

        {/* Dashboard metrics */}
        <section className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Total Findings" value={findings.length} />
          <Metric label="Open Findings" value={openCount} />
          <Metric label="Critical Findings" value={criticalCount} />
          <Metric label="Resolved Findings" value={resolvedCount} />
        </section>

        {/* Detected findings */}
        <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold">Detected Findings</h2>
              <p className="mt-1 text-sm text-slate-400">
                Repository-level exposure records
              </p>
            </div>

            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2"
              aria-label="Filter by severity"
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {message && (
            <p role="status" className="mb-4 text-sm text-green-400">
              {message}
            </p>
          )}

          {error && (
            <p role="alert" className="mb-4 text-sm text-red-400">
              {error}
            </p>
          )}

          {loading && (
            <p className="py-8 text-slate-400">Loading findings...</p>
          )}

          {!loading && filteredFindings.length === 0 && (
            <p className="py-8 text-slate-400">
              No findings match this filter.
            </p>
          )}

          {!loading && filteredFindings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-3 py-3">Repository / File</th>
                    <th className="px-3 py-3">Secret Type</th>
                    <th className="px-3 py-3">Severity</th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-3 py-3">Owner</th>
                    <th className="px-3 py-3">Update Status</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.finding_id}
                      className="border-b border-slate-800 last:border-0"
                    >
                      <td className="px-3 py-4">
                        <p className="font-medium">
                          {finding.repository_name}
                        </p>
                        <p className="mt-1 text-xs text-slate-400">
                          {finding.file_path}
                          {finding.line_number != null
                            ? `:${finding.line_number}`
                            : ""}
                        </p>
                      </td>

                      <td className="px-3 py-4">{finding.secret_type}</td>

                      <td className="px-3 py-4">
                        <Severity severity={finding.severity} />
                      </td>

                      <td className="px-3 py-4">
                        {finding.status.replaceAll("_", " ")}
                      </td>

                      <td className="px-3 py-4">
                        {finding.repository_owner}
                      </td>

                      <td className="px-3 py-4">
                        <div className="flex min-w-56 flex-col gap-2">
                          <select
                            value={
                              statusDrafts[finding.finding_id] ??
                              finding.status
                            }
                            onChange={(event) =>
                              setStatusDrafts((previous) => ({
                                ...previous,
                                [finding.finding_id]: event.target
                                  .value as Finding["status"],
                              }))
                            }
                            disabled={savingId === finding.finding_id}
                            className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-xs"
                            aria-label={`New status for finding ${finding.finding_id}`}
                          >
                            {statuses.map((status) => (
                              <option key={status} value={status}>
                                {status.replaceAll("_", " ")}
                              </option>
                            ))}
                          </select>

                          <button
                            type="button"
                            onClick={() => updateStatus(finding.finding_id)}
                            disabled={
                              savingId === finding.finding_id ||
                              (statusDrafts[finding.finding_id] ??
                                finding.status) === finding.status
                            }
                            className="rounded-lg bg-cyan-600 px-3 py-2 text-xs font-semibold text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {savingId === finding.finding_id
                              ? "Saving..."
                              : "Update status"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Scan History and Analytics */}
        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold">
                Scan History & Analytics
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                Historical scan status from MySQL and evidence summaries
                from MongoDB.
              </p>
            </div>

            <button
              type="button"
              onClick={() => setRefreshKey((key) => key + 1)}
              disabled={historyLoading}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm hover:bg-slate-800 disabled:opacity-50"
            >
              {historyLoading ? "Refreshing..." : "Refresh History"}
            </button>
          </div>

          <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Metric label="Total Scans" value={historyTotals.totalScans} />
            <Metric label="Completed" value={historyTotals.completed} />
            <Metric label="Failed" value={historyTotals.failed} />
            <Metric label="Running" value={historyTotals.running} />
          </div>

          {historyError && (
            <p role="alert" className="py-4 text-red-400">
              {historyError}
            </p>
          )}

          {historyLoading && (
            <p className="py-4 text-slate-400">Loading scan history...</p>
          )}

          {!historyLoading &&
            !historyError &&
            scanHistory.length === 0 && (
              <p className="py-4 text-slate-400">
                No scan history found.
              </p>
            )}

          {!historyLoading &&
            !historyError &&
            scanHistory.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="px-3 py-3">Scan</th>
                      <th className="px-3 py-3">Repository</th>
                      <th className="px-3 py-3">Status</th>
                      <th className="px-3 py-3">Findings</th>
                      <th className="px-3 py-3">Severity Breakdown</th>
                      <th className="px-3 py-3">Started</th>
                      <th className="px-3 py-3">Completed</th>
                    </tr>
                  </thead>

                  <tbody>
                    {scanHistory.map((scan) => (
                      <tr
                        key={scan.scanRunId}
                        className="border-b border-slate-800 last:border-0"
                      >
                        <td className="px-3 py-4 font-medium">
                          #{scan.scanRunId}
                        </td>

                        <td className="px-3 py-4">
                          {scan.repositoryName}
                        </td>

                        <td className="px-3 py-4">
                          <span
                            className={`rounded-full px-2 py-1 text-xs font-semibold ${
                              scan.status === "COMPLETED"
                                ? "bg-green-950 text-green-300"
                                : scan.status === "FAILED"
                                  ? "bg-red-950 text-red-300"
                                  : "bg-yellow-950 text-yellow-300"
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>

                        <td className="px-3 py-4">
                          {scan.totalFindings}
                        </td>

                        <td className="px-3 py-4 text-xs leading-6">
                          <span className="text-red-300">
                            Critical: {scan.evidenceSummary.critical}
                          </span>
                          <br />
                          <span className="text-orange-300">
                            High: {scan.evidenceSummary.high}
                          </span>
                          <br />
                          <span className="text-blue-300">
                            Medium: {scan.evidenceSummary.medium}
                          </span>
                          <br />
                          <span className="text-slate-400">
                            Low: {scan.evidenceSummary.low}
                          </span>
                        </td>

                        <td className="px-3 py-4 text-xs text-slate-400">
                          {new Date(scan.startedAt).toLocaleString()}
                        </td>

                        <td className="px-3 py-4 text-xs text-slate-400">
                          {scan.completedAt
                            ? new Date(scan.completedAt).toLocaleString()
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </section>

        {/* MongoDB Scan Evidence */}
        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="mb-5">
            <h2 className="text-xl font-semibold">Scan Evidence</h2>
            <p className="mt-1 text-sm text-slate-400">
              Flexible scan metadata and masked evidence stored in MongoDB.
            </p>
          </div>

          {evidenceLoading && (
            <p className="py-4 text-slate-400">
              Loading scan evidence...
            </p>
          )}

          {evidenceError && (
            <p role="alert" className="py-4 text-red-400">
              {evidenceError}
            </p>
          )}

          {!evidenceLoading &&
            !evidenceError &&
            scanEvidence.length === 0 && (
              <p className="py-4 text-slate-400">
                No scan evidence found.
              </p>
            )}

          {!evidenceLoading &&
            !evidenceError &&
            scanEvidence.map((scan) => (
              <div
                key={scan.scanRunId}
                className="mb-4 rounded-lg border border-slate-800 p-4 last:mb-0"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="font-semibold">
                      {scan.repositoryName}
                    </h3>
                    <p className="mt-1 text-xs text-slate-400">
                      Scanner: {scan.scanner} · Scan #{scan.scanRunId}
                    </p>
                  </div>

                  <p className="text-xs text-slate-400">
                    {new Date(scan.createdAt).toLocaleString()}
                  </p>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
                  <Metric label="Total" value={scan.findingsSummary.total} />
                  <Metric
                    label="Critical"
                    value={scan.findingsSummary.critical ?? 0}
                  />
                  <Metric label="High" value={scan.findingsSummary.high} />
                  <Metric label="Medium" value={scan.findingsSummary.medium} />
                  <Metric label="Low" value={scan.findingsSummary.low} />
                </div>

                <div className="mt-4 space-y-3">
                  {scan.evidence.map((item) => (
                    <div
                      key={`${scan.scanRunId}-${item.findingId}`}
                      className="rounded-lg bg-slate-950 p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium">
                          {item.secretType}
                        </span>
                        <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-300">
                          Finding #{item.findingId}
                        </span>
                      </div>

                      <p className="mt-2 break-all text-sm text-slate-300">
                        {item.filePath}:{item.lineNumber}
                      </p>

                      <p className="mt-2 break-all font-mono text-sm text-cyan-300">
                        {item.maskedPreview}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
        </section>

        <footer className="mt-6 text-xs text-slate-500">
          Development dashboard · Findings from MySQL · Scan evidence from
          MongoDB
        </footer>
      </div>
    </main>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-3 text-3xl font-bold">{value}</p>
    </div>
  );
}

function Severity({ severity }: { severity: Finding["severity"] }) {
  const styles = {
    LOW: "bg-slate-800 text-slate-300",
    MEDIUM: "bg-blue-950 text-blue-300",
    HIGH: "bg-orange-950 text-orange-300",
    CRITICAL: "bg-red-950 text-red-300",
  };

  return (
    <span
      className={`inline-block rounded-full px-3 py-1 text-xs font-semibold ${styles[severity]}`}
    >
      {severity}
    </span>
  );
}
