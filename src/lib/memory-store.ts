// In-memory fallback repository for findings, status history, and scan history
// Used when local MySQL or MongoDB daemons are offline or not yet initialized

export type InMemoryFinding = {
  finding_id: number;
  repository_id: number;
  repository_name: string;
  repository_owner: string;
  secret_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "REMEDIATION_IN_PROGRESS" | "RESOLVED" | "FALSE_POSITIVE";
  file_path: string;
  line_number: number | null;
  first_seen: string;
};

export type InMemoryScan = {
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

const INITIAL_FINDINGS: InMemoryFinding[] = [
  {
    finding_id: 1,
    repository_id: 1,
    repository_name: "demo-payment-service",
    repository_owner: "Security Admin",
    secret_type: "AWS_ACCESS_KEY_ID",
    severity: "CRITICAL",
    status: "OPEN",
    file_path: "config/settings.py",
    line_number: 5,
    first_seen: "2026-10-01T10:01:00Z",
  },
  {
    finding_id: 2,
    repository_id: 1,
    repository_name: "demo-payment-service",
    repository_owner: "Security Admin",
    secret_type: "API_KEY",
    severity: "HIGH",
    status: "INVESTIGATING",
    file_path: "config/settings.py",
    line_number: 4,
    first_seen: "2026-10-01T10:01:05Z",
  },
  {
    finding_id: 3,
    repository_id: 1,
    repository_name: "demo-payment-service",
    repository_owner: "Security Admin",
    secret_type: "DATABASE_URL",
    severity: "HIGH",
    status: "RESOLVED",
    file_path: "config/settings.py",
    line_number: 6,
    first_seen: "2026-10-01T10:01:10Z",
  },
  {
    finding_id: 4,
    repository_id: 2,
    repository_name: "auth-identity-provider",
    repository_owner: "SOC Analyst Lead",
    secret_type: "TOKEN",
    severity: "CRITICAL",
    status: "REMEDIATION_IN_PROGRESS",
    file_path: "src/auth/jwt.service.ts",
    line_number: 42,
    first_seen: "2026-10-02T14:02:00Z",
  },
  {
    finding_id: 5,
    repository_id: 2,
    repository_name: "auth-identity-provider",
    repository_owner: "SOC Analyst Lead",
    secret_type: "PASSWORD",
    severity: "MEDIUM",
    status: "FALSE_POSITIVE",
    file_path: "docker-compose.yml",
    line_number: 14,
    first_seen: "2026-10-02T14:02:15Z",
  },
  {
    finding_id: 6,
    repository_id: 3,
    repository_name: "cloud-infrastructure-iac",
    repository_owner: "Security Admin",
    secret_type: "AWS_ACCESS_KEY_ID",
    severity: "CRITICAL",
    status: "OPEN",
    file_path: "terraform/variables.tf",
    line_number: 28,
    first_seen: "2026-10-03T16:03:00Z",
  },
];

declare global {
  var _inMemoryFindings: InMemoryFinding[] | undefined;
  var _inMemoryScans: InMemoryScan[] | undefined;
}

if (!global._inMemoryFindings) {
  global._inMemoryFindings = [...INITIAL_FINDINGS];
}

if (!global._inMemoryScans) {
  global._inMemoryScans = [
    {
      scanRunId: 1,
      repositoryName: "demo-payment-service",
      status: "COMPLETED",
      totalFindings: 3,
      startedAt: "2026-10-01T10:00:00Z",
      completedAt: "2026-10-01T10:02:15Z",
      evidenceSummary: { total: 3, critical: 1, high: 2, medium: 0, low: 0 },
    },
    {
      scanRunId: 2,
      repositoryName: "auth-identity-provider",
      status: "COMPLETED",
      totalFindings: 2,
      startedAt: "2026-10-02T14:00:00Z",
      completedAt: "2026-10-02T14:03:10Z",
      evidenceSummary: { total: 2, critical: 1, high: 0, medium: 1, low: 0 },
    },
  ];
}

export function getFallbackFindings(): InMemoryFinding[] {
  return global._inMemoryFindings ?? INITIAL_FINDINGS;
}

export function updateFallbackFindingStatus(
  findingId: number,
  newStatus: InMemoryFinding["status"],
): boolean {
  const list = global._inMemoryFindings ?? [];
  const item = list.find((f) => f.finding_id === findingId);
  if (!item) return false;
  item.status = newStatus;
  return true;
}

export function addFallbackScan(
  repositoryName: string,
  totalFindings: number,
  evidenceSummary: InMemoryScan["evidenceSummary"],
): number {
  const scans = global._inMemoryScans ?? [];
  const nextId = scans.length > 0 ? Math.max(...scans.map((s) => s.scanRunId)) + 1 : 1;
  const newScan: InMemoryScan = {
    scanRunId: nextId,
    repositoryName,
    status: "COMPLETED",
    totalFindings,
    startedAt: new Date(Date.now() - 2000).toISOString(),
    completedAt: new Date().toISOString(),
    evidenceSummary,
  };
  scans.unshift(newScan);
  return nextId;
}

export function getFallbackScans(): InMemoryScan[] {
  return global._inMemoryScans ?? [];
}

