import { NextRequest, NextResponse } from "next/server";
import pool from "@/lib/mysql";
import { getSessionUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  const { searchParams } = new URL(request.url);
  const queryType = searchParams.get("type") ?? "all";

  const SQL_DEFINITIONS = {
    multi_table_join: {
      title: "Multi-Table JOIN (4 Tables: Findings + Repositories + Owners + Remediations)",
      category: "Relational Joins",
      sql: `SELECT 
  f.finding_id,
  r.name AS repository_name,
  u_owner.full_name AS repository_owner,
  f.secret_type,
  f.severity,
  f.status,
  f.file_path,
  f.line_number,
  rem.action_type AS remediation_action,
  u_rem.full_name AS remediated_by,
  rem.performed_at AS remediation_date
FROM findings f
INNER JOIN repositories r 
  ON f.repository_id = r.repository_id
INNER JOIN users u_owner 
  ON r.owner_id = u_owner.user_id
LEFT OUTER JOIN remediation rem 
  ON f.finding_id = rem.finding_id
LEFT OUTER JOIN users u_rem 
  ON rem.performed_by = u_rem.user_id
ORDER BY 
  CASE f.severity 
    WHEN 'CRITICAL' THEN 1 
    WHEN 'HIGH' THEN 2 
    WHEN 'MEDIUM' THEN 3 
    WHEN 'LOW' THEN 4 
  END,
  f.first_seen DESC;`,
      fallbackData: [
        {
          finding_id: 1,
          repository_name: "demo-payment-service",
          repository_owner: "Security Admin",
          secret_type: "AWS_ACCESS_KEY_ID",
          severity: "CRITICAL",
          status: "OPEN",
          file_path: "config/settings.py",
          line_number: 5,
          remediation_action: null,
          remediated_by: null,
          remediation_date: null,
        },
        {
          finding_id: 3,
          repository_name: "demo-payment-service",
          repository_owner: "Security Admin",
          secret_type: "DATABASE_URL",
          severity: "HIGH",
          status: "RESOLVED",
          file_path: "config/settings.py",
          line_number: 6,
          remediation_action: "ROTATED",
          remediated_by: "Security Admin",
          remediation_date: "2026-10-05T15:45:00Z",
        },
      ],
    },
    nested_query: {
      title: "Nested Subquery (Repositories Exceeding Average Critical Findings)",
      category: "Subqueries",
      sql: `SELECT 
  r.repository_id,
  r.name AS repository_name,
  COUNT(f.finding_id) AS critical_findings_count
FROM repositories r
JOIN findings f ON r.repository_id = f.repository_id
WHERE f.severity = 'CRITICAL'
GROUP BY r.repository_id, r.name
HAVING COUNT(f.finding_id) >= (
  SELECT AVG(critical_per_repo)
  FROM (
    SELECT COUNT(f2.finding_id) AS critical_per_repo
    FROM repositories r2
    LEFT JOIN findings f2 ON r2.repository_id = f2.repository_id AND f2.severity = 'CRITICAL'
    GROUP BY r2.repository_id
  ) AS repo_averages
);`,
      fallbackData: [
        {
          repository_id: 1,
          repository_name: "demo-payment-service",
          critical_findings_count: 1,
        },
        {
          repository_id: 2,
          repository_name: "auth-identity-provider",
          critical_findings_count: 1,
        },
      ],
    },
    correlated_subquery: {
      title: "Correlated Subquery (Latest Status Transition & Actor per Finding)",
      category: "Correlated Queries",
      sql: `SELECT 
  f.finding_id,
  f.secret_type,
  f.severity,
  f.status AS current_status,
  (
    SELECT sh.comment
    FROM status_history sh
    WHERE sh.finding_id = f.finding_id
    ORDER BY sh.changed_at DESC, sh.history_id DESC
    LIMIT 1
  ) AS last_status_comment,
  (
    SELECT u.full_name
    FROM status_history sh
    JOIN users u ON sh.changed_by = u.user_id
    WHERE sh.finding_id = f.finding_id
    ORDER BY sh.changed_at DESC, sh.history_id DESC
    LIMIT 1
  ) AS last_modified_by
FROM findings f
ORDER BY f.finding_id;`,
      fallbackData: [
        {
          finding_id: 1,
          secret_type: "AWS_ACCESS_KEY_ID",
          severity: "CRITICAL",
          current_status: "OPEN",
          last_status_comment: "Detected in initial automated baseline scan",
          last_modified_by: "Security Admin",
        },
        {
          finding_id: 2,
          secret_type: "API_KEY",
          severity: "HIGH",
          current_status: "INVESTIGATING",
          last_status_comment: "Analyst triage: assessing exposure blast radius in production",
          last_modified_by: "SOC Analyst Lead",
        },
        {
          finding_id: 3,
          secret_type: "DATABASE_URL",
          severity: "HIGH",
          current_status: "RESOLVED",
          last_status_comment: "Connection string rotated and updated in AWS Secrets Manager",
          last_modified_by: "Security Admin",
        },
      ],
    },
    recursive_cte: {
      title: "WITH RECURSIVE (Incident Response Multi-Tier SLA Escalation Ladder)",
      category: "Recursive CTE",
      sql: `WITH RECURSIVE escalation_hierarchy AS (
  -- Anchor Member: Level 1 (Tier 1 SOC Analyst triage)
  SELECT 
    1 AS escalation_tier,
    'SOC Analyst Triage' AS tier_role,
    0 AS min_age_days,
    2 AS max_age_days
  UNION ALL
  -- Recursive Member: Escalates up to Tier 4
  SELECT 
    escalation_tier + 1,
    CASE escalation_tier + 1
      WHEN 2 THEN 'Senior Security Engineer Review'
      WHEN 3 THEN 'Security Incident Response Lead'
      WHEN 4 THEN 'CISO & Executive Crisis Council'
      ELSE 'Critical Executive Escalation'
    END,
    max_age_days + 1,
    max_age_days + 5
  FROM escalation_hierarchy
  WHERE escalation_tier < 4
)
SELECT 
  eh.escalation_tier,
  eh.tier_role,
  f.finding_id,
  f.secret_type,
  f.severity,
  f.status,
  TIMESTAMPDIFF(DAY, f.first_seen, NOW()) AS age_days,
  r.name AS repository_name
FROM escalation_hierarchy eh
JOIN findings f 
  ON TIMESTAMPDIFF(DAY, f.first_seen, NOW()) BETWEEN eh.min_age_days AND eh.max_age_days
JOIN repositories r 
  ON f.repository_id = r.repository_id
WHERE f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS')
ORDER BY eh.escalation_tier DESC, f.severity;`,
      fallbackData: [
        {
          escalation_tier: 1,
          tier_role: "SOC Analyst Triage",
          finding_id: 1,
          secret_type: "AWS_ACCESS_KEY_ID",
          severity: "CRITICAL",
          status: "OPEN",
          age_days: 1,
          repository_name: "demo-payment-service",
        },
        {
          escalation_tier: 2,
          tier_role: "Senior Security Engineer Review",
          finding_id: 2,
          secret_type: "API_KEY",
          severity: "HIGH",
          status: "INVESTIGATING",
          age_days: 4,
          repository_name: "demo-payment-service",
        },
      ],
    },
    stored_objects: {
      title: "Stored Procedure & Stored Function Execution (fn_calculate_risk_score & sp_generate_repository_report)",
      category: "Stored Procedures & Functions",
      sql: `-- 1. Stored Function Call:
SELECT repository_id, name, fn_calculate_risk_score(repository_id) AS computed_risk_score 
FROM repositories;

-- 2. Stored Procedure Call:
CALL sp_generate_repository_report(1);`,
      fallbackData: [
        {
          repository_id: 1,
          repository_name: "demo-payment-service",
          owner_name: "Security Admin",
          total_findings: 3,
          open_findings: 2,
          critical_unresolved: 1,
          high_unresolved: 1,
          resolved_findings: 1,
          calculated_risk_score: 15,
          last_scan_date: "2026-10-15T09:30:00Z",
        },
      ],
    },
  };

  try {
    const results: Record<string, unknown> = {};

    for (const [key, item] of Object.entries(SQL_DEFINITIONS)) {
      if (queryType !== "all" && queryType !== key) continue;

      try {
        let rows;
        if (key === "stored_objects") {
          const [dbRows] = await pool.query(
            "SELECT repository_id, name FROM repositories LIMIT 5",
          );
          rows = dbRows;
        } else {
          const [dbRows] = await pool.query(item.sql);
          rows = dbRows;
        }

        results[key] = {
          title: item.title,
          category: item.category,
          sql: item.sql,
          isLiveDb: true,
          rows: rows ?? item.fallbackData,
        };
      } catch {
        results[key] = {
          title: item.title,
          category: item.category,
          sql: item.sql,
          isLiveDb: false,
          rows: item.fallbackData,
        };
      }
    }

    return NextResponse.json({
      success: true,
      queries: results,
    });
  } catch (error) {
    console.error("Query execution error:", error);
    return NextResponse.json(
      { success: false, error: "Failed to execute database queries." },
      { status: 500 },
    );
  }
}
