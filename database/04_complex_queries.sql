-- ============================================================================
-- CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
-- PES University - Department of Computer Science and Engineering
-- DBMS Level 3 MiniProject
-- Script 04: Comprehensive SQL Operations: Joins, Nested, Correlated, Recursive CTE
-- Target Database: MySQL 8.0+
-- ============================================================================

USE secrets_monitor;

-- ============================================================================
-- 1. JOIN SQL QUERIES (Multi-table, Inner, Left Outer Joins)
-- ============================================================================

-- Query 1.1: 4-Table Join connecting Findings, Repositories, Repository Owner, and Remediation Performer
-- Purpose: Complete security audit trail for all resolved and in-progress exposures.
SELECT 
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
  f.first_seen DESC;

-- Query 1.2: Left Outer Join with Aggregation & Grouping
-- Purpose: Repository vulnerability posture report with total, open, and critical counts.
SELECT 
  r.repository_id,
  r.name AS repository_name,
  u.full_name AS owner_name,
  COUNT(f.finding_id) AS total_findings,
  SUM(CASE WHEN f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS') THEN 1 ELSE 0 END) AS active_findings,
  SUM(CASE WHEN f.severity = 'CRITICAL' AND f.status <> 'RESOLVED' THEN 1 ELSE 0 END) AS critical_open,
  fn_calculate_risk_score(r.repository_id) AS risk_score
FROM repositories r
JOIN users u ON r.owner_id = u.user_id
LEFT JOIN findings f ON r.repository_id = f.repository_id
GROUP BY r.repository_id, r.name, u.full_name
ORDER BY risk_score DESC;

-- ============================================================================
-- 2. NESTED SUBQUERIES (Subquery in WHERE / FROM)
-- ============================================================================

-- Query 2.1: Nested Query with Scalar Subquery in WHERE
-- Purpose: Identify repositories whose critical findings exceed the system-wide average per repository.
SELECT 
  r.repository_id,
  r.name AS repository_name,
  COUNT(f.finding_id) AS critical_findings_count
FROM repositories r
JOIN findings f ON r.repository_id = f.repository_id
WHERE f.severity = 'CRITICAL'
GROUP BY r.repository_id, r.name
HAVING COUNT(f.finding_id) >= (
  -- Scalar subquery computing average critical findings across all repositories
  SELECT AVG(critical_per_repo)
  FROM (
    SELECT COUNT(f2.finding_id) AS critical_per_repo
    FROM repositories r2
    LEFT JOIN findings f2 ON r2.repository_id = f2.repository_id AND f2.severity = 'CRITICAL'
    GROUP BY r2.repository_id
  ) AS repo_averages
);

-- Query 2.2: Nested Query using NOT IN / NOT EXISTS
-- Purpose: Find secure repositories that have ZERO active/open security findings.
SELECT 
  r.repository_id,
  r.name AS repository_name,
  r.source_url
FROM repositories r
WHERE r.repository_id NOT IN (
  -- Subquery finding all repositories with active findings
  SELECT DISTINCT repository_id
  FROM findings
  WHERE status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS')
);

-- ============================================================================
-- 3. CORRELATED SUBQUERIES
-- ============================================================================

-- Query 3.1: Correlated Subquery to find the latest status transition and actor for each finding
-- Purpose: Displays the exact last transition comment and who performed it for every finding.
SELECT 
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
ORDER BY f.finding_id;

-- Query 3.2: Correlated Subquery with EXISTS
-- Purpose: Find all findings that have undergone status triage at least once.
SELECT 
  f.finding_id,
  f.secret_type,
  f.severity,
  f.status,
  f.file_path
FROM findings f
WHERE EXISTS (
  SELECT 1 
  FROM status_history sh 
  WHERE sh.finding_id = f.finding_id
);

-- ============================================================================
-- 4. ADVANCED RECURSIVE QUERIES & CTE (Common Table Expressions)
-- ============================================================================

-- Query 4.1: WITH RECURSIVE - Hierarchical SLA Escalation Ladder
-- Purpose: Dynamically generate multi-tier incident escalation levels and assign unresolved
-- findings to their appropriate incident escalation level based on elapsed days.
WITH RECURSIVE escalation_hierarchy AS (
  -- Anchor Member: Level 1 (Tier 1 SOC Analyst triage)
  SELECT 
    1 AS escalation_tier,
    'SOC Analyst Triage' AS tier_role,
    0 AS min_age_days,
    2 AS max_age_days
  UNION ALL
  -- Recursive Member: Higher tiers of escalation
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
  fn_finding_age_days(f.finding_id) AS age_days,
  r.name AS repository_name
FROM escalation_hierarchy eh
JOIN findings f 
  ON fn_finding_age_days(f.finding_id) BETWEEN eh.min_age_days AND eh.max_age_days
JOIN repositories r 
  ON f.repository_id = r.repository_id
WHERE f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS')
ORDER BY eh.escalation_tier DESC, f.severity;

-- Query 4.2: CTE with Window Functions (ROW_NUMBER & DENSE_RANK)
-- Purpose: Rank findings within each repository by severity and detection recency.
WITH ranked_findings AS (
  SELECT 
    f.finding_id,
    f.repository_id,
    r.name AS repository_name,
    f.secret_type,
    f.severity,
    f.status,
    f.first_seen,
    ROW_NUMBER() OVER (
      PARTITION BY f.repository_id 
      ORDER BY 
        CASE f.severity 
          WHEN 'CRITICAL' THEN 1 
          WHEN 'HIGH' THEN 2 
          WHEN 'MEDIUM' THEN 3 
          WHEN 'LOW' THEN 4 
        END,
        f.first_seen DESC
    ) AS severity_rank_in_repo
  FROM findings f
  JOIN repositories r ON f.repository_id = r.repository_id
)
SELECT * 
FROM ranked_findings
WHERE severity_rank_in_repo <= 3;

-- ============================================================================
-- 5. DEMONSTRATION OF DML OPERATIONS (Data Manipulation Language)
-- ============================================================================

-- DML 5.1: INSERT
-- Registering a new repository
INSERT INTO repositories (name, source_url, owner_id)
VALUES ('payment-gateway-v2', 'https://github.com/enterprise/payment-gateway-v2.git', 1);

-- DML 5.2: SELECT with Multi-Criteria Filtering
SELECT finding_id, secret_type, severity, status, file_path
FROM findings
WHERE status = 'OPEN' AND severity IN ('HIGH', 'CRITICAL')
ORDER BY line_number ASC;

-- DML 5.3: UPDATE with Safe Transaction
UPDATE findings
SET status = 'INVESTIGATING', updated_at = NOW()
WHERE finding_id = 1 AND status = 'OPEN';

-- DML 5.4: DELETE (Safe removal of false positive status records)
-- Performed within transaction:
-- DELETE FROM findings WHERE finding_id = 999 AND status = 'FALSE_POSITIVE';

-- ============================================================================
-- 6. EXECUTING STORED PROCEDURES & STORED FUNCTIONS
-- ============================================================================

-- Function Invocation:
SELECT 
  repository_id, 
  name, 
  fn_calculate_risk_score(repository_id) AS computed_risk_score
FROM repositories;

-- Stored Procedure Invocation:
CALL sp_generate_repository_report(1);

-- Stored Procedure for Resolution:
-- CALL sp_resolve_finding(1, 1, 'ROTATED', 'Automated token rotation completed', 'PR #456', @success, @msg);
-- SELECT @success, @msg;

