-- ============================================================================
-- CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
-- PES University - Department of Computer Science and Engineering
-- DBMS Level 3 MiniProject
-- Script 03: Seed Sample Data
-- Target Database: MySQL 8.0+
-- ============================================================================

USE secrets_monitor;

SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------------------------------------------------------
-- 1. SEED USERS
-- Passwords:
-- admin@example.com    -> Admin@123  (Role: ADMIN)
-- analyst@example.com  -> Analyst@123 (Role: ANALYST)
-- dev@example.com      -> Dev@123     (Role: ANALYST)
-- (Bcrypt hashes with 10 salt rounds)
-- ----------------------------------------------------------------------------
INSERT INTO users (user_id, full_name, email, password_hash, role, is_active, created_at)
VALUES
  (1, 'Security Admin', 'admin@example.com', '$2b$10$Wq3l.z3OQ0tX9YlR0u4zdeYfB0oJ3u8G8JgH9Fv7s5B6r1T4Z2c.O', 'ADMIN', TRUE, '2026-09-01 09:00:00'),
  (2, 'SOC Analyst Lead', 'analyst@example.com', '$2b$10$x6yZ.r2Nl1vW8XkS9t3yceXeA9nI2t7F7IfG8Eu6r4A5q0S3Y1b.N', 'ANALYST', TRUE, '2026-09-02 10:30:00'),
  (3, 'Lead Developer', 'dev@example.com', '$2b$10$y7zA.s3Om2wX9YlT0u4zdfYfB0oJ3u8G8JgH9Fv7s5B6r1T4Z2c.P', 'ANALYST', TRUE, '2026-09-03 11:15:00')
ON DUPLICATE KEY UPDATE full_name = VALUES(full_name);

-- ----------------------------------------------------------------------------
-- 2. SEED REPOSITORIES
-- ----------------------------------------------------------------------------
INSERT INTO repositories (repository_id, name, source_url, owner_id, created_at)
VALUES
  (1, 'demo-payment-service', 'https://github.com/enterprise/demo-payment-service.git', 1, '2026-09-05 10:00:00'),
  (2, 'auth-identity-provider', 'https://github.com/enterprise/auth-identity-provider.git', 2, '2026-09-06 11:00:00'),
  (3, 'cloud-infrastructure-iac', 'https://github.com/enterprise/cloud-infra.git', 1, '2026-09-07 14:00:00'),
  (4, 'analytics-data-pipeline', 'https://github.com/enterprise/data-pipeline.git', 3, '2026-09-08 16:30:00')
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- ----------------------------------------------------------------------------
-- 3. SEED SCAN RUNS
-- ----------------------------------------------------------------------------
INSERT INTO scan_runs (scan_run_id, repository_id, started_by, status, started_at, completed_at, total_findings)
VALUES
  (1, 1, 1, 'COMPLETED', '2026-10-01 10:00:00', '2026-10-01 10:02:15', 3),
  (2, 2, 1, 'COMPLETED', '2026-10-02 14:00:00', '2026-10-02 14:03:10', 2),
  (3, 3, 1, 'COMPLETED', '2026-10-03 16:00:00', '2026-10-03 16:04:45', 4),
  (4, 1, 2, 'COMPLETED', '2026-10-15 09:30:00', '2026-10-15 09:31:50', 3)
ON DUPLICATE KEY UPDATE status = VALUES(status);

-- ----------------------------------------------------------------------------
-- 4. SEED FINDINGS
-- ----------------------------------------------------------------------------
INSERT INTO findings (finding_id, repository_id, scan_run_id, secret_type, fingerprint, masked_preview, file_path, line_number, severity, status, first_seen, last_seen, updated_at)
VALUES
  (1, 1, 1, 'AWS_ACCESS_KEY_ID', 'c1a5d6e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6', 'AKIA****123', 'config/settings.py', 5, 'CRITICAL', 'OPEN', '2026-10-01 10:01:00', '2026-10-15 09:31:00', '2026-10-15 09:31:00'),
  (2, 1, 1, 'API_KEY', 'd2b6e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8', 'sk_t****7890', 'config/settings.py', 4, 'HIGH', 'INVESTIGATING', '2026-10-01 10:01:05', '2026-10-15 09:31:05', '2026-10-16 11:20:00'),
  (3, 1, 1, 'DATABASE_URL', 'e3c7f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9', 'post****demo_db', 'config/settings.py', 6, 'HIGH', 'RESOLVED', '2026-10-01 10:01:10', '2026-10-01 10:01:10', '2026-10-05 15:45:00'),
  (4, 2, 2, 'TOKEN', 'f4d8a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1', 'ghp_****xy98', 'src/auth/jwt.service.ts', 42, 'CRITICAL', 'REMEDIATION_IN_PROGRESS', '2026-10-02 14:02:00', '2026-10-02 14:02:00', '2026-10-18 10:00:00'),
  (5, 2, 2, 'PASSWORD', 'a5e9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2', 'admi****Pass', 'docker-compose.yml', 14, 'MEDIUM', 'FALSE_POSITIVE', '2026-10-02 14:02:15', '2026-10-02 14:02:15', '2026-10-04 16:30:00'),
  (6, 3, 3, 'AWS_ACCESS_KEY_ID', 'b6f0c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3', 'AKIA****999', 'terraform/variables.tf', 28, 'CRITICAL', 'OPEN', '2026-10-03 16:03:00', '2026-10-03 16:03:00', '2026-10-03 16:03:00'),
  (7, 3, 3, 'SECRET', 'c7a1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4', 's3cr****tKey', 'scripts/deploy.sh', 8, 'HIGH', 'OPEN', '2026-10-03 16:03:30', '2026-10-03 16:03:30', '2026-10-03 16:03:30')
ON DUPLICATE KEY UPDATE status = VALUES(status);

-- ----------------------------------------------------------------------------
-- 5. SEED STATUS HISTORY
-- ----------------------------------------------------------------------------
INSERT INTO status_history (history_id, finding_id, old_status, new_status, changed_by, changed_at, comment)
VALUES
  (1, 2, 'OPEN', 'INVESTIGATING', 2, '2026-10-16 11:20:00', 'Analyst triage: assessing exposure blast radius in production'),
  (2, 3, 'OPEN', 'REMEDIATION_IN_PROGRESS', 2, '2026-10-04 14:10:00', 'Database password rotation scheduled with DBA'),
  (3, 3, 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 1, '2026-10-05 15:45:00', 'Connection string rotated and updated in AWS Secrets Manager'),
  (4, 4, 'OPEN', 'REMEDIATION_IN_PROGRESS', 2, '2026-10-18 10:00:00', 'GitHub Personal Access Token being revoked'),
  (5, 5, 'OPEN', 'FALSE_POSITIVE', 2, '2026-10-04 16:30:00', 'Local docker-compose test credential only, no production access')
ON DUPLICATE KEY UPDATE new_status = VALUES(new_status);

-- ----------------------------------------------------------------------------
-- 6. SEED REMEDIATION
-- ----------------------------------------------------------------------------
INSERT INTO remediation (remediation_id, finding_id, action_type, notes, evidence_reference, performed_by, performed_at)
VALUES
  (1, 3, 'ROTATED', 'Production DB credentials rotated and verified. Vault secret updated.', 'PR #1042 / JIRA SEC-891', 1, '2026-10-05 15:45:00')
ON DUPLICATE KEY UPDATE action_type = VALUES(action_type);

-- ----------------------------------------------------------------------------
-- 7. SEED AUDIT LOGS
-- ----------------------------------------------------------------------------
INSERT INTO audit_logs (audit_id, actor_id, action, entity_type, entity_id, details, created_at)
VALUES
  (1, 1, 'SCAN_TRIGGERED', 'scan_run', 1, JSON_OBJECT('repository', 'demo-payment-service', 'scanner', 'synthetic-demo-scanner'), '2026-10-01 10:00:00'),
  (2, 2, 'FINDING_STATUS_UPDATED', 'finding', 2, JSON_OBJECT('oldStatus', 'OPEN', 'newStatus', 'INVESTIGATING'), '2026-10-16 11:20:00'),
  (3, 1, 'FINDING_RESOLVED', 'finding', 3, JSON_OBJECT('action', 'ROTATED', 'ref', 'PR #1042'), '2026-10-05 15:45:00')
ON DUPLICATE KEY UPDATE action = VALUES(action);

SET FOREIGN_KEY_CHECKS = 1;

