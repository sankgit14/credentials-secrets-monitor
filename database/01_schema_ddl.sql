-- ============================================================================
-- CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
-- PES University - Department of Computer Science and Engineering
-- DBMS Level 3 MiniProject
-- Script 01: DDL Schema Definition with Keys, Integrity & Domain Constraints
-- Target Database: MySQL 8.0+
-- ============================================================================

CREATE DATABASE IF NOT EXISTS secrets_monitor
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE secrets_monitor;

-- Disable foreign key checks for clean teardown during development/re-initialization
SET FOREIGN_KEY_CHECKS = 0;
DROP VIEW IF EXISTS open_findings_view;
DROP VIEW IF EXISTS repository_risk_summary_view;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS remediation;
DROP TABLE IF EXISTS status_history;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

-- ----------------------------------------------------------------------------
-- 1. USERS TABLE
-- Authentication, authorization, and role-based access control (ADMIN / ANALYST)
-- ----------------------------------------------------------------------------
CREATE TABLE users (
  user_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  full_name VARCHAR(150) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('ADMIN', 'ANALYST') NOT NULL DEFAULT 'ANALYST',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Constraints
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_users_email (email),
  CONSTRAINT chk_users_role CHECK (role IN ('ADMIN', 'ANALYST')),
  CONSTRAINT chk_users_email_format CHECK (email LIKE '%@%.%')
) ENGINE=InnoDB COMMENT='Application users with RBAC roles';

-- ----------------------------------------------------------------------------
-- 2. REPOSITORIES TABLE
-- Tracked source code repositories undergoing secrets scanning
-- ----------------------------------------------------------------------------
CREATE TABLE repositories (
  repository_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  source_url VARCHAR(2048) NOT NULL,
  owner_id BIGINT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Constraints & Indexes
  PRIMARY KEY (repository_id),
  UNIQUE KEY uq_repositories_name (name),
  KEY idx_repositories_owner (owner_id),
  CONSTRAINT fk_repositories_owner
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Tracked repositories';

-- ----------------------------------------------------------------------------
-- 3. SCAN_RUNS TABLE
-- Records discrete scan executions triggered by security engineers/admins
-- ----------------------------------------------------------------------------
CREATE TABLE scan_runs (
  scan_run_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  repository_id BIGINT UNSIGNED NOT NULL,
  started_by BIGINT UNSIGNED NOT NULL,
  status ENUM('RUNNING', 'COMPLETED', 'FAILED') NOT NULL DEFAULT 'RUNNING',
  started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP NULL DEFAULT NULL,
  total_findings INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Constraints & Indexes
  PRIMARY KEY (scan_run_id),
  KEY idx_scan_repository_started (repository_id, started_at),
  KEY idx_scan_started_by (started_by),
  KEY idx_scan_status (status),
  CONSTRAINT chk_scan_status CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
  CONSTRAINT fk_scan_runs_repository
    FOREIGN KEY (repository_id) REFERENCES repositories(repository_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT fk_scan_runs_started_by
    FOREIGN KEY (started_by) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Discrete secret scanner executions';

-- ----------------------------------------------------------------------------
-- 4. FINDINGS TABLE
-- Detected secret tokens with cryptographic fingerprints and lifecycle status
-- ----------------------------------------------------------------------------
CREATE TABLE findings (
  finding_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  repository_id BIGINT UNSIGNED NOT NULL,
  scan_run_id BIGINT UNSIGNED NULL,
  secret_type VARCHAR(100) NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  masked_preview VARCHAR(255) NULL,
  file_path VARCHAR(2048) NOT NULL,
  line_number INT UNSIGNED NULL,
  severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  status ENUM('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'OPEN',
  first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  -- Constraints & Indexes
  PRIMARY KEY (finding_id),
  UNIQUE KEY uq_findings_repository_fingerprint (repository_id, fingerprint),
  KEY idx_findings_status_severity (status, severity),
  KEY idx_findings_repository_status (repository_id, status),
  KEY idx_findings_scan_run (scan_run_id),
  CONSTRAINT chk_findings_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  CONSTRAINT chk_findings_status CHECK (status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')),
  CONSTRAINT chk_findings_line_number CHECK (line_number IS NULL OR line_number > 0),
  CONSTRAINT fk_findings_repository
    FOREIGN KEY (repository_id) REFERENCES repositories(repository_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT fk_findings_scan_run
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(scan_run_id)
    ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB COMMENT='Individual detected secrets instances';

-- ----------------------------------------------------------------------------
-- 5. STATUS_HISTORY TABLE
-- Audit trail of lifecycle state transitions for each finding
-- ----------------------------------------------------------------------------
CREATE TABLE status_history (
  history_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  finding_id BIGINT UNSIGNED NOT NULL,
  old_status ENUM('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NULL,
  new_status ENUM('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL,
  changed_by BIGINT UNSIGNED NOT NULL,
  changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  comment TEXT NULL,
  
  -- Constraints & Indexes
  PRIMARY KEY (history_id),
  KEY idx_status_history_finding_changed (finding_id, changed_at),
  KEY idx_status_history_changed_by (changed_by),
  CONSTRAINT fk_status_history_finding
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_status_history_user
    FOREIGN KEY (changed_by) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Historical record of finding status transitions';

-- ----------------------------------------------------------------------------
-- 6. REMEDIATION TABLE
-- Actions taken to revoke, rotate, or remove exposed secrets
-- ----------------------------------------------------------------------------
CREATE TABLE remediation (
  remediation_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  finding_id BIGINT UNSIGNED NOT NULL,
  action_type ENUM('ROTATED', 'REVOKED', 'REMOVED', 'OTHER') NOT NULL,
  notes TEXT NULL,
  evidence_reference VARCHAR(2048) NULL,
  performed_by BIGINT UNSIGNED NOT NULL,
  performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Constraints & Indexes
  PRIMARY KEY (remediation_id),
  KEY idx_remediation_finding (finding_id),
  KEY idx_remediation_performed_by (performed_by),
  CONSTRAINT chk_remediation_action CHECK (action_type IN ('ROTATED', 'REVOKED', 'REMOVED', 'OTHER')),
  CONSTRAINT fk_remediation_finding
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT fk_remediation_user
    FOREIGN KEY (performed_by) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='Remediation records for resolved findings';

-- ----------------------------------------------------------------------------
-- 7. AUDIT_LOGS TABLE
-- System-wide immutable security audit log
-- ----------------------------------------------------------------------------
CREATE TABLE audit_logs (
  audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  actor_id BIGINT UNSIGNED NULL,
  action VARCHAR(100) NOT NULL,
  entity_type VARCHAR(100) NOT NULL,
  entity_id BIGINT UNSIGNED NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Constraints & Indexes
  PRIMARY KEY (audit_id),
  KEY idx_audit_actor_created (actor_id, created_at),
  KEY idx_audit_entity (entity_type, entity_id),
  CONSTRAINT fk_audit_logs_actor
    FOREIGN KEY (actor_id) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB COMMENT='Immutable security and compliance audit trail';

