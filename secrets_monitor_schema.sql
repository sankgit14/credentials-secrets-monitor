-- ============================================================================
-- CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
-- PES University - Department of Computer Science and Engineering
-- DBMS Level 3 MiniProject - Comprehensive Database Initialization Script
-- MySQL 8.0+ Relational Schema with Constraints, Procedures, Functions, & Triggers
-- ============================================================================

CREATE DATABASE IF NOT EXISTS secrets_monitor
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE secrets_monitor;

SET FOREIGN_KEY_CHECKS = 0;
DROP VIEW IF EXISTS open_findings_view;
DROP VIEW IF EXISTS repository_risk_summary_view;
DROP TRIGGER IF EXISTS trg_finding_status_history;
DROP TRIGGER IF EXISTS trg_remediation_audit;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS remediation;
DROP TABLE IF EXISTS status_history;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

-- 1. USERS
CREATE TABLE users (
  user_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  full_name VARCHAR(150) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('ADMIN', 'ANALYST') NOT NULL DEFAULT 'ANALYST',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_users_email (email),
  CONSTRAINT chk_users_role CHECK (role IN ('ADMIN', 'ANALYST')),
  CONSTRAINT chk_users_email_format CHECK (email LIKE '%@%.%')
) ENGINE=InnoDB;

-- 2. REPOSITORIES
CREATE TABLE repositories (
  repository_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  source_url VARCHAR(2048) NOT NULL,
  owner_id BIGINT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (repository_id),
  UNIQUE KEY uq_repositories_name (name),
  KEY idx_repositories_owner (owner_id),
  CONSTRAINT fk_repositories_owner
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 3. SCAN_RUNS
CREATE TABLE scan_runs (
  scan_run_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  repository_id BIGINT UNSIGNED NOT NULL,
  started_by BIGINT UNSIGNED NOT NULL,
  status ENUM('RUNNING', 'COMPLETED', 'FAILED') NOT NULL DEFAULT 'RUNNING',
  started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP NULL DEFAULT NULL,
  total_findings INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (scan_run_id),
  KEY idx_scan_repository_started (repository_id, started_at),
  KEY idx_scan_started_by (started_by),
  CONSTRAINT chk_scan_status CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
  CONSTRAINT fk_scan_runs_repository
    FOREIGN KEY (repository_id) REFERENCES repositories(repository_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT fk_scan_runs_started_by
    FOREIGN KEY (started_by) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 4. FINDINGS
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
) ENGINE=InnoDB;

-- 5. STATUS_HISTORY
CREATE TABLE status_history (
  history_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  finding_id BIGINT UNSIGNED NOT NULL,
  old_status ENUM('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NULL,
  new_status ENUM('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL,
  changed_by BIGINT UNSIGNED NOT NULL,
  changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  comment TEXT NULL,
  PRIMARY KEY (history_id),
  KEY idx_status_history_finding_changed (finding_id, changed_at),
  KEY idx_status_history_changed_by (changed_by),
  CONSTRAINT fk_status_history_finding
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_status_history_user
    FOREIGN KEY (changed_by) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 6. REMEDIATION
CREATE TABLE remediation (
  remediation_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  finding_id BIGINT UNSIGNED NOT NULL,
  action_type ENUM('ROTATED', 'REVOKED', 'REMOVED', 'OTHER') NOT NULL,
  notes TEXT NULL,
  evidence_reference VARCHAR(2048) NULL,
  performed_by BIGINT UNSIGNED NOT NULL,
  performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
) ENGINE=InnoDB;

-- 7. AUDIT_LOGS
CREATE TABLE audit_logs (
  audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  actor_id BIGINT UNSIGNED NULL,
  action VARCHAR(100) NOT NULL,
  entity_type VARCHAR(100) NOT NULL,
  entity_id BIGINT UNSIGNED NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (audit_id),
  KEY idx_audit_actor_created (actor_id, created_at),
  KEY idx_audit_entity (entity_type, entity_id),
  CONSTRAINT fk_audit_logs_actor
    FOREIGN KEY (actor_id) REFERENCES users(user_id)
    ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- TRIGGERS
-- ----------------------------------------------------------------------------
DELIMITER $$

CREATE TRIGGER trg_finding_status_history
AFTER UPDATE ON findings
FOR EACH ROW
BEGIN
  IF OLD.status <> NEW.status THEN
    INSERT INTO status_history
      (finding_id, old_status, new_status, changed_by, comment, changed_at)
    VALUES
      (NEW.finding_id, OLD.status, NEW.status,
       COALESCE(@app_user_id, 1), 'Automated status change', NOW());
  END IF;
END$$

CREATE TRIGGER trg_remediation_audit
AFTER INSERT ON remediation
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs
    (actor_id, action, entity_type, entity_id, details, created_at)
  VALUES
    (NEW.performed_by, 'REMEDIATION_RECORDED', 'remediation', NEW.remediation_id,
     JSON_OBJECT('finding_id', NEW.finding_id, 'action_type', NEW.action_type),
     NOW());
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- STORED FUNCTIONS
-- ----------------------------------------------------------------------------
DELIMITER $$

CREATE FUNCTION fn_calculate_risk_score(p_repository_id BIGINT UNSIGNED)
RETURNS INT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE v_score INT DEFAULT 0;
  SELECT COALESCE(SUM(
    CASE severity
      WHEN 'CRITICAL' THEN 10
      WHEN 'HIGH' THEN 5
      WHEN 'MEDIUM' THEN 2
      WHEN 'LOW' THEN 1
      ELSE 0
    END
  ), 0) INTO v_score
  FROM findings
  WHERE repository_id = p_repository_id
    AND status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS');
  RETURN v_score;
END$$

CREATE FUNCTION fn_finding_age_days(p_finding_id BIGINT UNSIGNED)
RETURNS INT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE v_days INT DEFAULT 0;
  SELECT TIMESTAMPDIFF(DAY, first_seen, NOW()) INTO v_days
  FROM findings
  WHERE finding_id = p_finding_id;
  RETURN COALESCE(v_days, 0);
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- STORED PROCEDURES
-- ----------------------------------------------------------------------------
DELIMITER $$

CREATE PROCEDURE sp_resolve_finding(
  IN p_finding_id BIGINT UNSIGNED,
  IN p_user_id BIGINT UNSIGNED,
  IN p_action_type VARCHAR(50),
  IN p_notes TEXT,
  IN p_evidence_ref VARCHAR(2048),
  OUT p_success BOOLEAN,
  OUT p_message VARCHAR(255)
)
proc_label: BEGIN
  DECLARE v_current_status VARCHAR(50);
  
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    SET p_success = FALSE;
    SET p_message = 'Transaction rolled back due to SQL error.';
  END;

  START TRANSACTION;
  
  SELECT status INTO v_current_status
  FROM findings
  WHERE finding_id = p_finding_id
  FOR UPDATE;
  
  IF v_current_status IS NULL THEN
    SET p_success = FALSE;
    SET p_message = 'Finding not found.';
    ROLLBACK;
    LEAVE proc_label;
  END IF;

  SET @app_user_id = p_user_id;

  UPDATE findings
  SET status = 'RESOLVED', updated_at = NOW()
  WHERE finding_id = p_finding_id;

  INSERT INTO remediation
    (finding_id, action_type, notes, evidence_reference, performed_by, performed_at)
  VALUES
    (p_finding_id, p_action_type, p_notes, p_evidence_ref, p_user_id, NOW());

  INSERT INTO audit_logs
    (actor_id, action, entity_type, entity_id, details, created_at)
  VALUES
    (p_user_id, 'FINDING_RESOLVED_VIA_SP', 'finding', p_finding_id,
     JSON_OBJECT('previous_status', v_current_status, 'action_type', p_action_type),
     NOW());

  COMMIT;
  SET p_success = TRUE;
  SET p_message = 'Finding successfully resolved and remediation logged.';
END$$

CREATE PROCEDURE sp_generate_repository_report(
  IN p_repository_id BIGINT UNSIGNED
)
BEGIN
  SELECT 
    r.repository_id,
    r.name AS repository_name,
    u.full_name AS owner_name,
    COUNT(f.finding_id) AS total_findings,
    SUM(CASE WHEN f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS') THEN 1 ELSE 0 END) AS open_findings,
    SUM(CASE WHEN f.severity = 'CRITICAL' AND f.status <> 'RESOLVED' THEN 1 ELSE 0 END) AS critical_unresolved,
    fn_calculate_risk_score(r.repository_id) AS risk_score
  FROM repositories r
  JOIN users u ON r.owner_id = u.user_id
  LEFT JOIN findings f ON r.repository_id = f.repository_id
  WHERE r.repository_id = p_repository_id
  GROUP BY r.repository_id, r.name, u.full_name;
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- VIEWS
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW open_findings_view AS
SELECT
  f.finding_id,
  f.repository_id,
  r.name AS repository_name,
  u.full_name AS repository_owner,
  f.scan_run_id,
  f.secret_type,
  f.masked_preview,
  f.file_path,
  f.line_number,
  f.severity,
  f.status,
  f.first_seen,
  f.last_seen,
  f.updated_at,
  fn_finding_age_days(f.finding_id) AS age_in_days
FROM findings f
JOIN repositories r ON r.repository_id = f.repository_id
JOIN users u ON r.owner_id = u.user_id
WHERE f.status IN ('OPEN', 'INVESTIGATING', 'REMEDIATION_IN_PROGRESS');
