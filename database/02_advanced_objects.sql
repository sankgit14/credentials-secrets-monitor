-- ============================================================================
-- CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
-- PES University - Department of Computer Science and Engineering
-- DBMS Level 3 MiniProject
-- Script 02: Advanced Database Objects: Stored Procedures, Functions, Triggers, Views
-- Target Database: MySQL 8.0+
-- ============================================================================

USE secrets_monitor;

-- ----------------------------------------------------------------------------
-- 1. TRIGGERS
-- ----------------------------------------------------------------------------

DROP TRIGGER IF EXISTS trg_finding_status_history;
DROP TRIGGER IF EXISTS trg_remediation_audit;

DELIMITER $$

-- Trigger 1: Automatically log status changes into status_history
CREATE TRIGGER trg_finding_status_history
AFTER UPDATE ON findings
FOR EACH ROW
BEGIN
  IF OLD.status <> NEW.status THEN
    INSERT INTO status_history
      (finding_id, old_status, new_status, changed_by, comment, changed_at)
    VALUES
      (NEW.finding_id, OLD.status, NEW.status,
       COALESCE(@app_user_id, 1), 'Automated status transition via system', NOW());
  END IF;
END$$

-- Trigger 2: Automatically write to audit_logs when a remediation is recorded
CREATE TRIGGER trg_remediation_audit
AFTER INSERT ON remediation
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs
    (actor_id, action, entity_type, entity_id, details, created_at)
  VALUES
    (NEW.performed_by, 'REMEDIATION_RECORDED', 'remediation', NEW.remediation_id,
     JSON_OBJECT('finding_id', NEW.finding_id, 'action_type', NEW.action_type, 'evidence_ref', NEW.evidence_reference),
     NOW());
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- 2. STORED FUNCTIONS
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS fn_calculate_risk_score;
DROP FUNCTION IF EXISTS fn_finding_age_days;

DELIMITER $$

-- Stored Function 1: Compute weighted repository risk score
-- Formula: (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 1) for open findings
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

-- Stored Function 2: Compute age in days since first detection
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
-- 3. STORED PROCEDURES
-- ----------------------------------------------------------------------------

DROP PROCEDURE IF EXISTS sp_resolve_finding;
DROP PROCEDURE IF EXISTS sp_generate_repository_report;

DELIMITER $$

-- Stored Procedure 1: Atomically resolve a finding and record remediation
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
  
  -- Validation handler
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    SET p_success = FALSE;
    SET p_message = 'Transaction rolled back due to SQL error.';
  END;

  START TRANSACTION;
  
  -- Check finding existence
  SELECT status INTO v_current_status
  FROM findings
  WHERE finding_id = p_finding_id
  FOR UPDATE;
  
  IF v_current_status IS NULL THEN
    SET p_success = FALSE;
    SET p_message = 'Finding does not exist.';
    ROLLBACK;
    LEAVE proc_label;
  END IF;

  -- Set session actor variable for the status trigger
  SET @app_user_id = p_user_id;

  -- Update finding status to RESOLVED
  UPDATE findings
  SET status = 'RESOLVED',
      updated_at = NOW()
  WHERE finding_id = p_finding_id;

  -- Insert into remediation table
  INSERT INTO remediation
    (finding_id, action_type, notes, evidence_reference, performed_by, performed_at)
  VALUES
    (p_finding_id, p_action_type, p_notes, p_evidence_ref, p_user_id, NOW());

  -- Insert audit log entry
  INSERT INTO audit_logs
    (actor_id, action, entity_type, entity_id, details, created_at)
  VALUES
    (p_user_id, 'FINDING_RESOLVED_VIA_SP', 'finding', p_finding_id,
     JSON_OBJECT('previous_status', v_current_status, 'action_type', p_action_type, 'notes', p_notes),
     NOW());

  COMMIT;
  SET p_success = TRUE;
  SET p_message = 'Finding successfully resolved and remediation recorded.';
END$$

-- Stored Procedure 2: Generate comprehensive analytics report for a repository
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
    SUM(CASE WHEN f.severity = 'HIGH' AND f.status <> 'RESOLVED' THEN 1 ELSE 0 END) AS high_unresolved,
    SUM(CASE WHEN f.status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_findings,
    fn_calculate_risk_score(r.repository_id) AS calculated_risk_score,
    MAX(sr.started_at) AS last_scan_date
  FROM repositories r
  JOIN users u ON r.owner_id = u.user_id
  LEFT JOIN findings f ON r.repository_id = f.repository_id
  LEFT JOIN scan_runs sr ON r.repository_id = sr.repository_id
  WHERE r.repository_id = p_repository_id
  GROUP BY r.repository_id, r.name, u.full_name;
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- 4. DATABASE VIEWS
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

CREATE OR REPLACE VIEW repository_risk_summary_view AS
SELECT
  r.repository_id,
  r.name AS repository_name,
  u.full_name AS owner_name,
  COUNT(f.finding_id) AS total_findings,
  SUM(CASE WHEN f.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
  SUM(CASE WHEN f.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
  SUM(CASE WHEN f.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
  SUM(CASE WHEN f.severity = 'LOW' THEN 1 ELSE 0 END) AS low_count,
  fn_calculate_risk_score(r.repository_id) AS risk_score
FROM repositories r
JOIN users u ON r.owner_id = u.user_id
LEFT JOIN findings f ON r.repository_id = f.repository_id
GROUP BY r.repository_id, r.name, u.full_name;

