# Comprehensive Viva Questions & Answers (DBMS Level 3)
## Credentials and Secrets Exposure Monitoring Platform
**PES University - Department of Computer Science and Engineering**

---

### Q1: What is the problem statement and why did you choose this architecture?
**Answer:**  
In modern DevSecOps pipelines, hardcoded credentials, cloud access tokens (e.g. AWS access keys), and database connection strings frequently leak into git repositories. Our project monitors and detects leaked secrets, stores their cryptographic fingerprints without storing raw sensitive credentials, manages remediation workflows (rotation/revocation), and enforces immutable audit trails.  
We adopted a **Polyglot Persistence Architecture**:
- **MySQL 8.0**: For ACID transactions, referential integrity across users, repositories, scans, findings, status transitions, and audit logs.
- **MongoDB**: For unstructured, polymorphic scanner evidence and analyst annotations where schema flexibility, JSON schema validation, and high-throughput ingestion are required.

---

### Q2: Explain the ER Diagram and relational normalization level.
**Answer:**  
The relational schema comprises 7 tables:
1. `users` (Surrogate PK: `user_id`, Unique Candidate Key: `email`)
2. `repositories` (Surrogate PK: `repository_id`, FK: `owner_id` $\to$ `users`)
3. `scan_runs` (Surrogate PK: `scan_run_id`, FKs: `repository_id`, `started_by`)
4. `findings` (Surrogate PK: `finding_id`, Composite UK: (`repository_id`, `fingerprint`))
5. `status_history` (Surrogate PK: `history_id`, FKs: `finding_id`, `changed_by`)
6. `remediation` (Surrogate PK: `remediation_id`, FKs: `finding_id`, `performed_by`)
7. `audit_logs` (Surrogate PK: `audit_id`, FK: `actor_id`)

**Normalization:**
- **1NF**: All column values are atomic; each row is identifiable by a primary key.
- **2NF**: In 1NF and no non-prime attribute is partially dependent on any candidate key (all candidate keys are either single attributes or surrogate keys).
- **3NF**: In 2NF and no non-prime attribute is transitively dependent on any candidate key.
- **BCNF**: For every non-trivial functional dependency $X \to Y$, $X$ is a superkey. Both `user_id` and `email` in `users` are superkeys, and (`repository_id`, `fingerprint`) in `findings` is a candidate key.

---

### Q3: How do the database triggers work in your system?
**Answer:**  
We implemented two triggers:
1. **`trg_finding_status_history`**:
   - Executes `AFTER UPDATE ON findings FOR EACH ROW`.
   - Checks `IF OLD.status <> NEW.status`.
   - Automatically inserts a record into `status_history` capturing `NEW.finding_id`, `OLD.status`, `NEW.status`, and `@app_user_id` (the authenticated actor session variable).
   - This guarantees that lifecycle audit records can never be skipped or bypassed, even if updates are made through CLI or external scripts.
2. **`trg_remediation_audit`**:
   - Executes `AFTER INSERT ON remediation FOR EACH ROW`.
   - Automatically inserts a JSON audit record into `audit_logs` containing the finding ID, action type, and evidence reference.

---

### Q4: Explain the Stored Procedure and Stored Function implemented.
**Answer:**  
1. **Stored Procedure (`sp_resolve_finding`)**:
   - Parameters: `p_finding_id`, `p_user_id`, `p_action_type`, `p_notes`, `p_evidence_ref`, `OUT p_success`, `OUT p_message`.
   - Atomicity: Wraps the transaction in `START TRANSACTION ... COMMIT`. Locks the finding using `SELECT ... FOR UPDATE`, sets the session user context `@app_user_id`, updates status to `'RESOLVED'`, inserts a remediation record, records an audit log, and handles exceptions with `DECLARE EXIT HANDLER FOR SQLEXCEPTION` doing a rollback.
2. **Stored Function (`fn_calculate_risk_score`)**:
   - Takes `p_repository_id` and computes a deterministic weighted score:
     $$\text{Risk Score} = (10 \times \text{Critical}) + (5 \times \text{High}) + (2 \times \text{Medium}) + (1 \times \text{Low})$$
     for all active/open findings.

---

### Q5: Explain the Recursive CTE (`WITH RECURSIVE`).
**Answer:**  
The recursive CTE builds a multi-tier SLA incident response escalation hierarchy:
- **Anchor Member**: Defines Tier 1 (`SOC Analyst Triage`) for finding ages between 0 and 2 days.
- **Recursive Member**: Dynamically generates Tier 2 (`Senior Engineer`), Tier 3 (`Incident Response Lead`), and Tier 4 (`CISO & Crisis Council`) with increasing SLA violation thresholds (`WHERE escalation_tier < 4`).
- It then joins with the `findings` table using `TIMESTAMPDIFF(DAY, f.first_seen, NOW()) BETWEEN eh.min_age_days AND eh.max_age_days` to categorize every unresolved finding into its current escalation tier.

---

### Q6: What are your Nested and Correlated Subqueries?
**Answer:**  
- **Nested Query**: Computes the average critical finding count across all repositories in a subquery and returns only those repositories whose critical findings exceed this benchmark.
- **Correlated Subquery**: In `findings`, evaluates an inner query on `status_history sh WHERE sh.finding_id = f.finding_id ORDER BY sh.changed_at DESC LIMIT 1` to dynamically project the most recent transition comment and modifier for each finding.

---

### Q7: Explain the NoSQL (MongoDB) RUD operations and Aggregation Pipeline.
**Answer:**  
- **Create (C)**: Inserts polymorphic scanner evidence and analyst annotations validated by MongoDB `$jsonSchema`.
- **Read (R)**: Queries documents by scan ID, secret type, and full-text search on file paths.
- **Update (U)**: Uses `$set` upsert logic to update verification status (`VERIFIED_EXPOSURE`, `FALSE_POSITIVE`) and analyst notes.
- **Delete (D)**: Uses `deleteOne()` to delete annotations or false positive evidence.
- **Aggregation Pipeline**: Executes `$unwind` on embedded evidence arrays, `$group` by `secretType`, and `$project` to calculate real-time exposure density across scans.

---

### Q8: How is Authentication and Role-Based Access Control (RBAC) enforced?
**Answer:**  
- **Frontend & Middleware**: Cryptographically signed JSON Web Tokens (`HS256` via `jose`) stored in `HttpOnly`, `SameSite=Lax` cookies.
- **Database Verification**: Each authenticated request verifies the user's active status and role (`ADMIN` vs `ANALYST`) in MySQL directly rather than blindly trusting decoded claims.
- **Role Permissions**:
  - `ADMIN`: Has full privileges (trigger scans, delete records, register repositories, manage users).
  - `ANALYST`: Can view dashboards, update finding status, record remediations, and add NoSQL annotations, but is restricted from deleting repositories or initiating raw scans.

