# Technology Justification: Polyglot Persistence Architecture
## Credentials and Secrets Exposure Monitoring Platform
**PES University - Department of Computer Science and Engineering**  
**Course:** Database Management System (Aug - Dec 2026)

---

## 1. Executive Summary

The **Credentials and Secrets Exposure Monitoring Platform** employs a **Polyglot Persistence** architecture, combining a Relational Database Management System (**MySQL 8.0**) and a Document/NoSQL Database (**MongoDB**). This dual-database design is chosen because no single database engine can optimally fulfill both the strict transactional consistency requirements of security audits and the high-ingestion, polymorphic requirements of secret detection evidence.

---

## 2. Comparative Matrix: Relational (MySQL) vs. NoSQL (MongoDB)

| Dimension | Relational Database (MySQL 8.0) | Document / NoSQL Database (MongoDB) |
| :--- | :--- | :--- |
| **Primary Domain** | Users, Repositories, Scans, Findings, Remediations, Audit Trail | Variable Scanner Evidence, Raw Detection ASTs, Analyst Annotations |
| **Data Model** | Tabular, Normalized (BCNF), Enforced Foreign Keys | BSON Document hierarchy, Flexible Embedded Arrays |
| **Consistency / ACID** | Strict ACID (Atomicity, Consistency, Isolation, Durability) | Base / Document-level atomicity, Eventual read consistency |
| **Integrity Enforcement** | Foreign Keys (`ON DELETE`, `ON UPDATE`), Check constraints, Triggers | JSON Schema Validation (`$jsonSchema`) |
| **Query Strengths** | Complex Multi-Table JOINs, Correlated Subqueries, Recursive CTEs | High-throughput bulk inserts, Aggregation Pipelines, Text Search |
| **Schema Evolution** | Rigorous schema migrations required | Frictionless polymorphic evidence ingestion from diverse scanners |

---

## 3. Technology Justification per Engine

### A. Why MySQL for Core Security Operations?
1. **Financial & Compliance Integrity (ACID Guarantees)**:
   - When a security finding changes status from `OPEN` to `RESOLVED`, multiple actions must happen atomically: the status must update, the remediation record must be inserted, and an audit trail must be created. Any failure must trigger an atomic `ROLLBACK`.
2. **Referential Integrity & Cascading Safety**:
   - Deleting a user or repository cannot orphan findings or audit records. MySQL foreign keys with `ON DELETE RESTRICT` and `ON UPDATE CASCADE` guarantee data consistency.
3. **Trigger-Enforced Immutability**:
   - `trg_finding_status_history` runs at the database kernel level to record who changed which status and when, making tampering impossible even if bypassed via raw SQL.
4. **Complex Relational Analytics**:
   - Incident response escalation workflows require `WITH RECURSIVE` queries to traverse multi-tiered SLA ladders dynamically.
   - Stored procedures (`sp_resolve_finding`) encapsulate multi-step transactions directly on the database engine.

### B. Why MongoDB for Scan Evidence & Scanner Payloads?
1. **Polymorphic Scanner Output**:
   - Different scanners (e.g., Gitleaks, TruffleHog, Semgrep, custom regex engines) produce radically different detection structures (AST tokens, commit hashes, entropy calculations, diff hunks). A rigid relational schema would require frequent costly `ALTER TABLE` operations or complex polymorphic joins.
2. **High-Throughput Bulk Ingestion**:
   - Code repositories can trigger tens of thousands of file evaluations in seconds. MongoDB's BSON document store enables zero-impedance bulk persistence of whole scan run documents with embedded evidence lists.
3. **Rich Aggregation Pipelines & Document RUD**:
   - MongoDB's `$facet`, `$unwind`, and `$group` aggregation operators allow real-time classification of secret types across millions of findings without locking operational relational tables.
4. **Analyst Evidence Annotations (Full RUD)**:
   - Document-level updates allow security analysts to append verification tags (`VERIFIED_EXPOSURE`, `FALSE_POSITIVE`) and JSON notes directly to the evidence artifact without schema constraints.

---

## 4. Conclusion
By strategically assigning transactional governance to MySQL and flexible evidence ingestion to MongoDB, the platform achieves both 100% compliance auditability and web-scale scanner throughput.

