# Credentials & Secrets Exposure Monitoring Platform
**PES University - Department of Computer Science and Engineering**  
**Database Management System (DBMS Level 3 MiniProject - Aug-Dec 2026)**

---

## Overview

The **Credentials and Secrets Exposure Monitoring Platform** is an enterprise security engineering solution built with a **Polyglot Persistence Architecture** (**MySQL 8.0** and **MongoDB**) and a **Next.js** web interface. It monitors source code repositories for leaked secrets, cryptographic keys, and database connection strings, stores masked previews with SHA-256 fingerprints, enforces lifecycle status triage, tracks remediation actions via database triggers and stored procedures, and provides an immutable compliance audit log.

---

## Key Features & Rubric Coverage (50 / 50 Marks)

1. **Database Design (5 Marks)**:
   - Full Entity-Relationship (ER) model documenting all 7 entities and NoSQL collections (`docs/DATABASE_DESIGN.md`).
   - Relational schemas normalized up to **Boyce-Codd Normal Form (BCNF)** with primary keys, foreign keys, and integrity constraints.
2. **Database Creation & Technology Justification (9 Marks)**:
   - `database/01_schema_ddl.sql`: Complete DDL with check constraints, unique constraints, and cascading integrity.
   - `database/init_mongodb.js`: MongoDB collections with JSON Schema Validation (`$jsonSchema`) and indexes.
   - `docs/TECHNOLOGY_JUSTIFICATION.md`: Academic rationale for Polyglot Persistence (MySQL for transactional ACID compliance, MongoDB for polymorphic scanner evidence).
3. **SQL Operations & Queries (8 Marks)**:
   - DML operations (INSERT, SELECT, UPDATE, DELETE) for repositories and findings.
   - Complex Multi-Table JOINs (connecting findings, repositories, repository owners, and remediation records).
   - Nested Subqueries (scalar benchmark comparisons) and Correlated Subqueries (last status transition and actor per finding).
   - Recursive Common Table Expressions (`WITH RECURSIVE`) modeling multi-tier incident response escalation ladders.
4. **Advanced Database Concepts (13 Marks)**:
   - **Stored Procedure**: `sp_resolve_finding` (atomic finding resolution and remediation logging) and `sp_generate_repository_report`.
   - **Stored Function**: `fn_calculate_risk_score` (weighted risk calculation) and `fn_finding_age_days`.
   - **Database Triggers**: `trg_finding_status_history` and `trg_remediation_audit`.
   - **NoSQL RUD & Aggregation Pipeline (7 Marks)**: Complete Read, Update/Upsert, Delete, and `$unwind ➔ $group` aggregation pipelines on MongoDB.
5. **Web Application & Database Integration (5 Marks)**:
   - Interactive Next.js dark-themed dashboard with tabs for Findings Triage, Advanced SQL Console, NoSQL RUD Explorer, Repositories Management, and Scan History.
   - Connection pooling and transaction management (`mysql2/promise` and `MongoClient`).
6. **Authentication & Authorization (4 Marks)**:
   - JWT sessions with `HttpOnly` cookies and `bcrypt` password hashing.
   - Minimum two roles (`ADMIN` and `ANALYST`) enforced at database and API layers.
7. **Documentation & Viva (6 Marks)**:
   - Comprehensive formal report (`DBMS_PROJECT_REPORT.md`).
   - Detailed viva questions and answers (`docs/VIVA_QUESTIONS_AND_ANSWERS.md`).

---

## Demo Credentials (RBAC)

The application includes two pre-configured demo roles for immediate evaluation:

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **ADMIN** | `admin@example.com` | `Admin@123` | Full privileges: Run scans, manage repositories, execute NoSQL deletions |
| **ANALYST** | `analyst@example.com` | `Analyst@123` | Operational privileges: Triage findings, resolve secrets, save NoSQL annotations |

---

## Quickstart & Setup Guide

### 1. Prerequisites
- Node.js (v18+)
- MySQL 8.0+
- MongoDB 6.0+

### 2. Configuration
Copy the sample environment variables:
```bash
cp .env.example .env.local
```

### 3. Initialize Databases
To run the automated schema DDL, stored procedures, triggers, seed data, and MongoDB validation:
```bash
node database/setup_all.js
```
*(Or execute scripts sequentially: `database/01_schema_ddl.sql`, `database/02_advanced_objects.sql`, `database/03_seed_data.sql`, and `database/init_mongodb.js`)*.

### 4. Run the Web Application
```bash
# Start development server
npm run dev

# Or build and run production server
npm run build
npm start
```

Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## Project Structure

```
credentials-secrets-monitor/
├── database/
│   ├── 01_schema_ddl.sql          # DDL with Primary/Foreign keys & Check constraints
│   ├── 02_advanced_objects.sql    # Stored Procedures, Functions, Triggers, Views
│   ├── 03_seed_data.sql           # Seed data for users, repositories, findings
│   ├── 04_complex_queries.sql     # Multi-Table Joins, Nested, Correlated, Recursive CTE
│   ├── init_mongodb.js            # MongoDB collections, $jsonSchema validation, indexes
│   └── setup_all.js               # One-click database initializer
├── docs/
│   ├── DATABASE_DESIGN.md         # ER diagram, relational schema, normalization (1NF-BCNF)
│   ├── TECHNOLOGY_JUSTIFICATION.md# Relational (MySQL) vs NoSQL (MongoDB) justification
│   └── VIVA_QUESTIONS_AND_ANSWERS.md # Academic viva preparation guide
├── sample-repo/                   # Synthetic test repository containing mock secrets
│   └── config/settings.py
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── analytics/queries/ # Advanced SQL Console endpoint
│   │   │   ├── auth/              # Authentication & JWT session handling
│   │   │   ├── evidence-rud/      # MongoDB Full RUD & Aggregation Pipeline
│   │   │   ├── findings/          # Finding retrieval, status update, SP resolve
│   │   │   ├── repositories/      # Relational DML operations (Insert, Select, Delete)
│   │   │   └── scan/              # Scanner engine & dual-database persistence
│   │   ├── dashboard-client.tsx   # Interactive 5-tab Next.js Dashboard
│   │   ├── login/                 # Role-based login page with quick demo switcher
│   │   └── page.tsx               # Protected root homepage
│   └── lib/
│       ├── auth.ts                # Session verification & MySQL user role check
│       ├── mongodb.ts             # MongoDB client connection pool
│       └── mysql.ts               # MySQL connection pool
├── DBMS_PROJECT_REPORT.md         # Formal academic submission report
└── README.md                      # Project documentation
```
