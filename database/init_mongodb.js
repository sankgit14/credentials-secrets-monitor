/**
 * ============================================================================
 * CREDENTIALS AND SECRETS EXPOSURE MONITORING PLATFORM
 * PES University - Department of Computer Science and Engineering
 * DBMS Level 3 MiniProject
 * Script: MongoDB Database Creation, Schema Validation & Indexes
 * ============================================================================
 */

const { MongoClient } = require("mongodb");

const uri = process.env.MONGODB_URI || "mongodb://localhost:27017";
const dbName = process.env.MONGODB_DATABASE || "secrets_monitor_evidence";

async function initializeMongo() {
  const client = new MongoClient(uri);

  try {
    await client.connect();
    console.log(`Connected to MongoDB. Initializing database: ${dbName}`);

    const db = client.db(dbName);

    // 1. Create collection with JSON Schema Validation
    const collections = await db.listCollections({ name: "scan_evidence" }).toArray();
    if (collections.length === 0) {
      await db.createCollection("scan_evidence", {
        validator: {
          $jsonSchema: {
            bsonType: "object",
            required: ["scanRunId", "repositoryName", "scanner", "findingsSummary", "evidence", "createdAt"],
            properties: {
              scanRunId: {
                bsonType: "number",
                description: "Must be a number matching MySQL scan_run_id and is required"
              },
              repositoryName: {
                bsonType: "string",
                description: "Must be a string and is required"
              },
              scanner: {
                bsonType: "string",
                description: "Scanner identifier string"
              },
              findingsSummary: {
                bsonType: "object",
                required: ["total"],
                properties: {
                  total: { bsonType: "number" },
                  critical: { bsonType: "number" },
                  high: { bsonType: "number" },
                  medium: { bsonType: "number" },
                  low: { bsonType: "number" }
                }
              },
              evidence: {
                bsonType: "array",
                description: "List of masked findings evidence",
                items: {
                  bsonType: "object",
                  required: ["findingId", "filePath", "secretType", "maskedPreview"],
                  properties: {
                    findingId: { bsonType: "number" },
                    filePath: { bsonType: "string" },
                    lineNumber: { bsonType: "number" },
                    secretType: { bsonType: "string" },
                    maskedPreview: { bsonType: "string" }
                  }
                }
              },
              createdAt: {
                bsonType: "date",
                description: "Timestamp when scan evidence was captured"
              }
            }
          }
        }
      });
      console.log("Collection 'scan_evidence' created with JSON Schema Validation.");
    }

    // 2. Create collection for Analyst Evidence Annotations (Supports Full RUD)
    const annotCols = await db.listCollections({ name: "evidence_annotations" }).toArray();
    if (annotCols.length === 0) {
      await db.createCollection("evidence_annotations", {
        validator: {
          $jsonSchema: {
            bsonType: "object",
            required: ["scanRunId", "findingId", "annotatedBy", "status", "updatedAt"],
            properties: {
              scanRunId: { bsonType: "number" },
              findingId: { bsonType: "number" },
              annotatedBy: { bsonType: "string" },
              status: {
                enum: ["VERIFIED_EXPOSURE", "FALSE_POSITIVE", "NEEDS_TRIAGE", "RESOLVED_VERIFIED"],
                description: "Verification status tag"
              },
              notes: { bsonType: "string" },
              tags: {
                bsonType: "array",
                items: { bsonType: "string" }
              },
              updatedAt: { bsonType: "date" }
            }
          }
        }
      });
      console.log("Collection 'evidence_annotations' created with JSON Schema Validation.");
    }

    // 3. Create Indexes for High Performance Querying
    const evidenceColl = db.collection("scan_evidence");
    await evidenceColl.createIndex({ scanRunId: 1 }, { unique: true });
    await evidenceColl.createIndex({ createdAt: -1 });
    await evidenceColl.createIndex({ "evidence.secretType": 1 });
    await evidenceColl.createIndex({ "evidence.filePath": "text" });

    const annotColl = db.collection("evidence_annotations");
    await annotColl.createIndex({ scanRunId: 1, findingId: 1 }, { unique: true });
    await annotColl.createIndex({ status: 1 });

    console.log("MongoDB indexes successfully created.");

    // 4. Seed Initial Sample Scan Evidence
    const count = await evidenceColl.countDocuments();
    if (count === 0) {
      await evidenceColl.insertOne({
        scanRunId: 1,
        repositoryName: "demo-payment-service",
        scanner: "synthetic-demo-scanner",
        findingsSummary: {
          total: 3,
          critical: 1,
          high: 2,
          medium: 0,
          low: 0
        },
        evidence: [
          {
            findingId: 1,
            filePath: "config/settings.py",
            lineNumber: 5,
            secretType: "AWS_ACCESS_KEY_ID",
            maskedPreview: "AKIA****123"
          },
          {
            findingId: 2,
            filePath: "config/settings.py",
            lineNumber: 4,
            secretType: "API_KEY",
            maskedPreview: "sk_t****7890"
          },
          {
            findingId: 3,
            filePath: "config/settings.py",
            lineNumber: 6,
            secretType: "DATABASE_URL",
            maskedPreview: "post****demo_db"
          }
        ],
        createdAt: new Date("2026-10-01T10:02:15Z")
      });

      await annotColl.insertOne({
        scanRunId: 1,
        findingId: 1,
        annotatedBy: "Security Admin",
        status: "VERIFIED_EXPOSURE",
        notes: "Live AWS access key detected in configuration file. Critical blast radius.",
        tags: ["p0", "cloud", "aws"],
        updatedAt: new Date()
      });

      console.log("Sample MongoDB scan evidence and annotation seeded.");
    }

    console.log("MongoDB initialization completed successfully.");
  } catch (err) {
    console.error("MongoDB initialization error:", err);
  } finally {
    await client.close();
  }
}

if (require.main === module) {
  initializeMongo();
}

module.exports = { initializeMongo };

