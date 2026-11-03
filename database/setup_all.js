/**
 * One-Click Database Setup Script
 * Initializes both MySQL 8.0 and MongoDB collections, schema validation, and seeds.
 * 
 * Usage:
 *   node database/setup_all.js
 */

const fs = require("fs");
const path = require("path");
const mysql = require("mysql2/promise");
const { MongoClient } = require("mongodb");

require("dotenv").config({ path: path.join(__dirname, "..", ".env.local") });

async function setupMySQL() {
  console.log("\n=================================");
  console.log("Setting up MySQL Database...");
  console.log("=================================");

  const config = {
    host: process.env.MYSQL_HOST || "localhost",
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASSWORD || "root",
    multipleStatements: true,
  };

  let connection;
  try {
    connection = await mysql.createConnection(config);
    console.log("Connected to MySQL server.");

    const ddlPath = path.join(__dirname, "01_schema_ddl.sql");
    const ddlSql = fs.readFileSync(ddlPath, "utf8");
    console.log("Executing Script 01: DDL with Constraints...");
    await connection.query(ddlSql);

    const advancedPath = path.join(__dirname, "02_advanced_objects.sql");
    const advancedSql = fs.readFileSync(advancedPath, "utf8");
    console.log("Executing Script 02: Procedures, Functions, Triggers, Views...");
    // Split and execute DELIMITER blocks or entire script
    await connection.query("USE secrets_monitor;");
    await connection.query(advancedSql);

    const seedPath = path.join(__dirname, "03_seed_data.sql");
    const seedSql = fs.readFileSync(seedPath, "utf8");
    console.log("Executing Script 03: Seed Sample Data...");
    await connection.query(seedSql);

    console.log("✓ MySQL database setup completed successfully!");
  } catch (err) {
    console.error("MySQL Setup Note (if server offline):", err.message);
  } finally {
    if (connection) await connection.end();
  }
}

async function setupMongoDB() {
  console.log("\n=================================");
  console.log("Setting up MongoDB Database...");
  console.log("=================================");

  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017";
  const dbName = process.env.MONGODB_DATABASE || "secrets_monitor_evidence";

  let client;
  try {
    client = new MongoClient(uri);
    await client.connect();
    console.log(`Connected to MongoDB. Target DB: ${dbName}`);

    const { initializeMongo } = require("./init_mongodb");
    await initializeMongo();

    console.log("✓ MongoDB setup completed successfully!");
  } catch (err) {
    console.error("MongoDB Setup Note (if server offline):", err.message);
  } finally {
    if (client) await client.close();
  }
}

async function main() {
  console.log("Credentials & Secrets Exposure Monitor - Database Initializer");
  await setupMySQL();
  await setupMongoDB();
  console.log("\nSetup routine finished.");
}

main();

