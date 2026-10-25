
import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";

export async function GET() {
  try {
    const client = await clientPromise;
    const databaseName =
      process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence";

    const db = client.db(databaseName);
    const ping = await db.command({ ping: 1 });
    const collections = await db
      .listCollections({}, { nameOnly: true })
      .toArray();

    return NextResponse.json({
      success: true,
      database: databaseName,
      ping: ping.ok === 1,
      collections: collections.map((collection) => collection.name),
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error);

    return NextResponse.json(
      { success: false, error: "MongoDB connection failed" },
      { status: 500 },
    );
  }
}
