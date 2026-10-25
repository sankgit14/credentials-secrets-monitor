
import { NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import { getSessionUser } from "@/lib/auth";

export async function GET() {
  const user = await getSessionUser();

  if (!user) {
    return NextResponse.json(
      { success: false, error: "Authentication required." },
      { status: 401 },
    );
  }

  try {
    const client = await clientPromise;
    const databaseName =
      process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence";

    const db = client.db(databaseName);

    const evidence = await db
      .collection("scan_evidence")
      .find(
        {},
        {
          projection: {
            _id: 0,
            scanRunId: 1,
            repositoryName: 1,
            scanner: 1,
            findingsSummary: 1,
            evidence: 1,
            createdAt: 1,
          },
        },
      )
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();

    return NextResponse.json({
      success: true,
      count: evidence.length,
      evidence,
    });
  } catch (error) {
    console.error("Scan evidence retrieval failed:", error);

    return NextResponse.json(
      { success: false, error: "Failed to retrieve scan evidence." },
      { status: 500 },
    );
  }
}
