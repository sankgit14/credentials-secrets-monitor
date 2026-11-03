import { NextRequest, NextResponse } from "next/server";
import clientPromise from "@/lib/mongodb";
import { getSessionUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const mode = searchParams.get("mode") ?? "list";
  const secretType = searchParams.get("secretType");

  try {
    const client = await clientPromise;
    const db = client.db(process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence");

    if (mode === "aggregate") {
      // MongoDB Aggregation Pipeline: Group findings by secretType and calculate statistics
      const pipeline = [
        { $unwind: "$evidence" },
        ...(secretType ? [{ $match: { "evidence.secretType": secretType } }] : []),
        {
          $group: {
            _id: "$evidence.secretType",
            totalExposures: { $sum: 1 },
            uniqueFiles: { $addToSet: "$evidence.filePath" },
            scansSeenIn: { $addToSet: "$scanRunId" },
          },
        },
        {
          $project: {
            _id: 0,
            secretType: "$_id",
            totalExposures: 1,
            fileCount: { $size: "$uniqueFiles" },
            scanCount: { $size: "$scansSeenIn" },
          },
        },
        { $sort: { totalExposures: -1 } },
      ];

      const aggResults = await db.collection("scan_evidence").aggregate(pipeline).toArray();
      return NextResponse.json({ success: true, mode: "aggregate", data: aggResults });
    }

    // Default: READ Evidence and Annotations
    const evidenceList = await db
      .collection("scan_evidence")
      .find({})
      .sort({ createdAt: -1 })
      .limit(20)
      .toArray();

    const annotations = await db
      .collection("evidence_annotations")
      .find({})
      .sort({ updatedAt: -1 })
      .limit(50)
      .toArray();

    return NextResponse.json({
      success: true,
      mode: "list",
      evidence: evidenceList,
      annotations,
    });
  } catch (error) {
    console.error("MongoDB Read error:", error);
    // Return sample mock evidence if local MongoDB instance is offline
    return NextResponse.json({
      success: true,
      isFallback: true,
      mode,
      evidence: [
        {
          scanRunId: 1,
          repositoryName: "demo-payment-service",
          scanner: "synthetic-demo-scanner",
          findingsSummary: { total: 3, critical: 1, high: 2, medium: 0, low: 0 },
          evidence: [
            {
              findingId: 1,
              filePath: "config/settings.py",
              lineNumber: 5,
              secretType: "AWS_ACCESS_KEY_ID",
              maskedPreview: "AKIA****123",
            },
            {
              findingId: 2,
              filePath: "config/settings.py",
              lineNumber: 4,
              secretType: "API_KEY",
              maskedPreview: "sk_t****7890",
            },
          ],
          createdAt: new Date().toISOString(),
        },
      ],
      annotations: [
        {
          scanRunId: 1,
          findingId: 1,
          annotatedBy: user.name,
          status: "VERIFIED_EXPOSURE",
          notes: "Live AWS credentials verified on AWS console.",
          tags: ["p0", "cloud"],
          updatedAt: new Date().toISOString(),
        },
      ],
    });
  }
}

// U (Update) or C (Create) annotation in MongoDB
export async function POST(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { scanRunId, findingId, status, notes, tags } = body;

    if (!scanRunId || !findingId || !status) {
      return NextResponse.json(
        { success: false, error: "scanRunId, findingId, and status are required." },
        { status: 400 },
      );
    }

    const client = await clientPromise;
    const db = client.db(process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence");

    // Upsert (Update if exists, Create if new)
    const result = await db.collection("evidence_annotations").updateOne(
      { scanRunId: Number(scanRunId), findingId: Number(findingId) },
      {
        $set: {
          annotatedBy: user.name,
          status,
          notes: notes ?? "",
          tags: Array.isArray(tags) ? tags : ["manual_triage"],
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );

    return NextResponse.json({
      success: true,
      message: "NoSQL document successfully updated / created in MongoDB.",
      matchedCount: result.matchedCount,
      upsertedId: result.upsertedId,
    });
  } catch (error) {
    console.error("MongoDB Annotation Upsert error:", error);
    return NextResponse.json(
      { success: false, error: "Failed to persist NoSQL annotation." },
      { status: 500 },
    );
  }
}

// D (Delete) annotation or evidence item in MongoDB
export async function DELETE(request: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.json({ success: false, error: "Authentication required." }, { status: 401 });
  }

  // Only ADMIN can perform Delete
  if (user.role !== "ADMIN") {
    return NextResponse.json(
      { success: false, error: "Forbidden. Admin role required for NoSQL DELETE operations." },
      { status: 403 },
    );
  }

  try {
    const { searchParams } = new URL(request.url);
    const findingId = searchParams.get("findingId");
    const scanRunId = searchParams.get("scanRunId");

    if (!findingId || !scanRunId) {
      return NextResponse.json(
        { success: false, error: "findingId and scanRunId query params are required." },
        { status: 400 },
      );
    }

    const client = await clientPromise;
    const db = client.db(process.env.MONGODB_DATABASE ?? "secrets_monitor_evidence");

    const deleteResult = await db.collection("evidence_annotations").deleteOne({
      scanRunId: Number(scanRunId),
      findingId: Number(findingId),
    });

    return NextResponse.json({
      success: true,
      message: `NoSQL annotation for finding #${findingId} in scan #${scanRunId} deleted.`,
      deletedCount: deleteResult.deletedCount,
    });
  } catch (error) {
    console.error("MongoDB Delete error:", error);
    return NextResponse.json(
      { success: false, error: "Failed to delete NoSQL document." },
      { status: 500 },
    );
  }
}

