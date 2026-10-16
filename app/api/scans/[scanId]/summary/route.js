import { NextResponse } from "next/server";
import { getScanById } from "@/lib/services/scanService";

export async function GET(request, { params }) {
  try {
    const resolvedParams = await params;
    const scanId = resolvedParams?.scanId;

    if (!scanId) {
      return NextResponse.json({ error: "Missing scanId parameter." }, { status: 400 });
    }

    const scan = await getScanById(scanId);
    if (!scan) {
      return NextResponse.json({ error: "Scan not found." }, { status: 404 });
    }

    const summary = {
      scanId: scan.id,
      projectName: scan.projectName,
      scannerType: scan.scannerType,
      fileName: scan.fileName,
      fileSize: scan.fileSize,
      uploadedAt: scan.uploadedAt,
      isDemo: scan.isDemo,
      status: scan.status,
      metrics: {
        total: scan.totalFindings,
        critical_high: scan.criticalHighCount,
        fixable: scan.fixableCount,
        fixable_percent: scan.fixablePercent,
        avg_score: scan.avgScore,
        p0: scan.p0Count,
        p1: scan.p1Count,
        p2: scan.p2Count,
        p3: scan.p3Count
      }
    };

    return NextResponse.json(summary);
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to retrieve scan summary." },
      { status: 500 }
    );
  }
}
