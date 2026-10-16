import { NextResponse } from "next/server";
import prisma from "@/lib/db";
import { createScanFromReport, getScanFindings, seedDemosIfEmpty } from "@/lib/services/scanService";
import { ENTERPRISE_CSV, OWASP_JSON, SNYK_JSON } from "@/lib/sampleData";

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const demoId = body.demoId || "enterprise";

    let demoScan = await prisma.scan.findFirst({
      where: { isDemo: true, demoId }
    });

    if (!demoScan) {
      // Create it if not already present
      let content = ENTERPRISE_CSV;
      let label = "enterprise_scan.csv";
      let proj = "Enterprise Multi-Stack Microservices";

      if (demoId === "owasp") {
        content = JSON.stringify(OWASP_JSON);
        label = "owasp_report.json";
        proj = "Billing Gateway Microservice";
      } else if (demoId === "snyk") {
        content = JSON.stringify(SNYK_JSON);
        label = "snyk_scan.json";
        proj = "Frontend Web Application";
      }

      const created = await createScanFromReport(content, label, {
        isDemo: true,
        demoId,
        customProjectName: proj
      });
      demoScan = created.scan;
    }

    const { findings } = await getScanFindings(demoScan.id, { limit: 500 });

    const metrics = {
      total: demoScan.totalFindings,
      critical_high: demoScan.criticalHighCount,
      fixable: demoScan.fixableCount,
      fixable_percent: demoScan.fixablePercent,
      avg_score: demoScan.avgScore,
      p0: demoScan.p0Count,
      p1: demoScan.p1Count,
      p2: demoScan.p2Count,
      p3: demoScan.p3Count
    };

    return NextResponse.json({
      scan: demoScan,
      metrics,
      records: findings,
      source_name: demoScan.fileName,
      provenance: {
        projectName: demoScan.projectName,
        scannerType: demoScan.scannerType,
        scanDate: demoScan.uploadedAt,
        fileName: demoScan.fileName,
        fileSize: demoScan.fileSize,
        isDemo: true,
        demoId,
        status: demoScan.status
      }
    });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to load demo scan." },
      { status: 500 }
    );
  }
}
