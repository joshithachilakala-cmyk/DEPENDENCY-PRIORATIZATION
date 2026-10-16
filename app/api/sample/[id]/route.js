import { NextResponse } from "next/server";
import prisma from "@/lib/db.js";
import { createScanFromReport, getScanFindings } from "@/lib/services/scanService.js";
import { ENTERPRISE_CSV, OWASP_JSON, SNYK_JSON } from "@/lib/sampleData.js";

export async function GET(request, { params }) {
  const resolvedParams = await params;
  const sampleId = resolvedParams?.id || "enterprise";

  try {
    let scan = await prisma.scan.findFirst({
      where: { isDemo: true, demoId: sampleId }
    });

    if (!scan) {
      let content = ENTERPRISE_CSV;
      let fileName = "enterprise_scan.csv";
      let proj = "Enterprise Multi-Stack Microservices";

      if (sampleId === "owasp") {
        content = JSON.stringify(OWASP_JSON);
        fileName = "owasp_report.json";
        proj = "Billing Gateway Microservice";
      } else if (sampleId === "snyk") {
        content = JSON.stringify(SNYK_JSON);
        fileName = "snyk_scan.json";
        proj = "Frontend Web Application";
      }

      const created = await createScanFromReport(content, fileName, {
        isDemo: true,
        demoId: sampleId,
        customProjectName: proj
      });
      scan = created.scan;
    }

    const { findings } = await getScanFindings(scan.id, { limit: 5000 });

    const metrics = {
      total: scan.totalFindings,
      critical_high: scan.criticalHighCount,
      fixable: scan.fixableCount,
      fixable_percent: scan.fixablePercent,
      avg_score: scan.avgScore,
      p0: scan.p0Count,
      p1: scan.p1Count,
      p2: scan.p2Count,
      p3: scan.p3Count
    };

    return NextResponse.json({
      scan,
      metrics,
      records: findings,
      provenance: {
        projectName: scan.projectName,
        scannerType: scan.scannerType,
        scanDate: scan.uploadedAt,
        fileName: scan.fileName,
        fileSize: scan.fileSize,
        isDemo: true,
        demoId: sampleId,
        status: scan.status
      },
      source_name: scan.fileName
    });
  } catch (error) {
    return NextResponse.json(
      { error: `Failed to load sample: ${error.message}` },
      { status: 500 }
    );
  }
}
