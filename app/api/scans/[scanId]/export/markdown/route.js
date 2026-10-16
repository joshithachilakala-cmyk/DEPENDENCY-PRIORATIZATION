import { NextResponse } from "next/server";
import { getScanById, getScanFindings } from "@/lib/services/scanService";
import { generateMarkdownPlan } from "@/lib/services/exportService";

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

    const { searchParams } = new URL(request.url);
    const search = searchParams.get("search") || "";
    const tier = searchParams.get("tier") || "ALL";
    const severity = searchParams.get("severity") || "ALL";
    const fix = searchParams.get("fix") || "ALL";
    const sort = searchParams.get("sort") || "score_desc";

    const { findings } = await getScanFindings(scanId, {
      search,
      tier,
      severity,
      fix,
      sort,
      limit: 5000
    });

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

    const markdownContent = generateMarkdownPlan({
      scan,
      findings,
      metrics
    });

    const safeName = (scan.fileName || "scan").replace(/\.[^/.]+$/, "");

    return new NextResponse(markdownContent, {
      status: 200,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="remediation_plan_${safeName}.md"`
      }
    });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to generate Markdown export." },
      { status: 500 }
    );
  }
}
