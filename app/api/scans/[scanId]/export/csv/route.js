import { NextResponse } from "next/server";
import { getScanById, getScanFindings } from "@/lib/services/scanService";
import { generateCsvExport } from "@/lib/services/exportService";

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

    const csvContent = generateCsvExport(findings);
    const safeName = (scan.fileName || "scan").replace(/\.[^/.]+$/, "");

    return new NextResponse(csvContent, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="prioritized_vulnerabilities_${safeName}.csv"`
      }
    });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to generate CSV export." },
      { status: 500 }
    );
  }
}
