import { NextResponse } from "next/server";
import { getScanFindings } from "@/lib/services/scanService";

export async function GET(request, { params }) {
  try {
    const resolvedParams = await params;
    const scanId = resolvedParams?.scanId;

    if (!scanId) {
      return NextResponse.json({ error: "Missing scanId parameter." }, { status: 400 });
    }

    const { searchParams } = new URL(request.url);
    const search = searchParams.get("search") || "";
    const tier = searchParams.get("tier") || "ALL";
    const severity = searchParams.get("severity") || "ALL";
    const fix = searchParams.get("fix") || "ALL";
    const sort = searchParams.get("sort") || "score_desc";
    const page = parseInt(searchParams.get("page") || "1", 10);
    const limit = parseInt(searchParams.get("limit") || "100", 10);

    const result = await getScanFindings(scanId, {
      search,
      tier,
      severity,
      fix,
      sort,
      page,
      limit
    });

    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to retrieve findings." },
      { status: 500 }
    );
  }
}
