import { NextResponse } from "next/server";
import { generateCsvExport } from "@/lib/services/exportService.js";

export async function POST(request) {
  try {
    const { records = [] } = await request.json();
    if (records.length === 0) {
      return NextResponse.json({ error: "No records to export." }, { status: 400 });
    }

    const csvContent = generateCsvExport(records);

    return new NextResponse(csvContent, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="prioritized_vulnerability_plan.csv"'
      }
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
