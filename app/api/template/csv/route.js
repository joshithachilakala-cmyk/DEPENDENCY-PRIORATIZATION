import { NextResponse } from "next/server";
import { generateCanonicalCsvTemplate } from "@/lib/parsers/index.js";

export async function GET() {
  const template = generateCanonicalCsvTemplate();
  return new NextResponse(template, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="dependency_scan_template.csv"'
    }
  });
}
