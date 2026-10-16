import { NextResponse } from "next/server";
import { generateMarkdownPlan } from "@/lib/services/exportService.js";

export async function POST(request) {
  try {
    const { records = [], metrics = {}, source_name = "Scan Report" } = await request.json();

    const markdownContent = generateMarkdownPlan({
      scan: { fileName: source_name, projectName: source_name },
      findings: records,
      metrics
    });

    return new NextResponse(markdownContent, {
      status: 200,
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": 'attachment; filename="remediation_plan.md"'
      }
    });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
