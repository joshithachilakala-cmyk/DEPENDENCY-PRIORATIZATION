import { NextResponse } from "next/server";
import { createScanFromReport, getScanFindings } from "@/lib/services/scanService";

const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB

export async function POST(request) {
  try {
    const contentType = request.headers.get("content-type") || "";
    let rawContent = "";
    let filename = "uploaded_scan.csv";
    let customProjectName = null;

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file");
      if (!file) {
        return NextResponse.json(
          { error: "No file attached. Please select a valid scan report file." },
          { status: 400 }
        );
      }

      if (file.size > MAX_FILE_SIZE) {
        return NextResponse.json(
          {
            error: `File size exceeds the 15 MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB). Please upload a smaller slice.`
          },
          { status: 400 }
        );
      }

      filename = file.name || "uploaded_scan";
      rawContent = await file.text();
      customProjectName = formData.get("projectName") || null;
    } else {
      const body = await request.json();
      rawContent = body.content || "";
      filename = body.filename || "pasted_report.json";
      customProjectName = body.projectName || null;
    }

    if (!rawContent.trim()) {
      return NextResponse.json(
        { error: "The uploaded file is empty. Please verify the report contains scan results." },
        { status: 400 }
      );
    }

    const { scan, metrics } = await createScanFromReport(rawContent, filename, {
      isDemo: false,
      customProjectName
    });

    const { findings } = await getScanFindings(scan.id, { limit: 500 });

    return NextResponse.json({
      scan,
      metrics,
      records: findings,
      source_name: filename,
      provenance: {
        projectName: scan.projectName,
        scannerType: scan.scannerType,
        scanDate: scan.uploadedAt,
        fileName: scan.fileName,
        fileSize: scan.fileSize,
        isDemo: scan.isDemo,
        status: scan.status
      }
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: error.message || "An unexpected error occurred while parsing and persisting the scan report."
      },
      { status: 400 }
    );
  }
}
