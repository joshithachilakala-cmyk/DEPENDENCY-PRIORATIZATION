import { NextResponse } from "next/server";
import prisma from "@/lib/db";
import { ALGORITHM_VERSION } from "@/lib/services/scoringEngine";

export async function GET() {
  try {
    const scanCount = await prisma.scan.count();
    const findingCount = await prisma.finding.count();

    return NextResponse.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      service: "Dependency Prioritizer - SCA Risk Engine",
      scoring_algorithm_version: ALGORITHM_VERSION,
      database: {
        connected: true,
        provider: "sqlite",
        total_scans: scanCount,
        total_findings: findingCount
      }
    });
  } catch (error) {
    return NextResponse.json(
      {
        status: "degraded",
        timestamp: new Date().toISOString(),
        error: error.message
      },
      { status: 503 }
    );
  }
}
