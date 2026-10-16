import { NextResponse } from "next/server";
import prisma from "@/lib/db";

export async function GET(request, { params }) {
  try {
    const resolvedParams = await params;
    const scanId = resolvedParams?.scanId;
    const findingId = resolvedParams?.findingId;

    if (!scanId || !findingId) {
      return NextResponse.json({ error: "Missing scanId or findingId parameter." }, { status: 400 });
    }

    const finding = await prisma.finding.findFirst({
      where: {
        id: findingId,
        scanId
      },
      include: {
        dependencyContext: true,
        remediation: true
      }
    });

    if (!finding) {
      return NextResponse.json({ error: "Finding not found." }, { status: 404 });
    }

    return NextResponse.json({ finding });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to retrieve finding details." },
      { status: 500 }
    );
  }
}
