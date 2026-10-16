import { NextResponse } from "next/server";
import { getScanById } from "@/lib/services/scanService";
import prisma from "@/lib/db";

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

    return NextResponse.json({ scan });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to retrieve scan." },
      { status: 500 }
    );
  }
}

export async function DELETE(request, { params }) {
  try {
    const resolvedParams = await params;
    const scanId = resolvedParams?.scanId;

    if (!scanId) {
      return NextResponse.json({ error: "Missing scanId parameter." }, { status: 400 });
    }

    await prisma.scan.delete({
      where: { id: scanId }
    });

    return NextResponse.json({ success: true, message: "Scan deleted successfully." });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to delete scan." },
      { status: 500 }
    );
  }
}
