import { NextResponse } from "next/server";
import { listScans, seedDemosIfEmpty } from "@/lib/services/scanService";

export async function GET() {
  try {
    await seedDemosIfEmpty();
    const scans = await listScans();
    return NextResponse.json({ scans });
  } catch (error) {
    return NextResponse.json(
      { error: error.message || "Failed to retrieve scan history." },
      { status: 500 }
    );
  }
}
