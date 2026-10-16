import { PrismaClient } from "@prisma/client";
import { createScanFromReport } from "../lib/services/scanService.js";
import { ENTERPRISE_CSV, OWASP_JSON, SNYK_JSON } from "../lib/sampleData.js";

const prisma = new PrismaClient();

async function main() {
  console.log("Seeding initial scan data into database...");

  // Clear existing demos to ensure deterministic seed
  await prisma.scan.deleteMany({
    where: { isDemo: true }
  });

  const enterprise = await createScanFromReport(ENTERPRISE_CSV, "enterprise_scan.csv", {
    isDemo: true,
    demoId: "enterprise",
    customProjectName: "Enterprise Multi-Stack Microservices"
  });
  console.log(`✓ Seeded Enterprise Demo: ${enterprise.scan.id} (${enterprise.metrics.total} findings)`);

  const owasp = await createScanFromReport(JSON.stringify(OWASP_JSON), "owasp_report.json", {
    isDemo: true,
    demoId: "owasp",
    customProjectName: "Billing Gateway Microservice"
  });
  console.log(`✓ Seeded OWASP Demo: ${owasp.scan.id} (${owasp.metrics.total} findings)`);

  const snyk = await createScanFromReport(JSON.stringify(SNYK_JSON), "snyk_scan.json", {
    isDemo: true,
    demoId: "snyk",
    customProjectName: "Frontend Web Application"
  });
  console.log(`✓ Seeded Snyk Demo: ${snyk.scan.id} (${snyk.metrics.total} findings)`);

  console.log("Seeding completed successfully.");
}

main()
  .catch((e) => {
    console.error("Seeding error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
