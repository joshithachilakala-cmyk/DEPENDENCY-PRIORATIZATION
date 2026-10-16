import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import prisma from "../lib/db.js";
import { createScanFromReport, getScanById, getScanFindings, listScans } from "../lib/services/scanService.js";

describe("Database & ORM Relational Test Suite", () => {
  let createdScanId = null;

  before(async () => {
    // Ensure test database connection is healthy
    await prisma.$connect();
  });

  after(async () => {
    if (createdScanId) {
      await prisma.scan.delete({ where: { id: createdScanId } }).catch(() => {});
    }
    await prisma.$disconnect();
  });

  test("Transactionally persists Scan, Findings, DependencyContext, and Remediation", async () => {
    const csvContent = `library,version,cve_id,severity,cvss,fix_available,fix_version,exposure,description\n"test-lib","1.0.0","CVE-2024-9999","CRITICAL","9.8","true","1.0.1","DIRECT / PRODUCTION","Critical arbitrary code execution"\n"dev-tool","2.0.0","CVE-2024-8888","MEDIUM","4.5","false","","DIRECT / DEV","Local dev denial of service"`;

    const { scan, metrics } = await createScanFromReport(csvContent, "test_integration.csv", {
      isDemo: false,
      customProjectName: "Integration Test Project"
    });

    createdScanId = scan.id;
    assert.ok(createdScanId);
    assert.equal(scan.projectName, "Integration Test Project");
    assert.equal(scan.totalFindings, 2);
    assert.equal(metrics.total, 2);
    assert.ok(metrics.critical_high >= 1);

    // Verify relations in database
    const fetchedFindings = await prisma.finding.findMany({
      where: { scanId: createdScanId },
      include: { dependencyContext: true, remediation: true }
    });

    assert.equal(fetchedFindings.length, 2);
    const critical = fetchedFindings.find(f => f.library === "test-lib");
    assert.ok(critical);
    assert.equal(critical.severity, "CRITICAL");
    assert.equal(critical.dependencyContext.isDirect, true);
    assert.equal(critical.dependencyContext.isProduction, true);
    assert.equal(critical.remediation.fixAvailable, true);
    assert.equal(critical.remediation.priorityTier, "P0");
  });

  test("Queries findings with server-side search, filtering, and sorting", async () => {
    assert.ok(createdScanId);

    // 1. Search filter
    const searchRes = await getScanFindings(createdScanId, { search: "test-lib" });
    assert.equal(searchRes.findings.length, 1);
    assert.equal(searchRes.findings[0].library, "test-lib");

    // 2. Priority Tier filter
    const p0Res = await getScanFindings(createdScanId, { tier: "P0" });
    assert.equal(p0Res.findings.length, 1);
    assert.equal(p0Res.findings[0].risk.tier, "P0");

    // 3. Fix status filter
    const noFixRes = await getScanFindings(createdScanId, { fix: "NO_FIX" });
    assert.equal(noFixRes.findings.length, 1);
    assert.equal(noFixRes.findings[0].library, "dev-tool");

    // 4. Sorting by CVSS descending
    const sortRes = await getScanFindings(createdScanId, { sort: "cvss_desc" });
    assert.equal(sortRes.findings[0].library, "test-lib", "Highest CVSS must be first");
  });

  test("ListScans returns scan provenance and metadata", async () => {
    const scans = await listScans();
    assert.ok(Array.isArray(scans));
    assert.ok(scans.length > 0);
    const found = scans.find(s => s.id === createdScanId);
    assert.ok(found);
    assert.equal(found.fileName, "test_integration.csv");
  });
});
