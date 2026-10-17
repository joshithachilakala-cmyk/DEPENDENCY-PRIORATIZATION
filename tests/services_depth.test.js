import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import prisma from "../lib/db.js";
import {
  createScanFromReport,
  getScanById,
  listScans,
  getScanFindings
} from "../lib/services/scanService.js";
import {
  sanitizeCsvCell,
  generateCsvExport,
  generateMarkdownPlan
} from "../lib/services/exportService.js";

describe("In-Depth Unit Tests: exportService.js", () => {
  describe("sanitizeCsvCell: CWE-1236 Formula Injection Defense", () => {
    test("neutralizes formula command prefixes (=, +, -, @, \\t, \\r)", () => {
      assert.equal(sanitizeCsvCell("=1+1"), `"'=1+1"`);
      assert.equal(sanitizeCsvCell("+cmd|' /C calc'!A0"), `"'+cmd|' /C calc'!A0"`);
      assert.equal(sanitizeCsvCell("-SUM(A1:A10)"), `"'-SUM(A1:A10)"`);
      assert.equal(sanitizeCsvCell("@import(malicious)"), `"'@import(malicious)"`);
      assert.equal(sanitizeCsvCell("\tpayload"), `"'\tpayload"`);
      assert.equal(sanitizeCsvCell("\rpayload"), `"'\rpayload"`);
    });

    test("escapes quotes and handles line breaks and nulls", () => {
      assert.equal(sanitizeCsvCell(null), '""');
      assert.equal(sanitizeCsvCell(undefined), '""');
      assert.equal(sanitizeCsvCell('package "quoted" name'), '"package ""quoted"" name"');
      assert.equal(sanitizeCsvCell("line 1\nline 2"), '"line 1 line 2"');
    });
  });

  describe("generateCsvExport & generateMarkdownPlan", () => {
    const mockFindings = [
      {
        rank: 1,
        library: "lodash",
        version: "4.17.20",
        cve_id: "CVE-2021-23337",
        severity: "HIGH",
        cvss: 7.4,
        exposure: "DIRECT / PRODUCTION",
        fix_available: true,
        fix_version: "4.17.21",
        description: "Prototype pollution in template",
        risk: {
          tier: "P0",
          score: 88,
          rationale: "Immediate P0 review"
        },
        remediation: {
          actionTitle: "Upgrade lodash to 4.17.21",
          upgradeCommand: "npm install lodash@4.17.21",
          semverJumpLabel: "Patch / Bugfix Update"
        }
      }
    ];

    test("generates RFC 4180 CSV export with matching column headers", () => {
      const csv = generateCsvExport(mockFindings);
      assert.ok(csv.includes("Priority_Rank,Priority_Tier,Risk_Score,Library"));
      assert.ok(csv.includes('"lodash"'));
      assert.ok(csv.includes('"CVE-2021-23337"'));
      assert.ok(csv.includes('"YES (Mandatory Human Gate)"'));
    });

    test("generates Markdown remediation plan with SLA metrics and NVD links", () => {
      const plan = generateMarkdownPlan({
        scan: {
          projectName: "Deep Test App",
          scannerType: "OWASP Dependency-Check",
          fileName: "test_report.json"
        },
        findings: mockFindings,
        metrics: {
          total: 1,
          critical_high: 1,
          fixable: 1,
          fixable_percent: 100,
          avg_score: 88,
          p0: 1,
          p1: 0,
          p2: 0,
          p3: 0
        }
      });

      assert.ok(plan.includes("# Dependency Vulnerability Prioritization & Remediation Plan"));
      assert.ok(plan.includes("Deep Test App"));
      assert.ok(plan.includes("Mandatory Human Gate"));
      assert.ok(plan.includes("https://nvd.nist.gov/vuln/detail/CVE-2021-23337"));
      assert.ok(plan.includes("`lodash@4.17.20`"));
    });
  });
});

describe("In-Depth Integration Tests: scanService.js & Database Lifecycle", () => {
  let createdScanId = null;

  test("createScanFromReport parses, scores, ranks, and saves to database", async () => {
    const csvContent = `library,version,cve_id,severity,cvss,fix_version,fix_available,exposure,description
express,4.16.0,CVE-2022-24999,HIGH,7.5,4.18.2,true,DIRECT / PRODUCTION,prototype pollution in qs
minimist,0.0.8,CVE-2020-7598,MEDIUM,5.3,1.2.6,true,TRANSITIVE / DEV,prototype pollution in parse
mocha,8.0.0,CVE-2021-0000,LOW,3.1,,false,TRANSITIVE / TEST,unverified test dependency bug`;

    const result = await createScanFromReport(csvContent, "integration_deep_scan.csv", {
      customProjectName: "Deep Integration Suite"
    });

    assert.ok(result.scan);
    assert.equal(result.scan.projectName, "Deep Integration Suite");
    assert.equal(result.metrics.total, 3);
    createdScanId = result.scan.id;

    const { findings } = await getScanFindings(createdScanId);
    assert.equal(findings.length, 3);
    assert.equal(findings[0].rank, 1);
    assert.ok(findings[0].risk.score >= findings[1].risk.score);
  });

  test("listScans returns persisted scans", async () => {
    const scans = await listScans();
    assert.ok(scans.length > 0);
    const found = scans.find(s => s.id === createdScanId);
    assert.ok(found);
    assert.equal(found.projectName, "Deep Integration Suite");
  });

  test("getScanById returns scan record with summary metrics", async () => {
    const scan = await getScanById(createdScanId);
    assert.ok(scan);
    assert.equal(scan.totalFindings, 3);
  });

  test("getScanFindings filters by search query", async () => {
    const { findings, total } = await getScanFindings(createdScanId, { search: "express" });
    assert.equal(total, 1);
    assert.equal(findings[0].library, "express");
  });

  test("getScanFindings filters by severity and tier", async () => {
    const { findings: highFindings } = await getScanFindings(createdScanId, { severity: "HIGH" });
    assert.equal(highFindings.length, 1);
    assert.equal(highFindings[0].library, "express");
  });

  test("getScanFindings filters by fix availability", async () => {
    const { findings: fixableFindings } = await getScanFindings(createdScanId, { fix: "FIXABLE" });
    assert.ok(fixableFindings.length >= 1);
    assert.ok(fixableFindings.every(f => f.fix_available === true));
  });

  test("getScanFindings supports pagination and sorting", async () => {
    const page1 = await getScanFindings(createdScanId, { page: 1, limit: 2 });
    assert.equal(page1.findings.length, 2);
    assert.equal(page1.page, 1);

    const page2 = await getScanFindings(createdScanId, { page: 2, limit: 2 });
    assert.equal(page2.findings.length, 1);
    assert.equal(page2.page, 2);

    const sortedAsc = await getScanFindings(createdScanId, { sort: "library_asc" });
    assert.equal(sortedAsc.findings[0].library, "express");
  });

  after(async () => {
    if (createdScanId) {
      await prisma.scan.delete({ where: { id: createdScanId } });
    }
    await prisma.$disconnect();
  });
});
