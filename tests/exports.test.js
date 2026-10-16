import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { sanitizeCsvCell, generateCsvExport, generateMarkdownPlan } from "../lib/services/exportService.js";
import { generateCanonicalCsvTemplate } from "../lib/parsers/index.js";
import { parseCsv } from "../lib/parsers/csvParser.js";

describe("Export and Reporting Test Suite", () => {
  test("SanitizeCsvCell protects against formula injection (CWE-1236)", () => {
    assert.equal(sanitizeCsvCell("=1+1"), `"'=1+1"`);
    assert.equal(sanitizeCsvCell("+cmd|' /C calc'!A0"), `"'+cmd|' /C calc'!A0"`);
    assert.equal(sanitizeCsvCell("-SUM(A1:A10)"), `"'-SUM(A1:A10)"`);
    assert.equal(sanitizeCsvCell("@SUM(A1:A10)"), `"'@SUM(A1:A10)"`);
    assert.equal(sanitizeCsvCell("\tcalc"), `"'\tcalc"`);
    assert.equal(sanitizeCsvCell('Safe "text" with quote'), `"Safe ""text"" with quote"`);
  });

  test("GenerateCsvExport creates valid RFC 4180 headers and rows", () => {
    const findings = [
      {
        rank: 1,
        library: "log4j-core",
        version: "2.14.1",
        cve_id: "CVE-2021-44228",
        severity: "CRITICAL",
        cvss: 10.0,
        cvss_source: "REPORTED_CVSS",
        fix_available: true,
        fix_version: "2.17.1",
        exposure: "DIRECT / PRODUCTION",
        dependency_path: "log4j-core@2.14.1",
        risk: { score: 100.0, tier: "P0", rationale: "Immediate Review" },
        remediation: {
          actionTitle: "Upgrade log4j-core to 2.17.1",
          upgradeCommand: "mvn update",
          semverJumpLabel: "Minor Update",
          fixAvailable: true
        }
      }
    ];

    const csvOutput = generateCsvExport(findings);
    assert.ok(csvOutput.includes("Priority_Rank,Priority_Tier,Risk_Score"));
    assert.ok(csvOutput.includes('"log4j-core"'));
    assert.ok(csvOutput.includes('"P0"'));
    assert.ok(csvOutput.includes('"100"'));
    assert.ok(csvOutput.includes('"YES (Mandatory Human Gate)"'));
  });

  test("GenerateMarkdownPlan produces structured Markdown with human review notice", () => {
    const scan = {
      projectName: "Core Microservices",
      scannerType: "OWASP Dependency-Check",
      fileName: "owasp_report.json",
      uploadedAt: new Date().toISOString()
    };
    const findings = [
      {
        rank: 1,
        library: "spring-beans",
        version: "5.3.18",
        cve_id: "CVE-2022-22965",
        cvss: 9.8,
        exposure: "DIRECT / PRODUCTION",
        fix_available: true,
        fix_version: "5.3.19",
        risk: { score: 99.1, tier: "P0", rationale: "Spring4Shell RCE" },
        remediation: {
          actionTitle: "Upgrade spring-beans to 5.3.19",
          upgradeCommand: "mvn update spring-beans",
          semverNotice: "Minor bugfix",
          fixVersion: "5.3.19"
        }
      }
    ];
    const metrics = {
      total: 1,
      critical_high: 1,
      fixable: 1,
      fixable_percent: 100,
      avg_score: 99.1,
      p0: 1,
      p1: 0,
      p2: 0,
      p3: 0
    };

    const mdOutput = generateMarkdownPlan({ scan, findings, metrics });

    assert.ok(mdOutput.includes("# Dependency Vulnerability Prioritization & Remediation Plan"));
    assert.ok(mdOutput.includes("Mandatory Human Gate: Automated patches must never be deployed directly to production"));
    assert.ok(mdOutput.includes("### SLA & Triage Queue Breakdown"));
    assert.ok(mdOutput.includes("## 4. Mandatory Human Quality Gate Checklist"));
  });

  test("Canonical CSV template matches actual CSV parser schema", () => {
    const template = generateCanonicalCsvTemplate();
    const { records } = parseCsv(template, "template.csv");

    assert.ok(records.length >= 3, "Template must parse into valid records");
    assert.equal(records[0].library, "log4j-core");
    assert.equal(records[0].cve_id, "CVE-2021-44228");
    assert.equal(records[0].cvss, 10.0);
  });
});
