import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { parseCsv } from "../lib/parsers/csvParser.js";
import { parseOwaspJson } from "../lib/parsers/owaspParser.js";
import { parseSnykJson } from "../lib/parsers/snykParser.js";
import { parseNpmAuditJson } from "../lib/parsers/npmAuditParser.js";
import { ingestReport } from "../lib/parsers/index.js";

describe("SCA Report Parsers Test Suite", () => {
  test("Generic CSV parser handles standard headers and quoted commas", () => {
    const csvData = `library,version,cve_id,severity,cvss,fix_available,fix_version,exposure,description\n"log4j-core","2.14.1","CVE-2021-44228","CRITICAL","10.0","true","2.17.1","DIRECT / PRODUCTION","Remote Code Execution, JNDI flaw"`;
    const { records, provenance } = parseCsv(csvData, "test.csv");

    assert.equal(records.length, 1);
    assert.equal(records[0].library, "log4j-core");
    assert.equal(records[0].version, "2.14.1");
    assert.equal(records[0].cve_id, "CVE-2021-44228");
    assert.equal(records[0].severity, "CRITICAL");
    assert.equal(records[0].cvss, 10.0);
    assert.equal(records[0].fix_available, true);
    assert.equal(records[0].is_direct, true);
    assert.equal(records[0].is_production, true);
    assert.equal(provenance.scannerType, "Generic CSV Export");
  });

  test("CSV parser deduplicates repeated findings within the same scan", () => {
    const csvData = `library,version,cve_id,severity,cvss\n"lodash","4.17.15","CVE-2020-8203","HIGH","7.4"\n"lodash","4.17.15","CVE-2020-8203","HIGH","7.4"`;
    const { records } = parseCsv(csvData, "dedup_test.csv");

    assert.equal(records.length, 1, "Duplicate finding should be deduplicated");
  });

  test("CSV parser handles missing CVSS score by inferring from severity", () => {
    const csvData = `library,version,cve_id,severity,cvss\n"express","4.16.0","CVE-2022-24999","HIGH",""`;
    const { records } = parseCsv(csvData, "inferred.csv");

    assert.equal(records.length, 1);
    assert.equal(records[0].cvss, 8.0, "High severity without CVSS should infer 8.0");
    assert.equal(records[0].cvss_source, "INFERRED_FROM_SEVERITY");
  });

  test("CSV parser neutralizes formula injection in cells", () => {
    const maliciousCsv = `library,version,cve_id,severity,cvss\n"=cmd|' /C calc'!A0","1.0.0","CVE-2023-0001","LOW","2.0"`;
    const { records } = parseCsv(maliciousCsv, "injection.csv");

    assert.equal(records.length, 1);
    assert.ok(!records[0].library.startsWith("="), "Leading formula equals sign should be stripped during ingestion");
  });

  test("OWASP Dependency-Check JSON parser extracts dependencies and CVSS v3/v2", () => {
    const owaspSample = {
      projectInfo: { name: "Billing Microservice", reportDate: "2026-10-16T12:00:00Z" },
      scanInfo: { engineVersion: "8.4.0" },
      dependencies: [
        {
          fileName: "spring-beans-5.3.18.jar",
          isVirtual: false,
          vulnerabilities: [
            {
              name: "CVE-2022-22965",
              severity: "CRITICAL",
              cvssv3: { baseScore: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
              description: "Spring Framework RCE via Data Binding (Spring4Shell)."
            }
          ]
        }
      ]
    };

    const { records, provenance } = parseOwaspJson(owaspSample, "owasp.json");
    assert.equal(records.length, 1);
    assert.equal(records[0].library, "spring-beans");
    assert.equal(records[0].version, "5.3.18");
    assert.equal(records[0].cve_id, "CVE-2022-22965");
    assert.equal(records[0].cvss, 9.8);
    assert.equal(records[0].severity, "CRITICAL");
    assert.equal(records[0].is_direct, true);
    assert.ok(provenance.scannerType.includes("OWASP"));
  });

  test("Snyk CLI JSON parser extracts vulnerabilities and dependency 'from' chain", () => {
    const snykSample = {
      projectName: "Frontend Web Application",
      vulnerabilities: [
        {
          packageName: "minimist",
          version: "1.2.5",
          id: "SNYK-JS-MINIMIST-559764",
          identifiers: { CVE: ["CVE-2020-7598"] },
          severity: "medium",
          cvssScore: 5.6,
          fixedIn: ["1.2.6"],
          from: ["frontend-app@1.0.0", "mkdirp@0.5.1", "minimist@1.2.5"],
          title: "Prototype Pollution in minimist"
        }
      ]
    };

    const { records, provenance } = parseSnykJson(snykSample, "snyk.json");
    assert.equal(records.length, 1);
    assert.equal(records[0].library, "minimist");
    assert.equal(records[0].version, "1.2.5");
    assert.equal(records[0].cve_id, "CVE-2020-7598");
    assert.equal(records[0].fix_available, true);
    assert.equal(records[0].fix_version, "1.2.6");
    assert.equal(records[0].is_direct, false, "Chain length > 2 indicates transitive dependency");
    assert.equal(records[0].dependency_path, "frontend-app@1.0.0 → mkdirp@0.5.1 → minimist@1.2.5");
    assert.ok(provenance.scannerType.includes("Snyk"));
  });

  test("npm audit JSON parser parses vulnerability tree and dev dependencies", () => {
    const npmSample = {
      name: "node-service",
      vulnerabilities: {
        mocha: {
          name: "mocha",
          severity: "high",
          isDirect: true,
          isDev: true,
          fixAvailable: true,
          range: "7.0.0",
          nodes: ["mocha@7.0.0"],
          via: [{ title: "Command injection in mocha", url: "https://nvd.nist.gov/vuln/detail/CVE-2020-7774" }]
        }
      }
    };

    const { records } = parseNpmAuditJson(npmSample, "npm-audit.json");
    assert.equal(records.length, 1);
    assert.equal(records[0].library, "mocha");
    assert.equal(records[0].is_direct, true);
    assert.equal(records[0].is_production, false, "isDev: true must flag is_production: false");
    assert.equal(records[0].exposure, "DIRECT / DEV");
  });

  test("ingestReport validates file size and empty inputs safely", () => {
    assert.throws(
      () => ingestReport("", "empty.csv"),
      /The uploaded scan report is empty/
    );

    assert.throws(
      () => ingestReport("invalid,header,only\n", "empty.csv"),
      /Missing required package\/library name column/
    );

    assert.throws(
      () => ingestReport("{ broken json", "broken.json"),
      /Malformed JSON/
    );
  });
});
