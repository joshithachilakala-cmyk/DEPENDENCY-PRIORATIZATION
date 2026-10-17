import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  cleanText,
  parseCsvRows,
  parseCvssValue,
  normalizeSeverity,
  normalizeExposureScope,
  parseCsv,
  CANONICAL_CSV_HEADERS
} from "../lib/parsers/csvParser.js";
import { parseOwaspJson } from "../lib/parsers/owaspParser.js";
import { parseSnykJson } from "../lib/parsers/snykParser.js";
import { parseNpmAuditJson } from "../lib/parsers/npmAuditParser.js";
import { ingestReport, generateCanonicalCsvTemplate } from "../lib/parsers/index.js";

describe("In-Depth Unit Tests: csvParser.js", () => {
  describe("cleanText & formula injection stripping", () => {
    test("handles null, undefined, empty inputs", () => {
      assert.equal(cleanText(null), "");
      assert.equal(cleanText(undefined), "");
      assert.equal(cleanText(""), "");
      assert.equal(cleanText("  hello  "), "hello");
      const { rows } = parseCsvRows("library,version\npkg,1.0");
      assert.equal(rows.length, 1);
    });

    test("strips formula injection prefixes (=, +, -, @, \\t, \\r)", () => {
      const csv = `library,version,cve_id,severity,cvss\n"=cmd|' /C calc'!A0","+1.0.0","-CVE-1234","@HIGH","\t9.5"`;
      const { records } = parseCsv(csv, "injection_deep.csv");
      assert.equal(records.length, 1);
      assert.equal(records[0].library, "cmd|' /C calc'!A0");
      assert.equal(records[0].version, "1.0.0");
      assert.equal(records[0].cve_id, "CVE-1234");
      assert.equal(records[0].cvss, 9.5);
    });
  });

  describe("parseCsvRows: quotes, commas, escapes, CRLF", () => {
    test("parses escaped quotes inside quoted strings", () => {
      const csv = `library,version,description\n"my-lib","1.0.0","Contains ""special"" quotes and, commas"`;
      const { rows } = parseCsvRows(csv);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].description, 'Contains "special" quotes and, commas');
    });

    test("handles Windows \\r\\n and Unix \\n seamlessly", () => {
      const csvCRLF = "library,version\r\npkg1,1.0\r\npkg2,2.0\r\n";
      const { rows: rowsCRLF } = parseCsvRows(csvCRLF);
      assert.equal(rowsCRLF.length, 2);
      assert.equal(rowsCRLF[0].library, "pkg1");
      assert.equal(rowsCRLF[1].library, "pkg2");
    });

    test("returns empty arrays for empty content, or headers with 0 rows for single line", () => {
      assert.deepEqual(parseCsvRows(""), { headers: [], rows: [] });
      assert.deepEqual(parseCsvRows("   "), { headers: [], rows: [] });
      const single = parseCsvRows("only_header_line");
      assert.deepEqual(single.rows, []);
      assert.equal(single.headers[0], "onlyheaderline");
    });
  });

  describe("parseCvssValue: numeric parsing & severity fallback", () => {
    test("parses valid numeric CVSS within 0 to 10 range", () => {
      assert.deepEqual(parseCvssValue("9.8"), { score: 9.8, source: "REPORTED_CVSS" });
      assert.deepEqual(parseCvssValue(7), { score: 7.0, source: "REPORTED_CVSS" });
      assert.deepEqual(parseCvssValue("0.0"), { score: 0.0, source: "REPORTED_CVSS" });
      assert.deepEqual(parseCvssValue(10), { score: 10.0, source: "REPORTED_CVSS" });
    });

    test("falls back to severity mapping when CVSS is null, empty or NaN", () => {
      assert.deepEqual(parseCvssValue("", "CRITICAL"), { score: 9.5, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue(null, "HIGH"), { score: 8.0, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue(undefined, "MEDIUM"), { score: 5.5, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue("invalid_num", "LOW"), { score: 2.5, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue("invalid_num", "INFO"), { score: 2.5, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue(null, "UNKNOWN"), { score: 5.0, source: "ESTIMATED_FALLBACK" });
    });

    test("ignores out-of-range numeric values (e.g. > 10 or < 0) and uses fallback", () => {
      assert.deepEqual(parseCvssValue("15.0", "HIGH"), { score: 8.0, source: "INFERRED_FROM_SEVERITY" });
      assert.deepEqual(parseCvssValue("-2.0", "MEDIUM"), { score: 5.5, source: "INFERRED_FROM_SEVERITY" });
    });
  });

  describe("normalizeSeverity: text mapping and score alignment", () => {
    test("normalizes text severity strings case-insensitively", () => {
      assert.equal(normalizeSeverity("critical", 5.0), "CRITICAL");
      assert.equal(normalizeSeverity("High", 5.0), "HIGH");
      assert.equal(normalizeSeverity("moderate", 5.0), "MEDIUM"); // 'med' check or cvss
      assert.equal(normalizeSeverity("MEDIUM", 5.0), "MEDIUM");
      assert.equal(normalizeSeverity("low", 5.0), "LOW");
      assert.equal(normalizeSeverity("informational", 5.0), "LOW");
    });

    test("aligns severity from CVSS when text is unspecified or unknown", () => {
      assert.equal(normalizeSeverity("", 9.5), "CRITICAL");
      assert.equal(normalizeSeverity(null, 7.5), "HIGH");
      assert.equal(normalizeSeverity("unknown", 4.5), "MEDIUM");
      assert.equal(normalizeSeverity("", 2.0), "LOW");
    });
  });

  describe("normalizeExposureScope: runtime & dependency classification", () => {
    test("defaults unspecified scope to DIRECT / PRODUCTION", () => {
      const exp = normalizeExposureScope("");
      assert.equal(exp.label, "DIRECT / PRODUCTION");
      assert.equal(exp.isDirect, true);
      assert.equal(exp.isProd, true);
      assert.equal(exp.source, "ASSUMED_DEFAULT");
    });

    test("detects transitive and dev/test variations", () => {
      const transProd = normalizeExposureScope("transitive dependency");
      assert.equal(transProd.label, "TRANSITIVE / PRODUCTION");
      assert.equal(transProd.isDirect, false);
      assert.equal(transProd.isProd, true);

      const directDev = normalizeExposureScope("devDependency");
      assert.equal(directDev.label, "DIRECT / DEV");
      assert.equal(directDev.isDirect, true);
      assert.equal(directDev.isProd, false);

      const transTest = normalizeExposureScope("sub-dependency in test suite");
      assert.equal(transTest.label, "TRANSITIVE / DEV");
      assert.equal(transTest.isDirect, false);
      assert.equal(transTest.isProd, false);
    });
  });

  describe("parseCsv: header aliases & deduplication", () => {
    test("supports various alias columns for package, version, and fix", () => {
      const csv = `component,package_version,vuln_id,risk,base_score,solution,environment\n"custom-pkg","3.2.1","VULN-001","CRIT","9.1","4.0.0","transitive production"`;
      const { records } = parseCsv(csv, "alias.csv");
      assert.equal(records.length, 1);
      assert.equal(records[0].library, "custom-pkg");
      assert.equal(records[0].version, "3.2.1");
      assert.equal(records[0].cve_id, "VULN-001");
      assert.equal(records[0].severity, "CRITICAL");
      assert.equal(records[0].cvss, 9.1);
      assert.equal(records[0].fix_version, "4.0.0");
      assert.equal(records[0].fix_available, true);
      assert.equal(records[0].is_direct, false);
    });

    test("throws descriptive error when required package/library column is absent", () => {
      const invalidCsv = "cve_id,severity,cvss\nCVE-2021-0001,HIGH,7.5";
      assert.throws(
        () => parseCsv(invalidCsv, "missing_pkg.csv"),
        /Missing required package\/library name column/
      );
    });
  });
});

describe("In-Depth Unit Tests: owaspParser.js", () => {
  test("throws if input is not an object or dependencies is not array", () => {
    assert.throws(() => parseOwaspJson(null), /Input is not a JSON object/);
    assert.throws(() => parseOwaspJson({ dependencies: "not_an_array" }), /'dependencies' must be an array/);
  });

  test("handles OWASP JAR filenames and extracts library + version", () => {
    const data = {
      projectInfo: { name: "Java App" },
      dependencies: [
        {
          fileName: "commons-collections-3.2.1.jar",
          isVirtual: false,
          vulnerabilities: [
            {
              name: "CVE-2015-7501",
              severity: "CRITICAL",
              cvssv3: { baseScore: 9.8 },
              description: "Remote code execution deserialization flaw."
            }
          ]
        }
      ]
    };
    const { records } = parseOwaspJson(data, "owasp_jar.json");
    assert.equal(records.length, 1);
    assert.equal(records[0].library, "commons-collections");
    assert.equal(records[0].version, "3.2.1");
    assert.equal(records[0].severity, "CRITICAL");
  });

  test("handles CVSS v2 fallback when CVSS v3 is absent in OWASP", () => {
    const data = {
      dependencies: [
        {
          fileName: "old-lib.jar",
          vulnerabilities: [
            {
              name: "CVE-2010-0001",
              severity: "HIGH",
              cvssv2: { score: 7.5, vectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P" }
            }
          ]
        }
      ]
    };
    const { records } = parseOwaspJson(data);
    assert.equal(records[0].cvss, 7.5);
    assert.equal(records[0].cvss_vector, "AV:N/AC:L/Au:N/C:P/I:P/A:P");
  });
});

describe("In-Depth Unit Tests: snykParser.js", () => {
  test("throws if data is not a valid object or array", () => {
    assert.throws(() => parseSnykJson("invalid_string"), /Input is not a JSON object/);
  });

  test("handles array of multi-project Snyk reports", () => {
    const multiProjectData = [
      {
        projectName: "Service A",
        vulnerabilities: [
          { packageName: "axios", version: "0.21.1", identifiers: { CVE: ["CVE-2021-3749"] }, severity: "high", cvssScore: 7.5, fixedIn: ["0.21.2"] }
        ]
      },
      {
        projectName: "Service B",
        vulnerabilities: [
          { packageName: "qs", version: "6.5.2", identifiers: { CVE: ["CVE-2022-24999"] }, severity: "high", cvssScore: 7.5, fixedIn: ["6.5.3"] }
        ]
      }
    ];

    const { records, provenance } = parseSnykJson(multiProjectData, "snyk_multi.json");
    assert.equal(records.length, 2);
    assert.equal(records[0].library, "axios");
    assert.equal(records[1].library, "qs");
  });

  test("correctly flags direct vs transitive dependency from Snyk 'from' chain", () => {
    const data = {
      vulnerabilities: [
        {
          packageName: "direct-lib",
          version: "1.0.0",
          from: ["root-app", "direct-lib@1.0.0"],
          severity: "low"
        },
        {
          packageName: "deep-lib",
          version: "2.0.0",
          from: ["root-app", "mid-lib@1.0.0", "deep-lib@2.0.0"],
          severity: "low"
        }
      ]
    };

    const { records } = parseSnykJson(data);
    assert.equal(records[0].is_direct, true);
    assert.equal(records[1].is_direct, false);
  });
});

describe("In-Depth Unit Tests: npmAuditParser.js", () => {
  test("throws if data is not an object or vulnerabilities key is missing", () => {
    assert.throws(() => parseNpmAuditJson(null), /Input is not a JSON object/);
    assert.throws(() => parseNpmAuditJson({ not_vulns: true }), /Missing vulnerabilities object/);
  });

  test("parses advisory URL to extract CVE/GHSA identifier", () => {
    const data = {
      vulnerabilities: {
        semver: {
          severity: "high",
          range: "<7.5.2",
          isDirect: false,
          isDev: false,
          fixAvailable: true,
          nodes: ["node_modules/semver"],
          via: [
            {
              url: "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw",
              title: "Regular expression denial of service in semver"
            }
          ]
        }
      }
    };

    const { records } = parseNpmAuditJson(data);
    assert.equal(records.length, 1);
    assert.equal(records[0].cve_id, "GHSA-c2qf-rxjj-qqgw");
    assert.equal(records[0].description, "Regular expression denial of service in semver");
    assert.equal(records[0].fix_available, true);
  });
});

describe("In-Depth Unit Tests: index.js (Ingestion Gateway)", () => {
  test("enforces non-string type guard", () => {
    assert.throws(() => ingestReport(12345), /Report content must be a string/);
  });

  test("enforces maximum file size limit (15 MB)", () => {
    const bigContent = "a".repeat(15 * 1024 * 1024 + 10);
    assert.throws(() => ingestReport(bigContent, "big.csv"), /File exceeds maximum allowed size/);
  });

  test("generates canonical CSV template that matches parser header schema", () => {
    const tpl = generateCanonicalCsvTemplate();
    const firstLine = tpl.split("\n")[0];
    assert.equal(firstLine, CANONICAL_CSV_HEADERS.join(","));
  });

  test("parses generic JSON array containing findings list", () => {
    const genericJson = JSON.stringify({
      findings: [
        { packageName: "lib-a", version: "1.0", severity: "high", cvssScore: 7.5 }
      ]
    });
    const { records } = ingestReport(genericJson, "findings.json");
    assert.equal(records.length, 1);
    assert.equal(records[0].library, "lib-a");
  });
});
