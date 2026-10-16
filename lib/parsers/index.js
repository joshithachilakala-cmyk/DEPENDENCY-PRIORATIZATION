/**
 * Unified Ingestion & Validation Gateway for Vulnerability Scan Reports
 * Supported formats:
 * 1. Generic CSV (and standard template)
 * 2. OWASP Dependency-Check JSON
 * 3. Snyk JSON
 * 4. npm audit JSON
 */

import { parseCsv, CANONICAL_CSV_HEADERS } from "./csvParser.js";
import { parseOwaspJson } from "./owaspParser.js";
import { parseSnykJson } from "./snykParser.js";
import { parseNpmAuditJson } from "./npmAuditParser.js";

export const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB
export const MAX_RECORD_LIMIT = 5000;

/**
 * Generate canonical CSV template matching parser schema exactly.
 */
export function generateCanonicalCsvTemplate() {
  const exampleRows = [
    CANONICAL_CSV_HEADERS.join(","),
    '"log4j-core","2.14.1","CVE-2021-44228","CRITICAL","10.0","true","2.17.1","DIRECT / PRODUCTION","Remote Code Execution via JNDI lookup","log4j-core@2.14.1"',
    '"lodash","4.17.15","CVE-2020-8203","HIGH","7.4","true","4.17.21","TRANSITIVE / PRODUCTION","Prototype pollution in zipObjectDeep","root -> express -> lodash@4.17.15"',
    '"mocha","7.0.0","CVE-2020-7774","MEDIUM","5.3","true","8.0.0","DIRECT / DEV","Command injection in test runner","mocha@7.0.0"'
  ];
  return exampleRows.join("\n");
}

/**
 * Ingest, validate, and parse a raw vulnerability scan report.
 */
export function ingestReport(rawContent, originalFilename = "scan_report") {
  if (typeof rawContent !== "string") {
    throw new Error("Report content must be a string.");
  }

  const trimmed = rawContent.trim();
  if (!trimmed) {
    throw new Error("The uploaded scan report is empty. Please verify the file contains findings.");
  }

  if (Buffer.byteLength(trimmed, "utf8") > MAX_FILE_SIZE_BYTES) {
    throw new Error(`File exceeds maximum allowed size of 15 MB (${(Buffer.byteLength(trimmed, "utf8") / (1024 * 1024)).toFixed(1)} MB).`);
  }

  const safeFilename = originalFilename.replace(/[^a-zA-Z0-9._\-]/g, "_");
  let result;

  // 1. Check if content is JSON
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let parsedData;
    try {
      parsedData = JSON.parse(trimmed);
    } catch (e) {
      throw new Error(`Malformed JSON in ${safeFilename}: ${e.message}`);
    }

    if (!parsedData || typeof parsedData !== "object") {
      throw new Error("Invalid JSON report structure.");
    }

    // Determine specific JSON scanner format
    if (parsedData.dependencies && Array.isArray(parsedData.dependencies)) {
      result = parseOwaspJson(parsedData, safeFilename);
    } else if (Array.isArray(parsedData.vulnerabilities) || (Array.isArray(parsedData) && parsedData[0]?.vulnerabilities)) {
      result = parseSnykJson(parsedData, safeFilename);
    } else if (parsedData.vulnerabilities && typeof parsedData.vulnerabilities === "object" && !Array.isArray(parsedData.vulnerabilities)) {
      result = parseNpmAuditJson(parsedData, safeFilename);
    } else {
      // Check for generic JSON findings array
      const candidates = ["findings", "vulnerabilities", "alerts", "data", "results"];
      let foundList = null;
      for (const k of candidates) {
        if (Array.isArray(parsedData[k])) {
          foundList = parsedData[k];
          break;
        }
      }
      if (Array.isArray(foundList)) {
        result = parseSnykJson({ vulnerabilities: foundList }, safeFilename);
      } else {
        throw new Error(
          "Unrecognized JSON scanner format. Supported formats: OWASP Dependency-Check JSON, Snyk JSON, npm audit JSON, or JSON with a findings/vulnerabilities list."
        );
      }
    }
  } else {
    // 2. Parse as CSV
    result = parseCsv(trimmed, safeFilename);
  }

  if (!result || !result.records || result.records.length === 0) {
    throw new Error(
      "No valid vulnerability findings were identified in the report. Ensure the file has required component headers (library, package) or contains reported scanner vulnerabilities."
    );
  }

  if (result.records.length > MAX_RECORD_LIMIT) {
    result.records = result.records.slice(0, MAX_RECORD_LIMIT);
    result.provenance.status = `Completed (Truncated to max ${MAX_RECORD_LIMIT} findings)`;
  }

  return result;
}
