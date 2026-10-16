/**
 * Parser for Snyk CLI / API JSON Reports
 */

import { parseCvssValue, normalizeSeverity } from "./csvParser.js";

export function parseSnykJson(data, fileName = "snyk_scan.json") {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid Snyk report: Input is not a JSON object.");
  }

  // Snyk can be a single scan object or an array of multi-project scans
  const scanReports = Array.isArray(data) ? data : [data];
  const records = [];
  const seenKeys = new Set();
  let projectName = data.projectName || data.packageManager || "Node.js Application";

  for (const report of scanReports) {
    if (report.projectName) projectName = report.projectName;
    const vulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];

    for (const v of vulns) {
      const library = v.packageName || v.name || "Unknown";
      const version = v.version || "Current";
      const cveList = (v.identifiers && Array.isArray(v.identifiers.CVE)) ? v.identifiers.CVE : [];
      const cveId = cveList.length > 0 ? cveList[0] : (v.id || "SNYK-VULN");

      const rawSeverity = v.severity || "medium";
      const { score: cvss, source: cvssSource } = parseCvssValue(v.cvssScore, rawSeverity);
      const severity = normalizeSeverity(rawSeverity, cvss);

      const fixedIn = Array.isArray(v.fixedIn) ? v.fixedIn : [];
      const fixAvailable = fixedIn.length > 0;
      const fixVersion = fixAvailable ? fixedIn[0] : "No Patch Available";

      const fromChain = Array.isArray(v.from) ? v.from : [];
      const isDirect = fromChain.length <= 2;
      const dependencyPath = fromChain.length > 0 ? fromChain.join(" → ") : `${library}@${version}`;
      const exposure = isDirect ? "DIRECT / PRODUCTION" : "TRANSITIVE / PRODUCTION";

      const dedupKey = `${library}::${version}::${cveId}`.toLowerCase();
      if (seenKeys.has(dedupKey)) continue;
      seenKeys.add(dedupKey);

      records.push({
        library,
        version,
        cve_id: cveId,
        severity,
        cvss,
        cvss_source: cvssSource,
        fix_available: fixAvailable,
        fix_version: fixVersion,
        exposure,
        exposure_source: "REPORTED",
        is_direct: isDirect,
        is_production: true,
        dependency_path: dependencyPath,
        description: (v.title || v.description || "Security vulnerability detected by Snyk.").slice(0, 500)
      });
    }
  }

  const provenance = {
    projectName,
    scannerType: "Snyk CLI Vulnerability Scan",
    scanDate: data.displayTargetFile || new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: records.length > 0 ? "Completed Successfully" : "Warning: No records found"
  };

  return { records, provenance };
}
