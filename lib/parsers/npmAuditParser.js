/**
 * Parser for npm audit (v7, v8, v9, v10) JSON reports
 */

import { parseCvssValue, normalizeSeverity } from "./csvParser.js";

export function parseNpmAuditJson(data, fileName = "npm_audit.json") {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid npm audit report: Input is not a JSON object.");
  }

  if (!data.vulnerabilities || typeof data.vulnerabilities !== "object" || Array.isArray(data.vulnerabilities)) {
    throw new Error("Invalid npm audit report: Missing vulnerabilities object.");
  }
  const vulns = data.vulnerabilities;

  const records = [];
  const seenKeys = new Set();

  for (const pkgName in vulns) {
    const details = vulns[pkgName];
    if (!details || typeof details !== "object") continue;

    const rawSeverity = details.severity || "medium";
    const { score: cvss, source: cvssSource } = parseCvssValue(null, rawSeverity);
    const severity = normalizeSeverity(rawSeverity, cvss);
    const fixAvailable = Boolean(details.fixAvailable);

    const via = Array.isArray(details.via) ? details.via : [];
    let cveId = "N/A";
    let description = `Vulnerability detected in ${pkgName}`;
    let advisoryCvss = null;

    for (const item of via) {
      if (typeof item === "object" && item !== null) {
        if (item.url && (item.url.includes("CVE") || item.url.includes("GHSA"))) {
          cveId = item.url.split("/").pop();
        }
        if (item.title) description = item.title;
        if (item.cvss && item.cvss.score) advisoryCvss = item.cvss.score;
        break;
      }
    }

    const finalCvss = advisoryCvss ? parseCvssValue(advisoryCvss, rawSeverity) : { score: cvss, source: cvssSource };
    const version = details.range || "Installed";
    const isDirect = Boolean(details.isDirect);
    const isProduction = !Boolean(details.isDev);
    const exposure = `${isDirect ? "DIRECT" : "TRANSITIVE"} / ${isProduction ? "PRODUCTION" : "DEV"}`;

    const nodes = Array.isArray(details.nodes) ? details.nodes : [];
    const dependencyPath = nodes.length > 0 ? nodes[0] : `${pkgName}@${version}`;

    const dedupKey = `${pkgName}::${version}::${cveId}`.toLowerCase();
    if (seenKeys.has(dedupKey)) continue;
    seenKeys.add(dedupKey);

    records.push({
      library: pkgName,
      version,
      cve_id: cveId,
      severity,
      cvss: finalCvss.score,
      cvss_source: finalCvss.source,
      fix_available: fixAvailable,
      fix_version: fixAvailable ? "Upgrade via npm audit fix" : "No Patch Available",
      exposure,
      exposure_source: "REPORTED",
      is_direct: isDirect,
      is_production: isProduction,
      dependency_path: dependencyPath,
      description: description.slice(0, 500)
    });
  }

  const provenance = {
    projectName: data.name || "NPM Project",
    scannerType: "npm audit (v7+)",
    scanDate: new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: records.length > 0 ? "Completed Successfully" : "Warning: No records found"
  };

  return { records, provenance };
}
