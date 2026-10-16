/**
 * Parser for OWASP Dependency-Check JSON Reports (v6.x - v9.x)
 */

import { parseCvssValue, normalizeSeverity } from "./csvParser.js";

export function parseOwaspJson(data, fileName = "owasp_report.json") {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid OWASP report: Input is not a JSON object.");
  }

  const dependencies = data.dependencies || [];
  if (!Array.isArray(dependencies)) {
    throw new Error("Invalid OWASP report: 'dependencies' must be an array.");
  }

  const records = [];
  const seenKeys = new Set();

  for (const dep of dependencies) {
    const filename = dep.fileName || dep.filePath || "Unknown Dependency";
    const packages = Array.isArray(dep.packages) ? dep.packages : [];
    const pkgId = packages.length > 0 ? (packages[0].id || "") : "";

    let library = filename;
    let version = "Detected";

    if (pkgId && pkgId.includes("@")) {
      const parts = pkgId.split("@");
      version = parts.pop();
      library = parts.join("@").split("/").pop();
    } else if (filename.endsWith(".jar") || filename.endsWith(".war")) {
      // e.g. log4j-core-2.14.1.jar -> log4j-core, 2.14.1
      const base = filename.replace(/\.(jar|war)$/i, "");
      const match = base.match(/^(.*?)-(\d+[\.\d\w\-]*)$/);
      if (match) {
        library = match[1];
        version = match[2];
      }
    }

    const vulnerabilities = Array.isArray(dep.vulnerabilities) ? dep.vulnerabilities : [];
    const isDirect = !Boolean(dep.isVirtual);
    const exposure = isDirect ? "DIRECT / PRODUCTION" : "TRANSITIVE / PRODUCTION";
    const dependencyPath = dep.filePath || dep.fileName || `${library}@${version}`;

    for (const v of vulnerabilities) {
      const cveId = v.name || v.id || ("OWASP-" + library);
      const cvssV3 = v.cvssv3 || {};
      const cvssV2 = v.cvssv2 || {};
      const reportedScore = cvssV3.baseScore ?? cvssV2.score ?? null;
      const rawSeverity = v.severity || "MEDIUM";

      const { score: cvss, source: cvssSource } = parseCvssValue(reportedScore, rawSeverity);
      const severity = normalizeSeverity(rawSeverity, cvss);
      const description = v.description || "Vulnerability identified by OWASP Dependency-Check.";
      const notes = (v.notes || "").toLowerCase();
      const fixAvailable = notes.includes("patch") || notes.includes("fix") || notes.includes("upgrade");

      const dedupKey = `${library}::${version}::${cveId}`.toLowerCase();
      if (seenKeys.has(dedupKey)) continue;
      seenKeys.add(dedupKey);

      records.push({
        library,
        version,
        cve_id: cveId,
        cvss_vector: cvssV3.vectorString || cvssV2.vectorString || null,
        severity,
        cvss,
        cvss_source: cvssSource,
        fix_available: fixAvailable,
        fix_version: fixAvailable ? "Upgrade to latest secure release" : "No Patch Available",
        exposure,
        exposure_source: "REPORTED",
        is_direct: isDirect,
        is_production: true,
        dependency_path: dependencyPath,
        description: description.slice(0, 500)
      });
    }
  }

  const projectInfo = data.projectInfo || {};
  const scanInfo = data.scanInfo || {};

  const provenance = {
    projectName: projectInfo.name || "Java Application",
    scannerType: `OWASP Dependency-Check v${scanInfo.engineVersion || "8.x"}`,
    scanDate: projectInfo.reportDate || new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: records.length > 0 ? "Completed Successfully" : "Warning: No records found"
  };

  return { records, provenance };
}
