/**
 * Multi-Format Vulnerability Report Parser
 * Handles:
 * - Generic CSV with resilient header mapping & diagnostics
 * - OWASP Dependency-Check JSON
 * - Snyk CLI JSON
 * - npm audit JSON
 * - Generic JSON findings
 *
 * Extracts vulnerability records, dependency paths, and report provenance.
 */

function cleanText(str) {
  if (str === null || str === undefined) return "";
  return String(str).trim();
}

function parseCvss(val, severityFallback = "MEDIUM") {
  if (val !== null && val !== undefined && val !== "") {
    const num = parseFloat(val);
    if (!isNaN(num) && num >= 0 && num <= 10) {
      return { score: Math.round(num * 10) / 10, source: "REPORTED_CVSS" };
    }
  }

  const sev = cleanText(severityFallback).toUpperCase();
  if (sev.includes("CRIT")) return { score: 9.5, source: "INFERRED_FROM_SEVERITY" };
  if (sev.includes("HIGH")) return { score: 8.0, source: "INFERRED_FROM_SEVERITY" };
  if (sev.includes("MED")) return { score: 5.5, source: "INFERRED_FROM_SEVERITY" };
  if (sev.includes("LOW")) return { score: 2.5, source: "INFERRED_FROM_SEVERITY" };
  return { score: 5.0, source: "ESTIMATED_FALLBACK" };
}

function normalizeSeverity(sevStr, cvss) {
  const sev = cleanText(sevStr).toUpperCase();
  if (sev.includes("CRIT")) return "CRITICAL";
  if (sev.includes("HIGH")) return "HIGH";
  if (sev.includes("MED")) return "MEDIUM";
  if (sev.includes("LOW") || sev.includes("INFO")) return "LOW";

  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  return "LOW";
}

function normalizeBoolean(val) {
  if (typeof val === "boolean") return val;
  const s = cleanText(val).toLowerCase();
  return ["true", "1", "yes", "y", "t", "available", "fixed"].includes(s);
}

function normalizeExposure(scope) {
  const s = cleanText(scope).toLowerCase();
  if (!s) {
    return {
      label: "DIRECT / PRODUCTION",
      isDirect: true,
      isProd: true,
      source: "ASSUMED_DEFAULT"
    };
  }

  let isDirect = true;
  let isProd = true;

  if (s.includes("transitive") || s.includes("indirect") || s.includes("sub-dependency") || s.includes("subdependency")) {
    isDirect = false;
  }
  if (s.includes("dev") || s.includes("test") || s.includes("build") || s.includes("optional")) {
    isProd = false;
  }

  const label = `${isDirect ? "DIRECT" : "TRANSITIVE"} / ${isProd ? "PRODUCTION" : "DEV"}`;
  return { label, isDirect, isProd, source: "REPORTED" };
}

// Resilient CSV parser supporting quotes and escaped commas
function parseCsvRows(csvText) {
  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) return { headers: [], rows: [] };

  function splitLine(line) {
    const row = [];
    let insideQuotes = false;
    let current = "";
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        insideQuotes = !insideQuotes;
      } else if (char === ',' && !insideQuotes) {
        row.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    row.push(current.trim());
    return row.map(v => v.replace(/^"|"$/g, '').trim());
  }

  const headers = splitLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const values = splitLine(lines[i]);
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = values[idx] !== undefined ? values[idx] : "";
    });
    rows.push(obj);
  }
  return { headers, rows };
}

function findCol(headers, candidates) {
  const cleanMap = {};
  headers.forEach(h => {
    cleanMap[h.toLowerCase().replace(/[\s_\-]/g, "")] = h;
  });

  for (const c of candidates) {
    const cleanCand = c.toLowerCase().replace(/[\s_\-]/g, "");
    if (cleanMap[cleanCand]) return cleanMap[cleanCand];
  }
  for (const c of candidates) {
    const cleanCand = c.toLowerCase().replace(/[\s_\-]/g, "");
    for (const k in cleanMap) {
      if (k.includes(cleanCand)) return cleanMap[k];
    }
  }
  return null;
}

export function parseCsvReport(content, fileName = "scan_report.csv") {
  const { headers, rows } = parseCsvRows(content);
  if (!headers || headers.length === 0) {
    throw new Error("CSV file is empty or does not contain a header row.");
  }

  const libCol = findCol(headers, ["library", "package", "component", "dependency", "name", "module", "artifact"]);
  if (!libCol) {
    throw new Error(
      `Required column missing: Could not find package/library name column in CSV. Found headers: [${headers.join(", ")}]. Expected: library, package, or component.`
    );
  }

  const verCol = findCol(headers, ["version", "installed_version", "current_version", "package_version"]);
  const cveCol = findCol(headers, ["cve_id", "cve", "vulnerability_id", "id", "vuln_id", "advisory"]);
  const sevCol = findCol(headers, ["severity", "risk", "level"]);
  const cvssCol = findCol(headers, ["cvss", "cvss_score", "score", "base_score", "cvss_v3"]);
  const fixVerCol = findCol(headers, ["fix_version", "fixed_in", "patched_version", "target_version", "solution"]);
  const fixAvailCol = findCol(headers, ["fix_available", "has_fix", "patch_available"]);
  const expCol = findCol(headers, ["exposure", "dependency_type", "scope", "type", "environment"]);
  const descCol = findCol(headers, ["description", "summary", "details", "title"]);
  const pathCol = findCol(headers, ["path", "dependency_path", "chain", "dependency_chain"]);

  const records = [];
  for (const r of rows) {
    const lib = cleanText(r[libCol]);
    if (!lib) continue;

    const ver = cleanText(verCol ? r[verCol] : "Unknown") || "Unknown";
    const cve = cleanText(cveCol ? r[cveCol] : "N/A") || "N/A";
    const rawSev = cleanText(sevCol ? r[sevCol] : "MEDIUM") || "MEDIUM";
    const rawCvss = cvssCol ? r[cvssCol] : null;
    const fixVer = cleanText(fixVerCol ? r[fixVerCol] : "");
    const desc = cleanText(descCol ? r[descCol] : "Vulnerability identified in dependency.");
    const depPath = cleanText(pathCol ? r[pathCol] : "");

    const { score: cvss, source: cvssSource } = parseCvss(rawCvss, rawSev);
    const severity = normalizeSeverity(rawSev, cvss);

    let fixAvailable = false;
    if (fixAvailCol && r[fixAvailCol] !== undefined && r[fixAvailCol] !== "") {
      fixAvailable = normalizeBoolean(r[fixAvailCol]);
    } else {
      fixAvailable = Boolean(fixVer && !["none", "n/a", "no", "false", ""].includes(fixVer.toLowerCase()));
    }

    const exposureInfo = normalizeExposure(expCol ? r[expCol] : "");

    records.push({
      library: lib,
      version: ver,
      cve_id: cve,
      severity,
      cvss,
      cvss_source: cvssSource,
      fix_available: fixAvailable,
      fix_version: fixVer || (fixAvailable ? "Upgrade Available" : "No Patch Available"),
      exposure: exposureInfo.label,
      exposure_source: exposureInfo.source,
      is_direct: exposureInfo.isDirect,
      dependency_path: depPath || `${lib}@${ver}`,
      description: desc
    });
  }

  const provenance = {
    projectName: fileName.replace(/\.[^/.]+$/, "").replace(/[_\-]/g, " "),
    scannerType: "Generic CSV Export",
    scanDate: new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: records.length > 0 ? "Completed Successfully" : "Warning: No records found"
  };

  return { records, provenance };
}

export function parseOwaspJson(data, fileName = "owasp_report.json") {
  const records = [];
  const deps = data.dependencies || [];

  for (const dep of deps) {
    const filename = dep.fileName || dep.filePath || "Unknown Dependency";
    const packages = dep.packages || [];
    let pkgId = packages.length > 0 ? packages[0].id || "" : "";
    let libName = filename;
    let version = "Detected";

    if (pkgId && pkgId.includes("/") && pkgId.includes("@")) {
      libName = pkgId.split("/").pop().split("@")[0];
      version = pkgId.split("@").pop();
    }

    const vulns = dep.vulnerabilities || [];
    const isDirect = !dep.isVirtual;
    const exposure = isDirect ? "DIRECT / PRODUCTION" : "TRANSITIVE / PRODUCTION";
    const depPath = dep.filePath || filename;

    for (const v of vulns) {
      const cveId = v.name || ("VULN-" + filename);
      const cvssV3 = v.cvssv3 || {};
      const cvssV2 = v.cvssv2 || {};
      const score = cvssV3.baseScore || cvssV2.score || null;
      const rawSev = v.severity || "MEDIUM";
      const { score: cvss, source: cvssSource } = parseCvss(score, rawSev);
      const severity = normalizeSeverity(rawSev, cvss);
      const desc = v.description || "Vulnerability detected by OWASP Dependency-Check.";
      const notes = v.notes || "";
      const fixAvailable = notes.toLowerCase().includes("fix") || notes.toLowerCase().includes("patch");

      records.push({
        library: libName,
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
        dependency_path: depPath,
        description: desc.slice(0, 400)
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
    status: "Completed Successfully"
  };

  return { records, provenance };
}

export function parseSnykJson(data, fileName = "snyk_scan.json") {
  const records = [];
  const vulns = data.vulnerabilities || [];

  for (const v of vulns) {
    const libName = v.packageName || v.name || "Unknown";
    const version = v.version || "Current";
    const cveList = (v.identifiers && v.identifiers.CVE) || [];
    const cveId = cveList.length > 0 ? cveList[0] : (v.id || "SNYK-VULN");
    const { score: cvss, source: cvssSource } = parseCvss(v.cvssScore, v.severity);
    const severity = normalizeSeverity(v.severity, cvss);
    const fixedIn = v.fixedIn || [];
    const fixAvailable = fixedIn.length > 0;
    const fixVer = fixAvailable ? fixedIn[0] : "No Patch Available";
    
    // Dependency path from Snyk 'from' array
    const fromChain = Array.isArray(v.from) ? v.from : [];
    const isDirect = fromChain.length <= 2;
    const depPath = fromChain.length > 0 ? fromChain.join(" → ") : `${libName}@${version}`;
    const exposure = isDirect ? "DIRECT / PRODUCTION" : "TRANSITIVE / PRODUCTION";

    records.push({
      library: libName,
      version,
      cve_id: cveId,
      severity,
      cvss,
      cvss_source: cvssSource,
      fix_available: fixAvailable,
      fix_version: fixVer,
      exposure,
      exposure_source: "REPORTED",
      is_direct: isDirect,
      dependency_path: depPath,
      description: (v.title || v.description || "Security vulnerability detected by Snyk.").slice(0, 400)
    });
  }

  const provenance = {
    projectName: data.projectName || data.packageManager || "Node.js Application",
    scannerType: "Snyk CLI Vulnerability Scan",
    scanDate: data.displayTargetFile || new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: "Completed Successfully"
  };

  return { records, provenance };
}

export function parseNpmAuditJson(data, fileName = "npm_audit.json") {
  const records = [];
  const vulns = data.vulnerabilities || {};

  for (const pkgName in vulns) {
    const details = vulns[pkgName];
    const rawSev = details.severity || "medium";
    const { score: cvss, source: cvssSource } = parseCvss(null, rawSev);
    const severity = normalizeSeverity(rawSev, cvss);
    const fixAvailable = Boolean(details.fixAvailable);
    const via = details.via || [];
    let cveId = "N/A";
    let desc = `Vulnerability detected in ${pkgName}`;

    for (const item of via) {
      if (typeof item === "object") {
        if (item.url && (item.url.includes("CVE") || item.url.includes("GHSA"))) {
          cveId = item.url.split("/").pop();
        }
        if (item.title) desc = item.title;
        break;
      }
    }

    records.push({
      library: pkgName,
      version: details.range || "Installed",
      cve_id: cveId,
      severity,
      cvss,
      cvss_source: cvssSource,
      fix_available: fixAvailable,
      fix_version: fixAvailable ? "Upgrade via npm audit fix" : "No Patch Available",
      exposure: details.isDirect ? "DIRECT / PRODUCTION" : "TRANSITIVE / PRODUCTION",
      exposure_source: "REPORTED",
      is_direct: Boolean(details.isDirect),
      dependency_path: details.nodes && details.nodes.length > 0 ? details.nodes.join(" → ") : pkgName,
      description: desc
    });
  }

  const provenance = {
    projectName: data.name || "NPM Project",
    scannerType: "npm audit (v7+)",
    scanDate: new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: "Completed Successfully"
  };

  return { records, provenance };
}

export function parseGenericJson(data, fileName = "scan.json") {
  let items = [];
  if (Array.isArray(data)) {
    items = data;
  } else if (typeof data === "object" && data !== null) {
    for (const k of ["vulnerabilities", "findings", "alerts", "data", "results", "reports"]) {
      if (Array.isArray(data[k])) {
        items = data[k];
        break;
      }
    }
  }

  if (items.length === 0) {
    throw new Error("Could not find a vulnerability array in JSON. Looked for keys: vulnerabilities, findings, alerts, data, results.");
  }

  const records = [];
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const lib = cleanText(item.library || item.package || item.name || item.component || item.artifact);
    if (!lib) continue;

    const ver = cleanText(item.version || item.installed_version || "Current");
    const cve = cleanText(item.cve_id || item.cve || item.id || "N/A");
    const { score: cvss, source: cvssSource } = parseCvss(item.cvss || item.cvss_score, item.severity);
    const severity = normalizeSeverity(item.severity, cvss);
    const fixAvailable = normalizeBoolean(item.fix_available) || Boolean(item.fix_version);
    const fixVer = cleanText(item.fix_version) || (fixAvailable ? "Patch Available" : "No Patch Available");
    const exposureInfo = normalizeExposure(item.exposure || item.scope || "");
    const depPath = cleanText(item.dependency_path || item.path || `${lib}@${ver}`);

    records.push({
      library: lib,
      version: ver,
      cve_id: cve,
      severity,
      cvss,
      cvss_source: cvssSource,
      fix_available: fixAvailable,
      fix_version: fixVer,
      exposure: exposureInfo.label,
      exposure_source: exposureInfo.source,
      is_direct: exposureInfo.isDirect,
      dependency_path: depPath,
      description: cleanText(item.description || item.summary || "Vulnerability finding.")
    });
  }

  const provenance = {
    projectName: data.project || data.name || fileName.replace(/\.[^/.]+$/, ""),
    scannerType: "JSON Vulnerability Report",
    scanDate: data.date || data.timestamp || new Date().toISOString(),
    fileName,
    totalParsed: records.length,
    status: "Completed Successfully"
  };

  return { records, provenance };
}

export function ingestScanReport(rawContent, fileName = "report") {
  const content = (rawContent || "").trim();
  if (!content) {
    throw new Error("File is empty. Please upload a report with scan findings.");
  }

  // Attempt JSON parsing if content looks like JSON
  if (content.startsWith("{") || content.startsWith("[")) {
    try {
      const data = JSON.parse(content);
      if (data && typeof data === "object") {
        if (data.dependencies) return parseOwaspJson(data, fileName);
        if (Array.isArray(data.vulnerabilities)) return parseSnykJson(data, fileName);
        if (data.vulnerabilities && typeof data.vulnerabilities === "object") return parseNpmAuditJson(data, fileName);
        return parseGenericJson(data, fileName);
      }
    } catch (e) {
      if (content.startsWith("{") || content.startsWith("[")) {
        throw new Error(`Invalid JSON syntax in ${fileName}: ${e.message}`);
      }
    }
  }

  // Fallback to CSV
  return parseCsvReport(content, fileName);
}
