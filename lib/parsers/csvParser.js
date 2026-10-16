/**
 * Canonical CSV Parser for Dependency Vulnerability Reports
 * Supports:
 * - RFC 4180 quoted strings, commas, newlines
 * - Flexible header mapping
 * - Data normalization and type coercion
 * - Formula injection sanitization
 */

export const CANONICAL_CSV_HEADERS = [
  "library",
  "version",
  "cve_id",
  "severity",
  "cvss",
  "fix_available",
  "fix_version",
  "exposure",
  "description",
  "dependency_path"
];

function cleanText(val) {
  if (val === null || val === undefined) return "";
  let str = String(val).trim();
  // Strip dangerous formula injection prefixes if present in raw cell
  if (/^[=+\-@\t\r]/.test(str)) {
    str = str.replace(/^[=+\-@\t\r]+/, "");
  }
  return str;
}

export function parseCsvRows(csvText) {
  const content = (csvText || "").trim();
  if (!content) return { headers: [], rows: [] };

  const lines = [];
  let currentLine = "";
  let insideQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];
    const nextChar = content[i + 1];

    if (char === '"') {
      if (insideQuotes && nextChar === '"') {
        currentLine += '"';
        i++; // skip escaped quote
      } else {
        insideQuotes = !insideQuotes;
      }
    } else if ((char === '\r' && nextChar === '\n') && !insideQuotes) {
      lines.push(currentLine);
      currentLine = "";
      i++; // skip \n
    } else if ((char === '\n' || char === '\r') && !insideQuotes) {
      lines.push(currentLine);
      currentLine = "";
    } else {
      currentLine += char;
    }
  }
  if (currentLine.trim()) {
    lines.push(currentLine);
  }

  if (lines.length === 0) return { headers: [], rows: [] };

  function splitRow(line) {
    const cols = [];
    let cell = "";
    let inQuote = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      const nextChar = line[i + 1];

      if (char === '"') {
        if (inQuote && nextChar === '"') {
          cell += '"';
          i++;
        } else {
          inQuote = !inQuote;
        }
      } else if (char === ',' && !inQuote) {
        cols.push(cell.trim());
        cell = "";
      } else {
        cell += char;
      }
    }
    cols.push(cell.trim());
    return cols.map(c => c.replace(/^"|"$/g, "").trim());
  }

  const rawHeaders = splitRow(lines[0]);
  const headers = rawHeaders.map(h => cleanText(h).toLowerCase().replace(/[\s_\-]/g, ""));
  const headerMap = {};
  rawHeaders.forEach((h, idx) => {
    headerMap[headers[idx]] = rawHeaders[idx];
  });

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = splitRow(line);
    const rowObj = {};
    rawHeaders.forEach((origHeader, idx) => {
      rowObj[origHeader] = values[idx] !== undefined ? values[idx] : "";
    });
    rows.push(rowObj);
  }

  return { rawHeaders, headers, headerMap, rows };
}

function findMatchingHeader(headers, candidates) {
  for (const c of candidates) {
    const cleanCand = c.toLowerCase().replace(/[\s_\-]/g, "");
    const match = headers.find(h => h.toLowerCase().replace(/[\s_\-]/g, "") === cleanCand);
    if (match) return match;
  }
  for (const c of candidates) {
    const cleanCand = c.toLowerCase().replace(/[\s_\-]/g, "");
    const match = headers.find(h => h.toLowerCase().replace(/[\s_\-]/g, "").includes(cleanCand));
    if (match) return match;
  }
  return null;
}

export function parseCvssValue(val, fallbackSeverity = "MEDIUM") {
  if (val !== null && val !== undefined && val !== "") {
    const num = parseFloat(val);
    if (!isNaN(num) && num >= 0 && num <= 10) {
      return { score: Math.round(num * 10) / 10, source: "REPORTED_CVSS" };
    }
  }

  const s = String(fallbackSeverity || "").toUpperCase();
  if (s.includes("CRIT")) return { score: 9.5, source: "INFERRED_FROM_SEVERITY" };
  if (s.includes("HIGH")) return { score: 8.0, source: "INFERRED_FROM_SEVERITY" };
  if (s.includes("MED")) return { score: 5.5, source: "INFERRED_FROM_SEVERITY" };
  if (s.includes("LOW") || s.includes("INFO")) return { score: 2.5, source: "INFERRED_FROM_SEVERITY" };
  return { score: 5.0, source: "ESTIMATED_FALLBACK" };
}

export function normalizeSeverity(rawSeverity, cvss) {
  const s = String(rawSeverity || "").toUpperCase();
  if (s.includes("CRIT")) return "CRITICAL";
  if (s.includes("HIGH")) return "HIGH";
  if (s.includes("MED")) return "MEDIUM";
  if (s.includes("LOW") || s.includes("INFO")) return "LOW";

  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  return "LOW";
}

export function normalizeExposureScope(rawScope) {
  const s = String(rawScope || "").toLowerCase();
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

export function parseCsv(csvContent, fileName = "scan_report.csv") {
  const { rawHeaders, rows } = parseCsvRows(csvContent);
  if (!rawHeaders || rawHeaders.length === 0) {
    throw new Error("CSV report is empty or missing a header row.");
  }

  const libCol = findMatchingHeader(rawHeaders, ["library", "package", "component", "dependency", "name", "module", "artifact"]);
  if (!libCol) {
    throw new Error(
      `Invalid CSV: Missing required package/library name column. Found headers: [${rawHeaders.join(", ")}]. Expected: library, package, or component.`
    );
  }

  const verCol = findMatchingHeader(rawHeaders, ["version", "installed_version", "current_version", "package_version"]);
  const cveCol = findMatchingHeader(rawHeaders, ["cve_id", "cve", "vulnerability_id", "id", "vuln_id", "advisory"]);
  const sevCol = findMatchingHeader(rawHeaders, ["severity", "risk", "level"]);
  const cvssCol = findMatchingHeader(rawHeaders, ["cvss", "cvss_score", "score", "base_score", "cvss_v3"]);
  const fixVerCol = findMatchingHeader(rawHeaders, ["fix_version", "fixed_in", "patched_version", "target_version", "solution"]);
  const fixAvailCol = findMatchingHeader(rawHeaders, ["fix_available", "has_fix", "patch_available"]);
  const expCol = findMatchingHeader(rawHeaders, ["exposure", "dependency_type", "scope", "type", "environment"]);
  const descCol = findMatchingHeader(rawHeaders, ["description", "summary", "details", "title"]);
  const pathCol = findMatchingHeader(rawHeaders, ["dependency_path", "path", "chain", "dependency_chain"]);

  const records = [];
  const seenKeys = new Set();

  for (const r of rows) {
    const library = cleanText(r[libCol]);
    if (!library) continue;

    const version = cleanText(verCol ? r[verCol] : "Unknown") || "Unknown";
    const cveId = cleanText(cveCol ? r[cveCol] : "N/A") || "N/A";
    const rawSev = cleanText(sevCol ? r[sevCol] : "MEDIUM") || "MEDIUM";
    const rawCvss = cvssCol ? r[cvssCol] : null;
    const fixVersionRaw = cleanText(fixVerCol ? r[fixVerCol] : "");
    const description = cleanText(descCol ? r[descCol] : `Vulnerability detected in ${library}`);
    const depPathRaw = cleanText(pathCol ? r[pathCol] : "");

    // Deduplication identity within scan
    const dedupKey = `${library}::${version}::${cveId}`.toLowerCase();
    if (seenKeys.has(dedupKey)) {
      continue;
    }
    seenKeys.add(dedupKey);

    const { score: cvss, source: cvssSource } = parseCvssValue(rawCvss, rawSev);
    const severity = normalizeSeverity(rawSev, cvss);

    let fixAvailable = false;
    if (fixAvailCol && r[fixAvailCol] !== undefined && r[fixAvailCol] !== "") {
      const v = cleanText(r[fixAvailCol]).toLowerCase();
      fixAvailable = ["true", "1", "yes", "y", "t", "available", "fixed"].includes(v);
    } else {
      fixAvailable = Boolean(fixVersionRaw && !["none", "n/a", "no", "false", ""].includes(fixVersionRaw.toLowerCase()));
    }

    const fixVersion = fixVersionRaw || (fixAvailable ? "Upgrade Available" : "No Patch Available");
    const exposureInfo = normalizeExposureScope(expCol ? r[expCol] : "");
    const dependencyPath = depPathRaw || `${library}@${version}`;

    records.push({
      library,
      version,
      cve_id: cveId,
      severity,
      cvss,
      cvss_source: cvssSource,
      fix_available: fixAvailable,
      fix_version: fixVersion,
      exposure: exposureInfo.label,
      exposure_source: exposureInfo.source,
      is_direct: exposureInfo.isDirect,
      is_production: exposureInfo.isProd,
      dependency_path: dependencyPath,
      description
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
