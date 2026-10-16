/**
 * Export and Reporting Service
 * Generates RFC 4180 CSV with formula injection defense and structured Markdown remediation plans.
 */

import { HUMAN_REVIEW_NOTICE } from "./remediationService.js";

/**
 * Sanitize cell to prevent CSV Formula Injection (CWE-1236).
 * If a cell begins with =, +, -, @, tab, or carriage return, prepend a single quote (').
 */
export function sanitizeCsvCell(value) {
  if (value === null || value === undefined) return '""';
  let str = String(value);

  // Neutralize formula injection
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }

  // Escape internal double quotes by doubling them
  const escaped = str.replace(/"/g, '""').replace(/\r?\n/g, ' ');
  return `"${escaped}"`;
}

/**
 * Generate RFC 4180 compliant CSV export with formula injection defense.
 */
export function generateCsvExport(findings = []) {
  const headers = [
    "Priority_Rank",
    "Priority_Tier",
    "Risk_Score",
    "Library",
    "Installed_Version",
    "CVE_ID",
    "Severity",
    "CVSS_Base",
    "CVSS_Source",
    "Fix_Available",
    "Fix_Version",
    "Exposure_Scope",
    "Dependency_Path",
    "Recommended_Action",
    "Upgrade_Command",
    "SemVer_Jump_Risk",
    "Human_Review_Required",
    "Rationale"
  ];

  const rows = findings.map((f) => {
    const risk = f.risk || {};
    const rem = f.remediation || {};
    const dep = f.dependencyContext || {};

    return [
      sanitizeCsvCell(f.rank || ""),
      sanitizeCsvCell(risk.tier || f.remediation?.priorityTier || "P3"),
      sanitizeCsvCell(risk.score ?? f.remediation?.priorityScore ?? 0),
      sanitizeCsvCell(f.library || ""),
      sanitizeCsvCell(f.version || ""),
      sanitizeCsvCell(f.cve_id || f.cveId || "N/A"),
      sanitizeCsvCell(f.severity || ""),
      sanitizeCsvCell(f.cvss ?? ""),
      sanitizeCsvCell(f.cvss_source || f.cvssSource || "REPORTED_CVSS"),
      sanitizeCsvCell(f.fix_available || rem.fixAvailable ? "Yes" : "No"),
      sanitizeCsvCell(f.fix_version || rem.fixVersion || ""),
      sanitizeCsvCell(f.exposure || dep.exposureLabel || ""),
      sanitizeCsvCell(f.dependency_path || dep.dependencyPath || ""),
      sanitizeCsvCell(rem.actionTitle || rem.action_title || ""),
      sanitizeCsvCell(rem.upgradeCommand || rem.upgrade_command || ""),
      sanitizeCsvCell(rem.semverJumpLabel || rem.version_jump?.label || "Unknown"),
      sanitizeCsvCell("YES (Mandatory Human Gate)"),
      sanitizeCsvCell(risk.rationale || rem.scoreRationale || f.description || "")
    ].join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}

/**
 * Generate comprehensive Markdown Remediation Plan.
 */
export function generateMarkdownPlan({ scan = {}, findings = [], metrics = {} }) {
  const sourceName = scan.fileName || scan.projectName || "Scan Report";
  const scanner = scan.scannerType || "Generic SCA Scan";
  const dateStr = scan.uploadedAt ? new Date(scan.uploadedAt).toUTCString() : new Date().toUTCString();

  const lines = [
    "# Dependency Vulnerability Prioritization & Remediation Plan",
    `**Project:** \`${scan.projectName || "Multi-Stack Application"}\``,
    `**Scanner Engine:** \`${scanner}\``,
    `**Report Source:** \`${sourceName}\``,
    `**Generated Date:** ${dateStr}`,
    `**Assessment Model:** Contextual Risk Engine v2.1 (CVSS 45%, Reachability 25%, Exploit 15%, Patch 15%)`,
    "",
    "> [!IMPORTANT]",
    `> **${HUMAN_REVIEW_NOTICE}**`,
    "",
    "## 1. Executive Summary & Exposure Metrics",
    "",
    `- **Total Evaluated Findings:** ${metrics.total ?? findings.length}`,
    `- **Critical & High Priority Findings (P0 / P1):** ${metrics.critical_high ?? 0}`,
    `- **Patch Actionability:** ${metrics.fixable ?? 0} of ${metrics.total ?? findings.length} findings have verified vendor patches (${metrics.fixable_percent ?? 0}%)`,
    `- **Average Contextual Risk Score:** ${metrics.avg_score ?? 0} / 100`,
    "",
    "### SLA & Triage Queue Breakdown",
    `- **P0 - Critical (Immediate 24-Hour Review):** ${metrics.p0 ?? 0} findings`,
    `- **P1 - High (Current Sprint - 7 Days):** ${metrics.p1 ?? 0} findings`,
    `- **P2 - Medium (Next Milestone - 30 Days):** ${metrics.p2 ?? 0} findings`,
    `- **P3 - Low (Quarterly Scheduled Maintenance):** ${metrics.p3 ?? 0} findings`,
    "",
    "## 2. Prioritized Action Queue",
    "",
    "| Rank | Priority | Score | Component | Vulnerability | CVSS | Exposure | Fix Status | SemVer Risk | Recommended Action |",
    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
  ];

  findings.forEach((f) => {
    const risk = f.risk || {};
    const rem = f.remediation || {};
    const dep = f.dependencyContext || {};
    const tier = risk.tier || rem.priorityTier || "P3";
    const score = risk.score ?? rem.priorityScore ?? 0;
    const cve = f.cve_id || f.cveId || "N/A";
    const cveLink = cve.startsWith("CVE-") ? `[${cve}](https://nvd.nist.gov/vuln/detail/${cve})` : cve;
    const fixAvail = f.fix_available || rem.fixAvailable;
    const fixVer = f.fix_version || rem.fixVersion || "";
    const fixStatus = fixAvail ? `Patch: \`${fixVer}\`` : "No Patch (Compensating Controls)";
    const semver = rem.semverJumpLabel || rem.version_jump?.label || "Unknown";
    const action = rem.actionTitle || rem.action_title || "Remediate component";
    const exposure = f.exposure || dep.exposureLabel || "DIRECT / PRODUCTION";

    lines.push(
      `| #${f.rank} | **${tier}** | ${score}/100 | \`${f.library}@${f.version}\` | ${cveLink} | ${f.cvss} | ${exposure} | ${fixStatus} | ${semver} | ${action} |`
    );
  });

  lines.push(
    "",
    "## 3. Detailed Remediation Instructions",
    ""
  );

  findings.forEach((f) => {
    const risk = f.risk || {};
    const rem = f.remediation || {};
    const tier = risk.tier || rem.priorityTier || "P3";
    const score = risk.score ?? rem.priorityScore ?? 0;
    const cve = f.cve_id || f.cveId || "N/A";
    const cmd = rem.upgradeCommand || rem.upgrade_command || "";
    const path = f.dependency_path || f.dependencyPath || `${f.library}@${f.version}`;
    const rationale = risk.rationale || rem.scoreRationale || f.description || "";
    const semverNotice = rem.semverNotice || rem.version_jump?.notice || "";

    lines.push(
      `### #${f.rank}. ${f.library} (${tier} - Score: ${score}/100)`,
      `- **Vulnerability:** ${cve}`,
      `- **Installed Version:** \`${f.version}\` → **Target Fix:** \`${rem.fixVersion || f.fix_version || "Compensating Controls"}\``,
      `- **Dependency Path:** \`${path}\``,
      `- **Prioritization Rationale:** ${rationale}`,
      semverNotice ? `- **Compatibility Warning:** ${semverNotice}` : "",
      cmd ? `\n\`\`\`bash\n${cmd}\n\`\`\`\n` : ""
    );
  });

  lines.push(
    "## 4. Mandatory Human Quality Gate Checklist",
    "- [ ] Created an isolated Git branch (`sec/<component>-update`) for dependency upgrade.",
    "- [ ] Ran full automated unit and integration regression test suites.",
    "- [ ] Inspected dependency tree for conflicting transitive dependencies.",
    "- [ ] Verified application smoke tests in staging/pre-production environment.",
    "- [ ] Obtained peer security code review before merging into release branch."
  );

  return lines.join("\n");
}
