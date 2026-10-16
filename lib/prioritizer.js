/**
 * Explainable Contextual Risk Scoring & Remediation Engine
 * 
 * Provides:
 * 1. Fully explainable, weighted risk score (0 - 100)
 * 2. Visual mathematical formula breakdown
 * 3. Confidence indicators distinguishing missing data from genuine low risk
 * 4. Semantic version compatibility assessment (breaking change warnings)
 * 5. Actionable ecosystem commands and quality gate checklists
 */

export const HUMAN_REVIEW_NOTICE =
  "Mandatory Human Gate: Automated patches must never be deployed directly to production without branch isolation, regression testing, and code review.";

/**
 * Determine dependency package manager ecosystem.
 */
export function detectEcosystem(packageName) {
  const name = (packageName || "").toLowerCase();
  if (
    name.endsWith(".jar") ||
    name.endsWith(".war") ||
    ["org.", "com.", "io.", "apache", "spring", "log4j", "jackson", "commons", "h2"].some(p => name.includes(p))
  ) {
    return "maven";
  }
  if (
    name.endsWith(".whl") ||
    ["django", "flask", "requests", "numpy", "pandas", "pillow", "pyyaml", "tornado", "urllib3", "redis"].some(p => name.includes(p))
  ) {
    return "pip";
  }
  if (
    ["lodash", "axios", "react", "vue", "express", "webpack", "babel", "next", "minimist", "jsonwebtoken", "mocha", "eslint"].some(p => name.includes(p))
  ) {
    return "npm";
  }
  return "generic";
}

/**
 * Compare two semver-like strings to determine update risk.
 */
export function evaluateVersionJump(currentVer, targetVer) {
  if (!currentVer || !targetVer || targetVer === "No Patch Available" || targetVer === "Upgrade Available") {
    return {
      type: "UNKNOWN",
      label: "Unknown / No Version Specified",
      warningLevel: "info",
      notice: "No target patch version specified. Manual review required."
    };
  }

  const cleanCurrent = currentVer.replace(/^[^\d]*/, "");
  const cleanTarget = targetVer.replace(/^[^\d]*/, "");

  const currParts = cleanCurrent.split(".").map(n => parseInt(n, 10));
  const targetParts = cleanTarget.split(".").map(n => parseInt(n, 10));

  if (isNaN(currParts[0]) || isNaN(targetParts[0])) {
    return {
      type: "CUSTOM",
      label: "Non-standard version format",
      warningLevel: "warning",
      notice: "Custom version naming scheme. Test thoroughly before deploying."
    };
  }

  // Major version jump
  if (targetParts[0] > currParts[0]) {
    return {
      type: "MAJOR",
      label: `Major Upgrade (${currParts[0]}.x → ${targetParts[0]}.x)`,
      warningLevel: "high_risk",
      notice: "⚠️ Major version upgrade: High probability of breaking API changes and removed deprecations. Consult vendor migration guide before merging."
    };
  }

  // Minor version jump
  if (targetParts[1] > (currParts[1] || 0)) {
    return {
      type: "MINOR",
      label: `Minor Update (${currParts[0]}.${currParts[1] || 0} → ${targetParts[0]}.${targetParts[1] || 0})`,
      warningLevel: "moderate",
      notice: "Minor version update: Features added backward-compatibly. Run full test suite to verify no subtle behavioral changes."
    };
  }

  // Patch version update
  return {
    type: "PATCH",
    label: "Patch / Bugfix Update",
    warningLevel: "low_risk",
    notice: "Patch release: Backward-compatible security bugfix. Lower risk of breaking changes, but smoke testing is still mandatory."
  };
}

/**
 * Calculate fully explainable contextual priority score.
 * Formula:
 * Final Score (0 - 100) =
 *   (CVSS * 10 * 0.45)           [Base Severity: max 45 pts]
 * + (Reachability Score * 0.25)   [Production Context: max 25 pts]
 * + (Exploit Score * 0.15)        [Exploit Evidence: max 15 pts]
 * + (Actionability Score * 0.15)  [Patch Urgency: max 15 pts]
 */
export function evaluateRisk(item) {
  const cvss = typeof item.cvss === "number" && !isNaN(item.cvss) ? item.cvss : 5.0;
  const cvssSource = item.cvss_source || "REPORTED_CVSS";
  const exposureStr = String(item.exposure || "DIRECT / PRODUCTION").toUpperCase();
  const exposureSource = item.exposure_source || "REPORTED";
  const hasFix = Boolean(item.fix_available);
  const textContent = `${item.description || ""} ${item.cve_id || ""}`.toLowerCase();

  // 1. Base Severity Contribution (Weight: 45%)
  const cvssPoints = Math.round(cvss * 10);
  const cvssContribution = Math.round(cvssPoints * 0.45 * 10) / 10;

  // 2. Reachability & Exposure (Weight: 25%)
  let reachabilityRaw = 20;
  let reachabilityLabel = "Transitive Dev (Lowest Risk)";

  if (exposureStr.includes("DIRECT") && exposureStr.includes("PROD")) {
    reachabilityRaw = 100;
    reachabilityLabel = "Direct Production (Direct Runtime Exposure)";
  } else if (exposureStr.includes("TRANSITIVE") && exposureStr.includes("PROD")) {
    reachabilityRaw = 75;
    reachabilityLabel = "Transitive Production (Indirect Runtime Exposure)";
  } else if (exposureStr.includes("DIRECT") && exposureStr.includes("DEV")) {
    reachabilityRaw = 40;
    reachabilityLabel = "Direct Dev / Build Tool (Non-Production)";
  }
  const reachabilityContribution = Math.round(reachabilityRaw * 0.25 * 10) / 10;

  // 3. Exploit Evidence (Weight: 15%)
  let exploitRaw = 25;
  let exploitLabel = "No Active Exploit Recorded";
  let exploitEvidenceType = "STANDARD";

  if (["rce", "remote code", "command injection", "arbitrary code", "log4shell", "spring4shell", "deserialization"].some(k => textContent.includes(k))) {
    exploitRaw = 100;
    exploitLabel = "Active Critical Threat (Remote Code Execution / Injection)";
    exploitEvidenceType = "HIGH_THREAT";
  } else if (["sql", "ssrf", "prototype pollution", "bypass", "privilege escalation"].some(k => textContent.includes(k))) {
    exploitRaw = 75;
    exploitLabel = "Elevated Vector (SSRF / Bypass / Prototype Pollution)";
    exploitEvidenceType = "KNOWN_EXPLOIT";
  } else if (["dos", "denial of service", "redos", "overflow"].some(k => textContent.includes(k))) {
    exploitRaw = 50;
    exploitLabel = "Moderate Threat (Denial of Service)";
    exploitEvidenceType = "MODERATE";
  }
  const exploitContribution = Math.round(exploitRaw * 0.15 * 10) / 10;

  // 4. Actionability & Patch Urgency (Weight: 15%)
  const patchRaw = hasFix ? 100 : 40;
  const patchLabel = hasFix
    ? "Verified Vendor Patch Available (High Actionability)"
    : "No Official Patch Available (Compensating Controls Required)";
  const patchContribution = Math.round(patchRaw * 0.15 * 10) / 10;

  // 5. Total Mathematical Sum
  const totalRaw = cvssContribution + reachabilityContribution + exploitContribution + patchContribution;
  const finalScore = Math.round(Math.min(100, Math.max(5, totalRaw)) * 10) / 10;

  // 6. Deterministic Priority Tier & SLA
  let tier = "P3";
  let tierLabel = "P3 - Low / Scheduled";
  let sla = "Triage in quarterly maintenance";

  const isProduction = exposureStr.includes("PROD");
  const isDirect = exposureStr.includes("DIRECT");

  if (isProduction && (cvss >= 9.0 || (cvss >= 7.5 && exploitEvidenceType === "HIGH_THREAT"))) {
    tier = "P0";
    tierLabel = "P0 - Critical (Immediate Review)";
    sla = "Triage and act within 24 hours";
  } else if (isProduction && cvss >= 7.0) {
    tier = "P1";
    tierLabel = "P1 - High (Current Sprint)";
    sla = "Resolve within 7 days";
  } else if (isProduction && cvss >= 4.0) {
    tier = "P2";
    tierLabel = "P2 - Medium (Next Milestone)";
    sla = "Target within 30 days";
  } else if (!isProduction && cvss >= 7.0 && isDirect) {
    tier = "P2";
    tierLabel = "P2 - Medium (Dev Tooling)";
    sla = "Resolve in next tooling update";
  }

  // 7. Data Confidence & Missing Field Differentiation
  let dataConfidence = "HIGH (All fields verified in report)";
  let isEstimated = false;

  if (cvssSource !== "REPORTED_CVSS") {
    dataConfidence = "PARTIAL (CVSS estimated from severity label)";
    isEstimated = true;
  }
  if (exposureSource === "ASSUMED_DEFAULT") {
    dataConfidence = "PARTIAL (Exposure unspecified; defaulted to Direct Production)";
    isEstimated = true;
  }

  // 8. Plain English Rationale
  let rationale = `Ranked ${tier} (Score: ${finalScore}/100) because it is a CVSS ${cvss} finding in ${reachabilityLabel}.`;
  if (exploitEvidenceType === "HIGH_THREAT") {
    rationale += " Elevated priority due to verified Remote Code Execution / Injection threat vector.";
  }
  if (hasFix) {
    rationale += ` Actionable patch is available (${item.fix_version}).`;
  } else {
    rationale += " No patch exists yet; defensive configuration mitigation is required.";
  }

  return {
    score: finalScore,
    tier,
    tier_label: tierLabel,
    sla,
    rationale,
    confidence: {
      level: dataConfidence,
      isEstimated,
      cvssSource,
      exposureSource
    },
    formula: {
      cvss_input: cvss,
      cvss_contribution: cvssContribution,
      reachability_input: reachabilityLabel,
      reachability_contribution: reachabilityContribution,
      exploit_input: exploitLabel,
      exploit_contribution: exploitContribution,
      patch_input: patchLabel,
      patch_contribution: patchContribution
    }
  };
}

/**
 * Generate actionable remediation steps and compatibility assessment.
 */
export function buildRemediation(item, risk) {
  const lib = item.library || "package";
  const ver = item.version || "current";
  const fixVer = item.fix_version || "";
  const hasFix = Boolean(item.fix_available);
  const ecosystem = detectEcosystem(lib);
  const depPath = item.dependency_path || `${lib}@${ver}`;

  const versionJump = evaluateVersionJump(ver, fixVer);

  let upgradeCommand = "";
  let actionTitle = "";
  let steps = [];

  if (hasFix && fixVer && !["No Patch Available", "Unknown", "none"].includes(fixVer.toLowerCase())) {
    actionTitle = `Upgrade ${lib} to ${fixVer}`;

    if (ecosystem === "npm") {
      upgradeCommand = `npm install ${lib}@${fixVer} --save`;
      steps = [
        `1. Create an isolated branch: git checkout -b sec/${lib}-update`,
        `2. Execute upgrade: npm install ${lib}@${fixVer}`,
        "3. Run automated unit and integration tests (npm test) to detect breaking changes.",
        "4. Verify transitive package resolution using npm ls " + lib,
        "5. Submit pull request with changelog diff and seek peer code review."
      ];
    } else if (ecosystem === "pip") {
      upgradeCommand = `pip install --upgrade ${lib}>=${fixVer}`;
      steps = [
        `1. Create an isolated branch: git checkout -b sec/${lib}-update`,
        `2. Update requirements.txt or pyproject.toml: ${lib}>=${fixVer}`,
        "3. Run pytest regression test suites in an isolated virtualenv.",
        "4. Deploy to staging and verify dependent service health before production merge."
      ];
    } else if (ecosystem === "maven") {
      upgradeCommand = `<dependency>\n  <groupId>...</groupId>\n  <artifactId>${lib}</artifactId>\n  <version>${fixVer}</version>\n</dependency>`;
      steps = [
        `1. Update <version>${fixVer}</version> in pom.xml / build.gradle`,
        "2. Run clean build and unit tests: mvn clean test",
        "3. Inspect dependency hierarchy for conflicting versions: mvn dependency:tree",
        "4. Validate in QA/staging environment prior to release."
      ];
    } else {
      upgradeCommand = `Upgrade ${lib} to version ${fixVer}`;
      steps = [
        `1. Update manifest specification to target version ${fixVer}`,
        "2. Run regression and integration test suites.",
        "3. Perform security validation before production deployment."
      ];
    }
  } else {
    actionTitle = `Apply Compensating Controls for ${lib}`;
    upgradeCommand = "# No official vendor patch available. Implement compensating controls.";
    steps = [
      "1. Restrict external network ingress to vulnerable endpoints or code paths.",
      "2. Apply strict WAF sanitization and input validation rules.",
      "3. If feasible, disable optional vulnerable submodules in application configuration.",
      "4. Monitor vendor security advisories and CVE tracker for upcoming releases."
    ];
  }

  return {
    action_title: actionTitle,
    upgrade_command: upgradeCommand,
    ecosystem,
    dependency_path: depPath,
    version_jump: versionJump,
    steps,
    notice: HUMAN_REVIEW_NOTICE
  };
}

/**
 * Main prioritization pipeline for a collection of vulnerability findings.
 */
export function prioritizeVulnerabilities(rawFindings) {
  if (!Array.isArray(rawFindings) || rawFindings.length === 0) {
    return {
      records: [],
      metrics: {
        total: 0,
        critical_high: 0,
        fixable: 0,
        fixable_percent: 0,
        avg_score: 0,
        p0: 0,
        p1: 0,
        p2: 0,
        p3: 0
      }
    };
  }

  let p0 = 0;
  let p1 = 0;
  let p2 = 0;
  let p3 = 0;
  let fixable = 0;
  let totalScore = 0;

  const enriched = rawFindings.map((item, idx) => {
    const risk = evaluateRisk(item);
    const remediation = buildRemediation(item, risk);

    totalScore += risk.score;

    if (risk.tier === "P0") p0++;
    else if (risk.tier === "P1") p1++;
    else if (risk.tier === "P2") p2++;
    else p3++;

    if (item.fix_available) fixable++;

    return {
      id: idx + 1,
      ...item,
      risk,
      remediation
    };
  });

  // Sort: Highest risk score first, tie-break on CVSS
  enriched.sort((a, b) => {
    if (b.risk.score !== a.risk.score) return b.risk.score - a.risk.score;
    return (b.cvss || 0) - (a.cvss || 0);
  });

  // Assign sequential rank
  enriched.forEach((item, index) => {
    item.rank = index + 1;
  });

  const total = enriched.length;
  const criticalHigh = p0 + p1;
  const avgScore = total > 0 ? Math.round((totalScore / total) * 10) / 10 : 0;
  const fixablePercent = total > 0 ? Math.round((fixable / total) * 1000) / 10 : 0;

  return {
    records: enriched,
    metrics: {
      total,
      critical_high: criticalHigh,
      fixable,
      fixable_percent: fixablePercent,
      avg_score: avgScore,
      p0,
      p1,
      p2,
      p3
    }
  };
}
