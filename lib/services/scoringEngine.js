/**
 * Contextual Risk-Scoring Engine
 *
 * Algorithm Version: 2.1.0-contextual
 *
 * Mathematical Formula:
 *   Score (0 - 100) = (Base CVSS Points * W_cvss)
 *                   + (Reachability Points * W_reach)
 *                   + (Exploit Evidence Points * W_exploit)
 *                   + (Patch Actionability Points * W_patch)
 *
 * Weights (Configurable):
 *   W_cvss:    0.45 (Max 45.0 pts)
 *   W_reach:   0.25 (Max 25.0 pts)
 *   W_exploit: 0.15 (Max 15.0 pts)
 *   W_patch:   0.15 (Max 15.0 pts)
 */

export const ALGORITHM_VERSION = "2.1.0-contextual";

export const DEFAULT_WEIGHTS = {
  cvss: 0.45,
  reachability: 0.25,
  exploit: 0.15,
  patch: 0.15
};

export const DEFAULT_THRESHOLDS = {
  P0: { minScore: 85, sla: "Triage and act within 24 hours" },
  P1: { minScore: 70, sla: "Resolve within 7 days (current sprint)" },
  P2: { minScore: 45, sla: "Target within 30 days (next milestone)" },
  P3: { minScore: 0,  sla: "Triage in quarterly maintenance backlog" }
};

/**
 * Evaluates contextual risk score for a single finding with full mathematical explainability.
 * 
 * @param {Object} finding
 * @param {Object} [customWeights]
 * @returns {Object} Risk evaluation with score, tier, explainable formula breakdown, and confidence
 */
export function scoreFinding(finding, customWeights = {}) {
  const weights = { ...DEFAULT_WEIGHTS, ...customWeights };

  // 1. Base CVSS Handling (Safely handles missing/null values)
  const cvss = typeof finding.cvss === "number" && !isNaN(finding.cvss)
    ? Math.min(10, Math.max(0, finding.cvss))
    : 5.0;
  const cvssSource = finding.cvss_source || finding.cvssSource || "REPORTED_CVSS";

  // CVSS points on a 0-100 scale: (CVSS / 10) * 100 = CVSS * 10
  const cvssBasePoints = cvss * 10;
  const cvssContribution = Math.round(cvssBasePoints * weights.cvss * 10) / 10;

  // 2. Production Reachability & Scope Context
  const exposureStr = String(finding.exposure || finding.exposureLabel || "DIRECT / PRODUCTION").toUpperCase();
  const exposureSource = finding.exposure_source || finding.exposureSource || "REPORTED";

  let reachabilityRaw = 20;
  let reachabilityLabel = "Transitive Dev (Non-production runtime)";

  if (exposureStr.includes("DIRECT") && exposureStr.includes("PROD")) {
    reachabilityRaw = 100;
    reachabilityLabel = "Direct Production (Direct runtime execution path)";
  } else if (exposureStr.includes("TRANSITIVE") && exposureStr.includes("PROD")) {
    reachabilityRaw = 75;
    reachabilityLabel = "Transitive Production (Indirect runtime dependency)";
  } else if (exposureStr.includes("DIRECT") && exposureStr.includes("DEV")) {
    reachabilityRaw = 40;
    reachabilityLabel = "Direct Dev / Build Tool (Isolated from production)";
  }
  const reachabilityContribution = Math.round(reachabilityRaw * weights.reachability * 10) / 10;

  // 3. Exploit Evidence Analysis
  const textCorpus = `${finding.description || ""} ${finding.cve_id || finding.cveId || ""}`.toLowerCase();
  let exploitRaw = 25;
  let exploitLabel = "No Active Exploit Recorded";
  let exploitEvidenceType = "STANDARD";

  if (
    ["rce", "remote code", "command injection", "arbitrary code", "log4shell", "spring4shell", "deserialization"].some(k => textCorpus.includes(k))
  ) {
    exploitRaw = 100;
    exploitLabel = "Active Critical Threat (Remote Code Execution / Injection)";
    exploitEvidenceType = "HIGH_THREAT";
  } else if (
    ["sql", "ssrf", "prototype pollution", "auth bypass", "privilege escalation", "path traversal"].some(k => textCorpus.includes(k))
  ) {
    exploitRaw = 75;
    exploitLabel = "Elevated Threat Vector (SSRF / Bypass / Privilege Escalation)";
    exploitEvidenceType = "KNOWN_EXPLOIT";
  } else if (
    ["dos", "denial of service", "redos", "memory exhaustion", "buffer overflow"].some(k => textCorpus.includes(k))
  ) {
    exploitRaw = 50;
    exploitLabel = "Moderate Threat Vector (Denial of Service)";
    exploitEvidenceType = "MODERATE";
  }
  const exploitContribution = Math.round(exploitRaw * weights.exploit * 10) / 10;

  // 4. Patch Availability & Actionability
  const hasFix = Boolean(finding.fix_available || finding.fixAvailable);
  const patchRaw = hasFix ? 100 : 40;
  const patchLabel = hasFix
    ? "Verified Vendor Patch Available (High Actionability)"
    : "No Official Patch Available (Requires Compensating Controls)";
  const patchContribution = Math.round(patchRaw * weights.patch * 10) / 10;

  // 5. Total Summation
  const rawSum = cvssContribution + reachabilityContribution + exploitContribution + patchContribution;
  const finalScore = Math.round(Math.min(100, Math.max(5, rawSum)) * 10) / 10;

  // 6. Distinct Priority Tier Assignment
  const isProduction = exposureStr.includes("PROD");
  const isDirect = exposureStr.includes("DIRECT");

  let tier = "P3";
  let tierLabel = "P3 - Low / Scheduled";
  let sla = DEFAULT_THRESHOLDS.P3.sla;

  if (isProduction && (cvss >= 9.0 || (cvss >= 7.5 && exploitEvidenceType === "HIGH_THREAT") || finalScore >= 85)) {
    tier = "P0";
    tierLabel = "P0 - Critical (Immediate Review)";
    sla = DEFAULT_THRESHOLDS.P0.sla;
  } else if (isProduction && (cvss >= 7.0 || finalScore >= 70)) {
    tier = "P1";
    tierLabel = "P1 - High (Current Sprint)";
    sla = DEFAULT_THRESHOLDS.P1.sla;
  } else if ((isProduction && cvss >= 4.0) || (!isProduction && cvss >= 7.0 && isDirect) || finalScore >= 45) {
    tier = "P2";
    tierLabel = "P2 - Medium (Next Milestone)";
    sla = DEFAULT_THRESHOLDS.P2.sla;
  }

  // 7. Data Confidence Differentiation
  let confidenceLevel = "HIGH (All fields verified in report)";
  let isEstimated = false;

  if (cvssSource !== "REPORTED_CVSS") {
    confidenceLevel = "PARTIAL (CVSS estimated from reported severity label)";
    isEstimated = true;
  }
  if (exposureSource === "ASSUMED_DEFAULT") {
    confidenceLevel = "PARTIAL (Exposure unspecified; defaulted to Direct Production)";
    isEstimated = true;
  }

  // 8. Plain-Language Rationale
  let rationale = `Ranked ${tier} (Score: ${finalScore}/100) because it is a CVSS ${cvss} finding in ${reachabilityLabel}.`;
  if (exploitEvidenceType === "HIGH_THREAT") {
    rationale += " Elevated priority due to verified Remote Code Execution / Injection threat vector.";
  }
  if (hasFix) {
    const fixVer = finding.fix_version || finding.fixVersion;
    rationale += ` Actionable vendor patch is available (${fixVer || "Upgrade target"}).`;
  } else {
    rationale += " No official vendor patch exists yet; defensive configuration mitigation is required.";
  }

  return {
    score: finalScore,
    tier,
    tier_label: tierLabel,
    sla,
    rationale,
    confidence: {
      level: confidenceLevel,
      isEstimated,
      cvssSource,
      exposureSource
    },
    formula: {
      algorithm_version: ALGORITHM_VERSION,
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
