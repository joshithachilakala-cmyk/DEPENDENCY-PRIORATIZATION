import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { scoreFinding, DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS } from "../lib/services/scoringEngine.js";
import { evaluateVersionJump, buildRemediationRecommendation } from "../lib/services/remediationService.js";

describe("Contextual Risk-Scoring Engine Test Suite", () => {
  test("Risk scoring is strictly deterministic", () => {
    const finding = {
      library: "log4j-core",
      version: "2.14.1",
      cve_id: "CVE-2021-44228",
      severity: "CRITICAL",
      cvss: 10.0,
      exposure: "DIRECT / PRODUCTION",
      fix_available: true,
      fix_version: "2.17.1",
      description: "Remote code execution JNDI lookup flaw"
    };

    const res1 = scoreFinding(finding);
    const res2 = scoreFinding(finding);

    assert.equal(res1.score, res2.score);
    assert.equal(res1.tier, res2.tier);
    assert.deepEqual(res1.formula, res2.formula);
  });

  test("Calculates correct mathematical contributions for Critical Production RCE", () => {
    const finding = {
      library: "log4j-core",
      cvss: 10.0,
      exposure: "DIRECT / PRODUCTION",
      fix_available: true,
      description: "Remote code execution flaw"
    };

    const res = scoreFinding(finding);

    // CVSS: 10 * 10 * 0.45 = 45.0 pts
    // Reachability: 100 * 0.25 = 25.0 pts
    // Exploit (RCE): 100 * 0.15 = 15.0 pts
    // Patch: 100 * 0.15 = 15.0 pts
    // Total = 100.0 pts -> P0
    assert.equal(res.formula.cvss_contribution, 45.0);
    assert.equal(res.formula.reachability_contribution, 25.0);
    assert.equal(res.formula.exploit_contribution, 15.0);
    assert.equal(res.formula.patch_contribution, 15.0);
    assert.equal(res.score, 100.0);
    assert.equal(res.tier, "P0");
    assert.ok(res.sla.includes("24 hours"));
  });

  test("Non-production build tool with moderate CVSS is deprioritized to P2/P3", () => {
    const finding = {
      library: "eslint",
      cvss: 5.3,
      exposure: "DIRECT / DEV",
      fix_available: true,
      description: "Regular expression denial of service"
    };

    const res = scoreFinding(finding);

    // CVSS: 53 * 0.45 = 23.9 pts
    // Reachability (Direct Dev): 40 * 0.25 = 10.0 pts
    // Exploit (ReDoS): 50 * 0.15 = 7.5 pts
    // Patch: 100 * 0.15 = 15.0 pts
    // Score ~ 56.4
    assert.ok(res.score < 60);
    assert.ok(["P2", "P3"].includes(res.tier));
    assert.ok(res.formula.reachability_input.includes("Direct Dev"));
  });

  test("Missing CVSS is tagged as PARTIAL confidence rather than genuine low risk", () => {
    const finding = {
      library: "custom-lib",
      cvss: 8.0,
      cvss_source: "INFERRED_FROM_SEVERITY",
      exposure: "DIRECT / PRODUCTION",
      fix_available: false,
      description: "Unspecified vulnerability"
    };

    const res = scoreFinding(finding);

    assert.equal(res.confidence.isEstimated, true);
    assert.ok(res.confidence.level.includes("PARTIAL"));
    assert.equal(res.confidence.cvssSource, "INFERRED_FROM_SEVERITY");
  });

  test("Boundary value tests (CVSS 0.0 to 10.0)", () => {
    const zeroCvss = scoreFinding({ cvss: 0.0, exposure: "TRANSITIVE / DEV", fix_available: false });
    assert.ok(zeroCvss.score >= 5.0, "Score should respect minimum floor of 5.0");

    const maxCvss = scoreFinding({ cvss: 10.0, exposure: "DIRECT / PRODUCTION", fix_available: true, description: "rce" });
    assert.equal(maxCvss.score, 100.0, "Score cannot exceed 100.0");
  });
});

describe("Remediation & SemVer Analysis Test Suite", () => {
  test("Detects MAJOR version jump and flags breaking change warning", () => {
    const jump = evaluateVersionJump("7.32.0", "8.0.0");
    assert.equal(jump.type, "MAJOR");
    assert.equal(jump.warningLevel, "high_risk");
    assert.ok(jump.notice.includes("Major version upgrade"));
  });

  test("Detects MINOR version jump as moderate backward-compatible update", () => {
    const jump = evaluateVersionJump("2.14.1", "2.17.1");
    assert.equal(jump.type, "MINOR");
    assert.equal(jump.warningLevel, "moderate");
    assert.ok(jump.notice.includes("backward-compatibly"));
  });

  test("Detects PATCH version bugfix as low risk", () => {
    const jump = evaluateVersionJump("4.17.19", "4.17.21");
    assert.equal(jump.type, "PATCH");
    assert.equal(jump.warningLevel, "low_risk");
  });

  test("Generates ecosystem-specific upgrade command and human review notice", () => {
    const finding = {
      library: "lodash",
      version: "4.17.15",
      fix_available: true,
      fix_version: "4.17.21"
    };
    const risk = { score: 84.6, tier: "P1", tier_label: "P1 - High", sla: "7 days", rationale: "Contextual risk" };

    const rem = buildRemediationRecommendation(finding, risk);
    assert.equal(rem.ecosystem, "npm");
    assert.ok(rem.upgradeCommand.includes("npm install lodash@4.17.21"));
    assert.ok(rem.notice.includes("Mandatory Human Gate"));
    assert.equal(rem.steps.length > 0, true);
  });
});
