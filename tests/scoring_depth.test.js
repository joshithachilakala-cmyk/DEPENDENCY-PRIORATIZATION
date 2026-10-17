import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  scoreFinding,
  DEFAULT_WEIGHTS,
  DEFAULT_THRESHOLDS,
  ALGORITHM_VERSION
} from "../lib/services/scoringEngine.js";
import {
  detectEcosystem,
  evaluateVersionJump,
  buildRemediationRecommendation,
  HUMAN_REVIEW_NOTICE
} from "../lib/services/remediationService.js";

describe("In-Depth Unit Tests: scoringEngine.js", () => {
  test("exposes algorithm version and default configurations", () => {
    assert.equal(ALGORITHM_VERSION, "2.1.0-contextual");
    assert.equal(DEFAULT_WEIGHTS.cvss, 0.45);
    assert.equal(DEFAULT_WEIGHTS.reachability, 0.25);
    assert.equal(DEFAULT_WEIGHTS.exploit, 0.15);
    assert.equal(DEFAULT_WEIGHTS.patch, 0.15);
    assert.equal(DEFAULT_THRESHOLDS.P0.minScore, 85);
  });

  describe("scoreFinding: custom weights override", () => {
    test("allows overriding weight factors", () => {
      const finding = {
        cvss: 10.0,
        exposure: "DIRECT / PRODUCTION",
        description: "Arbitrary command execution",
        fix_available: true
      };

      // Custom weights where CVSS is 1.0 (100%) and everything else is 0
      const evaluated = scoreFinding(finding, {
        cvss: 1.0,
        reachability: 0,
        exploit: 0,
        patch: 0
      });

      assert.equal(evaluated.score, 100);
      assert.equal(evaluated.formula.cvss_contribution, 100);
      assert.equal(evaluated.formula.reachability_contribution, 0);
    });
  });

  describe("scoreFinding: Exploit evidence text classification", () => {
    test("detects HIGH_THREAT keywords: rce, command injection, deserialization, log4shell", () => {
      const keywords = ["rce", "remote code execution", "command injection", "arbitrary code", "log4shell", "spring4shell", "deserialization"];
      for (const kw of keywords) {
        const res = scoreFinding({
          cvss: 5.0,
          exposure: "TRANSITIVE / DEV",
          description: `Vulnerable to ${kw} in parser`
        });
        assert.match(res.rationale, /Remote Code Execution \/ Injection/);
        assert.equal(res.formula.exploit_contribution, 15); // 100 * 0.15 = 15
      }
    });

    test("detects KNOWN_EXPLOIT keywords: sql, ssrf, prototype pollution, auth bypass, privilege escalation, path traversal", () => {
      const keywords = ["sql injection", "ssrf vulnerability", "prototype pollution in merge", "auth bypass", "privilege escalation", "path traversal"];
      for (const kw of keywords) {
        const res = scoreFinding({
          cvss: 5.0,
          exposure: "TRANSITIVE / DEV",
          description: `Bug: ${kw}`
        });
        assert.equal(res.formula.exploit_contribution, 11.3); // 75 * 0.15 = 11.25 -> 11.3
      }
    });

    test("detects MODERATE keywords: dos, denial of service, redos, memory exhaustion, buffer overflow", () => {
      const keywords = ["dos attack", "denial of service issue", "redos via regex", "memory exhaustion", "buffer overflow"];
      for (const kw of keywords) {
        const res = scoreFinding({
          cvss: 5.0,
          exposure: "TRANSITIVE / DEV",
          description: `Risk of ${kw}`
        });
        assert.equal(res.formula.exploit_contribution, 7.5); // 50 * 0.15 = 7.5
      }
    });

    test("falls back to STANDARD when no exploit keywords match", () => {
      const res = scoreFinding({
        cvss: 5.0,
        exposure: "TRANSITIVE / DEV",
        description: "Informational version disclosure in headers"
      });
      assert.equal(res.formula.exploit_contribution, 3.8); // 25 * 0.15 = 3.75 -> 3.8
    });
  });

  describe("scoreFinding: Reachability tiers & bounds", () => {
    test("DIRECT / PROD -> 25 contribution points (100 * 0.25)", () => {
      const res = scoreFinding({ exposure: "DIRECT / PRODUCTION" });
      assert.equal(res.formula.reachability_contribution, 25);
    });

    test("TRANSITIVE / PROD -> 18.8 contribution points (75 * 0.25)", () => {
      const res = scoreFinding({ exposure: "TRANSITIVE / PRODUCTION" });
      assert.equal(res.formula.reachability_contribution, 18.8);
    });

    test("DIRECT / DEV -> 10 contribution points (40 * 0.25)", () => {
      const res = scoreFinding({ exposure: "DIRECT / DEVELOPMENT" });
      assert.equal(res.formula.reachability_contribution, 10);
    });

    test("TRANSITIVE / DEV (default) -> 5 contribution points (20 * 0.25)", () => {
      const res = scoreFinding({ exposure: "TRANSITIVE / TEST" });
      assert.equal(res.formula.reachability_contribution, 5);
    });
  });

  describe("scoreFinding: Priority Tier boundaries", () => {
    test("Production finding with CVSS >= 9.0 receives P0 regardless of exploit", () => {
      const res = scoreFinding({
        cvss: 9.1,
        exposure: "DIRECT / PRODUCTION",
        description: "Minor flaw without active exploit",
        fix_available: false
      });
      assert.equal(res.tier, "P0");
    });

    test("Production finding with CVSS >= 7.5 and HIGH_THREAT receives P0", () => {
      const res = scoreFinding({
        cvss: 7.8,
        exposure: "TRANSITIVE / PRODUCTION",
        description: "remote code execution in parser",
        fix_available: false
      });
      assert.equal(res.tier, "P0");
    });

    test("Production finding with moderate CVSS (7.0 - 8.9) receives P1", () => {
      const res = scoreFinding({
        cvss: 7.2,
        exposure: "DIRECT / PRODUCTION",
        description: "Standard data disclosure",
        fix_available: false
      });
      assert.equal(res.tier, "P1");
    });

    test("Non-production finding with CVSS 8.0 but isolated dev dependency receives P2", () => {
      const res = scoreFinding({
        cvss: 8.0,
        exposure: "DIRECT / DEV",
        description: "Standard flaw",
        fix_available: false
      });
      assert.equal(res.tier, "P2");
    });

    test("Non-production finding with low CVSS receives P3", () => {
      const res = scoreFinding({
        cvss: 2.0,
        exposure: "TRANSITIVE / DEV",
        description: "Low flaw",
        fix_available: false
      });
      assert.equal(res.tier, "P3");
    });
  });

  describe("scoreFinding: Confidence differentiation", () => {
    test("tags confidence as HIGH when CVSS is verified reported", () => {
      const res = scoreFinding({
        cvss: 7.5,
        cvss_source: "REPORTED_CVSS",
        exposure_source: "VERIFIED"
      });
      assert.equal(res.confidence.isEstimated, false);
      assert.match(res.confidence.level, /HIGH/);
    });

    test("tags confidence as PARTIAL when CVSS is derived from severity text", () => {
      const res = scoreFinding({
        cvss: 8.0,
        cvss_source: "ESTIMATED_FROM_SEVERITY"
      });
      assert.equal(res.confidence.isEstimated, true);
      assert.match(res.confidence.level, /PARTIAL/);
    });
  });
});

describe("In-Depth Unit Tests: remediationService.js", () => {
  describe("detectEcosystem: heuristic package detection", () => {
    test("detects Maven ecosystem for Java packages and JAR/WAR extensions", () => {
      assert.equal(detectEcosystem("log4j-core.jar"), "maven");
      assert.equal(detectEcosystem("com.fasterxml.jackson.core:jackson-databind"), "maven");
      assert.equal(detectEcosystem("org.springframework.boot"), "maven");
      assert.equal(detectEcosystem("h2database"), "maven");
      assert.equal(detectEcosystem("app.war"), "maven");
    });

    test("detects Pip ecosystem for Python wheels and popular libraries", () => {
      assert.equal(detectEcosystem("requests-2.28.0-py3-none-any.whl"), "pip");
      assert.equal(detectEcosystem("django"), "pip");
      assert.equal(detectEcosystem("flask"), "pip");
      assert.equal(detectEcosystem("urllib3"), "pip");
      assert.equal(detectEcosystem("pyyaml"), "pip");
    });

    test("detects NPM ecosystem for JavaScript packages", () => {
      assert.equal(detectEcosystem("lodash"), "npm");
      assert.equal(detectEcosystem("axios"), "npm");
      assert.equal(detectEcosystem("express"), "npm");
      assert.equal(detectEcosystem("jsonwebtoken"), "npm");
      assert.equal(detectEcosystem("eslint"), "npm");
    });

    test("falls back to generic for unknown package formats", () => {
      assert.equal(detectEcosystem("custom-internal-binary"), "generic");
      assert.equal(detectEcosystem(""), "generic");
      assert.equal(detectEcosystem(null), "generic");
    });
  });

  describe("evaluateVersionJump: SemVer comparison", () => {
    test("handles missing or placeholder versions as UNKNOWN", () => {
      const cases = [
        [null, null],
        ["1.0.0", ""],
        ["1.0.0", "No Patch Available"],
        ["1.0.0", "Upgrade Available"]
      ];
      for (const [curr, target] of cases) {
        const res = evaluateVersionJump(curr, target);
        assert.equal(res.type, "UNKNOWN");
        assert.equal(res.warningLevel, "info");
      }
    });

    test("handles non-standard custom version schemes as CUSTOM", () => {
      const res = evaluateVersionJump("2024.1", "alpha-dev-build");
      assert.equal(res.type, "CUSTOM");
      assert.equal(res.warningLevel, "warning");
    });

    test("flags MAJOR version jumps with high_risk warning", () => {
      const res = evaluateVersionJump("2.1.4", "3.0.0");
      assert.equal(res.type, "MAJOR");
      assert.equal(res.warningLevel, "high_risk");
      assert.match(res.notice, /breaking API changes/i);
    });

    test("flags MINOR version updates with moderate warning", () => {
      const res = evaluateVersionJump("1.2.0", "1.3.1");
      assert.equal(res.type, "MINOR");
      assert.equal(res.warningLevel, "moderate");
      assert.match(res.notice, /Features added backward-compatibly/i);
    });

    test("flags PATCH bugfixes with low_risk warning", () => {
      const res = evaluateVersionJump("1.2.0", "1.2.4");
      assert.equal(res.type, "PATCH");
      assert.equal(res.warningLevel, "low_risk");
      assert.match(res.notice, /Patch release/i);
    });
  });

  describe("buildRemediationRecommendation: action plan and CLI commands", () => {
    test("generates npm install command and validation steps for npm packages", () => {
      const finding = {
        library: "lodash",
        version: "4.17.20",
        fix_available: true,
        fix_version: "4.17.21"
      };
      const rec = buildRemediationRecommendation(finding);
      assert.equal(rec.fixAvailable, true);
      assert.equal(rec.upgradeCommand, "npm install lodash@4.17.21 --save");
      assert.equal(rec.actionTitle, "Upgrade lodash to 4.17.21");
      assert.equal(rec.steps.length, 5);
      assert.match(rec.steps[1], /npm install lodash@4.17.21/);
    });

    test("generates pip install command for python packages", () => {
      const finding = {
        library: "requests",
        version: "2.25.0",
        fix_available: true,
        fix_version: "2.31.0"
      };
      const rec = buildRemediationRecommendation(finding);
      assert.equal(rec.fixAvailable, true);
      assert.equal(rec.upgradeCommand, "pip install --upgrade requests>=2.31.0");
      assert.equal(rec.steps.length, 4);
    });

    test("generates maven XML snippet for maven packages", () => {
      const finding = {
        library: "log4j-core.jar",
        version: "2.14.0",
        fix_available: true,
        fix_version: "2.17.1"
      };
      const rec = buildRemediationRecommendation(finding);
      assert.equal(rec.fixAvailable, true);
      assert.match(rec.upgradeCommand, /<version>2\.17\.1<\/version>/);
      assert.equal(rec.steps.length, 4);
    });

    test("provides compensating controls when no patch is available", () => {
      const finding = {
        library: "legacy-lib",
        version: "0.9.1",
        fix_available: false,
        fix_version: ""
      };
      const rec = buildRemediationRecommendation(finding);
      assert.equal(rec.fixAvailable, false);
      assert.equal(rec.actionTitle, "Apply Compensating Controls for legacy-lib");
      assert.match(rec.upgradeCommand, /compensating controls/i);
      assert.ok(rec.steps.length >= 4);
    });

    test("includes mandatory human review notice and steps", () => {
      const finding = {
        library: "express",
        version: "4.16.0",
        fix_available: true,
        fix_version: "4.18.2"
      };
      const rec = buildRemediationRecommendation(finding);
      assert.equal(rec.notice, HUMAN_REVIEW_NOTICE);
      assert.equal(rec.steps.length, 5);
    });
  });
});
