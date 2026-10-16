/**
 * Remediation & Compatibility Analysis Service
 * 
 * Rules:
 * - Never fabricate fixed versions.
 * - Distinguish verified fixed version vs suggested upgrade vs no known fix.
 * - Flag breaking changes for major version increments.
 * - Human-in-the-loop quality gate is mandatory.
 */

export const HUMAN_REVIEW_NOTICE =
  "Mandatory Human Gate: Automated patches must never be deployed directly to production without branch isolation, regression testing, and code review.";

/**
 * Determine dependency package manager ecosystem.
 */
export function detectEcosystem(packageName) {
  const name = String(packageName || "").toLowerCase();
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
 * Compare two semver-like strings to determine upgrade risk.
 */
export function evaluateVersionJump(currentVer, targetVer) {
  if (!currentVer || !targetVer || targetVer === "No Patch Available" || targetVer === "Upgrade Available") {
    return {
      type: "UNKNOWN",
      label: "Unknown / No Version Specified",
      warningLevel: "info",
      notice: "No target patch version specified by scanner. Manual investigation required."
    };
  }

  const cleanCurrent = String(currentVer).replace(/^[^\d]*/, "");
  const cleanTarget = String(targetVer).replace(/^[^\d]*/, "");

  const currParts = cleanCurrent.split(".").map(n => parseInt(n, 10));
  const targetParts = cleanTarget.split(".").map(n => parseInt(n, 10));

  if (isNaN(currParts[0]) || isNaN(targetParts[0])) {
    return {
      type: "CUSTOM",
      label: "Non-standard version format",
      warningLevel: "warning",
      notice: "Target version uses custom naming or date scheme. Inspect release notes prior to deployment."
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
 * Generate actionable remediation steps and quality gate checklist.
 */
export function buildRemediationRecommendation(finding, risk) {
  const lib = finding.library || "package";
  const ver = finding.version || "current";
  const fixVer = finding.fix_version || finding.fixVersion || "";
  const hasFix = Boolean(finding.fix_available || finding.fixAvailable);
  const ecosystem = detectEcosystem(lib);
  const depPath = finding.dependency_path || finding.dependencyPath || `${lib}@${ver}`;

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
    fixAvailable: hasFix,
    fixVersion: fixVer || (hasFix ? "Upgrade Available" : "No Patch Available"),
    actionTitle,
    upgradeCommand,
    ecosystem,
    dependencyPath: depPath,
    semverJumpType: versionJump.type,
    semverJumpLabel: versionJump.label,
    semverWarningLevel: versionJump.warningLevel,
    semverNotice: versionJump.notice,
    steps,
    notice: HUMAN_REVIEW_NOTICE
  };
}
