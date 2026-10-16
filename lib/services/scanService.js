/**
 * Scan Persistence & Query Service
 * Handles relational storage, transactional ingestion, querying, and metrics calculation.
 */

import prisma from "../db.js";
import { ingestReport } from "../parsers/index.js";
import { scoreFinding } from "./scoringEngine.js";
import { buildRemediationRecommendation } from "./remediationService.js";
import { ENTERPRISE_CSV, OWASP_JSON, SNYK_JSON } from "../sampleData.js";

/**
 * Ingest, score, and persist a scan report transactionally into SQLite/PostgreSQL.
 */
export async function createScanFromReport(rawContent, fileName = "scan_report.csv", options = {}) {
  const { isDemo = false, demoId = null, customProjectName = null } = options;

  // 1. Ingest and normalize findings
  const { records: rawFindings, provenance } = ingestReport(rawContent, fileName);

  const projectName = customProjectName || provenance.projectName || fileName.replace(/\.[^/.]+$/, "");
  const scannerType = provenance.scannerType || "Generic SCA Scanner";

  // 2. Score findings and build remediations
  let p0 = 0;
  let p1 = 0;
  let p2 = 0;
  let p3 = 0;
  let fixable = 0;
  let totalScore = 0;

  const scoredRecords = rawFindings.map((f, idx) => {
    const risk = scoreFinding(f);
    const remediation = buildRemediationRecommendation(f, risk);

    totalScore += risk.score;
    if (risk.tier === "P0") p0++;
    else if (risk.tier === "P1") p1++;
    else if (risk.tier === "P2") p2++;
    else p3++;

    if (f.fix_available || remediation.fixAvailable) fixable++;

    return {
      rawIndex: idx + 1,
      finding: f,
      risk,
      remediation
    };
  });

  // Sort: Highest risk score first, tie-break on CVSS
  scoredRecords.sort((a, b) => {
    if (b.risk.score !== a.risk.score) return b.risk.score - a.risk.score;
    return (b.finding.cvss || 0) - (a.finding.cvss || 0);
  });

  // Assign 1-indexed ranks
  scoredRecords.forEach((item, index) => {
    item.rank = index + 1;
  });

  const totalFindings = scoredRecords.length;
  const criticalHighCount = p0 + p1;
  const avgScore = totalFindings > 0 ? Math.round((totalScore / totalFindings) * 10) / 10 : 0;
  const fixablePercent = totalFindings > 0 ? Math.round((fixable / totalFindings) * 1000) / 10 : 0;
  const fileSizeStr = `${Math.round(Buffer.byteLength(rawContent, "utf8") / 1024 * 10) / 10} KB`;

  // 3. Persist transactionally
  const scan = await prisma.$transaction(async (tx) => {
    // If it's a demo and already exists, remove earlier demo to refresh
    if (isDemo && demoId) {
      await tx.scan.deleteMany({
        where: { isDemo: true, demoId }
      });
    }

    const createdScan = await tx.scan.create({
      data: {
        projectName,
        scannerType,
        fileName,
        fileSize: fileSizeStr,
        status: "COMPLETED",
        isDemo,
        demoId,
        totalFindings,
        criticalHighCount,
        fixableCount: fixable,
        fixablePercent,
        avgScore,
        p0Count: p0,
        p1Count: p1,
        p2Count: p2,
        p3Count: p3
      }
    });

    for (const item of scoredRecords) {
      const f = item.finding;
      const risk = item.risk;
      const rem = item.remediation;

      await tx.finding.create({
        data: {
          scanId: createdScan.id,
          rank: item.rank,
          library: f.library,
          version: f.version,
          cveId: f.cve_id || "N/A",
          severity: f.severity,
          cvss: f.cvss,
          cvssSource: f.cvss_source,
          cvssVector: f.cvss_vector || null,
          description: f.description || "",
          affectedRange: f.affected_range || null,
          dependencyPath: f.dependency_path,
          dependencyContext: {
            create: {
              isDirect: f.is_direct,
              isProduction: f.is_production !== false,
              exposureLabel: f.exposure,
              exposureSource: f.exposure_source || "REPORTED",
              dependencyPath: f.dependency_path,
              reachabilityEvidence: risk.formula?.reachability_input || null
            }
          },
          remediation: {
            create: {
              fixAvailable: rem.fixAvailable,
              fixVersion: rem.fixVersion,
              actionTitle: rem.actionTitle,
              upgradeCommand: rem.upgradeCommand,
              ecosystem: rem.ecosystem,
              semverJumpType: rem.semverJumpType,
              semverJumpLabel: rem.semverJumpLabel,
              semverWarningLevel: rem.semverWarningLevel,
              semverNotice: rem.semverNotice,
              priorityTier: risk.tier,
              priorityTierLabel: risk.tier_label,
              priorityScore: risk.score,
              sla: risk.sla,
              scoreCvssPoints: risk.formula?.cvss_contribution || 0,
              scoreReachabilityPoints: risk.formula?.reachability_contribution || 0,
              scoreExploitPoints: risk.formula?.exploit_contribution || 0,
              scorePatchPoints: risk.formula?.patch_contribution || 0,
              scoreRationale: risk.rationale,
              confidenceLevel: risk.confidence?.level || "HIGH",
              isEstimated: risk.confidence?.isEstimated || false,
              humanReviewNotice: rem.notice
            }
          }
        }
      });
    }

    return createdScan;
  });

  return {
    scan,
    metrics: {
      total: totalFindings,
      critical_high: criticalHighCount,
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

/**
 * List all persisted scans with finding counts and metadata.
 */
export async function listScans() {
  return await prisma.scan.findMany({
    orderBy: { uploadedAt: "desc" }
  });
}

/**
 * Get a specific scan with summary metrics.
 */
export async function getScanById(scanId) {
  return await prisma.scan.findUnique({
    where: { id: scanId }
  });
}

/**
 * Query findings for a scan with filtering, sorting, and pagination.
 */
export async function getScanFindings(scanId, query = {}) {
  const {
    search = "",
    tier = "ALL",
    severity = "ALL",
    fix = "ALL",
    sort = "score_desc",
    page = 1,
    limit = 100
  } = query;

  const where = {
    scanId
  };

  if (search.trim()) {
    const q = search.trim();
    where.OR = [
      { library: { contains: q } },
      { cveId: { contains: q } },
      { description: { contains: q } }
    ];
  }

  if (severity !== "ALL") {
    where.severity = severity.toUpperCase();
  }

  if (tier !== "ALL") {
    where.remediation = {
      priorityTier: tier.toUpperCase()
    };
  }

  if (fix === "FIXABLE") {
    where.remediation = {
      ...(where.remediation || {}),
      fixAvailable: true
    };
  } else if (fix === "NO_FIX") {
    where.remediation = {
      ...(where.remediation || {}),
      fixAvailable: false
    };
  }

  let orderBy = { rank: "asc" };
  if (sort === "score_desc") {
    orderBy = { rank: "asc" };
  } else if (sort === "cvss_desc") {
    orderBy = { cvss: "desc" };
  } else if (sort === "name_asc") {
    orderBy = { library: "asc" };
  } else if (sort === "rank_asc") {
    orderBy = { rank: "asc" };
  }

  const take = Math.min(500, Math.max(1, parseInt(limit, 10) || 100));
  const skip = (Math.max(1, parseInt(page, 10) || 1) - 1) * take;

  const [totalFiltered, rawFindings] = await Promise.all([
    prisma.finding.count({ where }),
    prisma.finding.findMany({
      where,
      orderBy,
      take,
      skip,
      include: {
        dependencyContext: true,
        remediation: true
      }
    })
  ]);

  // Transform to standardized frontend representation
  const findings = rawFindings.map((f) => {
    const rem = f.remediation || {};
    const dep = f.dependencyContext || {};

    return {
      id: f.id,
      rank: f.rank,
      library: f.library,
      version: f.version,
      cve_id: f.cveId,
      severity: f.severity,
      cvss: f.cvss,
      cvss_source: f.cvssSource,
      cvss_vector: f.cvssVector,
      fix_available: rem.fixAvailable,
      fix_version: rem.fixVersion,
      exposure: dep.exposureLabel || "DIRECT / PRODUCTION",
      exposure_source: dep.exposureSource || "REPORTED",
      is_direct: dep.isDirect,
      is_production: dep.isProduction,
      dependency_path: dep.dependencyPath || f.dependencyPath,
      description: f.description,
      risk: {
        score: rem.priorityScore,
        tier: rem.priorityTier,
        tier_label: rem.priorityTierLabel,
        sla: rem.sla,
        rationale: rem.scoreRationale,
        confidence: {
          level: rem.confidenceLevel,
          isEstimated: rem.isEstimated,
          cvssSource: f.cvssSource,
          exposureSource: dep.exposureSource
        },
        formula: {
          cvss_input: f.cvss,
          cvss_contribution: rem.scoreCvssPoints,
          reachability_input: dep.reachabilityEvidence || dep.exposureLabel,
          reachability_contribution: rem.scoreReachabilityPoints,
          exploit_input: "Evaluated Threat Vector",
          exploit_contribution: rem.scoreExploitPoints,
          patch_input: rem.fixAvailable ? "Verified Vendor Patch" : "Compensating Controls",
          patch_contribution: rem.scorePatchPoints
        }
      },
      remediation: {
        action_title: rem.actionTitle,
        upgrade_command: rem.upgradeCommand,
        ecosystem: rem.ecosystem,
        dependency_path: dep.dependencyPath || f.dependencyPath,
        version_jump: {
          type: rem.semverJumpType,
          label: rem.semverJumpLabel,
          warningLevel: rem.semverWarningLevel,
          notice: rem.semverNotice
        },
        steps: [
          `1. Prepare fix for ${f.library}`,
          rem.upgradeCommand ? `2. Run: ${rem.upgradeCommand}` : "2. Configure defensive boundary controls",
          "3. Run automated regression test suite.",
          "4. Deploy to QA/staging before production merge."
        ],
        notice: rem.humanReviewNotice
      }
    };
  });

  return {
    findings,
    total: totalFiltered,
    page: parseInt(page, 10) || 1,
    limit: take
  };
}

/**
 * Seed initial demo reports (Enterprise CSV, OWASP JSON, Snyk JSON) if database is empty.
 */
export async function seedDemosIfEmpty() {
  const existingCount = await prisma.scan.count();
  if (existingCount > 0) return;

  try {
    await createScanFromReport(ENTERPRISE_CSV, "enterprise_scan.csv", {
      isDemo: true,
      demoId: "enterprise",
      customProjectName: "Enterprise Multi-Stack Microservices"
    });

    await createScanFromReport(JSON.stringify(OWASP_JSON), "owasp_report.json", {
      isDemo: true,
      demoId: "owasp",
      customProjectName: "Billing Gateway Microservice"
    });

    await createScanFromReport(JSON.stringify(SNYK_JSON), "snyk_scan.json", {
      isDemo: true,
      demoId: "snyk",
      customProjectName: "Frontend Web Application"
    });
  } catch (err) {
    console.error("Failed to seed initial demo scans:", err);
  }
}
