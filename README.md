# 🛡️ Dependency Prioritizer — SCA Risk Engine

> **Contextual Vulnerability Prioritization, Remediation Planning & Full-Stack SCA Platform**  
> Built with **Next.js (App Router, React 19, Vanilla CSS)**, **Prisma ORM**, and **SQLite / PostgreSQL**.

---

## 📋 System Overview

Development and security teams are overwhelmed by raw vulnerability scanner outputs containing hundreds of noisy alerts. **Dependency Prioritizer** ingests pre-generated reports, persists them in a normalized database, calculates an explainable **contextual risk score** (incorporating runtime reachability, directness, exploit intelligence, and patch urgency), and presents an actionable remediation plan subject to human review.

---

## 🏗️ Architecture & Stack

- **Frontend:** Next.js 16 (App Router), React 19, Vanilla CSS (dark cybersecurity theme, zero Tailwind dependencies).
- **Backend & REST API:** Next.js Route Handlers with modular service layers:
  - `lib/db.js`: Prisma client singleton with connection pooling and hot-reloading guard.
  - `lib/parsers/`: Dedicated format parsers with content-type inspection, RFC 4180 parsing, deduplication, and formula sanitization.
  - `lib/services/scoringEngine.js`: Dedicated, deterministic contextual risk-scoring engine (v2.1.0-contextual).
  - `lib/services/remediationService.js`: Actionable ecosystem-specific remediation, SemVer jump risk analysis, and quality gate checklists.
  - `lib/services/scanService.js`: Transactional scan persistence, relational queries, search/filtering, and summary statistics.
  - `lib/services/exportService.js`: RFC 4180 CSV export with CWE-1236 formula injection protection and Markdown remediation plans.
- **Database:** Prisma ORM with SQLite (`dev.db`) for instant zero-configuration local runs on Windows, with complete PostgreSQL migration support.
- **Testing:** Node.js native test runner (`node:test`, `node:assert/strict`) covering parsers, scoring engine, relational database persistence, and exports.

---

## 📐 Normalized Database Schema

- **Scan:** `id` (cuid), `projectName`, `scannerType`, `fileName`, `fileSize`, `uploadedAt`, `status`, `isDemo`, `demoId`, summary counts (`totalFindings`, `criticalHighCount`, `fixableCount`, `avgScore`, `p0Count`, `p1Count`, `p2Count`, `p3Count`).
- **Finding:** `id` (cuid), `scanId` (foreign key, cascade delete), `rank`, `library`, `version`, `cveId`, `severity`, `cvss`, `cvssSource`, `cvssVector`, `description`, `dependencyPath`.
  - *Unique Index:* `[scanId, library, version, cveId]` ensures deduplication within a scan.
- **DependencyContext:** `id` (cuid), `findingId` (1-to-1 foreign key), `isDirect`, `isProduction`, `exposureLabel`, `exposureSource`, `dependencyPath`, `reachabilityEvidence`.
- **RemediationRecommendation:** `id` (cuid), `findingId` (1-to-1 foreign key), `fixAvailable`, `fixVersion`, `actionTitle`, `upgradeCommand`, `ecosystem`, `semverJumpType`, `semverJumpLabel`, `semverWarningLevel`, `semverNotice`, `priorityTier`, `priorityScore`, `sla`, score contributions (`scoreCvssPoints`, `scoreReachabilityPoints`, `scoreExploitPoints`, `scorePatchPoints`), `scoreRationale`, `confidenceLevel`, `humanReviewNotice`.

---

## 🧮 Contextual Risk-Scoring Formula

$$\text{Final Score (0 – 100)} = (CVSS \times 10 \times 0.45) + (\text{Reachability} \times 0.25) + (\text{Exploit} \times 0.15) + (\text{Patch} \times 0.15)$$

### 1. Base CVSS Severity (Weight: 45%, Max 45.0 pts)
- Directly proportional to CVSS v3.1 base score: $(CVSS \times 10) \times 0.45$.
- When CVSS is omitted by the scanner, it is inferred from severity label and explicitly tagged with `PARTIAL (Inferred)` confidence to prevent treating missing data as low risk.

### 2. Reachability & Runtime Exposure (Weight: 25%, Max 25.0 pts)
- **Direct Production (Direct Runtime Exposure):** $100 \times 0.25 = 25.0$ pts.
- **Transitive Production (Indirect Runtime Exposure):** $75 \times 0.25 = 18.8$ pts.
- **Direct Dev / Build Tool (Non-Production):** $40 \times 0.25 = 10.0$ pts.
- **Transitive Dev (Lowest Risk):** $20 \times 0.25 = 5.0$ pts.

### 3. Exploit Evidence Analysis (Weight: 15%, Max 15.0 pts)
- **Active Critical Threat (RCE / Injection / Deserialization):** $100 \times 0.15 = 15.0$ pts.
- **Elevated Vector (SSRF / Auth Bypass / Prototype Pollution):** $75 \times 0.15 = 11.3$ pts.
- **Moderate Vector (Denial of Service / Buffer Overflow):** $50 \times 0.15 = 7.5$ pts.
- **Standard Flaw (No Active Threat Vector):** $25 \times 0.15 = 3.8$ pts.

### 4. Patch Actionability (Weight: 15%, Max 15.0 pts)
- **Verified Vendor Patch Available:** $100 \times 0.15 = 15.0$ pts (High urgency to patch).
- **No Official Patch (Compensating Controls Required):** $40 \times 0.15 = 6.0$ pts.

### Priority Tiers & SLAs
- **P0 - Critical (Score $\ge$ 85 or Production RCE):** Immediate 24-hour review SLA.
- **P1 - High (Score 70 – 84 or Production High CVSS):** Scheduled in current sprint (within 7 days).
- **P2 - Medium (Score 45 – 69):** Target within 30 days (next milestone release).
- **P3 - Low (Score < 45):** Scheduled in quarterly maintenance backlog.

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, database connection status, and scoring algorithm version |
| `GET` | `/api/scans` | List all persisted scans with metadata, counts, and status |
| `GET` | `/api/scans/:scanId` | Retrieve scan details and metrics |
| `DELETE` | `/api/scans/:scanId` | Delete a scan and cascade-delete its findings |
| `POST` | `/api/scans/upload` | Upload report (multipart form or JSON), validate, score, and persist to database |
| `POST` | `/api/scans/demo` | Load or re-seed preloaded demo reports (`enterprise`, `owasp`, `snyk`) |
| `GET` | `/api/scans/:scanId/findings` | Query findings with search (`?search=`), filtering (`?tier=`, `?severity=`, `?fix=`), sorting (`?sort=`), and pagination |
| `GET` | `/api/scans/:scanId/summary` | Summary metrics and tier distribution for a scan |
| `GET` | `/api/scans/:scanId/findings/:findingId` | Deep-dive finding details with dependency context and remediation |
| `GET` | `/api/scans/:scanId/export/csv` | Export findings to CSV with formula injection protection (also `/export.csv`) |
| `GET` | `/api/scans/:scanId/export/markdown` | Export Markdown remediation plan (also `/remediation-plan.md`) |
| `GET` | `/api/template/csv` | Download canonical CSV template generated directly from parser schema |

---

## 🚀 Setup & Running Instructions (Windows)

### 1. Install Dependencies
```powershell
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env` (already preconfigured for SQLite):
```powershell
Copy-Item .env.example .env
```

### 3. Initialize Database & Run Seed
```powershell
# Sync database schema with Prisma
npx prisma db push

# Seed initial demo scan datasets
npm run seed
```

### 4. Run Automated Test Suite
```powershell
npm test
```
Executes all 24 unit and integration tests across parsers, scoring engine, database persistence, and exports.

### 5. Launch the Web Application
```powershell
npm run dev
```
Open your browser at **`http://localhost:3000`**.

---

## 🛡️ Mandatory Human Quality Gate

> [!IMPORTANT]
> **Safety Guardrail:** Automated dependency updates without developer validation can introduce breaking API changes, transitive dependency conflicts, and regression bugs. All upgrade recommendations must undergo branch isolation, unit/integration test suites, dependency tree conflict analysis, and staging validation prior to production release.
