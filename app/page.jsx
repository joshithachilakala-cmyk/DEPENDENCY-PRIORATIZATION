"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Upload,
  FileSpreadsheet,
  FileText,
  Search,
  Copy,
  ExternalLink,
  Layers,
  ArrowUpDown,
  History,
  Info,
  Clock,
  Terminal,
  FileCode,
  GitBranch,
  AlertCircle
} from "lucide-react";
import { ingestScanReport } from "@/lib/parser";
import { prioritizeVulnerabilities } from "@/lib/prioritizer";
import { ENTERPRISE_CSV, OWASP_JSON, SNYK_JSON } from "@/lib/sampleData";

const STORAGE_KEY = "dep_prioritizer_history";

export default function DependencyPrioritizerPage() {
  const [isMounted, setIsMounted] = useState(false);
  const [findings, setFindings] = useState([]);
  const [metrics, setMetrics] = useState({
    total: 0,
    critical_high: 0,
    fixable: 0,
    fixable_percent: 0,
    avg_score: 0,
    p0: 0,
    p1: 0,
    p2: 0,
    p3: 0
  });

  // Provenance state (uses static default date to prevent SSR hydration mismatch)
  const [provenance, setProvenance] = useState({
    projectName: "Enterprise Multi-Stack Microservices",
    scannerType: "Generic CSV Export",
    scanDate: "2026-10-16T12:00:00.000Z",
    fileName: "enterprise_scan.csv",
    fileSize: "2.1 KB",
    isDemo: true,
    status: "Completed Successfully"
  });

  const [currentScanId, setCurrentScanId] = useState(null);
  const [activePreset, setActivePreset] = useState("enterprise");
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState("");
  const [uploadError, setUploadError] = useState("");

  // Scan History
  const [scanHistory, setScanHistory] = useState([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  // Filters & Sorting
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTier, setSelectedTier] = useState("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedFix, setSelectedFix] = useState("ALL");
  const [selectedSort, setSelectedSort] = useState("score_desc");

  // Detail Modal & Checklist state
  const [activeModalRecord, setActiveModalRecord] = useState(null);
  const [checkedSteps, setCheckedSteps] = useState({});
  const [copied, setCopied] = useState(false);

  // Toast
  const [toastMessage, setToastMessage] = useState("");
  const [showToast, setShowToast] = useState(false);

  // Drag and Drop
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const showNotification = (msg) => {
    setToastMessage(msg);
    setShowToast(true);
    setTimeout(() => {
      setShowToast(false);
    }, 3000);
  };

  // Safe client-side date formatting
  const formatTimestamp = (dateStr) => {
    if (!isMounted || !dateStr) {
      return dateStr ? String(dateStr).split("T")[0] : "";
    }
    try {
      return new Date(dateStr).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });
    } catch (e) {
      return String(dateStr);
    }
  };

  const saveToHistory = (prov, recs, mets, scanId = null) => {
    try {
      if (typeof window === "undefined") return;
      const entry = {
        id: scanId || ("scan-" + Date.now()),
        timestamp: new Date().toISOString(),
        provenance: prov,
        metrics: mets,
        records: recs,
        recordCount: recs ? recs.length : 0,
        urgentCount: mets ? mets.critical_high : 0
      };

      setScanHistory((prev) => {
        const filtered = prev.filter((h) => h.provenance?.fileName !== prov.fileName);
        const updated = [entry, ...filtered].slice(0, 15);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
        } catch (err) {
          console.warn("Storage quota exceeded or error saving history:", err);
        }
        return updated;
      });
    } catch (e) {
      console.warn("Could not save to history:", e);
    }
  };

  const loadPreset = async (presetId, recordHistory = true) => {
    setLoading(true);
    setUploadError("");
    setUploadProgress("Loading scan data from database...");
    setActivePreset(presetId);

    try {
      const res = await fetch("/api/scans/demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ demoId: presetId })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `Failed to load demo scan (${res.status})`);
      }

      const data = await res.json();
      setFindings(data.records || []);
      setMetrics(data.metrics || {});
      setProvenance(data.provenance || {});
      setCurrentScanId(data.scan?.id || null);

      if (typeof window !== "undefined" && data.scan?.id) {
        localStorage.setItem("active_scan_id", data.scan.id);
      }
      setLoading(false);
      setUploadProgress("");

      if (recordHistory) {
        saveToHistory(data.provenance, data.records, data.metrics, data.scan?.id);
      }
    } catch (e) {
      console.warn("Backend demo load error, falling back to local fallback:", e);
      try {
        let content = ENTERPRISE_CSV;
        let label = "enterprise_scan.csv";
        let proj = "Enterprise Multi-Stack Microservices";
        let scanner = "Generic CSV Export";

        if (presetId === "owasp") {
          content = JSON.stringify(OWASP_JSON);
          label = "owasp_report.json";
          proj = "Billing Gateway Microservice";
          scanner = "OWASP Dependency-Check v8.4.0";
        } else if (presetId === "snyk") {
          content = JSON.stringify(SNYK_JSON);
          label = "snyk_scan.json";
          proj = "Frontend Web Application";
          scanner = "Snyk CLI v1.1290";
        }

        const { records, provenance: parsedProv } = ingestScanReport(content, label);
        const result = prioritizeVulnerabilities(records);

        const finalProv = {
          ...parsedProv,
          projectName: proj,
          scannerType: scanner,
          isDemo: true,
          demoId: presetId,
          fileName: label,
          fileSize: `${Math.round(content.length / 1024 * 10) / 10} KB`
        };

        setFindings(result.records);
        setMetrics(result.metrics);
        setProvenance(finalProv);
        setLoading(false);
        setUploadProgress("");
      } catch (err2) {
        setUploadError(`Failed to load preset: ${e.message}`);
        setLoading(false);
        setUploadProgress("");
      }
    }
  };

  // Mount effect: safely synchronize database scans, active scan, and history
  useEffect(() => {
    setIsMounted(true);

    const initDashboard = async () => {
      let activeId = null;
      try {
        if (typeof window !== "undefined") {
          activeId = localStorage.getItem("active_scan_id");
          const saved = localStorage.getItem(STORAGE_KEY);
          if (saved) {
            setScanHistory(JSON.parse(saved));
          }
        }
      } catch (e) {
        console.warn("Could not read localStorage:", e);
      }

      // Synchronize scan history from database
      try {
        const scansRes = await fetch("/api/scans");
        if (scansRes.ok) {
          const scansData = await scansRes.json();
          if (scansData.scans && scansData.scans.length > 0) {
            const dbHistory = scansData.scans.map((s) => ({
              id: s.id,
              timestamp: s.uploadedAt,
              provenance: {
                projectName: s.projectName,
                scannerType: s.scannerType,
                fileName: s.fileName,
                fileSize: s.fileSize,
                isDemo: s.isDemo,
                demoId: s.demoId,
                status: s.status
              },
              metrics: {
                total: s.totalFindings,
                critical_high: s.criticalHighCount,
                fixable: s.fixableCount,
                avg_score: s.avgScore,
                p0: s.p0Count,
                p1: s.p1Count,
                p2: s.p2Count,
                p3: s.p3Count
              },
              recordCount: s.totalFindings,
              urgentCount: s.criticalHighCount
            }));
            setScanHistory(dbHistory);
          }
        }
      } catch (e) {
        console.warn("Could not fetch scans from API:", e);
      }

      // If active scan exists in database, restore it
      if (activeId) {
        try {
          const [findingsRes, summaryRes] = await Promise.all([
            fetch(`/api/scans/${activeId}/findings?limit=500`),
            fetch(`/api/scans/${activeId}/summary`)
          ]);
          if (findingsRes.ok && summaryRes.ok) {
            const fData = await findingsRes.json();
            const sData = await summaryRes.json();
            setFindings(fData.findings || []);
            setMetrics(sData.metrics || {});
            setProvenance({
              projectName: sData.projectName,
              scannerType: sData.scannerType,
              scanDate: sData.uploadedAt,
              fileName: sData.fileName,
              fileSize: sData.fileSize,
              isDemo: sData.isDemo,
              status: sData.status
            });
            setCurrentScanId(activeId);
            setActivePreset(sData.isDemo ? (sData.demoId || "enterprise") : "");
            return;
          }
        } catch (e) {
          console.warn("Could not reload active scan from DB:", e);
        }
      }

      // Fallback: load enterprise demo
      loadPreset("enterprise", false);
    };

    initDashboard();
  }, []);

  const handleFileUpload = async (file) => {
    if (!file) return;

    setLoading(true);
    setUploadError("");
    setActivePreset("");
    setUploadProgress("Step 1/3: Reading report file...");

    if (file.size > 15 * 1024 * 1024) {
      setUploadError(`File is too large (${(file.size / (1024 * 1024)).toFixed(1)} MB). Maximum allowed size is 15 MB.`);
      setLoading(false);
      setUploadProgress("");
      return;
    }

    try {
      setUploadProgress("Step 2/3: Uploading & normalizing findings in SCA Risk Engine...");
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/scans/upload", {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `Upload failed with HTTP ${res.status}`);
      }

      setUploadProgress("Step 3/3: Persisting scan to database & computing contextual scores...");
      const data = await res.json();

      setFindings(data.records || []);
      setMetrics(data.metrics || {});
      setProvenance(data.provenance || {});
      setCurrentScanId(data.scan?.id || null);

      if (typeof window !== "undefined" && data.scan?.id) {
        localStorage.setItem("active_scan_id", data.scan.id);
      }

      setLoading(false);
      setUploadProgress("");
      saveToHistory(data.provenance, data.records, data.metrics, data.scan?.id);
      showNotification(`Successfully processed ${data.records.length} findings from ${file.name}`);
    } catch (err) {
      setUploadError(`Upload/Parsing Error: ${err.message}`);
      setLoading(false);
      setUploadProgress("");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // Filter & Sort
  const filteredRecords = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    const filtered = findings.filter((item) => {
      if (q) {
        const matchLib = (item.library || "").toLowerCase().includes(q);
        const matchCve = (item.cve_id || "").toLowerCase().includes(q);
        const matchDesc = (item.description || "").toLowerCase().includes(q);
        if (!matchLib && !matchCve && !matchDesc) return false;
      }

      if (selectedTier !== "ALL" && item.risk?.tier !== selectedTier) {
        return false;
      }

      if (selectedSeverity !== "ALL" && item.severity.toUpperCase() !== selectedSeverity) {
        return false;
      }

      if (selectedFix === "FIXABLE" && !item.fix_available) return false;
      if (selectedFix === "NO_FIX" && item.fix_available) return false;

      return true;
    });

    filtered.sort((a, b) => {
      if (selectedSort === "score_desc") return (b.risk?.score || 0) - (a.risk?.score || 0);
      if (selectedSort === "cvss_desc") return (b.cvss || 0) - (a.cvss || 0);
      if (selectedSort === "name_asc") return (a.library || "").localeCompare(b.library || "");
      if (selectedSort === "rank_asc") return a.rank - b.rank;
      return (b.risk?.score || 0) - (a.risk?.score || 0);
    });

    return filtered;
  }, [findings, searchQuery, selectedTier, selectedSeverity, selectedFix, selectedSort]);

  // Exports
  const handleExportCsv = async () => {
    try {
      const res = await fetch("/api/export/csv", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ records: filteredRecords })
      });
      if (!res.ok) throw new Error("CSV Export failed");
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prioritized_vulnerabilities_${provenance.fileName.replace(/\.[^/.]+$/, "")}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
      showNotification(`Exported ${filteredRecords.length} findings to CSV`);
    } catch (e) {
      showNotification(e.message);
    }
  };

  const handleExportMarkdown = async () => {
    try {
      const res = await fetch("/api/export/markdown", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          records: filteredRecords,
          metrics,
          source_name: `${provenance.projectName} (${provenance.fileName})`
        })
      });
      if (!res.ok) throw new Error("Markdown Export failed");
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `remediation_plan_${provenance.fileName.replace(/\.[^/.]+$/, "")}.md`;
      a.click();
      window.URL.revokeObjectURL(url);
      showNotification("Exported Remediation Plan to Markdown");
    } catch (e) {
      showNotification(e.message);
    }
  };

  const copyCommand = (cmd) => {
    if (!cmd) return;
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(true);
      showNotification("Copied command to clipboard");
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const toggleChecklistStep = (idx) => {
    setCheckedSteps((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  // Math for Posture Bar
  const totalCount = metrics.total || 1;
  const p0Width = Math.max(4, (metrics.p0 / totalCount) * 100);
  const p1Width = Math.max(4, (metrics.p1 / totalCount) * 100);
  const p2Width = Math.max(4, (metrics.p2 / totalCount) * 100);
  const p3Width = Math.max(4, (metrics.p3 / totalCount) * 100);

  return (
    <>
      {/* App Header */}
      <header className="app-header">
        <div className="header-container">
          <div className="brand">
            <div className="brand-icon">
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="brand-title">
                <h1>Dependency Prioritizer</h1>
                <span className="badge-tag">SCA Risk Engine</span>
              </div>
              <p className="brand-subtitle">
                Contextual Vulnerability Prioritization &amp; Remediation Plan
              </p>
            </div>
          </div>

          <div className="header-actions">
            <button
              className="btn btn-outline"
              onClick={() => setShowHistoryModal(true)}
              title="View past scans"
            >
              <History size={14} />
              <span>Scan History</span>
              {isMounted && scanHistory.length > 0 ? (
                <span className="badge-tag" suppressHydrationWarning>({scanHistory.length})</span>
              ) : null}
            </button>
            <a
              href="/api/template/csv"
              className="btn btn-outline"
              title="Download starter CSV template"
            >
              <FileSpreadsheet size={14} />
              CSV Template
            </a>
            <button
              className="btn btn-primary"
              onClick={() => loadPreset("enterprise")}
              title="Reload default enterprise scan"
            >
              Load Demo Scan
            </button>
          </div>
        </div>
      </header>

      {/* Mandatory Human Review Guardrail */}
      <div className="safety-banner">
        <div className="safety-content">
          <span className="safety-badge">Review Gate</span>
          <span>
            Automated production patching without testing is strictly prohibited. Mandatory developer review, automated test suites, and staging verification are required before merging.
          </span>
        </div>
      </div>

      <main className="main-container">
        {/* Scan Provenance & Summary Bar */}
        <div className="provenance-bar">
          <div className="provenance-items">
            <div className="prov-item">
              <span className="prov-label">Project</span>
              <span className="prov-value">
                <GitBranch size={13} color="#a1a1aa" />
                {provenance.projectName}
              </span>
            </div>

            <div className="prov-item">
              <span className="prov-label">Scanner Type</span>
              <span className="prov-value">
                <Terminal size={13} color="#a1a1aa" />
                {provenance.scannerType}
              </span>
            </div>

            <div className="prov-item">
              <span className="prov-label">Report File</span>
              <span className="prov-value">
                <FileCode size={13} color="#a1a1aa" />
                {provenance.fileName} <span style={{ color: "var(--text-tertiary)" }}>({provenance.fileSize})</span>
              </span>
            </div>

            <div className="prov-item">
              <span className="prov-label">Scan Timestamp</span>
              <span className="prov-value">
                <Clock size={13} color="#a1a1aa" />
                <span suppressHydrationWarning>{formatTimestamp(provenance.scanDate)}</span>
              </span>
            </div>
          </div>

          <div>
            <span className={`badge-source ${provenance.isDemo ? "demo" : "uploaded"}`}>
              {provenance.isDemo ? "📦 PRELOADED DEMO" : "📁 VERIFIED UPLOAD"}
            </span>
          </div>
        </div>

        {/* Ingestion & Upload Section */}
        <section className="ingestion-section card">
          <div className="section-header">
            <div>
              <h2>Scan Report Ingestion</h2>
              <p className="section-desc">
                Upload a vulnerability scan report or inspect preloaded reports.
              </p>
            </div>
            <div className="dropzone-limits">
              <span className="limit-tag">Accepted: .csv, .json, .xml, .txt</span>
              <span className="limit-tag">Max: 15 MB</span>
            </div>
          </div>

          <div className="ingestion-grid">
            {/* Drag & Drop Dropzone */}
            <div
              className={`dropzone ${isDragOver ? "dragover" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.json,.xml,.txt"
                style={{ display: "none" }}
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />
              <Upload size={24} color="#71717a" />
              <h3>Drag &amp; drop vulnerability scan report</h3>
              <p className="dropzone-hint">
                Supports generic CSV, OWASP Dependency-Check JSON, and Snyk / npm audit JSON
              </p>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ marginTop: "0.25rem" }}
                onClick={(e) => {
                  e.stopPropagation();
                  fileInputRef.current?.click();
                }}
              >
                Browse File
              </button>
            </div>

            {/* Presets */}
            <div className="presets-panel">
              <span className="preset-label">Pre-loaded Reports:</span>
              <div className="preset-buttons">
                <button
                  className={`preset-btn ${activePreset === "enterprise" ? "active" : ""}`}
                  onClick={() => loadPreset("enterprise")}
                >
                  <div className="preset-title">Enterprise Multi-Stack Scan (CSV)</div>
                  <div className="preset-meta">
                    15 findings (Log4j, Spring4Shell, Lodash, PyYAML, Pillow)
                  </div>
                </button>
                <button
                  className={`preset-btn ${activePreset === "owasp" ? "active" : ""}`}
                  onClick={() => loadPreset("owasp")}
                >
                  <div className="preset-title">OWASP Dependency-Check (JSON)</div>
                  <div className="preset-meta">Java Spring Gateway scan report</div>
                </button>
                <button
                  className={`preset-btn ${activePreset === "snyk" ? "active" : ""}`}
                  onClick={() => loadPreset("snyk")}
                >
                  <div className="preset-title">Snyk CLI Scan (JSON)</div>
                  <div className="preset-meta">Node.js / npm ecosystem report</div>
                </button>
              </div>
            </div>
          </div>

          {/* Upload Progress Status */}
          {loading && uploadProgress && (
            <div className="upload-status-box">
              <div className="spinner"></div>
              <span>{uploadProgress}</span>
            </div>
          )}

          {/* Actionable Error Callout */}
          {uploadError && (
            <div className="error-callout">
              <h5>
                <AlertCircle size={15} />
                Parsing Failed
              </h5>
              <div>{uploadError}</div>
              <div style={{ fontSize: "0.74rem", opacity: 0.9, marginTop: "0.25rem" }}>
                Tip: If using CSV, make sure column headers include <code>library</code> (or <code>package</code>), <code>version</code>, <code>cve_id</code>, and <code>severity</code>. You can download the starter template above for reference.
              </div>
            </div>
          )}
        </section>

        {/* Metrics Grid */}
        <section className="metrics-grid">
          <div className="metric-card card">
            <div className="metric-header">
              <span className="metric-title">Total Vulnerabilities</span>
              <div className="metric-icon">
                <Layers size={16} />
              </div>
            </div>
            <div className="metric-value">{metrics.total}</div>
            <div className="metric-footer">
              <span>Identified in report</span>
            </div>
          </div>

          <div className="metric-card card">
            <div className="metric-header">
              <span className="metric-title">Urgent Review (P0 / P1)</span>
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>
            </div>
            <div className="metric-value urgent-text">{metrics.critical_high}</div>
            <div className="metric-footer">
              <span className="badge-sla">SLA &le; 7 Days</span>
              <span>Needs immediate triage</span>
            </div>
          </div>

          <div className="metric-card card">
            <div className="metric-header">
              <span className="metric-title">Fixes Available</span>
              <div className="metric-icon">
                <ShieldCheck size={16} />
              </div>
            </div>
            <div className="metric-value">{metrics.fixable}</div>
            <div className="metric-footer">
              <span className="fixable-pct">{metrics.fixable_percent}% patchable</span>
              <span>with vendor releases</span>
            </div>
          </div>

          <div className="metric-card card">
            <div className="metric-header">
              <span className="metric-title">Average Risk Score</span>
              <div className="metric-icon">
                <ArrowUpDown size={16} />
              </div>
            </div>
            <div className="metric-value">
              {metrics.avg_score}
              <span className="unit">/100</span>
            </div>
            <div className="metric-footer">
              <span>Context-weighted risk</span>
            </div>
          </div>
        </section>

        {/* Posture Distribution */}
        <section className="posture-section card">
          <div className="posture-header">
            <h3>Triage Queue Distribution</h3>
            <span className="posture-note">
              Ranked by CVSS severity, runtime production reachability, and patch availability
            </span>
          </div>
          <div className="posture-bar">
            <div className="segment p0" style={{ width: `${p0Width}%` }} title="P0 Critical">
              P0: {metrics.p0}
            </div>
            <div className="segment p1" style={{ width: `${p1Width}%` }} title="P1 High">
              P1: {metrics.p1}
            </div>
            <div className="segment p2" style={{ width: `${p2Width}%` }} title="P2 Medium">
              P2: {metrics.p2}
            </div>
            <div className="segment p3" style={{ width: `${p3Width}%` }} title="P3 Low">
              P3: {metrics.p3}
            </div>
          </div>
          <div className="posture-legend">
            <span className="legend-item">
              <span className="legend-dot p0"></span> P0 - Critical (&le; 24h)
            </span>
            <span className="legend-item">
              <span className="legend-dot p1"></span> P1 - High (&le; 7d)
            </span>
            <span className="legend-item">
              <span className="legend-dot p2"></span> P2 - Medium (&le; 30d)
            </span>
            <span className="legend-item">
              <span className="legend-dot p3"></span> P3 - Low (Scheduled)
            </span>
          </div>
        </section>

        {/* Search, Filter & Export */}
        <section className="controls-section card">
          <div className="controls-grid">
            <div className="search-box">
              <Search size={15} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by package name, CVE ID, or keyword..."
              />
            </div>

            <div className="filter-group">
              <label>Priority Tier</label>
              <select value={selectedTier} onChange={(e) => setSelectedTier(e.target.value)}>
                <option value="ALL">All Tiers</option>
                <option value="P0">P0 - Critical</option>
                <option value="P1">P1 - High</option>
                <option value="P2">P2 - Medium</option>
                <option value="P3">P3 - Low</option>
              </select>
            </div>

            <div className="filter-group">
              <label>Severity</label>
              <select value={selectedSeverity} onChange={(e) => setSelectedSeverity(e.target.value)}>
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div className="filter-group">
              <label>Patch Status</label>
              <select value={selectedFix} onChange={(e) => setSelectedFix(e.target.value)}>
                <option value="ALL">All Findings</option>
                <option value="FIXABLE">Fix Available Only</option>
                <option value="NO_FIX">No Patch Available</option>
              </select>
            </div>

            <div className="filter-group">
              <label>Sort By</label>
              <select value={selectedSort} onChange={(e) => setSelectedSort(e.target.value)}>
                <option value="score_desc">Risk Score (High &rarr; Low)</option>
                <option value="cvss_desc">CVSS Score (High &rarr; Low)</option>
                <option value="name_asc">Package Name (A &rarr; Z)</option>
                <option value="rank_asc">Priority Rank (1 &rarr; N)</option>
              </select>
            </div>

            <div className="export-actions">
              <button className="btn btn-outline" onClick={handleExportCsv} title="Export CSV">
                <FileSpreadsheet size={14} />
                CSV
              </button>
              <button className="btn btn-outline" onClick={handleExportMarkdown} title="Export Markdown">
                <FileText size={14} />
                Plan (.md)
              </button>
            </div>
          </div>
        </section>

        {/* Findings Table */}
        <section className="findings-section card">
          <div className="findings-header">
            <div>
              <h3>Prioritized Action Queue</h3>
              <p className="findings-count">
                Showing {filteredRecords.length} of {findings.length} findings
              </p>
            </div>
          </div>

          <div className="table-responsive">
            <table className="findings-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Rank</th>
                  <th style={{ width: 75 }}>Tier</th>
                  <th style={{ width: 90 }}>Score</th>
                  <th>Component &amp; Version</th>
                  <th>Vulnerability</th>
                  <th style={{ width: 100 }}>CVSS</th>
                  <th>Reachability</th>
                  <th>Fix Status</th>
                  <th>Recommended Action</th>
                  <th style={{ width: 85 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={10} className="loading-cell">
                      Analyzing findings...
                    </td>
                  </tr>
                ) : filteredRecords.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="loading-cell">
                      No findings match the current filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredRecords.map((item) => {
                    const tierClass = (item.risk?.tier || "P3").toLowerCase();
                    const sevClass = (item.severity || "medium").toLowerCase();
                    const nvdUrl = (item.cve_id || "").startsWith("CVE-")
                      ? `https://nvd.nist.gov/vuln/detail/${item.cve_id}`
                      : "#";

                    return (
                      <tr key={item.id}>
                        <td>
                          <strong>#{item.rank}</strong>
                        </td>
                        <td>
                          <span className={`badge-tier ${tierClass}`}>
                            {item.risk?.tier}
                          </span>
                        </td>
                        <td className="score-cell">
                          {item.risk?.score}
                        </td>
                        <td>
                          <div className="lib-cell">
                            <span className="lib-name">{item.library}</span>
                            <span className="lib-ver">v{item.version}</span>
                          </div>
                        </td>
                        <td>
                          {item.cve_id !== "N/A" ? (
                            <a
                              href={nvdUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="cve-link"
                            >
                              {item.cve_id}
                            </a>
                          ) : (
                            <span style={{ color: "var(--text-tertiary)" }}>N/A</span>
                          )}
                        </td>
                        <td>
                          <span className={`badge-sev ${sevClass}`}>
                            {item.cvss} {item.severity}
                          </span>
                        </td>
                        <td>
                          <span className={`badge-exp ${item.is_direct ? "direct" : ""}`}>
                            {item.exposure}
                          </span>
                        </td>
                        <td>
                          {item.fix_available ? (
                            <span className="badge-fix yes">
                              Patch: {item.fix_version}
                            </span>
                          ) : (
                            <span className="badge-fix no">No Patch</span>
                          )}
                        </td>
                        <td>
                          <div className="action-text" title={item.remediation?.action_title}>
                            {item.remediation?.action_title}
                          </div>
                        </td>
                        <td>
                          <button
                            className="btn-inspect"
                            onClick={() => {
                              setActiveModalRecord(item);
                              setCheckedSteps({});
                            }}
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* Deep-Dive Remediation Modal Drawer */}
      {activeModalRecord && (
        <div
          className="modal-backdrop open"
          onClick={(e) => {
            if (e.target.classList.contains("modal-backdrop")) {
              setActiveModalRecord(null);
            }
          }}
        >
          <div className="modal-dialog">
            <div className="modal-header">
              <div className="modal-title-wrap">
                <span className={`badge-tier ${(activeModalRecord.risk?.tier || "P0").toLowerCase()}`}>
                  {activeModalRecord.risk?.tier}
                </span>
                <div>
                  <h3>{activeModalRecord.library}</h3>
                  <span className="modal-cve">{activeModalRecord.cve_id}</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setActiveModalRecord(null)}>
                &times;
              </button>
            </div>

            <div className="modal-body">
              {/* Prioritization Rationale */}
              <div className="rationale-box">
                <div className="rationale-label">
                  Explainable Prioritization Rationale (Score: {activeModalRecord.risk?.score} / 100)
                </div>
                <div className="rationale-text">
                  {activeModalRecord.risk?.rationale}
                </div>
              </div>

              {/* Requirement 1: Scoring Formula & Weighted Contributions */}
              <div className="formula-card">
                <div className="formula-header">
                  <h4>Scoring Formula Breakdown</h4>
                  <span className={`confidence-pill ${activeModalRecord.risk?.confidence?.isEstimated ? "partial" : "high"}`}>
                    {activeModalRecord.risk?.confidence?.level}
                  </span>
                </div>

                <div className="formula-grid">
                  <div className="formula-item">
                    <div className="formula-item-top">
                      <span className="formula-label">1. Base CVSS (45% Weight)</span>
                      <span className="formula-pts">+{activeModalRecord.risk?.formula?.cvss_contribution} pts</span>
                    </div>
                    <div className="formula-val">
                      CVSS {activeModalRecord.risk?.formula?.cvss_input} ({activeModalRecord.risk?.confidence?.cvssSource === "REPORTED_CVSS" ? "Reported" : "Estimated from Severity"})
                    </div>
                    <div className="formula-progress">
                      <div
                        className="formula-fill"
                        style={{ width: `${(activeModalRecord.risk?.formula?.cvss_contribution / 45) * 100}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="formula-item">
                    <div className="formula-item-top">
                      <span className="formula-label">2. Reachability (25% Weight)</span>
                      <span className="formula-pts">+{activeModalRecord.risk?.formula?.reachability_contribution} pts</span>
                    </div>
                    <div className="formula-val" title={activeModalRecord.risk?.formula?.reachability_input}>
                      {activeModalRecord.risk?.formula?.reachability_input}
                    </div>
                    <div className="formula-progress">
                      <div
                        className="formula-fill"
                        style={{ width: `${(activeModalRecord.risk?.formula?.reachability_contribution / 25) * 100}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="formula-item">
                    <div className="formula-item-top">
                      <span className="formula-label">3. Exploit Evidence (15% Weight)</span>
                      <span className="formula-pts">+{activeModalRecord.risk?.formula?.exploit_contribution} pts</span>
                    </div>
                    <div className="formula-val" title={activeModalRecord.risk?.formula?.exploit_input}>
                      {activeModalRecord.risk?.formula?.exploit_input}
                    </div>
                    <div className="formula-progress">
                      <div
                        className="formula-fill"
                        style={{ width: `${(activeModalRecord.risk?.formula?.exploit_contribution / 15) * 100}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="formula-item">
                    <div className="formula-item-top">
                      <span className="formula-label">4. Patch Actionability (15% Weight)</span>
                      <span className="formula-pts">+{activeModalRecord.risk?.formula?.patch_contribution} pts</span>
                    </div>
                    <div className="formula-val" title={activeModalRecord.risk?.formula?.patch_input}>
                      {activeModalRecord.risk?.formula?.patch_input}
                    </div>
                    <div className="formula-progress">
                      <div
                        className="formula-fill"
                        style={{ width: `${(activeModalRecord.risk?.formula?.patch_contribution / 15) * 100}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Requirement 4: Affected Dependency Path */}
              <div className="detail-section">
                <h4>Affected Dependency Path</h4>
                <div className="dep-path-box">
                  <span>ROOT → </span>
                  <span>{activeModalRecord.remediation?.dependency_path}</span>
                </div>
              </div>

              {/* Requirement 4: Version Comparison & Compatibility Assessment */}
              <div className="version-card">
                <div className="version-comparison">
                  <div className="version-box">
                    <span>Installed:</span>
                    <code>{activeModalRecord.version}</code>
                  </div>
                  <span>&rarr;</span>
                  <div className="version-box">
                    <span>Target:</span>
                    <code>{activeModalRecord.fix_available ? activeModalRecord.fix_version : "Compensating Controls"}</code>
                  </div>
                  <span className={`semver-badge ${activeModalRecord.remediation?.version_jump?.warningLevel}`}>
                    {activeModalRecord.remediation?.version_jump?.label}
                  </span>
                </div>

                <div className="semver-notice">
                  {activeModalRecord.remediation?.version_jump?.notice}
                </div>
              </div>

              {/* Finding Description & References */}
              <div className="detail-section">
                <h4>Vulnerability Summary</h4>
                <p className="detail-description">{activeModalRecord.description}</p>
                {activeModalRecord.cve_id.startsWith("CVE-") && (
                  <div className="meta-row">
                    <span>
                      Official Advisory:{" "}
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${activeModalRecord.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="cve-link"
                      >
                        NIST NVD Advisory &nearr;
                      </a>
                    </span>
                  </div>
                )}
              </div>

              {/* Suggested Upgrade Snippet */}
              <div className="detail-section">
                <h4>Remediation Snippet</h4>
                <div className="command-box">
                  <pre>
                    <code>{activeModalRecord.remediation?.upgrade_command}</code>
                  </pre>
                  <button
                    className="btn btn-secondary"
                    style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
                    onClick={() => copyCommand(activeModalRecord.remediation?.upgrade_command)}
                    title="Copy command"
                  >
                    <Copy size={13} />
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>

              {/* Verification Checklist */}
              <div className="detail-section">
                <h4>Developer Quality Gate Checklist</h4>
                <div className="checklist">
                  {activeModalRecord.remediation?.steps?.map((step, idx) => (
                    <label key={idx} className="check-item">
                      <input
                        type="checkbox"
                        checked={Boolean(checkedSteps[idx])}
                        onChange={() => toggleChecklistStep(idx)}
                      />
                      <span>{step}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setActiveModalRecord(null)}
              >
                Close
              </button>
              <button
                className="btn btn-primary"
                onClick={() => {
                  showNotification(`Marked ${activeModalRecord.library} as triaged`);
                  setActiveModalRecord(null);
                }}
              >
                Mark as Triaged
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Requirement 2: Scan History Modal */}
      {showHistoryModal && (
        <div
          className="modal-backdrop open"
          onClick={(e) => {
            if (e.target.classList.contains("modal-backdrop")) {
              setShowHistoryModal(false);
            }
          }}
        >
          <div className="modal-dialog" style={{ maxWidth: 640 }}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <History size={18} color="#818cf8" />
                <h3>Scan Session History</h3>
              </div>
              <button className="modal-close" onClick={() => setShowHistoryModal(false)}>
                &times;
              </button>
            </div>

            <div className="modal-body">
              <p style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                Revisit previously ingested scan reports or demo sessions:
              </p>

              {scanHistory.length === 0 ? (
                <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-tertiary)", fontSize: "0.82rem" }}>
                  No scan history recorded yet. Upload a report or load a demo to populate this list.
                </div>
              ) : (
                <div className="history-list">
                  {scanHistory.map((item) => {
                    const isCurrent = provenance.fileName === item.provenance?.fileName;

                    return (
                      <div
                        key={item.id}
                        className={`history-item ${isCurrent ? "active" : ""}`}
                        onClick={async () => {
                          if (item.id && !item.id.startsWith("scan-")) {
                            try {
                              setLoading(true);
                              const [fRes, sRes] = await Promise.all([
                                fetch(`/api/scans/${item.id}/findings?limit=500`),
                                fetch(`/api/scans/${item.id}/summary`)
                              ]);
                              if (fRes.ok && sRes.ok) {
                                const fData = await fRes.json();
                                const sData = await sRes.json();
                                setFindings(fData.findings || []);
                                setMetrics(sData.metrics || {});
                                setProvenance({
                                  projectName: sData.projectName,
                                  scannerType: sData.scannerType,
                                  scanDate: sData.uploadedAt,
                                  fileName: sData.fileName,
                                  fileSize: sData.fileSize,
                                  isDemo: sData.isDemo,
                                  status: sData.status
                                });
                                setCurrentScanId(item.id);
                                if (typeof window !== "undefined") {
                                  localStorage.setItem("active_scan_id", item.id);
                                }
                                showNotification(`Loaded scan: ${sData.fileName}`);
                                setLoading(false);
                                setShowHistoryModal(false);
                                return;
                              }
                            } catch (e) {
                              console.warn("Error loading scan from API:", e);
                            }
                          }
                          if (item.records && item.records.length > 0) {
                            setFindings(item.records);
                            if (item.metrics) setMetrics(item.metrics);
                            if (item.provenance) setProvenance(item.provenance);
                            setActivePreset(item.provenance?.isDemo ? (item.provenance?.demoId || "enterprise") : "");
                            showNotification(`Loaded scan: ${item.provenance?.fileName}`);
                          } else if (item.provenance?.isDemo && item.provenance?.demoId) {
                            loadPreset(item.provenance.demoId, false);
                          } else {
                            showNotification(`Revisiting scan: ${item.provenance?.fileName}`);
                          }
                          setShowHistoryModal(false);
                        }}
                      >
                        <div className="history-meta">
                          <div className="history-title">
                            <span>{item.provenance?.projectName || item.provenance?.fileName}</span>
                            <span className={`badge-source ${item.provenance?.isDemo ? "demo" : "uploaded"}`} style={{ fontSize: "0.62rem" }}>
                              {item.provenance?.isDemo ? "DEMO" : "UPLOAD"}
                            </span>
                            {isCurrent && (
                              <span style={{ fontSize: "0.68rem", color: "#6ee7b7", fontWeight: 600 }}>
                                (Current)
                              </span>
                            )}
                          </div>
                          <div className="history-sub">
                            {item.provenance?.fileName} • {item.recordCount} findings ({item.urgentCount} urgent) • <span suppressHydrationWarning>{formatTimestamp(item.timestamp)}</span>
                          </div>
                        </div>

                        <button className="btn btn-secondary" style={{ padding: "0.3rem 0.6rem", fontSize: "0.75rem" }}>
                          Select
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="modal-footer" style={{ justifyContent: "space-between" }}>
              <button
                className="btn btn-outline"
                style={{ fontSize: "0.75rem", color: "#f87171" }}
                onClick={() => {
                  try {
                    if (typeof window !== "undefined") {
                      localStorage.removeItem(STORAGE_KEY);
                    }
                  } catch (e) {}
                  setScanHistory([]);
                  showNotification("Cleared scan history");
                }}
              >
                Clear History
              </button>
              <button className="btn btn-secondary" onClick={() => setShowHistoryModal(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      <div className={`toast ${showToast ? "show" : ""}`}>{toastMessage}</div>
    </>
  );
}
