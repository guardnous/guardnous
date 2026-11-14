"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { getScan, API_URL } from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import SbomCard from "@/components/SbomCard";
import {
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  Shield,
  FileCode2,
  FolderGit2,
  AlertTriangle,
  Bug,
  Lock,
  Eye,
  FileSearch,
  Send,
  Database,
  Network,
  ClipboardCheck,
  Scale,
  Zap,
  BarChart3,
  ChevronDown,
  ChevronRight,
  Terminal,
  Download,
  FileText,
  FileSpreadsheet,
  FileJson,
  Globe,
} from "lucide-react";

/* ── Stage definitions (canonical pipeline order) ── */

type StageDefinition = {
  key: string;
  label: string;
  icon: any;
  description: string;
  isToolStage?: boolean;
};

const BASE_PIPELINE_STAGES: StageDefinition[] = [
  { key: "authenticating", label: "Authenticating", icon: Lock, description: "Validating credentials & permissions" },
  { key: "cloning", label: "Cloning Repository", icon: FolderGit2, description: "Fetching repository file tree" },
  { key: "dependency_analysis", label: "Dependency Analysis", icon: Database, description: "Analyzing manifests for vulnerable packages" },
  { key: "secret_scanning", label: "Secret Scanning", icon: Eye, description: "Detecting hardcoded secrets & credentials" },
  { key: "iac_scanning", label: "IaC Scanning", icon: FileSearch, description: "Orchestrating IaC security tools" },
  // Dynamic tool sub-stages are inserted after iac_scanning
  { key: "vulnerability_correlation", label: "Vulnerability Correlation", icon: Network, description: "Correlating CVEs across findings" },
  { key: "policy_evaluation", label: "Policy Evaluation", icon: ClipboardCheck, description: "Evaluating against security policies" },
  { key: "compliance_mapping", label: "Compliance Mapping", icon: Scale, description: "Mapping to CIS / SOC2 / NIST frameworks" },
  { key: "processing_results", label: "Processing Results", icon: Zap, description: "Aggregating & scoring findings" },
  { key: "generating_report", label: "Generating Report", icon: BarChart3, description: "Building scan report" },
  { key: "sending_notifications", label: "Sending Notifications", icon: Send, description: "Dispatching alerts & webhooks" },
  { key: "completed", label: "Completed", icon: CheckCircle2, description: "Scan finished" },
];

// Known IaC tool sub-stages — displayed with tool-specific labels
const IAC_TOOL_STAGES: Record<string, { label: string; description: string }> = {
  iac_terraform: { label: "Terraform Scanner", description: "Scanning .tf / .tfvars files" },
  iac_cloudformation: { label: "CloudFormation Scanner", description: "Scanning CloudFormation / K8s / Ansible YAML templates" },
  iac_bicep: { label: "Bicep Scanner", description: "Scanning Azure Bicep templates" },
  iac_secrets: { label: "Secrets Scanner", description: "Scanning for embedded secrets in IaC" },
  iac_checkov: { label: "Checkov", description: "Policy-as-code static analysis" },
  iac_trivy: { label: "Trivy", description: "Vulnerability & misconfiguration scanner" },
  iac_semgrep: { label: "Semgrep", description: "Lightweight static analysis" },
  iac_tfsec: { label: "tfsec", description: "Terraform security scanner" },
  iac_gitleaks: { label: "Gitleaks", description: "Secret detection in code" },
};

/* A cloud posture assessment reads a cloud account; it clones nothing and runs no code scanners. */
const CLOUD_POSTURE_STAGES: StageDefinition[] = [
  { key: "cloud_discovery", label: "Reading the Cloud Account", icon: Globe, description: "Connecting and reading resource configuration" },
  { key: "cloud_evaluation", label: "Checking Rules", icon: ClipboardCheck, description: "Running posture rules on every resource" },
  { key: "cloud_findings", label: "Updating Findings", icon: Zap, description: "Opening, resolving and reopening findings" },
  { key: "completed", label: "Completed", icon: CheckCircle2, description: "Assessment finished" },
];

const isCloudPosture = (scanType?: string | null) => scanType === "cloud_posture";

/** Build the full stage list dynamically based on which tool stages exist in data */
function buildPipelineStages(
  stageDetails: Record<string, any> | null,
  logsByStage: Record<string, any[]>,
  scanType?: string | null,
): StageDefinition[] {
  if (isCloudPosture(scanType)) return CLOUD_POSTURE_STAGES;
  // Discover tool sub-stages from stage_details keys or log keys
  const toolKeys = new Set<string>();
  if (stageDetails) {
    for (const k of Object.keys(stageDetails)) {
      if (k.startsWith("iac_") && k !== "iac_scanning") toolKeys.add(k);
    }
  }
  for (const k of Object.keys(logsByStage)) {
    if (k.startsWith("iac_") && k !== "iac_scanning") toolKeys.add(k);
  }

  if (toolKeys.size === 0) return BASE_PIPELINE_STAGES;

  // Insert tool stages right after iac_scanning
  const result: StageDefinition[] = [];
  for (const stage of BASE_PIPELINE_STAGES) {
    result.push(stage);
    if (stage.key === "iac_scanning") {
      // Sort tool stages for consistent order
      const sorted = Array.from(toolKeys).sort();
      for (const tk of sorted) {
        const meta = IAC_TOOL_STAGES[tk];
        result.push({
          key: tk,
          label: meta?.label ?? tk.replace("iac_", "").replace(/_/g, " "),
          icon: FileSearch,
          description: meta?.description ?? "IaC tool scan",
          isToolStage: true,
        });
      }
    }
  }
  return result;
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return "—";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  return `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

type StageStatus = "completed" | "running" | "pending" | "failed" | "skipped";

function getStageStatus(
  stageKey: string,
  stageDetails: Record<string, any> | null,
  currentStage: string | null,
  scanStatus: string
): StageStatus {
  // Special case: the "completed" stage is the terminal marker
  if (stageKey === "completed") {
    if (scanStatus === "completed") return "completed";
    if (scanStatus === "failed" || scanStatus === "timed_out") return "failed";
    return "pending";
  }

  // If scan completed but stage_details is empty/null (sync scan path),
  // treat all stages as completed so they don't appear greyed out.
  const hasAnyDetail = stageDetails && Object.keys(stageDetails).length > 0;
  if (scanStatus === "completed" && !hasAnyDetail) return "completed";

  if (!stageDetails) {
    if (stageKey === currentStage) return "running";
    return "pending";
  }

  const detail = stageDetails[stageKey];
  // Stage has both start and end → completed
  if (detail && detail.end_time) return "completed";
  // Stage started but not ended
  if (detail && detail.start_time && !detail.end_time) {
    if (scanStatus === "completed") return "completed"; // scan finished, mark done
    if (scanStatus === "failed" || scanStatus === "timed_out") return "failed";
    return "running";
  }
  // No detail at all for this stage — if scan itself completed, mark stage completed too
  if (scanStatus === "completed") return "completed";
  if (scanStatus === "failed" || scanStatus === "timed_out") return "skipped";
  if (stageKey === currentStage) return "running";
  return "pending";
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-blue-400",
};

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = Number(params.id);

  const { data: scan, isLoading, error } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId),
    refetchInterval: (query) => {
      const s = query.state.data;
      if (s && (s.status === "running" || s.status === "pending" || s.status === "queued"))
        return 2000;
      return false;
    },
  });

  // ── All hooks MUST be before any conditional returns ──
  const [expandedStages, setExpandedStages] = useState<Set<string>>(new Set());
  const [logsByStage, setLogsByStage] = useState<Record<string, Array<{ ts: string; msg: string; level: string }>>>({});
  const eventSourceRef = useRef<EventSource | null>(null);
  const logEndRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const [exportOpen, setExportOpen] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const exportRef = useRef<HTMLDivElement>(null);

  const toggleStage = useCallback((key: string) => {
    setExpandedStages(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
        // Collapsing iac_scanning also collapses all child tool stages
        if (key === "iac_scanning") {
          for (const k of Array.from(next)) {
            if (k.startsWith("iac_") && k !== "iac_scanning") next.delete(k);
          }
        }
      } else {
        next.add(key);
        // Expanding iac_scanning also expands all child tool stages
        if (key === "iac_scanning") {
          // Discover all iac_* keys from logsByStage and stageDetails
          const sd: Record<string, any> | null = scan?.stage_details ?? null;
          const allKeys = new Set([
            ...Object.keys(logsByStage).filter(k => k.startsWith("iac_") && k !== "iac_scanning"),
            ...(sd ? Object.keys(sd).filter(k => k.startsWith("iac_") && k !== "iac_scanning") : []),
          ]);
          Array.from(allKeys).forEach(k => next.add(k));
        }
      }
      return next;
    });
  }, [logsByStage, scan?.stage_details]);

  // Fetch logs via REST (works for both completed and running scans)
  const fetchLogs = useCallback(async () => {
    if (!scanId || scanId <= 0) return;
    const token = typeof window !== "undefined"
      ? (localStorage.getItem("token") || sessionStorage.getItem("token"))
      : null;
    if (!token) {
      console.warn("[ScanLogs] No auth token in localStorage");
      return;
    }
    try {
      const url = `${API_URL}/api/v1/scans/${scanId}/logs`;
      console.log("[ScanLogs] Fetching logs from", url);
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        console.error("[ScanLogs] REST error", res.status, res.statusText);
        return;
      }
      const data = await res.json();
      const logCount = data?.logs?.length ?? 0;
      console.log("[ScanLogs] Received", logCount, "log entries");
      if (logCount > 0) {
        const grouped: Record<string, Array<{ ts: string; msg: string; level: string }>> = {};
        for (const entry of data.logs) {
          if (!entry.stage || entry.stage === "_system") continue;
          if (!grouped[entry.stage]) grouped[entry.stage] = [];
          grouped[entry.stage].push(entry);
        }
        console.log("[ScanLogs] Grouped into stages:", Object.keys(grouped));
        setLogsByStage(grouped);
      }
    } catch (err) {
      console.error("[ScanLogs] Fetch failed:", err);
    }
  }, [scanId]);

  // Fetch on mount and whenever scan completes
  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  // Synthesize stage logs from stage_details when real logs are empty
  useEffect(() => {
    if (!scan?.stage_details) return;
    // Only synthesize if logsByStage is empty (no real logs from API)
    if (Object.keys(logsByStage).length > 0) return;
    const sd = scan.stage_details as Record<string, any>;
    const synth: Record<string, Array<{ ts: string; msg: string; level: string }>> = {};
    const stageLabels: Record<string, string> = {
      authenticating: "Authenticating",
      cloning: "Cloning repository",
      dependency_analysis: "Dependency analysis",
      secret_scanning: "Secret scanning",
      iac_scanning: "IaC scanning orchestrator",
      iac_cloudformation: "CloudFormation scanner",
      iac_checkov: "Checkov policy-as-code analysis",
      iac_trivy: "Trivy vulnerability scanner",
      iac_semgrep: "Semgrep static analysis",
      iac_bicep: "Bicep template scanner",
      iac_terraform: "Terraform scanner",
      iac_secrets: "Secrets-in-IaC scanner",
      iac_tfsec: "tfsec scanner",
      iac_gitleaks: "Gitleaks scanner",
      iac_helm: "Helm chart scanner",
      vulnerability_correlation: "Vulnerability correlation",
      policy_evaluation: "Policy evaluation",
      compliance_mapping: "Compliance framework mapping",
      processing_results: "Result aggregation",
      generating_report: "Report generation",
      sending_notifications: "Notification dispatch",
      completed: "Scan completed",
      cloud_discovery: "Reading the cloud account",
      cloud_evaluation: "Rule checks",
      cloud_findings: "Findings update",
    };
    for (const [key, detail] of Object.entries(sd)) {
      if (!detail?.start_time) continue;
      const label = stageLabels[key] || key.replace(/_/g, " ");
      const logs: Array<{ ts: string; msg: string; level: string }> = [];
      logs.push({ ts: detail.start_time, msg: `✓ ${label} started`, level: "info" });
      if (detail.duration_ms != null) {
        logs.push({ ts: detail.end_time || detail.start_time, msg: `✓ ${label} completed in ${formatMs(detail.duration_ms)}`, level: "info" });
      } else if (detail.end_time) {
        const ms = new Date(detail.end_time).getTime() - new Date(detail.start_time).getTime();
        logs.push({ ts: detail.end_time, msg: `✓ ${label} completed in ${formatMs(ms)}`, level: "info" });
      }
      if (typeof detail.summary === "string" && detail.summary) {
        logs.push({ ts: detail.end_time || detail.start_time, msg: detail.summary, level: "info" });
      }
      synth[key] = logs;
    }
    if (Object.keys(synth).length > 0) {
      setLogsByStage(synth);
    }
  }, [scan?.stage_details]); // eslint-disable-line react-hooks/exhaustive-deps

  // SSE for live streaming on running/pending scans
  useEffect(() => {
    if (!scanId || scanId <= 0) return;
    if (!scan || !["running", "pending", "queued"].includes(scan.status)) return;
    const token = typeof window !== "undefined" ? (localStorage.getItem("token") || sessionStorage.getItem("token")) : null;
    if (!token) return;

    const url = `${API_URL}/api/v1/scans/${scanId}/logs/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const entry = JSON.parse(event.data);
        if (!entry.stage || entry.stage === "_system") return;
        setLogsByStage(prev => ({
          ...prev,
          [entry.stage]: [...(prev[entry.stage] || []), { ts: entry.ts, msg: entry.msg, level: entry.level }],
        }));
      } catch {}
    };

    es.onerror = () => { es.close(); };

    return () => { es.close(); };
  }, [scanId, scan?.status]);

  // Auto-scroll log panels
  useEffect(() => {
    expandedStages.forEach(stage => {
      const el = logEndRefs.current[stage];
      if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  }, [logsByStage, expandedStages]);

  // Close the export dropdown on outside click.
  // Hooks must stay above the early returns below: a hook that only runs once
  // the scan has loaded changes the hook count between renders and crashes the page.
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  if (isLoading) {
    return (
      <PageLayout title="Scan Details" icon={Shield}>
        <div className="flex items-center justify-center py-20">
          <Loader2 className="animate-spin text-blue-500" size={32} />
        </div>
      </PageLayout>
    );
  }

  if (error || !scan) {
    return (
      <PageLayout title="Scan Details" icon={Shield}>
        <div className="text-center py-20 text-slate-500">Scan not found.</div>
      </PageLayout>
    );
  }

  const stageDetails: Record<string, any> | null = scan.stage_details ?? null;
  const isRunning = scan.status === "running" || scan.status === "pending" || scan.status === "queued";
  const isFailed = scan.status === "failed" || scan.status === "timed_out";

  const handleExport = async (fmt: string) => {
    setExporting(fmt);
    setExportOpen(false);
    try {
      const token = localStorage.getItem("token") || sessionStorage.getItem("token");
      const res = await fetch(`${API_URL}/scans/${scanId}/export?format=${fmt}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Export failed" }));
        alert(err.detail || "Export failed");
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = fmt === "json" ? "json" : fmt;
      a.download = `guardnous_scan_${scanId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      alert("Export failed — network error");
    } finally {
      setExporting(null);
    }
  };

  // Build dynamic stage list (includes per-tool IaC sub-stages)
  const PIPELINE_STAGES = buildPipelineStages(stageDetails, logsByStage, scan.scan_type);
  const cloud = isCloudPosture(scan.scan_type);

  // Find the longest stage for the bar chart
  const maxDuration = stageDetails
    ? Math.max(1, ...Object.values(stageDetails).map((s: any) => s.duration_ms ?? 0))
    : 1;

  return (
    <PageLayout
      title={`Scan #${scan.id}`}
      icon={Shield}
    >
      {/* Back button + Export */}
      <div className="flex items-center justify-between mb-6">
        <button
          onClick={() => router.push("/scans")}
          className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
        >
          <ArrowLeft size={16} />
          Back to Scans
        </button>

        {scan.status === "completed" && (
          <div className="relative" ref={exportRef}>
            <button
              onClick={() => setExportOpen(!exportOpen)}
              disabled={!!exporting}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                bg-gradient-to-r from-orange-500 to-orange-600 text-white shadow-sm
                hover:from-orange-600 hover:to-orange-700 disabled:opacity-60 transition-all"
            >
              {exporting ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
              {exporting ? `Exporting ${exporting.toUpperCase()}…` : "Export Report"}
              <ChevronDown size={14} />
            </button>

            {exportOpen && (
              <div className="absolute right-0 mt-2 w-52 bg-white dark:bg-slate-800 rounded-xl shadow-xl
                border border-slate-200 dark:border-slate-700 py-1 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                <button
                  onClick={() => handleExport("pdf")}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200
                    hover:bg-orange-50 dark:hover:bg-slate-700 transition-colors"
                >
                  <FileText size={16} className="text-red-500" />
                  <div className="text-left">
                    <div className="font-medium">PDF Report</div>
                    <div className="text-xs text-slate-400">Formatted security report</div>
                  </div>
                </button>
                <button
                  onClick={() => handleExport("csv")}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200
                    hover:bg-orange-50 dark:hover:bg-slate-700 transition-colors"
                >
                  <FileSpreadsheet size={16} className="text-green-500" />
                  <div className="text-left">
                    <div className="font-medium">CSV Spreadsheet</div>
                    <div className="text-xs text-slate-400">All findings as rows</div>
                  </div>
                </button>
                <button
                  onClick={() => handleExport("json")}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200
                    hover:bg-orange-50 dark:hover:bg-slate-700 transition-colors"
                >
                  <FileJson size={16} className="text-blue-500" />
                  <div className="text-left">
                    <div className="font-medium">JSON Data</div>
                    <div className="text-xs text-slate-400">Raw structured data</div>
                  </div>
                </button>
                <button
                  onClick={() => handleExport("html")}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200
                    hover:bg-orange-50 dark:hover:bg-slate-700 transition-colors"
                >
                  <Globe size={16} className="text-purple-500" />
                  <div className="text-left">
                    <div className="font-medium">HTML Report</div>
                    <div className="text-xs text-slate-400">Standalone web page</div>
                  </div>
                </button>
              </div>
            )}
          </div>
        )}
      </div>
      {/* Header summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <SummaryCard
          label="Status"
          value={
            <span className={`inline-flex items-center gap-1.5 text-sm font-semibold ${
              scan.status === "completed" ? "text-emerald-600" :
              isFailed ? "text-red-600" :
              "text-blue-600"
            }`}>
              {scan.status === "completed" ? <CheckCircle2 size={16} /> :
               isFailed ? <XCircle size={16} /> :
               <Loader2 size={16} className="animate-spin" />}
              {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
            </span>
          }
        />
        <SummaryCard
          label={cloud ? "Cloud Account" : "Repository"}
          value={
            <div className="flex items-center gap-1.5 text-sm font-medium text-slate-900 dark:text-white truncate">
              {cloud ? <Globe size={14} className="text-slate-400 shrink-0" /> : <FolderGit2 size={14} className="text-slate-400 shrink-0" />}
              {cloud ? (scan.account_name || scan.file_name || "—") : (scan.repository_name || scan.file_name || "—")}
            </div>
          }
        />
        <SummaryCard
          label="Duration"
          value={
            <span className="flex items-center gap-1.5 text-sm font-medium text-slate-700 dark:text-slate-300">
              <Clock size={14} className="text-slate-400" />
              {formatDuration(scan.started_at, scan.completed_at)}
            </span>
          }
        />
        <SummaryCard
          label="Findings"
          value={
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold text-slate-900 dark:text-white">{scan.findings_count}</span>
              <div className="flex gap-1">
                {scan.critical_count > 0 && <SevBadge sev="critical" count={scan.critical_count} />}
                {scan.high_count > 0 && <SevBadge sev="high" count={scan.high_count} />}
                {scan.medium_count > 0 && <SevBadge sev="medium" count={scan.medium_count} />}
                {scan.low_count > 0 && <SevBadge sev="low" count={scan.low_count} />}
              </div>
            </div>
          }
        />
      </div>

      {/* Progress bar for running scans */}
      {isRunning && scan.progress !== null && (
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {(scan.stage ?? "processing").replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}
            </span>
            <span className="text-sm font-bold text-blue-600">{scan.progress}%</span>
          </div>
          <div className="w-full h-3 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Pipeline stages visualization */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden mb-8">
        <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800">
          <h2 className="text-base font-semibold text-slate-900 dark:text-white">Pipeline Stages</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {PIPELINE_STAGES.filter(s => s.key !== "completed").length + 1} stages · {cloud ? "cloud posture assessment" : `${scan.scan_type} scan`}
          </p>
        </div>

        <div className="divide-y divide-slate-50 dark:divide-slate-800/50">
          {PIPELINE_STAGES.map((stage, idx) => {
            const status = getStageStatus(stage.key, stageDetails, scan.stage, scan.status);
            const detail = stageDetails?.[stage.key];
            const duration = detail?.duration_ms;
            const Icon = stage.icon;
            const isExpanded = expandedStages.has(stage.key);
            const stageLogs = logsByStage[stage.key] || [];
            const hasLogs = stageLogs.length > 0;

            const isTool = !!(stage as any).isToolStage;

            // Hide tool sub-stages when parent iac_scanning is collapsed
            if (isTool && !expandedStages.has("iac_scanning")) return null;

            return (
              <div key={stage.key}>
                <div
                  onClick={() => toggleStage(stage.key)}
                  className={`flex items-center gap-4 py-3 transition-colors cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/30 ${
                    isTool ? "pl-16 pr-6 border-l-2 border-blue-200 dark:border-blue-800 ml-6 bg-slate-50/50 dark:bg-slate-800/20" : "px-6"
                  } ${
                    status === "running" ? "bg-blue-50/50 dark:bg-blue-900/10" :
                    status === "failed" ? "bg-red-50/50 dark:bg-red-900/10" :
                    ""
                  }`}
                >
                  {/* Expand arrow */}
                  <div className="w-4 shrink-0 text-slate-400">
                    {hasLogs || status !== "pending" ? (
                      isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />
                    ) : null}
                  </div>

                  {/* Step number / tool indicator */}
                  <div className="flex flex-col items-center w-8 shrink-0">
                    <div className={`${isTool ? "w-6 h-6" : "w-7 h-7"} rounded-full flex items-center justify-center text-xs font-bold ${
                      status === "completed" ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400" :
                      status === "running" ? "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400 ring-2 ring-blue-400/30" :
                      status === "failed" ? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400" :
                      "bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-600"
                    }`}>
                      {status === "completed" ? (
                        <CheckCircle2 size={isTool ? 12 : 14} />
                      ) : status === "running" ? (
                        <Loader2 size={isTool ? 12 : 14} className="animate-spin" />
                      ) : status === "failed" ? (
                        <XCircle size={isTool ? 12 : 14} />
                      ) : isTool ? (
                        <FileSearch size={10} />
                      ) : (
                        idx + 1
                      )}
                    </div>
                  </div>

                  {/* Icon */}
                  <div className={`shrink-0 ${
                    status === "completed" ? "text-emerald-500" :
                    status === "running" ? "text-blue-500" :
                    status === "failed" ? "text-red-500" :
                    "text-slate-300 dark:text-slate-600"
                  }`}>
                    <Icon size={18} />
                  </div>

                  {/* Label + description */}
                  <div className="flex-1 min-w-0">
                    <div className={`text-sm font-medium ${
                      status === "completed" ? "text-slate-900 dark:text-white" :
                      status === "running" ? "text-blue-700 dark:text-blue-400" :
                      status === "failed" ? "text-red-700 dark:text-red-400" :
                      "text-slate-400 dark:text-slate-600"
                    }`}>
                      {stage.label}
                      {hasLogs && (
                        <span className="ml-2 text-[10px] font-normal text-slate-400">
                          <Terminal size={10} className="inline mr-0.5" />{stageLogs.length} logs
                        </span>
                      )}
                    </div>
                    <div className={`text-xs ${
                      status === "pending" || status === "skipped" ? "text-slate-300 dark:text-slate-700" : "text-slate-400"
                    }`}>
                      {stage.description}
                    </div>
                    {typeof detail?.summary === "string" && detail.summary && (
                      <div className="mt-0.5 text-xs text-slate-700 dark:text-slate-300">{detail.summary}</div>
                    )}
                  </div>

                  {/* Duration bar */}
                  <div className="w-32 shrink-0 hidden sm:block">
                    {duration != null && (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              status === "failed" ? "bg-red-400" : "bg-emerald-400"
                            }`}
                            style={{ width: `${Math.max(5, (duration / maxDuration) * 100)}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Duration text */}
                  <div className="w-16 text-right shrink-0">
                    {duration != null ? (
                      <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                        {formatMs(duration)}
                      </span>
                    ) : status === "running" ? (
                      <span className="text-xs text-blue-500 animate-pulse">running…</span>
                    ) : null}
                  </div>
                </div>

                {/* Collapsible terminal log panel — indented to align under stage title */}
                {isExpanded && (
                  <div className={`pb-2 ${isTool ? "ml-6 border-l-2 border-blue-200 dark:border-blue-800" : ""}`}>
                    <div className={`bg-[#0d1117] rounded-lg border border-slate-800 mr-6 ${
                      isTool ? "ml-[124px]" : "ml-[138px]"
                    }`}>
                    <div className="max-h-64 overflow-y-auto font-mono text-xs leading-5 py-3 px-4 scrollbar-thin">
                      {stageLogs.length === 0 ? (
                        <div className="text-slate-500 italic">
                          {status === "running" ? "Waiting for logs…" :
                           status === "pending" ? "Stage not started yet" :
                           "No logs recorded for this stage"}
                        </div>
                      ) : (
                        stageLogs.map((log, i) => (
                          <div key={i} className="flex gap-2">
                            <span className="text-slate-600 select-none shrink-0">
                              {log.ts ? new Date(log.ts).toLocaleTimeString() : ""}
                            </span>
                            <span className={
                              log.level === "error" ? "text-red-400" :
                              log.level === "warn" ? "text-amber-400" :
                              log.msg.startsWith("✓") ? "text-emerald-400" :
                              log.msg.startsWith("⚠") ? "text-amber-400" :
                              log.msg.startsWith("✗") ? "text-red-400" :
                              "text-slate-300"
                            }>
                              {log.msg}
                            </span>
                          </div>
                        ))
                      )}
                      <div ref={el => { logEndRefs.current[stage.key] = el; }} />
                    </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Scan metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <MetaCard title="Scan Info">
          <MetaRow label="Scan Type" value={cloud ? "Cloud posture" : scan.scan_type} />
          {cloud ? (
            <>
              <MetaRow label="Resources Checked" value={String(stageDetails?.resources ?? scan.files_scanned ?? 0)} />
              <MetaRow label="Checks Run" value={String(stageDetails?.checks ?? 0)} />
              <MetaRow label="Passed / Failed" value={`${stageDetails?.passed ?? 0} passed / ${stageDetails?.failed ?? 0} failed`} />
              <MetaRow label="Could Not Be Checked" value={String(stageDetails?.not_checked ?? 0)} />
            </>
          ) : (
            <>
              <MetaRow label="Files Scanned" value={`${scan.files_scanned ?? 0} / ${scan.files_total ?? 0}`} />
              <MetaRow label="Secrets Found" value={String(scan.secrets_found ?? 0)} />
              <MetaRow label="Dependencies" value={String(scan.dependencies_analyzed ?? 0)} />
              <MetaRow label="Policies Evaluated" value={`${scan.policies_passed ?? 0} passed / ${scan.policies_failed ?? 0} failed`} />
            </>
          )}
        </MetaCard>

        <MetaCard title="Timing">
          <MetaRow label="Created" value={scan.created_at ? new Date(scan.created_at).toLocaleString() : "—"} />
          <MetaRow label="Started" value={scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"} />
          <MetaRow label="Completed" value={scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"} />
          <MetaRow label="Total Duration" value={formatDuration(scan.started_at, scan.completed_at)} />
          <MetaRow
            label="Longest Stage"
            value={
              stageDetails
                ? (() => {
                    const sorted = Object.entries(stageDetails)
                      .filter(([, v]: [string, any]) => v.duration_ms != null)
                      .sort(([, a]: [string, any], [, b]: [string, any]) => b.duration_ms - a.duration_ms);
                    if (sorted.length === 0) return "—";
                    const [name, info] = sorted[0] as [string, any];
                    return `${name.replace(/_/g, " ")} (${formatMs(info.duration_ms)})`;
                  })()
                : "—"
            }
          />
        </MetaCard>
      </div>

      {/* Software bill of materials (repository assessments with a stored dependency inventory) */}
      {!cloud && !isRunning && scan.repository_name && <SbomCard scanId={scan.id} />}

      {/* Error message */}
      {scan.error_message && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-4 mb-8">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle size={16} className="text-red-600" />
            <span className="text-sm font-semibold text-red-700 dark:text-red-400">Error</span>
          </div>
          <p className="text-sm text-red-600 dark:text-red-300 font-mono">{scan.error_message}</p>
        </div>
      )}

      {/* Risk score */}
      {scan.risk_score != null && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <h2 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Risk Score</h2>
          <div className="flex items-center gap-6">
            <div className={`text-5xl font-bold ${
              scan.risk_score >= 80 ? "text-red-600" :
              scan.risk_score >= 50 ? "text-amber-500" :
              "text-emerald-600"
            }`}>
              {scan.risk_score}
            </div>
            <div className="flex-1">
              <div className="h-4 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    scan.risk_score >= 80 ? "bg-gradient-to-r from-red-400 to-red-600" :
                    scan.risk_score >= 50 ? "bg-gradient-to-r from-amber-400 to-orange-500" :
                    "bg-gradient-to-r from-emerald-400 to-emerald-600"
                  }`}
                  style={{ width: `${scan.risk_score}%` }}
                />
              </div>
              <div className="flex justify-between mt-1 text-xs text-slate-400">
                <span>Low risk</span>
                <span>High risk</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}

/* ── Helper components ── */

function SummaryCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
      <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">{label}</div>
      {value}
    </div>
  );
}

function SevBadge({ sev, count }: { sev: string; count: number }) {
  const colors: Record<string, string> = {
    critical: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    high: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
    medium: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    low: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold ${colors[sev] ?? ""}`}>
      {count} {sev.charAt(0).toUpperCase()}
    </span>
  );
}

function MetaCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">{title}</h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-400">{label}</span>
      <span className="text-sm text-slate-700 dark:text-slate-300">{value}</span>
    </div>
  );
}
