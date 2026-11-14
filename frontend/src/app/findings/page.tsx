"use client";

import React, { useState, useCallback, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import api, { startAgentRun } from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Search,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronLeft,
  ChevronRight,
  Shield,
  Loader2,
  CheckCircle2,
  EyeOff,
  ExternalLink,
  Cloud,
  Clock,
  MapPin,
  Tag,
  FileCode,
  Code,
  Wrench,
  Sparkles,
} from "lucide-react";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Status = "open" | "triaged" | "in_progress" | "resolved" | "false_positive" | "suppressed";

interface Finding {
  id: number;
  title: string;
  description: string;
  severity: Severity;
  status: Status;
  resource_type: string;
  resource_name: string;
  cloud_provider: string;
  region: string;
  rule_id: string;
  recommendation: string;
  remediation: string;
  scan_id: number;
  file_path: string | null;
  line_number: number | null;
  code_snippet: string | null;
  category: string | null;
  cve_id: string | null;
  is_fixed: boolean;
  is_ignored: boolean;
  created_at: string;
  updated_at: string;
  repository_url: string | null;
  sla_deadline?: string | null;
  first_seen_at?: string | null;
  sla_status?: SlaStatus;
  sla_days_remaining?: number | null;
}

type SlaStatus = "none" | "on_track" | "due_soon" | "overdue" | "met" | "missed";

interface SlaSummary {
  open: { overdue: number; due_soon: number; on_track: number; none: number; total: number; with_sla: number };
  oldest_overdue: { id: number; title: string; severity: string; days_overdue: number } | null;
  resolved: { days: number; met: number; missed: number; total: number; met_percent: number | null };
  has_sla: boolean;
}

const SLA_STYLE: Record<Exclude<SlaStatus, "none">, string> = {
  overdue: "border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300",
  due_soon: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300",
  on_track: "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300",
  met: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300",
  missed: "border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300",
};

/** Short text for the SLA indicator; null when the finding has no SLA. */
function slaLabel(f: Pick<Finding, "sla_status" | "sla_days_remaining">): string | null {
  const days = f.sla_days_remaining ?? 0;
  switch (f.sla_status) {
    case "overdue": return days === 0 ? "Overdue" : `Overdue ${-days} d`;
    case "due_soon": return days === 0 ? "Due today" : `Due in ${days} d`;
    case "on_track": return `${days} d left`;
    case "met": return "SLA met";
    case "missed": return "SLA missed";
    default: return null;
  }
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

interface FindingsResponse {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

const SEVERITY_META: Record<
  Severity,
  {
    label: string;
    icon: React.ElementType;
    badge: string;
    cardBg: string;
    cardBorder: string;
    cardText: string;
    cardIcon: string;
  }
> = {
  CRITICAL: {
    label: "Critical",
    icon: ShieldAlert,
    badge: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    cardBg: "bg-red-50 dark:bg-red-900/20",
    cardBorder: "border-red-200 dark:border-red-800",
    cardText: "text-red-500",
    cardIcon: "text-red-500",
  },
  HIGH: {
    label: "High",
    icon: AlertTriangle,
    badge: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
    cardBg: "bg-orange-50 dark:bg-orange-900/20",
    cardBorder: "border-orange-200 dark:border-orange-800",
    cardText: "text-orange-500",
    cardIcon: "text-orange-500",
  },
  MEDIUM: {
    label: "Medium",
    icon: AlertCircle,
    badge: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
    cardBg: "bg-yellow-50 dark:bg-yellow-900/20",
    cardBorder: "border-yellow-200 dark:border-yellow-800",
    cardText: "text-yellow-500",
    cardIcon: "text-yellow-500",
  },
  LOW: {
    label: "Low",
    icon: Info,
    badge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    cardBg: "bg-blue-50 dark:bg-blue-900/20",
    cardBorder: "border-blue-200 dark:border-blue-800",
    cardText: "text-blue-500",
    cardIcon: "text-blue-500",
  },
};

const STATUS_META: Record<Status, { label: string; dot: string; text: string }> = {
  open: { label: "Open", dot: "bg-red-500", text: "text-red-700 dark:text-red-400" },
  triaged: { label: "Triaged", dot: "bg-blue-500", text: "text-blue-700 dark:text-blue-400" },
  in_progress: { label: "In Progress", dot: "bg-yellow-500", text: "text-yellow-700 dark:text-yellow-400" },
  resolved: { label: "Resolved", dot: "bg-emerald-500", text: "text-emerald-700 dark:text-emerald-400" },
  false_positive: { label: "False Positive", dot: "bg-violet-400", text: "text-violet-600 dark:text-violet-400" },
  suppressed: { label: "Suppressed", dot: "bg-slate-400", text: "text-slate-500 dark:text-slate-400" },
};

const PAGE_SIZE = 15;

function relativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  const diffMo = Math.floor(diffDay / 30);
  if (diffMo < 12) return `${diffMo}mo ago`;
  return `${Math.floor(diffMo / 12)}y ago`;
}

function cloudIcon(provider: string): string {
  switch (provider?.toLowerCase()) {
    case "aws": return "🟠";
    case "azure": return "🔵";
    case "gcp": return "🔴";
    default: return "☁️";
  }
}

export default function FindingsPage() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "");
  const [status, setStatus] = useState("");
  const [sla, setSla] = useState("");
  const [cloudProvider, setCloudProvider] = useState("");
  const [category, setCategory] = useState(searchParams.get("category") || "");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [actionLoading, setActionLoading] = useState<Record<number, string>>({});

  // Sync URL params on navigation
  useEffect(() => {
    const urlSev = searchParams.get("severity") || "";
    const urlCat = searchParams.get("category") || "";
    if (urlSev && urlSev !== severity) setSeverity(urlSev);
    if (urlCat && urlCat !== category) setCategory(urlCat);
  }, [searchParams]);

  const buildParams = useCallback(() => {
    const params: Record<string, string | number> = { page, page_size: PAGE_SIZE };
    if (search) params.search = search;
    if (severity) params.severity = severity;
    if (status) params.status = status;
    if (sla) params.sla = sla;
    if (cloudProvider) params.cloud_provider = cloudProvider;
    if (category) params.category = category;
    return params;
  }, [page, search, severity, status, sla, cloudProvider, category]);

  const { data, isLoading } = useQuery<FindingsResponse>({
    queryKey: ["findings", page, search, severity, status, sla, cloudProvider, category],
    queryFn: async () => {
      const res = await api.get("/findings", { params: buildParams() });
      return res.data;
    },
  });

  const findings = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const updateFinding = async (id: number, action: string, body: Record<string, unknown>) => {
    setActionLoading((prev) => ({ ...prev, [id]: action }));
    try {
      // The triage endpoint also applies the decision to the same finding in other scans
      // of the repository and keeps it on the next scan.
      await api.post(`/findings/${id}/triage`, body);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["findings-summary"] });
    } finally {
      setActionLoading((prev) => { const n = { ...prev }; delete n[id]; return n; });
    }
  };

  const handleResolve = (id: number) => updateFinding(id, "resolve", { status: "resolved" });
  const handleSuppress = (id: number) =>
    updateFinding(id, "suppress", { status: "false_positive", reason: "Marked as a false positive from the findings list" });
  const handleTriaged = (id: number) => updateFinding(id, "triage", { status: "triaged" });
  const handleReopen = (id: number) => updateFinding(id, "reopen", { status: "open" });

  const [triageRun, setTriageRun] = useState<{ id?: number; error?: string; busy?: boolean }>({});
  const startTriage = async () => {
    setTriageRun({ busy: true });
    try {
      const run = await startAgentRun({
        agent_id: "triage_agent",
        goal:
          "Triage the open findings in the queue, most severe first. Read the evidence for each, " +
          "then propose your decisions as one list for me to review.",
      });
      setTriageRun({ id: run.id });
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setTriageRun({ error: detail || "The triage run could not be started." });
    }
  };

  const { data: summaryData } = useQuery<{ total: number; by_severity: Record<Severity, number> }>({
    queryKey: ["findings-summary"],
    queryFn: async () => {
      const res = await api.get("/findings/summary");
      return res.data;
    },
  });

  // Prefix "findings" so a triage decision refreshes it together with the list
  const { data: slaSummary } = useQuery<SlaSummary>({
    queryKey: ["findings", "sla-summary"],
    queryFn: async () => {
      const res = await api.get("/findings/sla/summary");
      return res.data;
    },
  });

  const severityCounts: Record<Severity, number> = summaryData?.by_severity ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  const handleSeverityClick = (sev: Severity) => {
    setSeverity((prev) => (prev === sev ? "" : sev));
    setPage(1);
  };

  return (
    <PageLayout
      title="Findings"
      subtitle="Security findings across your infrastructure"
      icon={ShieldAlert}
      actions={
        <button
          onClick={startTriage}
          disabled={triageRun.busy}
          title="The Triage Agent reads the open findings and proposes a list of decisions. Nothing changes until you approve the list."
          className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold bg-orange-600 hover:bg-orange-700 text-white disabled:opacity-50 transition-colors"
        >
          {triageRun.busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          Triage with AI
        </button>
      }
    >
      {(triageRun.id || triageRun.error) && (
        <div
          className={`mb-6 rounded-2xl border px-5 py-4 text-sm ${
            triageRun.error
              ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200"
              : "border-orange-200 bg-orange-50 text-orange-900 dark:border-orange-900 dark:bg-orange-950/40 dark:text-orange-100"
          }`}
        >
          {triageRun.error ?? (
            <>
              Triage run #{triageRun.id} has started. It will propose a list of decisions and wait for your approval;
              nothing changes before that.{" "}
              <a href="/agent-runs" className="font-semibold underline">Open Agent Runs</a>
            </>
          )}
        </div>
      )}
      {/* ── Stats Row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
          const meta = SEVERITY_META[sev];
          const Icon = meta.icon;
          const isActive = severity === sev;
          return (
            <button
              key={sev}
              onClick={() => handleSeverityClick(sev)}
              className={`${meta.cardBg} rounded-2xl border ${meta.cardBorder} p-6 text-left transition-all hover:shadow-md ${
                isActive ? "ring-2 ring-orange-500 shadow-md" : ""
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-2xl font-bold ${meta.cardText}`}>
                    {severityCounts[sev]}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                    {meta.label}
                  </p>
                </div>
                <Icon className={`w-8 h-8 ${meta.cardIcon} opacity-60`} />
              </div>
            </button>
          );
        })}
      </div>

      {/* ── SLA strip: only when at least one finding has an SLA ── */}
      {slaSummary?.has_sla && (
        <div className="mb-6 flex flex-wrap items-center gap-x-8 gap-y-2 rounded-2xl border border-slate-200 bg-white px-6 py-3 text-sm dark:border-slate-800 dark:bg-slate-900">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">SLA</span>
          <button
            type="button"
            onClick={() => { setSla(sla === "overdue" ? "" : "overdue"); setPage(1); }}
            className="text-slate-600 hover:underline dark:text-slate-300"
          >
            <span className={`font-semibold ${slaSummary.open.overdue > 0 ? "text-red-600 dark:text-red-400" : "text-slate-900 dark:text-white"}`}>
              {slaSummary.open.overdue}
            </span>{" "}
            overdue
          </button>
          <button
            type="button"
            onClick={() => { setSla(sla === "due_soon" ? "" : "due_soon"); setPage(1); }}
            className="text-slate-600 hover:underline dark:text-slate-300"
          >
            <span className={`font-semibold ${slaSummary.open.due_soon > 0 ? "text-amber-600 dark:text-amber-400" : "text-slate-900 dark:text-white"}`}>
              {slaSummary.open.due_soon}
            </span>{" "}
            due soon
          </button>
          <span className="text-slate-600 dark:text-slate-300">
            <span className="font-semibold text-slate-900 dark:text-white">
              {slaSummary.resolved.met_percent == null ? "—" : `${Math.round(slaSummary.resolved.met_percent)}%`}
            </span>{" "}
            met in the last {slaSummary.resolved.days} days
            {slaSummary.resolved.total > 0 && (
              <span className="text-slate-400 dark:text-slate-500"> ({slaSummary.resolved.met} of {slaSummary.resolved.total} resolved)</span>
            )}
          </span>
          {slaSummary.oldest_overdue && (
            <span className="text-slate-500 dark:text-slate-400">
              Oldest overdue: {slaSummary.oldest_overdue.days_overdue} d
            </span>
          )}
        </div>
      )}

      {/* ── Filters Bar ── */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 mb-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="w-full pl-11 pr-4 h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
            />
          </div>

          <select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={status}
            onChange={(e) => { setStatus(e.target.value); setPage(1); }}
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="triaged">Triaged</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>

          <select
            value={sla}
            onChange={(e) => { setSla(e.target.value); setPage(1); }}
            aria-label="SLA"
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
          >
            <option value="">SLA: All</option>
            <option value="overdue">SLA: Overdue</option>
            <option value="due_soon">SLA: Due soon</option>
            <option value="on_track">SLA: On track</option>
          </select>

          <select
            value={cloudProvider}
            onChange={(e) => { setCloudProvider(e.target.value); setPage(1); }}
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
          >
            <option value="">All Providers</option>
            <option value="aws">AWS</option>
            <option value="azure">Azure</option>
            <option value="gcp">GCP</option>
          </select>
        </div>
      </div>

      {/* ── Main Content ── */}
      {isLoading ? (
        <div className="flex items-center justify-center py-24">
          <Loader2 className="w-8 h-8 animate-spin text-orange-500" />
        </div>
      ) : findings.length === 0 ? (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
          <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-slate-400" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
            No findings yet
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Run a scan to discover security issues
          </p>
        </div>
      ) : (
        <>
          {/* ── Findings Table ── */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden overflow-y-auto" style={{ maxHeight: "70vh" }}>
              <table className="w-full table-fixed">
                <colgroup>
                  <col style={{ width: "100px" }} />
                  <col />
                  <col style={{ width: "240px" }} />
                  <col style={{ width: "100px" }} />
                  <col style={{ width: "120px" }} />
                  <col style={{ width: "90px" }} />
                </colgroup>
                <thead className="hidden lg:table-header-group sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                  <tr className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                    <th className="px-4 py-3 text-left border-r border-slate-200 dark:border-slate-700" style={{ resize: "horizontal", overflow: "hidden", minWidth: 80 }}>Severity</th>
                    <th className="px-4 py-3 text-left border-r border-slate-200 dark:border-slate-700" style={{ resize: "horizontal", overflow: "hidden", minWidth: 120 }}>Title</th>
                    <th className="px-4 py-3 text-left border-r border-slate-200 dark:border-slate-700" style={{ resize: "horizontal", overflow: "hidden", minWidth: 120 }}>Location</th>
                    <th className="px-4 py-3 text-left border-r border-slate-200 dark:border-slate-700" style={{ resize: "horizontal", overflow: "hidden", minWidth: 80 }}>Cloud</th>
                    <th className="px-4 py-3 text-left border-r border-slate-200 dark:border-slate-700" style={{ resize: "horizontal", overflow: "hidden", minWidth: 80 }}>Status</th>
                    <th className="px-4 py-3 text-left">Found</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {findings.map((f, idx) => {
                const sevMeta = SEVERITY_META[f.severity] ?? SEVERITY_META.LOW;
                const statusMeta = STATUS_META[f.status] ?? STATUS_META.open;
                const isExpanded = expandedId === f.id;
                const slaText = slaLabel(f);
                const fileLink = f.repository_url && f.file_path
                  ? `${f.repository_url}/blob/main/${f.file_path}${f.line_number ? `#L${f.line_number}` : ""}`
                  : null;
                const locationLabel = f.resource_name || f.file_path || "—";

                return (
                  <React.Fragment key={f.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : f.id)}
                      className={`cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/60 ${
                        idx % 2 === 1 ? "bg-slate-50/40 dark:bg-slate-800/20" : ""
                      } ${isExpanded ? "bg-orange-50/30 dark:bg-orange-900/10" : ""}`}
                    >
                      {/* Severity badge */}
                      <td className="px-4 py-3.5">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${sevMeta.badge}`}>
                          <sevMeta.icon className="w-3 h-3" />
                          {sevMeta.label}
                        </span>
                      </td>

                      {/* Title */}
                      <td className="px-4 py-3.5">
                        <p className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate" title={f.title}>
                          {f.title}
                        </p>
                      </td>

                      {/* Location (was Resource — now shows file path with link) */}
                      <td className="px-4 py-3.5">
                        {fileLink ? (
                          <a
                            href={fileLink}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="group flex items-center gap-1 text-sm text-orange-600 dark:text-orange-400 hover:underline truncate font-mono"
                            title={`${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`}
                          >
                            <FileCode className="w-3.5 h-3.5 shrink-0" />
                            <span className="truncate">{f.file_path}{f.line_number ? `:${f.line_number}` : ""}</span>
                            <ExternalLink className="w-3 h-3 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </a>
                        ) : (
                          <p className="text-sm text-slate-600 dark:text-slate-300 truncate font-mono" title={locationLabel}>
                            {locationLabel}
                          </p>
                        )}
                      </td>

                      {/* Cloud */}
                      <td className="px-4 py-3.5">
                        <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          <span className="text-[10px]">{cloudIcon(f.cloud_provider)}</span>
                          {f.cloud_provider?.toUpperCase() ?? "—"}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${statusMeta.dot}`} />
                          <span className={`text-xs font-medium ${statusMeta.text}`}>
                            {statusMeta.label}
                          </span>
                        </div>
                        {slaText && f.sla_status && f.sla_status !== "none" && (
                          <span
                            title={`SLA deadline ${formatDate(f.sla_deadline)}`}
                            className={`mt-1.5 inline-block whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${SLA_STYLE[f.sla_status]}`}
                          >
                            {slaText}
                          </span>
                        )}
                      </td>

                      {/* Found */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                          <Clock className="w-3.5 h-3.5" />
                          {relativeTime(f.created_at)}
                        </div>
                      </td>
                    </tr>

                    {/* ── Expanded Detail ── */}
                    {isExpanded && (
                      <tr>
                      <td colSpan={6} className="p-0">
                      <div className="px-6 pb-6 pt-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                        <div className="grid md:grid-cols-2 gap-6 mb-6">
                          {/* Left — Description + Code Snippet */}
                          <div className="space-y-4">
                            <div>
                              <h4 className="text-sm font-semibold text-slate-900 dark:text-white mb-2">
                                Description
                              </h4>
                              <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">
                                {f.description || "No description available."}
                              </p>
                            </div>

                            {/* First seen and SLA deadline */}
                            <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
                              <div>
                                <dt className="text-xs text-slate-500 dark:text-slate-400">First seen</dt>
                                <dd className="font-medium text-slate-900 dark:text-slate-100">{formatDate(f.first_seen_at ?? f.created_at)}</dd>
                              </div>
                              <div>
                                <dt className="text-xs text-slate-500 dark:text-slate-400">SLA deadline</dt>
                                <dd className="font-medium text-slate-900 dark:text-slate-100">
                                  {f.sla_deadline ? formatDate(f.sla_deadline) : "No SLA"}
                                  {slaText && <span className="ml-2 font-normal text-slate-500 dark:text-slate-400">{slaText}</span>}
                                </dd>
                              </div>
                            </dl>

                            {/* File location */}
                            {f.file_path && (
                              <div className="rounded-xl bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-4">
                                <h4 className="text-sm font-semibold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
                                  <FileCode className="w-4 h-4 text-orange-500" />
                                  Location
                                </h4>
                                {fileLink ? (
                                  <a
                                    href={fileLink}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center gap-2 text-sm font-mono text-orange-600 dark:text-orange-400 hover:underline"
                                  >
                                    {f.file_path}
                                    {f.line_number != null && (
                                      <span className="font-semibold">:{f.line_number}</span>
                                    )}
                                    <ExternalLink className="w-3.5 h-3.5" />
                                  </a>
                                ) : (
                                  <p className="text-sm font-mono text-slate-700 dark:text-slate-300">
                                    {f.file_path}
                                    {f.line_number != null && (
                                      <span className="text-orange-600 dark:text-orange-400 font-semibold">:{f.line_number}</span>
                                    )}
                                  </p>
                                )}
                              </div>
                            )}

                            {/* Code snippet */}
                            {f.code_snippet && (
                              <div className="rounded-xl bg-slate-900 dark:bg-slate-950 border border-slate-700 overflow-hidden">
                                <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 border-b border-slate-700">
                                  <Code className="w-3.5 h-3.5 text-slate-400" />
                                  <span className="text-xs text-slate-400 font-medium">Vulnerable Code</span>
                                  {f.line_number != null && (
                                    <span className="ml-auto text-xs text-slate-500">Line {f.line_number}</span>
                                  )}
                                </div>
                                <pre className="p-4 text-sm text-slate-200 overflow-x-auto leading-relaxed">
                                  <code>{f.code_snippet}</code>
                                </pre>
                              </div>
                            )}

                            {/* Recommendation info box */}
                            {(f.recommendation || f.remediation) && (
                              <div className="rounded-xl bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4">
                                <h4 className="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-1.5 flex items-center gap-2">
                                  <Wrench className="w-4 h-4" />
                                  Remediation
                                </h4>
                                <p className="text-sm text-blue-700 dark:text-blue-400 leading-relaxed">
                                  {f.remediation || f.recommendation}
                                </p>
                              </div>
                            )}
                          </div>

                          {/* Right — Metadata */}
                          <div className="space-y-3">
                            <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 p-4 space-y-3">
                              <div className="flex items-center justify-between text-sm">
                                <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                  <Tag className="w-4 h-4" /> Rule ID
                                </span>
                                <span className="font-mono text-xs text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded-lg">
                                  {f.rule_id}
                                </span>
                              </div>
                              {f.category && (
                                <div className="flex items-center justify-between text-sm">
                                  <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                    <Shield className="w-4 h-4" /> Category
                                  </span>
                                  <span className="text-slate-900 dark:text-slate-200">{f.category}</span>
                                </div>
                              )}
                              {f.cve_id && (
                                <div className="flex items-center justify-between text-sm">
                                  <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                    <ShieldAlert className="w-4 h-4" /> CVE
                                  </span>
                                  <a
                                    href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-mono text-xs text-orange-600 dark:text-orange-400 hover:underline"
                                  >
                                    {f.cve_id}
                                  </a>
                                </div>
                              )}
                              <div className="flex items-center justify-between text-sm">
                                <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                  <MapPin className="w-4 h-4" /> Region
                                </span>
                                <span className="text-slate-900 dark:text-slate-200">
                                  {f.region || "—"}
                                </span>
                              </div>
                              <div className="flex items-center justify-between text-sm">
                                <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                  <Cloud className="w-4 h-4" /> Provider
                                </span>
                                <span className="text-slate-900 dark:text-slate-200">
                                  {f.cloud_provider?.toUpperCase() ?? "—"}
                                </span>
                              </div>
                              <div className="flex items-center justify-between text-sm">
                                <span className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                                  <Clock className="w-4 h-4" /> Updated
                                </span>
                                <span className="text-slate-900 dark:text-slate-200">
                                  {new Date(f.updated_at).toLocaleString()}
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Action buttons */}
                        <div className="flex flex-wrap gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
                          {f.status !== "resolved" && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleResolve(f.id); }}
                              disabled={!!actionLoading[f.id]}
                              className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-50 transition-colors"
                            >
                              {actionLoading[f.id] === "resolve" ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                              Mark Resolved
                            </button>
                          )}
                          {(f.status ?? "open") === "open" && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleTriaged(f.id); }}
                              disabled={!!actionLoading[f.id]}
                              title="It is real and needs fixing"
                              className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 transition-colors"
                            >
                              {actionLoading[f.id] === "triage" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Tag className="w-4 h-4" />}
                              Mark Triaged
                            </button>
                          )}
                          {!f.is_ignored && f.status !== "false_positive" && f.status !== "resolved" && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleSuppress(f.id); }}
                              disabled={!!actionLoading[f.id]}
                              title="The scanner is wrong about this one. Kept on future scans."
                              className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 transition-colors"
                            >
                              {actionLoading[f.id] === "suppress" ? <Loader2 className="w-4 h-4 animate-spin" /> : <EyeOff className="w-4 h-4" />}
                              False Positive
                            </button>
                          )}
                          {(f.status === "false_positive" || f.status === "resolved" || f.status === "triaged") && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleReopen(f.id); }}
                              disabled={!!actionLoading[f.id]}
                              className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 transition-colors"
                            >
                              {actionLoading[f.id] === "reopen" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Clock className="w-4 h-4" />}
                              Reopen
                            </button>
                          )}
                          <a
                            href={`/findings?scan_id=${f.scan_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm font-semibold border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                          >
                            <ExternalLink className="w-4 h-4" />
                            View All from Scan
                          </a>
                        </div>
                      </div>
                    </td>
                    </tr>
                    )}
                  </React.Fragment>
                );
              })}
                </tbody>
              </table>
          </div>

          {/* ── Pagination ── */}
          <div className="flex items-center justify-between mt-6">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Showing{" "}
              <span className="font-medium text-slate-900 dark:text-slate-200">
                {(page - 1) * PAGE_SIZE + 1}
              </span>
              –
              <span className="font-medium text-slate-900 dark:text-slate-200">
                {Math.min(page * PAGE_SIZE, total)}
              </span>{" "}
              of{" "}
              <span className="font-medium text-slate-900 dark:text-slate-200">
                {total}
              </span>
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="inline-flex items-center gap-1.5 h-10 px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="inline-flex items-center gap-1.5 h-10 px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </PageLayout>
  );
}
