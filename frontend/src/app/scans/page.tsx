"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { getScans } from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import Link from "next/link";
import {
  ScanLine,
  Search,
  CheckCircle2,
  XCircle,
  Loader2,
  ChevronLeft,
  ChevronRight,
  FileCode2,
  FolderGit2,
} from "lucide-react";

interface ScanResponse {
  id: number;
  organization_id: number;
  scan_type: string;
  status: string;
  file_name: string | null;
  cloud_provider: string | null;
  risk_score: number | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  stage: string | null;
  progress: number | null;
  repository_url: string | null;
  repository_name: string | null;
  account_name: string | null;
  error_message: string | null;
  files_scanned: number | null;
  files_total: number | null;
}

interface ScansResponse {
  items: ScanResponse[];
  total: number;
  page: number;
  page_size: number;
}

const PAGE_SIZE = 20;

const STATUS_OPTIONS = ["All", "Completed", "Running", "Failed", "Pending"];
const TYPE_OPTIONS = ["All", "Terraform", "CloudFormation", "Bicep", "Repository", "Full"];

const STATUS_CONFIG: Record<string, { bg: string; text: string; dot: string }> = {
  completed: {
    bg: "bg-emerald-50 dark:bg-emerald-900/30",
    text: "text-emerald-700 dark:text-emerald-400",
    dot: "bg-emerald-500",
  },
  running: {
    bg: "bg-blue-50 dark:bg-blue-900/30",
    text: "text-blue-700 dark:text-blue-400",
    dot: "bg-blue-500",
  },
  failed: {
    bg: "bg-red-50 dark:bg-red-900/30",
    text: "text-red-700 dark:text-red-400",
    dot: "bg-red-500",
  },
  pending: {
    bg: "bg-amber-50 dark:bg-amber-900/30",
    text: "text-amber-700 dark:text-amber-400",
    dot: "bg-amber-500",
  },
};

function relativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

function formatDuration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt) return "—";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const secs = Math.floor((end - start) / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  if (mins < 60) return `${mins}m ${remSecs}s`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

function RiskBar({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-slate-400">—</span>;
  const color =
    score < 30 ? "bg-emerald-500" : score < 60 ? "bg-amber-500" : "bg-red-500";
  const textColor =
    score < 30
      ? "text-emerald-700 dark:text-emerald-400"
      : score < 60
        ? "text-amber-700 dark:text-amber-400"
        : "text-red-700 dark:text-red-400";
  return (
    <div className="flex items-center gap-2">
      <span className={`text-sm font-semibold ${textColor}`}>{score}</span>
      <div className="w-16 h-1.5 rounded-full bg-slate-100 dark:bg-slate-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

function SeverityDots({
  critical,
  high,
  medium,
  low,
  total,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm font-semibold text-slate-900 dark:text-white">{total}</span>
      <div className="flex items-center gap-1">
        {critical > 0 && (
          <span title={`${critical} critical`} className="flex items-center gap-0.5 text-xs text-red-600 dark:text-red-400">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            {critical}
          </span>
        )}
        {high > 0 && (
          <span title={`${high} high`} className="flex items-center gap-0.5 text-xs text-orange-600 dark:text-orange-400">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            {high}
          </span>
        )}
        {medium > 0 && (
          <span title={`${medium} medium`} className="flex items-center gap-0.5 text-xs text-amber-600 dark:text-amber-400">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            {medium}
          </span>
        )}
        {low > 0 && (
          <span title={`${low} low`} className="flex items-center gap-0.5 text-xs text-blue-600 dark:text-blue-400">
            <span className="w-2 h-2 rounded-full bg-blue-500" />
            {low}
          </span>
        )}
      </div>
    </div>
  );
}

export default function ScansPage() {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");

  const { data, isLoading, isError, error } = useQuery<ScansResponse>({
    queryKey: ["scans", page, statusFilter, typeFilter],
    queryFn: () => {
      const params: Record<string, string | number> = { page, page_size: PAGE_SIZE };
      if (statusFilter) params.status = statusFilter;
      if (typeFilter) params.scan_type = typeFilter;
      return getScans(params);
    },
    retry: 1,
  });

  const scans = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const filteredScans = search
    ? scans.filter(
        (s) =>
          (s.file_name && s.file_name.toLowerCase().includes(search.toLowerCase())) ||
          (s.repository_name && s.repository_name.toLowerCase().includes(search.toLowerCase()))
      )
    : scans;

  const completedCount = scans.filter((s) => s.status === "completed").length;
  const failedCount = scans.filter((s) => s.status === "failed").length;
  const runningCount = scans.filter((s) => s.status === "running").length;

  const rangeStart = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(page * PAGE_SIZE, total);

  const stats = [
    { label: "Total Assessments", value: total, icon: ScanLine, iconBg: "bg-orange-100 dark:bg-orange-900/40 text-orange-600 dark:text-orange-400" },
    { label: "Completed", value: completedCount, icon: CheckCircle2, iconBg: "bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400" },
    { label: "Failed", value: failedCount, icon: XCircle, iconBg: "bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400" },
    { label: "Running", value: runningCount, icon: Loader2, iconBg: "bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400" },
  ];

  return (
    <PageLayout title="Assessments" subtitle="Security assessment history and results" icon={ScanLine}>
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5 flex items-center gap-4"
          >
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${stat.iconBg}`}>
              <stat.icon size={18} />
            </div>
            <div>
              <p className="text-2xl font-bold text-slate-900 dark:text-white">{stat.value}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{stat.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by file or repo name…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full h-12 pl-11 pr-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s === "All" ? "" : s.toLowerCase()}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={typeFilter}
          onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
          className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
        >
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t === "All" ? "" : t.toLowerCase()}>
              {t}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden max-h-[calc(100vh-300px)] overflow-y-auto">
        {isLoading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 size={24} className="animate-spin text-orange-500" />
            <span className="ml-3 text-slate-500 dark:text-slate-400">Loading scans…</span>
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center justify-center py-24 px-6">
            <div className="w-16 h-16 rounded-2xl bg-red-50 dark:bg-red-900/30 flex items-center justify-center mb-4">
              <XCircle size={28} className="text-red-500" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              Failed to load scans
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-2 text-center max-w-sm">
              {(error as any)?.response?.data?.detail || (error as Error)?.message || "An unexpected error occurred while fetching scans."}
            </p>
          </div>
        ) : filteredScans.length === 0 ? (
          /* Empty State */
          <div className="flex flex-col items-center justify-center py-24 px-6">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
              <ScanLine size={28} className="text-slate-400" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              No scans yet
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-6 text-center max-w-sm">
              Run your first scan from the Integrations page to see results here.
            </p>
            <Link
              href="/integrations"
              className="inline-flex items-center h-12 px-6 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold transition-colors"
            >
              Go to Integrations
            </Link>
          </div>
        ) : (
          <>
            {/* Table Header */}
            <div className="hidden lg:grid grid-cols-[120px_minmax(140px,1.2fr)_minmax(100px,1fr)_160px_120px_80px_90px] gap-3 px-6 py-3 border-b border-slate-100 dark:border-slate-800 text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              <div>Status</div>
              <div>Source</div>
              <div>Type</div>
              <div>Findings</div>
              <div>Risk Score</div>
              <div>Duration</div>
              <div>Started</div>
            </div>

            {/* Rows */}
            {filteredScans.map((scan) => {
              const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
              const isRunning = scan.status === "running";

              return (
                <div
                  key={scan.id}
                  onClick={() => router.push(`/scans/${scan.id}`)}
                  className="grid grid-cols-1 lg:grid-cols-[120px_minmax(140px,1.2fr)_minmax(100px,1fr)_160px_120px_80px_90px] gap-2 lg:gap-3 px-6 py-4 border-b border-slate-50 dark:border-slate-800/50 hover:bg-slate-50 dark:bg-slate-800/50 dark:hover:bg-slate-800/30 transition-colors items-center cursor-pointer"
                >
                  {/* Status */}
                  <div>
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium ${cfg.bg} ${cfg.text}`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${cfg.dot} ${isRunning ? "animate-pulse" : ""}`}
                      />
                      {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                    </span>
                    {isRunning && scan.progress !== null && (
                      <div className="mt-2">
                        <div className="w-full h-1.5 rounded-full bg-slate-100 dark:bg-slate-800">
                          <div
                            className="h-full rounded-full bg-blue-500 transition-all"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <p className="text-[10px] text-slate-400 mt-0.5">
                          {scan.stage ?? "Processing"} · {scan.progress}%
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Source */}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 min-w-0">
                      {scan.repository_name ? (
                        <FolderGit2 size={14} className="text-slate-400 shrink-0" />
                      ) : (
                        <FileCode2 size={14} className="text-slate-400 shrink-0" />
                      )}
                      <span className="text-sm font-medium text-slate-900 dark:text-white truncate">
                        {scan.repository_name || scan.file_name || "—"}
                      </span>
                    </div>
                    {scan.account_name && (
                      <p className="text-xs text-slate-400 mt-0.5 truncate">{scan.account_name}</p>
                    )}
                  </div>

                  {/* Type */}
                  <div className="flex flex-wrap gap-1">
                    {scan.scan_type.split(",").map((t: string) => t.trim()).filter(Boolean).slice(0, 4).map((t: string) => (
                      <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                        {t}
                      </span>
                    ))}
                    {scan.scan_type.split(",").length > 4 && (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                        +{scan.scan_type.split(",").length - 4}
                      </span>
                    )}
                  </div>

                  {/* Findings */}
                  <div>
                    <SeverityDots
                      critical={scan.critical_count}
                      high={scan.high_count}
                      medium={scan.medium_count}
                      low={scan.low_count}
                      total={scan.findings_count}
                    />
                  </div>

                  {/* Risk Score */}
                  <div>
                    <RiskBar score={scan.risk_score} />
                  </div>

                  {/* Duration */}
                  <div className="text-sm text-slate-500 dark:text-slate-400">
                    {formatDuration(scan.started_at, scan.completed_at)}
                  </div>

                  {/* Started */}
                  <div className="text-sm text-slate-500 dark:text-slate-400">
                    {scan.started_at ? relativeTime(scan.started_at) : "—"}
                  </div>
                </div>
              );
            })}
          </>
        )}
      </div>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between mt-6">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Showing {rangeStart}–{rangeEnd} of {total}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="inline-flex items-center gap-1 h-10 px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft size={16} /> Previous
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="inline-flex items-center gap-1 h-10 px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
