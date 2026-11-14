"use client";

import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Activity,
  Search,
  Shield,
  RefreshCw,
  FileText,
  Download,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Clock,
  AlertTriangle,
  User,
  Calendar,
} from "lucide-react";

interface Job {
  id: number;
  job_id: string; // GN-SCN-00004 format from backend
  scan_type: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  stage: string | null;
  findings_count: number;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  repository_name: string | null;
  account_name: string | null;
  file_name: string | null;
  risk_score: number | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

interface JobsResponse {
  items: Job[];
  total: number;
  page: number;
  page_size: number;
}

const JOB_TYPE_CONFIG: Record<string, { icon: React.ElementType; label: string; color: string }> = {
  terraform: { icon: Shield, label: "Terraform Scan", color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" },
  cloudformation: { icon: Shield, label: "CloudFormation Scan", color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" },
  bicep: { icon: Shield, label: "Bicep Scan", color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" },
  secrets: { icon: Shield, label: "Secrets Scan", color: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" },
  full: { icon: Shield, label: "Full Scan", color: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400" },
  policy: { icon: FileText, label: "Policy Evaluation", color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" },
  audit: { icon: Activity, label: "Audit", color: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" },
  drift: { icon: Activity, label: "Drift Detection", color: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400" },
  sync: { icon: RefreshCw, label: "Sync", color: "bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400" },
  report: { icon: FileText, label: "Report", color: "bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400" },
  export: { icon: Download, label: "Export", color: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400" },
  remediation: { icon: Activity, label: "Remediation", color: "bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400" },
  repository: { icon: Shield, label: "Repository Scan", color: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400" },
  cloud_posture: { icon: Shield, label: "Cloud Posture", color: "bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400" },
};

/** What the job ran against: a repository, a cloud account, or an uploaded file. */
const targetOf = (j: Job) =>
  j.scan_type === "cloud_posture"
    ? (j.account_name ? `Cloud account: ${j.account_name}` : j.file_name)
    : (j.repository_name || j.file_name);

const STATUS_CONFIG: Record<string, { dotColor: string; bgColor: string; pulse?: boolean }> = {
  pending: { dotColor: "bg-yellow-500", bgColor: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" },
  running: { dotColor: "bg-blue-500", bgColor: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400", pulse: true },
  completed: { dotColor: "bg-green-500", bgColor: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400" },
  failed: { dotColor: "bg-red-500", bgColor: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" },
  cancelled: { dotColor: "bg-slate-400", bgColor: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400" },
};

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
  return `${diffDay}d ago`;
}

function formatDuration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt) return "—";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const totalSec = Math.max(0, Math.floor((end - start) / 1000));
  if (totalSec < 60) return `${totalSec}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function formatTimestamp(dateStr: string | null): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleString();
}

function progressBarColor(status: string): string {
  if (status === "completed") return "bg-green-500";
  if (status === "failed") return "bg-red-500";
  return "bg-blue-500";
}

export default function JobsPage() {
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const pageSize = 20;

  const { data, isLoading } = useQuery<JobsResponse>({
    queryKey: ["jobs", page, statusFilter, typeFilter],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, page_size: pageSize };
      if (statusFilter) params.status = statusFilter;
      if (typeFilter) params.type = typeFilter;
      const res = await api.get("/jobs", { params });
      return res.data;
    },
    refetchInterval: (query) => {
      const d = query.state.data as JobsResponse | undefined;
      if (!d) return false;
      return d.items.some((j) => j.status === "running" || j.status === "pending") ? 5000 : false;
    },
  });

  const jobs = data?.items ?? [];
  const total = data?.total ?? 0;

  const filteredJobs = useMemo(() => {
    if (!search.trim()) return jobs;
    const q = search.toLowerCase();
    return jobs.filter(
      (j) =>
        j.job_id.toLowerCase().includes(q) ||
        j.scan_type.toLowerCase().includes(q) ||
        j.status.toLowerCase().includes(q) ||
        (targetOf(j) || "").toLowerCase().includes(q)
    );
  }, [jobs, search]);

  const counts = useMemo(() => {
    const c = { total: 0, running: 0, completed: 0, failed: 0, pending: 0 };
    c.total = total;
    for (const j of jobs) {
      if (j.status === "running") c.running++;
      else if (j.status === "completed") c.completed++;
      else if (j.status === "failed") c.failed++;
      else if (j.status === "pending") c.pending++;
    }
    return c;
  }, [jobs, total]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const showStart = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const showEnd = Math.min(page * pageSize, total);

  return (
    <PageLayout
      title="Task Monitor"
      subtitle="Monitor running tasks and job history"
      icon={Activity}
    >
      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
        {[
          { label: "Total Tasks", value: counts.total, color: "text-orange-600 dark:text-orange-400", iconBg: "bg-orange-100 dark:bg-orange-900/40 text-orange-600 dark:text-orange-400", icon: Activity, glow: false },
          { label: "Running", value: counts.running, color: "text-blue-600 dark:text-blue-400", iconBg: "bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400", icon: RefreshCw, glow: true },
          { label: "Completed", value: counts.completed, color: "text-green-600 dark:text-green-400", iconBg: "bg-green-100 dark:bg-green-900/40 text-green-600 dark:text-green-400", icon: Activity, glow: false },
          { label: "Failed", value: counts.failed, color: "text-red-600 dark:text-red-400", iconBg: "bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400", icon: AlertTriangle, glow: false },
          { label: "Pending", value: counts.pending, color: "text-yellow-600 dark:text-yellow-400", iconBg: "bg-yellow-100 dark:bg-yellow-900/40 text-yellow-600 dark:text-yellow-400", icon: Clock, glow: false },
        ].map((stat) => {
          const Icon = stat.icon;
          const shouldPulse = stat.glow && stat.value > 0;
          return (
            <div
              key={stat.label}
              className={`bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 transition-all ${
                shouldPulse ? "ring-2 ring-blue-400/50 dark:ring-blue-500/30 shadow-lg shadow-blue-500/10" : ""
              }`}
            >
              <div className="flex items-center gap-4">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${stat.iconBg} ${shouldPulse ? "animate-pulse" : ""}`}>
                  <Icon className="w-6 h-6" />
                </div>
                <div>
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{stat.label}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap gap-3 mb-6">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search jobs..."
            className="w-full h-12 pl-11 pr-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-orange-500"
        >
          <option value="">All Status</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
        <select
          value={typeFilter}
          onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
          className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-orange-500"
        >
          <option value="">All Types</option>
          <option value="scan">Scan</option>
          <option value="sync">Sync</option>
          <option value="report">Report</option>
          <option value="export">Export</option>
        </select>
      </div>

      {/* Jobs Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-orange-500" />
        </div>
      ) : filteredJobs.length === 0 ? (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
          <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
            <Activity className="w-8 h-8 text-slate-400" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">No tasks found</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 max-w-md mx-auto">
            Tasks are created when you run assessments, generate reports, or sync data.
          </p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div className="overflow-auto max-h-[calc(100vh-300px)]">
            <table className="w-full">
              <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/80 backdrop-blur">
                <tr className="border-b border-slate-200 dark:border-slate-800">
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">ID</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Type</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider min-w-[160px]">Progress</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Created</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Duration</th>
                  <th className="w-10 px-3 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredJobs.map((job) => {
                  const isExpanded = expandedId === job.id;
                  const typeCfg = JOB_TYPE_CONFIG[job.scan_type] ?? { icon: Activity, label: job.scan_type, color: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400" };
                  const TypeIcon = typeCfg.icon;
                  const statusCfg = STATUS_CONFIG[job.status] ?? STATUS_CONFIG.pending;

                  return (
                    <React.Fragment key={job.id}>
                      <tr
                        onClick={() => setExpandedId(isExpanded ? null : job.id)}
                        className="cursor-pointer hover:bg-slate-50 dark:bg-slate-800/70 dark:hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="px-6 py-4">
                          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{job.job_id}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-slate-900 dark:text-slate-100 font-medium truncate max-w-[200px] block">
                            {targetOf(job) || "—"}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${typeCfg.color}`}>
                            <TypeIcon className="w-3.5 h-3.5" />
                            {typeCfg.label}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${statusCfg.bgColor}`}>
                            <span className="relative flex h-2 w-2">
                              {statusCfg.pulse && (
                                <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${statusCfg.dotColor}`} />
                              )}
                              <span className={`relative inline-flex h-2 w-2 rounded-full ${statusCfg.dotColor}`} />
                            </span>
                            {job.status.charAt(0).toUpperCase() + job.status.slice(1)}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="flex-1 h-2 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all duration-500 ${progressBarColor(job.status)} ${
                                  job.status === "running" ? "animate-pulse" : ""
                                }`}
                                style={{ width: `${job.progress}%` }}
                              />
                            </div>
                            <span className="text-xs font-medium text-slate-500 dark:text-slate-400 w-9 text-right">{job.progress}%</span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-slate-500 dark:text-slate-400">{relativeTime(job.created_at)}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-slate-500 dark:text-slate-400">{formatDuration(job.started_at, job.completed_at)}</span>
                        </td>
                        <td className="px-3 py-4 text-center">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-slate-400" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-slate-400" />
                          )}
                        </td>
                      </tr>

                      {/* Expanded Detail */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={8} className="px-6 pb-6 pt-2 bg-slate-50 dark:bg-slate-800/50 dark:bg-slate-800/30">
                            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                              <div>
                                <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">Job ID</p>
                                <p className="text-sm font-mono text-slate-900 dark:text-slate-100 break-all">{job.job_id}</p>
                              </div>
                              <div>
                                <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">Target</p>
                                <p className="text-sm text-slate-900 dark:text-slate-100 font-medium">{targetOf(job) || "—"}</p>
                              </div>
                              <div>
                                <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
                                  <User className="w-3 h-3" /> Created By
                                </p>
                                <p className="text-sm text-slate-900 dark:text-slate-100">{job.account_name ?? "—"}</p>
                              </div>
                              <div>
                                <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
                                  <Calendar className="w-3 h-3" /> Started At
                                </p>
                                <p className="text-sm text-slate-900 dark:text-slate-100">{formatTimestamp(job.started_at)}</p>
                              </div>
                              <div>
                                <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
                                  <Calendar className="w-3 h-3" /> Completed At
                                </p>
                                <p className="text-sm text-slate-900 dark:text-slate-100">{formatTimestamp(job.completed_at)}</p>
                              </div>
                            </div>

                            {job.status === "failed" && job.error_message && (
                              <div className="p-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 mb-4">
                                <div className="flex items-start gap-2">
                                  <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
                                  <div>
                                    <p className="text-sm font-semibold text-red-700 dark:text-red-400 mb-1">Error</p>
                                    <p className="text-sm text-red-600 dark:text-red-300">{job.error_message}</p>
                                  </div>
                                </div>
                              </div>
                            )}

                            {job.status === "completed" && job.findings_count > 0 && (
                              <div className="p-4 rounded-xl bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
                                <p className="text-sm font-semibold text-green-700 dark:text-green-400 mb-2">Findings Summary</p>
                                <div className="flex gap-3 text-xs">
                                  <span className="text-red-600 font-medium">Critical: {job.critical_count}</span>
                                  <span className="text-orange-600 font-medium">High: {job.high_count}</span>
                                  <span className="text-yellow-600 font-medium">Medium: {job.medium_count}</span>
                                  <span className="text-blue-600 font-medium">Low: {job.low_count}</span>
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 dark:border-slate-800">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Showing {showStart}–{showEnd} of {total}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="inline-flex items-center gap-1 px-3 h-9 rounded-lg border border-slate-200 dark:border-slate-800 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="inline-flex items-center gap-1 px-3 h-9 rounded-lg border border-slate-200 dark:border-slate-800 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
