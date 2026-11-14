"use client";

import React, { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import { getCVEStats, syncCVEDatabase } from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Bug,
  Search,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  RefreshCw,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Clock,
  ExternalLink,
  Package,
  Wrench,
  Link2,
} from "lucide-react";

/* ── Types ── */

interface CVEReference {
  url: string;
  source: string;
  source_type: string;
}

interface AffectedPackage {
  vendor?: string;
  product?: string;
  version_start?: string;
  version_end?: string;
}

interface CVE {
  id: number;
  cve_id: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss_score: number | null;
  cvss_vector: string | null;
  affected_packages: (AffectedPackage | string)[] | null;
  fix_versions: string[] | null;
  references: CVEReference[] | null;
  published_date: string;
  published_at?: string;
  last_modified: string;
  source: "nvd" | "ghsa";
  epss_score: number | null;
  epss_percentile: number | null;
}

interface CVEListResponse {
  items: CVE[];
  total: number;
  page: number;
  page_size: number;
}

interface CVEStatsResponse {
  total_cves: number;
  by_severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  by_source: { nvd: number; ghsa: number };
  with_epss: number;
  last_sync: string;
}

/* ── Constants ── */

const SEVERITY_CONFIG: Record<
  string,
  { badge: string; icon: React.ElementType; label: string; statColor: string; iconBg: string }
> = {
  CRITICAL: {
    badge: "bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    icon: ShieldAlert,
    label: "Critical",
    statColor: "text-red-600 dark:text-red-400",
    iconBg: "bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400",
  },
  HIGH: {
    badge: "bg-orange-50 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
    icon: AlertTriangle,
    label: "High",
    statColor: "text-orange-600 dark:text-orange-400",
    iconBg: "bg-orange-100 dark:bg-orange-900/40 text-orange-600 dark:text-orange-400",
  },
  MEDIUM: {
    badge: "bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    icon: AlertCircle,
    label: "Medium",
    statColor: "text-amber-600 dark:text-amber-400",
    iconBg: "bg-amber-100 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400",
  },
  LOW: {
    badge: "bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    icon: Info,
    label: "Low",
    statColor: "text-blue-600 dark:text-blue-400",
    iconBg: "bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400",
  },
};

const PAGE_SIZE = 20;

/* ── Helpers ── */

function formatRelativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  const diffMon = Math.floor(diffDay / 30);
  if (diffMon < 12) return `${diffMon}mo ago`;
  return `${Math.floor(diffMon / 12)}y ago`;
}

function cvssColor(score: number): string {
  if (score >= 9.0) return "bg-red-500";
  if (score >= 7.0) return "bg-orange-500";
  if (score >= 4.0) return "bg-amber-500";
  return "bg-green-500";
}

function cvssTextColor(score: number): string {
  if (score >= 9.0) return "text-red-600 dark:text-red-400";
  if (score >= 7.0) return "text-orange-600 dark:text-orange-400";
  if (score >= 4.0) return "text-amber-600 dark:text-amber-400";
  return "text-green-600 dark:text-green-400";
}

/* ── Component ── */

export default function CVEsPage() {
  const queryClient = useQueryClient();

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  // Stats
  const { data: stats, isLoading: statsLoading, isError: statsError } = useQuery<CVEStatsResponse>({
    queryKey: ["cve-stats"],
    queryFn: getCVEStats,
    retry: 1,
  });

  // CVE list
  const { data: cveData, isLoading: cvesLoading, isError: cvesError, error: cvesErrorObj } = useQuery<CVEListResponse>({
    queryKey: ["cves", page, searchQuery, severityFilter, sourceFilter],
    queryFn: async () => {
      const params: Record<string, string | number> = {
        page,
        page_size: PAGE_SIZE,
      };
      if (searchQuery) params.search = searchQuery;
      if (severityFilter !== "ALL") params.severity = severityFilter;
      if (sourceFilter !== "ALL") params.source = sourceFilter.toLowerCase();
      const res = await api.get("/cves", { params });
      return res.data;
    },
    retry: 1,
  });

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: syncCVEDatabase,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cve-stats"] });
      queryClient.invalidateQueries({ queryKey: ["cves"] });
    },
  });

  const handleSearch = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    setPage(1);
  }, []);

  const handleSeverityChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    setSeverityFilter(e.target.value);
    setPage(1);
  }, []);

  const handleSourceChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    setSourceFilter(e.target.value);
    setPage(1);
  }, []);

  const toggleExpand = useCallback((id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);

  const totalPages = cveData ? Math.ceil(cveData.total / PAGE_SIZE) : 0;
  const showFrom = cveData && cveData.total > 0 ? (page - 1) * PAGE_SIZE + 1 : 0;
  const showTo = cveData ? Math.min(page * PAGE_SIZE, cveData.total) : 0;

  return (
    <PageLayout
      title="CVE Database"
      subtitle="Common Vulnerabilities and Exposures tracking"
      icon={Bug}
      actions={
        <button
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="flex items-center gap-2 px-5 h-12 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold disabled:opacity-60 transition-colors"
        >
          {syncMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          Sync Database
        </button>
      }
    >
      <div className="space-y-6">
        {/* ── Stats Row ── */}
        {statsLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-7 h-7 animate-spin text-orange-500" />
          </div>
        ) : stats ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {/* Total */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-orange-100 dark:bg-orange-900/40 flex items-center justify-center">
                  <Bug className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.total_cves.toLocaleString()}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Total CVEs</p>
                </div>
              </div>
            </div>

            {/* Severity cards */}
            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
              const cfg = SEVERITY_CONFIG[sev];
              const SevIcon = cfg.icon;
              const count = stats.by_severity[sev] ?? 0;
              return (
                <div
                  key={sev}
                  className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${cfg.iconBg}`}>
                      <SevIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <p className={`text-2xl font-bold ${cfg.statColor}`}>
                        {count.toLocaleString()}
                      </p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{cfg.label}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}

        {/* ── Meta Row: Last Synced + Sources ── */}
        {stats && (
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-1.5">
              <Clock className="w-4 h-4" />
              <span>
                Last synced:{" "}
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  {stats.last_sync ? formatRelativeTime(stats.last_sync) : "Never"}
                </span>
              </span>
            </div>
            <span className="text-slate-300 dark:text-slate-600 dark:text-slate-300">|</span>
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs font-medium">
                NVD {(stats.by_source.nvd ?? 0).toLocaleString()}
              </span>
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-purple-50 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 text-xs font-medium">
                GHSA {(stats.by_source.ghsa ?? 0).toLocaleString()}
              </span>
            </div>
          </div>
        )}

        {/* ── Filters ── */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search CVE ID or description..."
              value={searchQuery}
              onChange={handleSearch}
              className="w-full h-12 pl-11 pr-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 transition-shadow"
            />
          </div>
          <select
            value={severityFilter}
            onChange={handleSeverityChange}
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500 transition-shadow"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select
            value={sourceFilter}
            onChange={handleSourceChange}
            className="h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500 transition-shadow"
          >
            <option value="ALL">All Sources</option>
            <option value="NVD">NVD</option>
            <option value="GHSA">GHSA</option>
          </select>
        </div>

        {/* ── CVE Table ── */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-x-hidden max-h-[calc(100vh-340px)] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-300 dark:scrollbar-thumb-slate-600 scrollbar-track-transparent">
          {cvesLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-7 h-7 animate-spin text-orange-500" />
            </div>
          ) : !cveData || cveData.items.length === 0 ? (
            /* Empty state */
            <div className="p-16 text-center">
              <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
                <Bug className="w-8 h-8 text-slate-400" />
              </div>
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                No CVEs in database
              </h3>
              <p className="text-sm text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                {searchQuery || severityFilter !== "ALL" || sourceFilter !== "ALL"
                  ? "No CVEs match your current filters. Try adjusting your search criteria."
                  : "Click \u2018Sync Database\u2019 to fetch the latest vulnerabilities."}
              </p>
            </div>
          ) : (
            <>
              {/* Table header */}
              <div className="hidden lg:grid grid-cols-[minmax(140px,1fr)_110px_110px_1fr_90px_100px] gap-4 px-6 py-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                <span>CVE ID</span>
                <span>Severity</span>
                <span>CVSS</span>
                <span>Description</span>
                <span>Source</span>
                <span>Published</span>
              </div>

              {/* Rows */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {cveData.items.map((cve) => {
                  const isExpanded = expandedId === cve.id;
                  const sevCfg = SEVERITY_CONFIG[cve.severity] ?? SEVERITY_CONFIG.LOW;

                  return (
                    <div key={cve.id}>
                      {/* Main row */}
                      <button
                        onClick={() => toggleExpand(cve.id)}
                        className="w-full text-left lg:grid lg:grid-cols-[minmax(140px,1fr)_110px_110px_1fr_90px_100px] gap-4 px-6 py-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors items-center"
                      >
                        {/* CVE ID */}
                        <div className="flex items-center gap-2 mb-2 lg:mb-0">
                          <span className="font-mono text-sm font-semibold text-orange-600 dark:text-orange-400">
                            {cve.cve_id}
                          </span>
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-slate-400 shrink-0" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                          )}
                        </div>

                        {/* Severity badge */}
                        <div>
                          <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold ${sevCfg.badge}`}>
                            {sevCfg.label}
                          </span>
                        </div>

                        {/* CVSS Score */}
                        <div className="my-2 lg:my-0">
                          {cve.cvss_score !== null ? (
                            <div className="flex items-center gap-2">
                              <span className={`text-sm font-bold ${cvssTextColor(cve.cvss_score)}`}>
                                {cve.cvss_score.toFixed(1)}
                              </span>
                              <div className="w-16 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${cvssColor(cve.cvss_score)}`}
                                  style={{ width: `${(cve.cvss_score / 10) * 100}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-400">N/A</span>
                          )}
                        </div>

                        {/* Description */}
                        <p className="text-sm text-slate-600 dark:text-slate-400 line-clamp-2">
                          {cve.description}
                        </p>

                        {/* Source badge */}
                        <div>
                          <span
                            className={`inline-flex px-2.5 py-1 rounded-lg text-xs font-semibold ${
                              cve.source === "nvd"
                                ? "bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
                                : "bg-purple-50 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400"
                            }`}
                          >
                            {(cve.source || "unknown").toUpperCase()}
                          </span>
                        </div>

                        {/* Published */}
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {formatRelativeTime(cve.published_date || cve.published_at || cve.last_modified)}
                        </span>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="px-6 pb-6 pt-2 bg-slate-50 dark:bg-slate-800/30 border-t border-slate-100 dark:border-slate-800">
                          <div className="grid md:grid-cols-2 gap-6">
                            {/* Left column */}
                            <div className="space-y-5">
                              {/* Full description */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                  Description
                                </h4>
                                <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
                                  {cve.description}
                                </p>
                              </div>

                              {/* CVSS Vector */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                  CVSS Vector
                                </h4>
                                {cve.cvss_vector ? (
                                  <code className="block text-xs font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-4 py-3 rounded-xl break-all">
                                    {cve.cvss_vector}
                                  </code>
                                ) : (
                                  <p className="text-sm text-slate-400">No CVSS vector available</p>
                                )}
                              </div>

                              {/* EPSS */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                  EPSS Score
                                </h4>
                                {cve.epss_score != null ? (
                                  <div className="flex items-center gap-4">
                                    <div className="flex items-center gap-2">
                                      <span className="text-lg font-bold text-slate-900 dark:text-white">
                                        {(Number(cve.epss_score) * 100).toFixed(2)}%
                                      </span>
                                      <span className="text-xs text-slate-500 dark:text-slate-400">probability</span>
                                    </div>
                                    {cve.epss_percentile != null && (
                                      <div className="flex items-center gap-2">
                                        <span className="text-lg font-bold text-slate-900 dark:text-white">
                                          {Number(cve.epss_percentile).toFixed(1)}%
                                        </span>
                                        <span className="text-xs text-slate-500 dark:text-slate-400">percentile</span>
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  <p className="text-sm text-slate-400">No EPSS data</p>
                                )}
                              </div>
                            </div>

                            {/* Right column */}
                            <div className="space-y-5">
                              {/* Affected Packages */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                  <Package className="w-3.5 h-3.5" />
                                  Affected Packages
                                </h4>
                                {(cve.affected_packages ?? []).length > 0 ? (
                                  <div className="flex flex-wrap gap-2">
                                    {(cve.affected_packages ?? []).map((pkg, idx) => {
                                      const label =
                                        typeof pkg === "string"
                                          ? pkg
                                          : [pkg.vendor, pkg.product, pkg.version_start, pkg.version_end]
                                              .filter(Boolean)
                                              .join(" ") || "unknown";
                                      return (
                                        <span
                                          key={idx}
                                          className="inline-flex px-3 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300"
                                        >
                                          {label}
                                        </span>
                                      );
                                    })}
                                  </div>
                                ) : (
                                  <p className="text-sm text-slate-400">No affected packages listed</p>
                                )}
                              </div>

                              {/* Fix Versions */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                  <Wrench className="w-3.5 h-3.5" />
                                  Fix Versions
                                </h4>
                                {(cve.fix_versions ?? []).length > 0 ? (
                                  <div className="flex flex-wrap gap-2">
                                    {(cve.fix_versions ?? []).map((ver) => (
                                      <span
                                        key={ver}
                                        className="inline-flex px-3 py-1 rounded-lg bg-green-50 dark:bg-green-900/20 text-xs font-mono text-green-700 dark:text-green-400"
                                      >
                                        {ver}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <p className="text-sm text-slate-400">No fix versions available</p>
                                )}
                              </div>

                              {/* References */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                  <Link2 className="w-3.5 h-3.5" />
                                  References
                                </h4>
                                {(cve.references ?? []).length > 0 ? (
                                  <div className="space-y-3">
                                    {Object.entries(
                                      (cve.references ?? []).filter(Boolean).reduce<Record<string, CVEReference[]>>((acc, ref) => {
                                        const key = ref?.source_type || "Other";
                                        if (!acc[key]) acc[key] = [];
                                        acc[key].push(ref);
                                        return acc;
                                      }, {})
                                    ).map(([type, refs]) => (
                                      <div key={type}>
                                        <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 capitalize">
                                          {type}
                                        </p>
                                        <div className="space-y-1">
                                          {refs.map((ref, idx) => (
                                            <a
                                              key={idx}
                                              href={ref.url}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="flex items-center gap-1.5 text-xs text-orange-600 dark:text-orange-400 hover:underline truncate"
                                            >
                                              <ExternalLink className="w-3 h-3 shrink-0" />
                                              <span className="truncate">{ref.url}</span>
                                            </a>
                                          ))}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <p className="text-sm text-slate-400">No references</p>
                                )}
                              </div>

                              {/* Last Modified */}
                              <div>
                                <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">
                                  Last Modified
                                </h4>
                                <p className="text-sm text-slate-700 dark:text-slate-300">
                                  {cve.last_modified
                                    ? new Date(cve.last_modified).toLocaleDateString("en-US", {
                                        year: "numeric",
                                        month: "long",
                                        day: "numeric",
                                      })
                                    : "Unknown"}
                                </p>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Pagination */}
              {cveData.total > 0 && (
                <div className="flex items-center justify-between px-6 py-4 border-t border-slate-100 dark:border-slate-800">
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Showing{" "}
                    <span className="font-medium text-slate-700 dark:text-slate-300">
                      {showFrom}–{showTo}
                    </span>{" "}
                    of{" "}
                    <span className="font-medium text-slate-700 dark:text-slate-300">
                      {cveData.total.toLocaleString()}
                    </span>
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page <= 1}
                      className="inline-flex items-center gap-1 px-3 h-9 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      <ChevronLeft className="w-4 h-4" />
                      Previous
                    </button>
                    <button
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      disabled={page >= totalPages}
                      className="inline-flex items-center gap-1 px-3 h-9 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      Next
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </PageLayout>
  );
}
