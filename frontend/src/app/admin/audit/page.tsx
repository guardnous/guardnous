"use client";

import React, { useState, useMemo, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  ScrollText,
  Download,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Plus,
  Eye,
  Pencil,
  Trash2,
  LogIn,
  LogOut,
  RefreshCw,
  Globe,
  Monitor,
} from "lucide-react";

/* ── Types ── */

interface AuditLogRaw {
  id: number;
  created_at: string;
  user_id: number | null;
  action: string;
  resource_type: string;
  resource_id: number | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
}

interface AuditLog {
  id: string;
  timestamp: string;
  user_name: string;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
}

interface User {
  id: string;
  full_name: string;
}

/* ── Constants ── */

const ACTION_STYLES: Record<string, string> = {
  create: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400",
  read: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400",
  update: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400",
  delete: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400",
  login: "bg-orange-50 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400",
  logout: "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300",
};

const ACTION_ICONS: Record<string, React.ReactNode> = {
  create: <Plus size={12} />,
  read: <Eye size={12} />,
  update: <Pencil size={12} />,
  delete: <Trash2 size={12} />,
  login: <LogIn size={12} />,
  logout: <LogOut size={12} />,
};

const ACTIONS = ["create", "read", "update", "delete", "login", "logout"] as const;
const RESOURCE_TYPES = [
  "user", "role", "tenant", "group", "scan",
  "finding", "report", "integration", "agent", "setting",
] as const;

const PAGE_SIZE = 20;

const INPUT_CLS =
  "h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 px-4 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500 transition-shadow";

/* ── Helpers ── */

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function exportCsv(logs: AuditLog[]) {
  const header = "Timestamp,User,Email,Action,Resource Type,Resource ID\n";
  const rows = logs.map((l) =>
    [l.timestamp, l.user_name, l.user_email, l.action, l.resource_type, l.resource_id]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(",")
  );
  const blob = new Blob([header + rows.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Stat Card ── */

function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {label}
        </span>
        <div className="w-9 h-9 rounded-xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-500 dark:text-slate-400">
          {icon}
        </div>
      </div>
      <p className="text-2xl font-bold text-slate-900 dark:text-white">{value.toLocaleString()}</p>
    </div>
  );
}

/* ── Page ── */

export default function AdminAuditPage() {
  const [page, setPage] = useState(1);
  const [userId, setUserId] = useState("");
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [liveRefresh, setLiveRefresh] = useState(false);

  /* Fetch flat array from /audit/logs */
  const { data: allLogs = [], isLoading, isFetching } = useQuery<AuditLog[]>({
    queryKey: ["admin-audit-logs"],
    queryFn: () =>
      api.get("/audit/logs?limit=500").then((r) =>
        (r.data as AuditLogRaw[]).map((raw) => ({
          id: String(raw.id),
          timestamp: raw.created_at,
          user_name: (raw.details?.user_name as string) || "System",
          user_email: (raw.details?.user_email as string) || "",
          action: raw.action,
          resource_type: raw.resource_type,
          resource_id: raw.resource_id != null ? String(raw.resource_id) : "—",
          details: raw.details || {},
          ip_address: raw.ip_address || undefined,
          user_agent: raw.user_agent || undefined,
        }))
      ),
    refetchInterval: liveRefresh ? 10_000 : false,
  });

  const { data: users = [] } = useQuery<User[]>({
    queryKey: ["admin-users-list"],
    queryFn: () => api.get("/users/").then((r) => r.data),
  });

  /* Client-side filtering */
  const filtered = useMemo(() => {
    let result = allLogs;
    if (userId) result = result.filter((l) => l.user_name === userId || l.user_email === userId);
    if (action) result = result.filter((l) => l.action === action);
    if (resourceType) result = result.filter((l) => l.resource_type === resourceType);
    if (startDate) {
      const start = new Date(startDate).getTime();
      result = result.filter((l) => new Date(l.timestamp).getTime() >= start);
    }
    if (endDate) {
      const end = new Date(endDate).getTime() + 86_400_000;
      result = result.filter((l) => new Date(l.timestamp).getTime() < end);
    }
    return result;
  }, [allLogs, userId, action, resourceType, startDate, endDate]);

  /* Stats from full (unfiltered) array */
  const stats = useMemo(() => {
    const counts = { create: 0, update: 0, delete: 0 };
    for (const log of allLogs) {
      if (log.action in counts) counts[log.action as keyof typeof counts]++;
    }
    return { total: allLogs.length, ...counts };
  }, [allLogs]);

  /* Client-side pagination */
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = useMemo(
    () => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [filtered, page]
  );

  const resetPage = useCallback(() => setPage(1), []);

  /* Reset page when filters change */
  useEffect(() => { resetPage(); }, [userId, action, resourceType, startDate, endDate, resetPage]);

  const breadcrumbs = [{ label: "Admin" }, { label: "Audit Logs" }];

  return (
    <PageLayout
      title="Audit Logs"
      subtitle="Track all platform activity and changes"
      icon={ScrollText}
      breadcrumbs={breadcrumbs}
      actions={
        <div className="flex items-center gap-3">
          {/* Live refresh toggle */}
          <button
            onClick={() => setLiveRefresh((v) => !v)}
            className={`h-12 rounded-xl px-5 font-semibold text-sm flex items-center gap-2 transition-colors ${
              liveRefresh
                ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                : "border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
            }`}
          >
            <RefreshCw size={16} className={isFetching && liveRefresh ? "animate-spin" : ""} />
            {liveRefresh ? "Live" : "Auto-refresh"}
          </button>
          {/* Export CSV */}
          <button
            onClick={() => exportCsv(filtered)}
            className="bg-orange-600 hover:bg-orange-700 text-white rounded-xl h-12 px-5 font-semibold text-sm flex items-center gap-2 transition-colors"
          >
            <Download size={16} />
            Export CSV
          </button>
        </div>
      }
    >
      {/* Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Events" value={stats.total} icon={<ScrollText size={18} />} />
        <StatCard label="Create" value={stats.create} icon={<Plus size={18} />} />
        <StatCard label="Update" value={stats.update} icon={<Pencil size={18} />} />
        <StatCard label="Delete" value={stats.delete} icon={<Trash2 size={18} />} />
      </div>

      {/* Filters Bar */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5 mb-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <select value={userId} onChange={(e) => setUserId(e.target.value)} className={INPUT_CLS}>
            <option value="">All Users</option>
            {users.map((u) => (
              <option key={u.id} value={u.full_name}>{u.full_name}</option>
            ))}
          </select>

          <select value={action} onChange={(e) => setAction(e.target.value)} className={INPUT_CLS}>
            <option value="">All Actions</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>{a.charAt(0).toUpperCase() + a.slice(1)}</option>
            ))}
          </select>

          <select value={resourceType} onChange={(e) => setResourceType(e.target.value)} className={INPUT_CLS}>
            <option value="">All Resources</option>
            {RESOURCE_TYPES.map((r) => (
              <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
            ))}
          </select>

          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            placeholder="Start date"
            className={INPUT_CLS}
          />

          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            placeholder="End date"
            className={INPUT_CLS}
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden max-h-[calc(100vh-300px)] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 shrink-0">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {filtered.length.toLocaleString()} log {filtered.length === 1 ? "entry" : "entries"}
          </p>
          {liveRefresh && (
            <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Refreshing every 10s
            </span>
          )}
        </div>

        {/* Empty state */}
        {!isLoading && allLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 px-6">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-5">
              <ScrollText size={28} className="text-slate-400 dark:text-slate-500" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              No audit logs recorded yet
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 text-center max-w-sm">
              Activity will appear here as users interact with the platform
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-auto flex-1">
              <table className="w-full text-sm">
                <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                  <tr className="border-b border-slate-200 dark:border-slate-800">
                    {["Timestamp", "User", "Action", "Resource Type", "Resource ID", ""].map((h) => (
                      <th
                        key={h || "expand"}
                        className="text-left px-6 py-3.5 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {paged.map((log) => {
                    const isExpanded = expandedId === log.id;
                    const ip = log.ip_address;
                    const ua = log.user_agent;

                    return (
                      <React.Fragment key={log.id}>
                        <tr
                          className="border-b border-slate-100 dark:border-slate-800/50 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer"
                          onClick={() => setExpandedId(isExpanded ? null : log.id)}
                        >
                          <td className="px-6 py-3.5 text-slate-600 dark:text-slate-300 whitespace-nowrap">
                            <span title={new Date(log.timestamp).toLocaleString()}>
                              {relativeTime(log.timestamp)}
                            </span>
                          </td>
                          <td className="px-6 py-3.5">
                            <p className="font-medium text-slate-900 dark:text-white leading-tight">
                              {log.user_name}
                            </p>
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              {log.user_email}
                            </p>
                          </td>
                          <td className="px-6 py-3.5">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium ${
                                ACTION_STYLES[log.action] || ACTION_STYLES.read
                              }`}
                            >
                              {ACTION_ICONS[log.action]}
                              {log.action}
                            </span>
                          </td>
                          <td className="px-6 py-3.5 text-slate-600 dark:text-slate-300 capitalize">
                            {log.resource_type}
                          </td>
                          <td className="px-6 py-3.5 text-slate-500 dark:text-slate-400 font-mono text-xs">
                            {log.resource_id}
                          </td>
                          <td className="px-6 py-3.5">
                            {isExpanded ? (
                              <ChevronUp size={14} className="text-slate-400" />
                            ) : (
                              <ChevronDown size={14} className="text-slate-400" />
                            )}
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr>
                            <td colSpan={6} className="px-6 py-4 bg-slate-50 dark:bg-slate-800/30">
                              <div className="space-y-3">
                                {/* IP & User Agent */}
                                {(ip || ua) && (
                                  <div className="flex flex-wrap gap-4 text-xs text-slate-500 dark:text-slate-400">
                                    {ip && (
                                      <span className="inline-flex items-center gap-1.5">
                                        <Globe size={12} /> {ip}
                                      </span>
                                    )}
                                    {ua && (
                                      <span className="inline-flex items-center gap-1.5">
                                        <Monitor size={12} />
                                        <span className="max-w-md truncate">{ua}</span>
                                      </span>
                                    )}
                                  </div>
                                )}
                                {/* JSON details */}
                                <pre className="text-xs text-slate-600 dark:text-slate-300 overflow-x-auto whitespace-pre-wrap font-mono bg-white dark:bg-slate-900 rounded-xl p-4 border border-slate-200 dark:border-slate-800">
                                  {JSON.stringify(log.details, null, 2)}
                                </pre>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}

                  {filtered.length === 0 && allLogs.length > 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-slate-400">
                        No logs match the selected filters
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 dark:border-slate-800">
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Showing {Math.min((page - 1) * PAGE_SIZE + 1, filtered.length)}–
                {Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors"
                >
                  <ChevronLeft size={16} className="text-slate-600 dark:text-slate-300" />
                </button>
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300 min-w-[80px] text-center">
                  {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors"
                >
                  <ChevronRight size={16} className="text-slate-600 dark:text-slate-300" />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </PageLayout>
  );
}
