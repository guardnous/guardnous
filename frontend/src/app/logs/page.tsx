"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import PageLayout from "@/components/PageLayout";
import {
  ScrollText, RefreshCw, Trash2, Filter, Search,
  ChevronDown, ArrowDownToLine, Pause, Play, BarChart3,
} from "lucide-react";

import api, { API_URL } from "@/lib/api";

interface LogEntry {
  id: number;
  level: string;
  category: string;
  message: string;
  source: string;
  user_email: string | null;
  request_method: string | null;
  request_path: string | null;
  status_code: number | null;
  duration_ms: number | null;
  created_at: string;
}

interface LogStats {
  by_level: Record<string, number>;
  by_category: Record<string, number>;
  total: number;
}

const LEVELS = ["DEBUG", "VERBOSE", "INFO", "WARNING", "ERROR", "CRITICAL"];
const CATEGORIES = [
  "AUTH", "USER", "SCAN", "REPORT", "INTEGRATION", "SETTINGS",
  "SYSTEM", "API", "SECURITY", "AI", "IAM", "GOVERNANCE", "NOTIFICATION",
];

const levelColor: Record<string, string> = {
  DEBUG:    "text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800/10",
  VERBOSE:  "text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800/10",
  INFO:     "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10",
  WARNING:  "text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-500/10",
  ERROR:    "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10",
  CRITICAL: "text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-700/20 font-bold",
};

const levelBadge: Record<string, string> = {
  DEBUG:    "bg-gray-200 text-gray-700 dark:bg-gray-600 dark:text-gray-200",
  VERBOSE:  "bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300",
  INFO:     "bg-blue-100 text-blue-700 dark:bg-blue-600 dark:text-blue-100",
  WARNING:  "bg-yellow-100 text-yellow-800 dark:bg-yellow-600 dark:text-yellow-100",
  ERROR:    "bg-red-100 text-red-700 dark:bg-red-600 dark:text-red-100",
  CRITICAL: "bg-red-200 text-red-800 dark:bg-red-800 dark:text-red-100",
};

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [streaming, setStreaming] = useState(false);
  const [tail, setTail] = useState(true);
  const [level, setLevel] = useState("");
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [showStats, setShowStats] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { page: String(page), page_size: "100" };
      if (level) params.level = level;
      if (category) params.category = category;
      if (search) params.search = search;
      const { data } = await api.get("/logs", { params });
      setLogs(data.logs || []);
      setTotal(data.total || 0);
    } catch (err) { console.error("fetchLogs error:", err); }
    setLoading(false);
  }, [page, level, category, search]);

  const fetchStats = useCallback(async () => {
    try {
      const { data } = await api.get("/logs/stats");
      setStats(data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchLogs(); fetchStats(); }, [fetchLogs, fetchStats]);

  // Auto-scroll when in tail mode
  useEffect(() => {
    if (tail && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs, tail]);

  const startStreaming = () => {
    const tk = localStorage.getItem("token");
    if (!tk || esRef.current) return;
    const es = new EventSource(`${API_URL}/api/v1/logs/stream?token=${tk}`);
    es.onmessage = (ev) => {
      try {
        const entry: LogEntry = JSON.parse(ev.data);
        setLogs(prev => [...prev.slice(-499), entry]);
      } catch { /* ignore */ }
    };
    es.onerror = () => { es.close(); setStreaming(false); esRef.current = null; };
    esRef.current = es;
    setStreaming(true);
  };

  const stopStreaming = () => {
    esRef.current?.close();
    esRef.current = null;
    setStreaming(false);
  };

  const clearLogs = async () => {
    if (!confirm("Clear all logs? This action cannot be undone.")) return;
    await api.delete("/logs", { params: { all: true } });
    fetchLogs();
    fetchStats();
  };

  const totalPages = Math.ceil(total / 100);

  return (
    <PageLayout title="System Logs" icon={ScrollText}>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        {/* Stream toggle */}
        <button
          onClick={streaming ? stopStreaming : startStreaming}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
            streaming
              ? "bg-green-600 text-white animate-pulse"
              : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          }`}
        >
          {streaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          {streaming ? "Live" : "Start Live"}
        </button>

        {/* Tail toggle */}
        <button
          onClick={() => setTail(!tail)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-all ${
            tail ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          }`}
        >
          <ArrowDownToLine className="w-4 h-4" />
          Auto-scroll
        </button>

        {/* Refresh */}
        <button
          onClick={() => { fetchLogs(); fetchStats(); }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600 transition-all"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>

        {/* Filters toggle */}
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-all ${
            showFilters ? "bg-orange-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          }`}
        >
          <Filter className="w-4 h-4" />
          Filters
        </button>

        {/* Stats toggle */}
        <button
          onClick={() => setShowStats(!showStats)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm transition-all ${
            showStats ? "bg-purple-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          Stats
        </button>

        {/* Clear */}
        <button
          onClick={clearLogs}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm bg-gray-100 text-red-500 hover:bg-red-50 dark:bg-gray-700 dark:text-red-400 dark:hover:bg-red-600/20 transition-all ml-auto"
        >
          <Trash2 className="w-4 h-4" />
          Clear Old
        </button>

        <span className="text-xs text-gray-500 dark:text-gray-400">{total} entries</span>
      </div>

      {/* Filters panel */}
      {showFilters && (
        <div className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 dark:text-gray-400">Level:</span>
            <select
              value={level}
              onChange={(e) => { setLevel(e.target.value); setPage(1); }}
              className="bg-white text-gray-800 dark:bg-gray-700 dark:text-gray-200 text-sm rounded px-2 py-1 border border-gray-300 dark:border-gray-600"
            >
              <option value="">All</option>
              {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500 dark:text-gray-400">Category:</span>
            <select
              value={category}
              onChange={(e) => { setCategory(e.target.value); setPage(1); }}
              className="bg-white text-gray-800 dark:bg-gray-700 dark:text-gray-200 text-sm rounded px-2 py-1 border border-gray-300 dark:border-gray-600"
            >
              <option value="">All</option>
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search logs..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="bg-white text-gray-800 dark:bg-gray-700 dark:text-gray-200 text-sm rounded px-2 py-1 border border-gray-300 dark:border-gray-600 w-full"
            />
          </div>
        </div>
      )}

      {/* Stats bar */}
      {showStats && stats && (
        <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex flex-wrap gap-4">
            <div>
              <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">By Level (24h)</span>
              <div className="flex gap-2 flex-wrap">
                {Object.entries(stats.by_level).map(([k, v]) => (
                  <span key={k} className={`text-xs px-2 py-0.5 rounded ${levelBadge[k] || "bg-gray-200 text-gray-700 dark:bg-gray-600 dark:text-gray-200"}`}>
                    {k}: {v}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <span className="text-xs text-gray-500 dark:text-gray-400 block mb-1">By Category (24h)</span>
              <div className="flex gap-2 flex-wrap">
                {Object.entries(stats.by_category).map(([k, v]) => (
                  <span key={k} className="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-700 dark:bg-gray-600 dark:text-gray-200">
                    {k}: {v}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Log entries */}
      <div
        ref={logRef}
        className="bg-white dark:bg-gray-950 rounded-lg border border-gray-200 dark:border-gray-700 overflow-y-auto font-mono text-xs"
        style={{ maxHeight: "calc(100vh - 280px)" }}
      >
        {logs.length === 0 && !loading && (
          <div className="flex items-center justify-center h-40 text-gray-500 dark:text-gray-400">
            No log entries found
          </div>
        )}
        {logs.map((entry) => (
          <div
            key={entry.id}
            className={`flex items-start gap-3 px-3 py-1.5 border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/30 ${levelColor[entry.level] || ""}`}
          >
            {/* Timestamp */}
            <span className="text-gray-500 dark:text-gray-400 whitespace-nowrap shrink-0">
              {new Date(entry.created_at).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </span>

            {/* Level badge */}
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0 w-16 text-center ${levelBadge[entry.level] || "bg-gray-200 dark:bg-gray-600"}`}>
              {entry.level}
            </span>

            {/* Category */}
            <span className="text-gray-500 dark:text-gray-400 shrink-0 w-24 truncate">
              [{entry.category}]
            </span>

            {/* Message */}
            <span className="text-gray-800 dark:text-gray-200 flex-1 break-all">
              {entry.message}
            </span>

            {/* Source */}
            {entry.source && (
              <span className="text-gray-400 dark:text-gray-500 shrink-0 text-[10px]">
                {entry.source}
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Pagination */}
      {!streaming && totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-3">
          <button
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
            className="px-3 py-1 text-sm bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40"
          >
            Prev
          </button>
          <span className="text-sm text-gray-500 dark:text-gray-400">
            Page {page} of {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage(p => p + 1)}
            className="px-3 py-1 text-sm bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 rounded hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}
    </PageLayout>
  );
}
