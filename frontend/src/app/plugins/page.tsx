"use client";

import React, { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPlugins,
  togglePlugin,
  getPluginVersions,
  installPluginVersion,
  activatePluginVersion,
  rollbackPluginVersion,
  getVersionPolicy,
  updateVersionPolicy,
  getSupplyChainHealth,
  getPluginIntegrity,
  approvePluginBinary,
} from "@/lib/api";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Puzzle,
  Search,
  Shield,
  Key,
  Code,
  FileCheck,
  Bug,
  Loader2,
  BookOpen,
  X,
  ChevronRight,
  Zap,
  Layers,
  Power,
  Cloud,
  Building2,
  Download,
  RotateCcw,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Package,
  Settings2,
  Activity,
} from "lucide-react";

/* ─────────────────────────── Types ─────────────────────────── */

interface Plugin {
  name: string;
  display_name: string;
  description: string;
  plugin_type: "native" | "external";
  enabled: boolean;
  capabilities: string[];
  severity_levels: string[];
  total_rules: number;
}

interface PluginsResponse {
  plugins: Plugin[];
  total: number;
  enabled_count: number;
  native_count: number;
  external_count: number;
}

interface PluginVersion {
  plugin_name: string;
  version: string;
  status: string;
  install_method: string;
  sha256: string | null;
  binary_path: string | null;
  installed_at: number | null;
  cve_ids: string[];
  size_bytes: number;
}

interface VersionsResponse {
  plugin_name: string;
  versions: PluginVersion[];
  active_version: string | null;
  total: number;
}

interface VersionPolicy {
  plugin_name: string;
  pinned_version: string | null;
  auto_update: boolean;
  auto_rollback: boolean;
  max_cached_versions: number;
  blocked_versions: string[];
}

interface SupplyChainAlert {
  alert_id: string;
  severity: string;
  plugin_name: string;
  alert_type: string;
  title: string;
  description: string;
  cve_ids: string[];
  auto_remediated: boolean;
  timestamp: number;
}

interface SupplyChainReport {
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  alerts: SupplyChainAlert[];
  plugins_checked: string[];
  auto_remediations: number;
}

/* ── Version Management Panel (inside modal) ── */

function VersionPanel({ pluginName }: { pluginName: string }) {
  const queryClient = useQueryClient();
  const [installVersion, setInstallVersion] = useState("");

  const { data: vData, isLoading: vLoading } = useQuery<VersionsResponse>({
    queryKey: ["plugin-versions", pluginName],
    queryFn: () => getPluginVersions(pluginName),
  });

  const { data: policy } = useQuery<VersionPolicy>({
    queryKey: ["plugin-policy", pluginName],
    queryFn: () => getVersionPolicy(pluginName),
  });

  const activateMut = useMutation({
    mutationFn: (ver: string) => activatePluginVersion(pluginName, ver),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugin-versions", pluginName] }),
  });

  const installMut = useMutation({
    mutationFn: (ver: string) => installPluginVersion(pluginName, ver),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["plugin-versions", pluginName] });
      setInstallVersion("");
    },
  });

  const rollbackMut = useMutation({
    mutationFn: () => rollbackPluginVersion(pluginName),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugin-versions", pluginName] }),
  });

  const policyMut = useMutation({
    mutationFn: (upd: Record<string, unknown>) => updateVersionPolicy(pluginName, upd),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugin-policy", pluginName] }),
  });

  if (vLoading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-slate-600 dark:text-slate-400">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading versions…
      </div>
    );
  }

  const versions = vData?.versions ?? [];
  const activeVer = vData?.active_version;

  const statusColor = (s: string) => {
    switch (s) {
      case "active": return "text-emerald-800 bg-emerald-100 border-emerald-300 dark:text-emerald-400 dark:bg-emerald-900/30 dark:border-emerald-800/40";
      case "available": return "text-blue-800 bg-blue-100 border-blue-300 dark:text-blue-400 dark:bg-blue-900/30 dark:border-blue-800/40";
      case "vulnerable": return "text-red-800 bg-red-100 border-red-300 dark:text-red-400 dark:bg-red-900/30 dark:border-red-800/40";
      case "downloading": return "text-amber-800 bg-amber-100 border-amber-300 dark:text-amber-400 dark:bg-amber-900/30 dark:border-amber-800/40";
      default: return "text-slate-700 bg-slate-100 border-slate-300 dark:text-slate-400 dark:bg-slate-800/30 dark:border-slate-700/40";
    }
  };

  return (
    <div className="space-y-4">
      {/* Active Version Badge */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Package className="w-4 h-4 text-orange-600 dark:text-orange-400" />
          <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">
            Active: <span className="text-orange-700 dark:text-orange-400 font-mono">{activeVer || "none"}</span>
          </span>
        </div>
        <button
          onClick={() => rollbackMut.mutate()}
          disabled={rollbackMut.isPending || versions.length < 2}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-50 text-amber-800 border border-amber-300 hover:bg-amber-100 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800/40 dark:hover:bg-amber-900/40 transition-colors disabled:opacity-40"
        >
          <RotateCcw className="w-3 h-3" />
          Rollback
        </button>
      </div>

      {/* Cached Versions List */}
      {versions.length > 0 ? (
        <div className="space-y-2">
          {versions.map((v) => (
            <div
              key={v.version}
              className={`flex items-center justify-between rounded-xl border px-4 py-3 ${
                v.version === activeVer
                  ? "bg-orange-50 border-orange-300 dark:bg-orange-900/10 dark:border-orange-700/40"
                  : "bg-slate-50 border-slate-200 dark:bg-slate-800/30 dark:border-slate-700/30"
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-sm font-mono text-slate-900 dark:text-slate-100">{v.version}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${statusColor(v.status)}`}>
                  {v.status}
                </span>
                {v.cve_ids.length > 0 && (
                  <span className="flex items-center gap-1 text-red-700 dark:text-red-400 text-[11px]">
                    <ShieldAlert className="w-3 h-3" />
                    {v.cve_ids.length} CVE{v.cve_ids.length > 1 ? "s" : ""}
                  </span>
                )}
              </div>
              {v.status === "available" && (
                <button
                  onClick={() => activateMut.mutate(v.version)}
                  disabled={activateMut.isPending}
                  className="text-xs px-3 py-1 rounded-lg bg-emerald-50 text-emerald-800 border border-emerald-300 hover:bg-emerald-100 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/40 dark:hover:bg-emerald-900/40 transition-colors disabled:opacity-40"
                >
                  Activate
                </button>
              )}
              {v.version === activeVer && (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              )}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-xs text-slate-600 dark:text-slate-500 italic">No cached versions</p>
      )}

      {/* Install New Version */}
      <div className="flex gap-2">
        <input
          type="text"
          value={installVersion}
          onChange={(e) => setInstallVersion(e.target.value)}
          placeholder="e.g. 1.96.0"
          className="flex-1 h-9 px-3 rounded-lg border border-slate-300 bg-white text-sm text-slate-900 placeholder:text-slate-500 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-200 dark:placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-orange-500"
        />
        <button
          onClick={() => installVersion && installMut.mutate(installVersion)}
          disabled={!installVersion || installMut.isPending}
          className="flex items-center gap-1.5 px-4 h-9 rounded-lg text-xs font-semibold bg-orange-600 text-white hover:bg-orange-700 transition-colors disabled:opacity-40"
        >
          <Download className="w-3.5 h-3.5" />
          Install
        </button>
      </div>

      {/* Policy Settings */}
      {policy && (
        <div className="rounded-xl border border-slate-200 bg-slate-50 dark:border-slate-700/40 dark:bg-slate-800/20 p-4 space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <Settings2 className="w-4 h-4 text-slate-500 dark:text-slate-400" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400">Version Policy</span>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={policy.auto_update}
                onChange={(e) => policyMut.mutate({ auto_update: e.target.checked })}
                className="rounded border-slate-300 bg-white dark:border-slate-600 dark:bg-slate-800 text-orange-500 focus:ring-orange-500"
              />
              Auto-update
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={policy.auto_rollback}
                onChange={(e) => policyMut.mutate({ auto_rollback: e.target.checked })}
                className="rounded border-slate-300 bg-white dark:border-slate-600 dark:bg-slate-800 text-orange-500 focus:ring-orange-500"
              />
              Auto-rollback on CVE
            </label>
          </div>
          {policy.pinned_version && (
            <p className="text-[11px] text-amber-700 dark:text-amber-400">
              ⚠ Pinned to <span className="font-mono">{policy.pinned_version}</span>
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Adapter files that could not be loaded at startup ── */

interface PluginLoadError {
  module: string;
  adapter: string;
  error: string;
}

function LoadErrorsBox() {
  const { data } = useQuery<{ load_errors: PluginLoadError[] }>({
    queryKey: ["plugin-load-errors"],
    queryFn: () => api.get("/plugins/load-errors").then((r) => r.data),
    retry: false,
  });
  const errors = data?.load_errors ?? [];
  if (errors.length === 0) return null;
  return (
    <div className="mb-6 rounded-2xl border border-amber-300 bg-amber-50 p-4 dark:border-amber-800/50 dark:bg-amber-900/20">
      <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
        {errors.length === 1 ? "1 scanner adapter was not loaded" : `${errors.length} scanner adapters were not loaded`}
      </p>
      <p className="mt-1 text-xs text-amber-800 dark:text-amber-300">
        The other scanners are working. Fix the file and restart the server; the full error is in the server log.
      </p>
      <ul className="mt-3 space-y-1.5">
        {errors.map((e) => (
          <li key={`${e.module}:${e.adapter}`} className="text-xs text-amber-900 dark:text-amber-200">
            <span className="font-mono font-semibold">{e.module}{e.adapter ? ` (${e.adapter})` : ""}</span>
            <span className="ml-2 break-words">{e.error}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ── Scanner binary integrity ── */

interface IntegrityItem {
  plugin: string;
  binary: string;
  status: "verified" | "not_pinned_yet" | "mismatch" | "not_installed";
  path: string | null;
  sha256: string | null;
  expected_sha256: string | null;
  approved_by: string | null;
}

const INTEGRITY_LABEL: Record<IntegrityItem["status"], { text: string; cls: string }> = {
  verified: { text: "Verified", cls: "text-emerald-700 border-emerald-300 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/40 dark:bg-emerald-900/20" },
  not_pinned_yet: { text: "Pinned on first scan", cls: "text-blue-700 border-blue-300 bg-blue-50 dark:text-blue-300 dark:border-blue-800/40 dark:bg-blue-900/20" },
  mismatch: { text: "Changed — blocked", cls: "text-red-700 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20" },
  not_installed: { text: "Not installed", cls: "text-gray-600 border-gray-300 bg-gray-100 dark:text-gray-400 dark:border-gray-700 dark:bg-gray-800/40" },
};

function IntegrityPanel() {
  const queryClient = useQueryClient();
  const { data } = useQuery<{ mode: string; items: IntegrityItem[] }>({
    queryKey: ["plugin-integrity"],
    queryFn: getPluginIntegrity,
    refetchInterval: 60_000,
    retry: 1,
  });
  const approve = useMutation({
    mutationFn: (plugin: string) => approvePluginBinary(plugin),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["plugin-integrity"] });
      queryClient.invalidateQueries({ queryKey: ["supply-chain-health"] });
    },
  });

  if (!data || data.items.length === 0) return null;
  const approveError = (approve.error as { response?: { data?: { detail?: string } } } | null)
    ?.response?.data?.detail;

  return (
    <div className="rounded-2xl border border-gray-200 bg-white px-5 py-4 mb-6 dark:border-gray-800 dark:bg-gray-900/40">
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm font-semibold text-gray-900 dark:text-gray-200">Scanner binary integrity</p>
        <p className="text-xs text-gray-500">
          SHA-256 checked before every scan · mode: {data.mode}
        </p>
      </div>
      {approveError && <p className="text-xs text-red-600 dark:text-red-400 mb-2">{approveError}</p>}
      <div className="space-y-2">
        {data.items.map((item) => {
          const label = INTEGRITY_LABEL[item.status];
          return (
            <div key={item.plugin} className="flex items-center gap-3 text-xs">
              <span className="w-24 font-medium text-gray-900 dark:text-gray-200">{item.plugin}</span>
              <span className={`px-2 py-0.5 rounded border ${label.cls}`}>{label.text}</span>
              <span className="flex-1 min-w-0 truncate font-mono text-gray-500" title={item.sha256 ?? ""}>
                {item.path ?? "—"}
                {item.sha256 ? ` · ${item.sha256.slice(0, 16)}…` : ""}
              </span>
              {item.status === "mismatch" && (
                <button
                  onClick={() => {
                    if (window.confirm(
                      `Approve the current ${item.binary} binary?\n\nExpected ${item.expected_sha256}\nFound    ${item.sha256}\n\nOnly approve if you upgraded this scanner yourself.`
                    )) approve.mutate(item.plugin);
                  }}
                  disabled={approve.isPending}
                  className="px-2 py-1 rounded border border-red-400 text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-700 dark:text-red-200 dark:hover:bg-red-900/30"
                >
                  Approve new binary
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Supply Chain Health Banner ── */

function SupplyChainBanner() {
  const { data, isLoading } = useQuery<SupplyChainReport>({
    queryKey: ["supply-chain-health"],
    queryFn: getSupplyChainHealth,
    refetchInterval: 300_000, // 5 min
    retry: 1,
  });

  if (isLoading || !data) return null;

  const hasCritical = data.critical_alerts > 0;
  const hasHigh = data.high_alerts > 0;

  if (data.total_alerts === 0) {
    return (
      <div className="flex items-center gap-3 rounded-2xl border border-emerald-300 bg-emerald-50 px-5 py-3 mb-6 dark:border-emerald-800/30 dark:bg-emerald-900/10">
        <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
        <p className="text-sm text-emerald-800 dark:text-emerald-300">
          Supply chain healthy — {data.plugins_checked.length} scanners verified, no CVEs or integrity issues.
        </p>
      </div>
    );
  }

  return (
    <div
      className={`rounded-2xl border px-5 py-4 mb-6 ${
        hasCritical
          ? "border-red-300 bg-red-50 dark:border-red-800/40 dark:bg-red-900/10"
          : hasHigh
          ? "border-amber-300 bg-amber-50 dark:border-amber-800/40 dark:bg-amber-900/10"
          : "border-blue-300 bg-blue-50 dark:border-blue-800/40 dark:bg-blue-900/10"
      }`}
    >
      <div className="flex items-start gap-3">
        <ShieldAlert className={`w-5 h-5 shrink-0 mt-0.5 ${hasCritical ? "text-red-600 dark:text-red-400" : hasHigh ? "text-amber-600 dark:text-amber-400" : "text-blue-600 dark:text-blue-400"}`} />
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold ${hasCritical ? "text-red-800 dark:text-red-300" : hasHigh ? "text-amber-800 dark:text-amber-300" : "text-blue-800 dark:text-blue-300"}`}>
            {data.total_alerts} supply chain alert{data.total_alerts !== 1 ? "s" : ""} detected
            {data.auto_remediations > 0 && (
              <span className="ml-2 text-xs font-normal text-emerald-700 dark:text-emerald-400">
                ({data.auto_remediations} auto-remediated)
              </span>
            )}
          </p>
          <div className="flex flex-wrap gap-2 mt-2">
            {data.alerts.slice(0, 3).map((a) => (
              <span
                key={a.alert_id}
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${
                  a.severity === "critical"
                    ? "text-red-800 bg-red-100 border-red-300 dark:text-red-400 dark:bg-red-900/30 dark:border-red-800/40"
                    : a.severity === "high"
                    ? "text-amber-800 bg-amber-100 border-amber-300 dark:text-amber-400 dark:bg-amber-900/30 dark:border-amber-800/40"
                    : "text-blue-800 bg-blue-100 border-blue-300 dark:text-blue-400 dark:bg-blue-900/30 dark:border-blue-800/40"
                }`}
              >
                {a.auto_remediated && <CheckCircle2 className="w-3 h-3" />}
                {a.plugin_name}: {a.title}
              </span>
            ))}
            {data.alerts.length > 3 && (
              <span className="text-[11px] text-slate-600 dark:text-slate-400">+{data.alerts.length - 3} more</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────── Helpers ─────────────────────────── */

type StatusFilter = "all" | "enabled" | "disabled";
type TypeFilter = "all" | "native" | "external";

function getPluginIcon(name: string): React.ElementType {
  const n = name.toLowerCase();
  if (n.includes("terraform") || n.includes("tfsec")) return Shield;
  if (n.includes("cloudformation")) return Cloud;
  if (n.includes("bicep")) return Building2;
  if (n.includes("secret") || n.includes("gitleaks") || n.includes("key")) return Key;
  if (n.includes("semgrep") || n.includes("code") || n.includes("sast")) return Code;
  if (n.includes("checkov") || n.includes("check") || n.includes("filecheck")) return FileCheck;
  if (n.includes("trivy") || n.includes("vuln") || n.includes("bug")) return Bug;
  if (n.includes("doc") || n.includes("readme")) return BookOpen;
  return Layers;
}

function getPluginGradient(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("terraform")) return "from-violet-500 to-purple-600";
  if (n.includes("cloudformation")) return "from-orange-500 to-amber-600";
  if (n.includes("bicep")) return "from-sky-500 to-blue-600";
  if (n.includes("secret") || n.includes("gitleaks")) return "from-red-500 to-rose-600";
  if (n.includes("semgrep")) return "from-amber-500 to-orange-600";
  if (n.includes("tfsec") || n.includes("checkov")) return "from-cyan-500 to-blue-600";
  if (n.includes("trivy")) return "from-emerald-500 to-teal-600";
  return "from-orange-500 to-blue-600";
}

/* ─────────────────────────── Component ─────────────────────── */

export default function PluginsPage() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selectedPlugin, setSelectedPlugin] = useState<Plugin | null>(null);

  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<PluginsResponse>({
    queryKey: ["plugins"],
    queryFn: getPlugins,
  });

  const toggleMutation = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      togglePlugin(name, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugins"] }),
  });

  const handleToggle = useCallback(
    (e: React.MouseEvent, plugin: Plugin) => {
      e.stopPropagation();
      toggleMutation.mutate({ name: plugin.name, enabled: !plugin.enabled });
    },
    [toggleMutation]
  );

  const plugins = data?.plugins ?? [];
  const totalCount = data?.total ?? plugins.length;
  const enabledCount = data?.enabled_count ?? plugins.filter((p) => p.enabled).length;
  const nativeCount = data?.native_count ?? plugins.filter((p) => p.plugin_type === "native").length;
  const externalCount = data?.external_count ?? plugins.filter((p) => p.plugin_type === "external").length;

  const filtered = useMemo(() => {
    return plugins.filter((p) => {
      if (typeFilter !== "all" && p.plugin_type !== typeFilter) return false;
      if (statusFilter === "enabled" && !p.enabled) return false;
      if (statusFilter === "disabled" && p.enabled) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          p.display_name.toLowerCase().includes(q) ||
          p.name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [plugins, typeFilter, statusFilter, search]);

  /* ── Stats Bar ── */
  const stats = [
    { label: "Total Plugins", value: totalCount, color: "text-slate-900 dark:text-slate-100" },
    { label: "Enabled", value: enabledCount, color: "text-emerald-600 dark:text-emerald-400", dot: "bg-emerald-500" },
    { label: "Native", value: nativeCount, color: "text-blue-600 dark:text-blue-400", badge: "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400" },
    { label: "External", value: externalCount, color: "text-purple-600 dark:text-purple-400", badge: "bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400" },
  ];

  return (
    <PageLayout title="Plugins" subtitle="Security scanning plugins and analyzers" icon={Puzzle}>
      {/* Supply Chain Health Banner */}
      <SupplyChainBanner />
      <LoadErrorsBox />
      <IntegrityPanel />

      {/* Stats Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map((s) => (
          <div
            key={s.label}
            className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5"
          >
            <div className="flex items-center gap-2 mb-1">
              {s.dot && <span className={`w-2 h-2 rounded-full ${s.dot}`} />}
              {s.badge && (
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${s.badge}`}>
                  {s.label === "Native" ? "NAT" : "EXT"}
                </span>
              )}
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400">{s.label}</span>
            </div>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filters Row */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-6">
        {/* Search */}
        <div className="relative flex-1 max-w-md w-full">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search plugins…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full h-12 pl-11 pr-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
          />
        </div>

        {/* Type Filter */}
        <div className="flex items-center rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden h-12">
          {(["all", "native", "external"] as TypeFilter[]).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-4 h-full text-sm font-medium transition-colors capitalize ${
                typeFilter === t
                  ? "bg-orange-600 text-white"
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Status Filter */}
        <div className="flex items-center rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden h-12">
          {(["all", "enabled", "disabled"] as StatusFilter[]).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-4 h-full text-sm font-medium transition-colors capitalize ${
                statusFilter === s
                  ? "bg-orange-600 text-white"
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-orange-500 animate-spin" />
          <span className="ml-3 text-sm text-slate-500 dark:text-slate-400">Loading plugins…</span>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && filtered.length === 0 && (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
          <Puzzle className="w-12 h-12 text-slate-300 dark:text-slate-700 dark:text-slate-200 mx-auto mb-3" />
          <p className="text-slate-900 dark:text-slate-100 font-semibold mb-1">No plugins found</p>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {search
              ? `No plugins match "${search}"`
              : "No plugins match the selected filters."}
          </p>
        </div>
      )}

      {/* Plugin Cards Grid */}
      {!isLoading && filtered.length > 0 && (
        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-5">
          {filtered.map((plugin) => {
            const Icon = getPluginIcon(plugin.name);
            const gradient = getPluginGradient(plugin.name);

            return (
              <button
                key={plugin.name}
                onClick={() => setSelectedPlugin(plugin)}
                className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 text-left hover:shadow-lg hover:shadow-slate-200/50 dark:hover:shadow-slate-950/50 hover:border-orange-300 dark:hover:border-orange-700 transition-all group flex flex-col h-full"
              >
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-11 h-11 rounded-xl bg-gradient-to-br ${gradient} flex items-center justify-center shadow-lg shadow-orange-500/10`}
                    >
                      <Icon className="w-5 h-5 text-white" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 truncate">
                        {plugin.display_name}
                      </h3>
                      <span
                        className={`inline-block mt-0.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          plugin.plugin_type === "native"
                            ? "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400"
                            : "bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400"
                        }`}
                      >
                        {plugin.plugin_type}
                      </span>
                    </div>
                  </div>

                  {/* Toggle Button */}
                  <button
                    onClick={(e) => handleToggle(e, plugin)}
                    disabled={toggleMutation.isPending}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ${
                      plugin.enabled ? "bg-emerald-500" : "bg-slate-300 dark:bg-slate-600"
                    }`}
                    title={plugin.enabled ? "Click to disable" : "Click to enable"}
                  >
                    <span
                      className={`inline-block h-4 w-4 rounded-full bg-white shadow-sm transform transition-transform ${
                        plugin.enabled ? "translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed mb-4 line-clamp-2 flex-grow">
                  {plugin.description}
                </p>

                {/* Capabilities */}
                {plugin.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {plugin.capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400"
                      >
                        {cap}
                      </span>
                    ))}
                  </div>
                )}

                {/* Footer */}
                <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-slate-800 mt-auto">
                  <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                    <Zap className="w-3.5 h-3.5" />
                    <span>{plugin.total_rules} rules</span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-300 dark:text-slate-600 dark:text-slate-300 group-hover:text-orange-500 transition-colors" />
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Plugin Detail Modal */}
      {selectedPlugin && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
          onClick={() => setSelectedPlugin(null)}
        >
          <div
            className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-start justify-between p-6 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div
                  className={`w-12 h-12 rounded-xl bg-gradient-to-br ${getPluginGradient(
                    selectedPlugin.name
                  )} flex items-center justify-center shadow-lg`}
                >
                  {React.createElement(getPluginIcon(selectedPlugin.name), {
                    className: "w-6 h-6 text-white",
                  })}
                </div>
                <div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                    {selectedPlugin.display_name}
                  </h2>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        selectedPlugin.plugin_type === "native"
                          ? "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400"
                          : "bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400"
                      }`}
                    >
                      {selectedPlugin.plugin_type}
                    </span>
                    <span className="flex items-center gap-1.5">
                      {selectedPlugin.enabled && (
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      )}
                      <span
                        className={`text-xs font-medium ${
                          selectedPlugin.enabled
                            ? "text-emerald-600 dark:text-emerald-400"
                            : "text-slate-400"
                        }`}
                      >
                        {selectedPlugin.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5">
              {/* Description */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400 mb-2">
                  Description
                </h4>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                  {selectedPlugin.description}
                </p>
              </div>

              {/* Rule Count */}
              <div className="flex items-center gap-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4">
                <Zap className="w-5 h-5 text-orange-500" />
                <div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {selectedPlugin.total_rules} Rules
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Total scanning rules available</p>
                </div>
              </div>

              {/* Capabilities */}
              {selectedPlugin.capabilities.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400 mb-2">
                    Capabilities
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedPlugin.capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="px-3 py-1 rounded-lg text-xs font-medium bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-400 border border-orange-100 dark:border-orange-800/30"
                      >
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Severity Levels */}
              {selectedPlugin.severity_levels && selectedPlugin.severity_levels.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400 mb-2">
                    Severity Levels
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedPlugin.severity_levels.map((level) => {
                      const l = level.toLowerCase();
                      const cls =
                        l === "critical"
                          ? "bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/30"
                          : l === "high"
                          ? "bg-orange-50 dark:bg-orange-900/20 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800/30"
                          : l === "medium"
                          ? "bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/30"
                          : l === "low"
                          ? "bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800/30"
                          : "bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700";
                      return (
                        <span
                          key={level}
                          className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize border ${cls}`}
                        >
                          {level}
                        </span>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Internal name */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400 mb-2">
                  Plugin ID
                </h4>
                <code className="text-xs font-mono text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-3 py-1.5 rounded-lg">
                  {selectedPlugin.name}
                </code>
              </div>

              {/* Version Management (external plugins only) */}
              {selectedPlugin.plugin_type === "external" && (
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400 mb-3 flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5" />
                    Version Management
                  </h4>
                  <VersionPanel pluginName={selectedPlugin.name} />
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between p-6 border-t border-slate-100 dark:border-slate-800">
              <button
                onClick={(e) => {
                  handleToggle(e as any, selectedPlugin);
                  setSelectedPlugin({ ...selectedPlugin, enabled: !selectedPlugin.enabled });
                }}
                disabled={toggleMutation.isPending}
                className={`flex items-center gap-2 px-5 h-12 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50 ${
                  selectedPlugin.enabled
                    ? "bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 hover:bg-red-100 dark:hover:bg-red-900/40"
                    : "bg-emerald-600 text-white hover:bg-emerald-700"
                }`}
              >
                <Power className="w-4 h-4" />
                {selectedPlugin.enabled ? "Disable Plugin" : "Enable Plugin"}
              </button>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-5 h-12 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
