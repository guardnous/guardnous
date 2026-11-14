"use client";

import React, { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import PageLayout from "@/components/PageLayout";
import {
  getIAMDashboard,
  getIAMIdentities,
  getIAMThreats,
  getIAMAttackPaths,
  startIAMScan,
  updateThreatStatus,
} from "@/lib/api";
import {
  Shield,
  ShieldAlert,
  Users,
  Bot,
  Key,
  AlertTriangle,
  Search,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Scan,
  Eye,
  Lock,
  Unlock,
  UserX,
  Activity,
  TrendingUp,
  Zap,
  Target,
  ChevronDown,
  ChevronUp,
  Cloud,
  CheckCircle2,
  XCircle,
  Info,
} from "lucide-react";

/* ─── Types ─────────────────────────────────────────────── */
interface Identity {
  id: number;
  cloud_provider: string;
  identity_type: string;
  external_id: string;
  display_name: string | null;
  email: string | null;
  is_active: boolean;
  days_inactive: number;
  risk_score: number;
  risk_level: string;
  risk_factors: Array<{ factor: string; score: number; details: string }>;
  permissions_count: number;
  admin_access: boolean;
  mfa_enabled: boolean | null;
  has_console_access: boolean | null;
  has_programmatic_access: boolean | null;
  access_keys: Array<Record<string, unknown>>;
  credential_age_days: number;
  attached_policies: Array<{ name: string; type: string }>;
  group_memberships: string[];
  created_at: string;
}

interface Threat {
  id: number;
  identity_id: number;
  threat_type: string;
  title: string;
  description: string | null;
  severity: string;
  confidence: number;
  detection_method: string | null;
  evidence: Record<string, unknown>;
  mitre_tactic: string | null;
  status: string;
  remediation_steps: Array<{ step: number; description: string; automated: boolean }>;
  auto_remediable: boolean;
  created_at: string;
}

interface AttackPath {
  id: number;
  title: string;
  description: string | null;
  severity: string;
  complexity: string;
  target_resource: string | null;
  path_steps: Array<{ step_num: number; action: string; resource: string }>;
  risk_score: number;
  status: string;
  created_at: string;
}

interface DashboardStats {
  total_identities: number;
  active_identities: number;
  dormant_identities: number;
  service_accounts: number;
  admin_users: number;
  mfa_disabled: number;
  total_threats: number;
  critical_threats: number;
  high_threats: number;
  open_threats: number;
  attack_paths: number;
  avg_risk_score: number;
  by_provider: Record<string, number>;
  by_identity_type: Record<string, number>;
  by_risk_level: Record<string, number>;
  credential_issues: number;
  excessive_permissions: number;
}

/* ─── Helpers ───────────────────────────────────────────── */
const SEVERITY_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: "bg-red-50 dark:bg-red-950/30", text: "text-red-700 dark:text-red-400", dot: "bg-red-500" },
  high: { bg: "bg-orange-50 dark:bg-orange-950/30", text: "text-orange-700 dark:text-orange-400", dot: "bg-orange-500" },
  medium: { bg: "bg-amber-50 dark:bg-amber-950/30", text: "text-amber-700 dark:text-amber-400", dot: "bg-amber-500" },
  low: { bg: "bg-blue-50 dark:bg-blue-950/30", text: "text-blue-700 dark:text-blue-400", dot: "bg-blue-500" },
  info: { bg: "bg-slate-50 dark:bg-slate-800/50", text: "text-slate-600 dark:text-slate-400", dot: "bg-slate-400" },
};

const RISK_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-slate-400",
};

const TYPE_ICONS: Record<string, React.ElementType> = {
  user: Users,
  service_account: Bot,
  role: Key,
  group: Users,
  federated: Cloud,
  api_key: Lock,
};

function SeverityBadge({ level }: { level: string }) {
  const c = SEVERITY_COLORS[level] || SEVERITY_COLORS.info;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${c.bg} ${c.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {level.toUpperCase()}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className="text-xs font-mono font-semibold text-slate-600 dark:text-slate-400 w-8 text-right">{Math.round(score)}</span>
    </div>
  );
}

/* ─── Tabs ──────────────────────────────────────────────── */
type TabKey = "overview" | "identities" | "threats" | "attack-paths";

const TABS: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "overview", label: "Overview", icon: Shield },
  { key: "identities", label: "Identities", icon: Users },
  { key: "threats", label: "Threats", icon: ShieldAlert },
  { key: "attack-paths", label: "Attack Paths", icon: Target },
];

/* ─── Component ─────────────────────────────────────────── */
export default function IAMPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const pageSize = 15;

  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["iam-dashboard"],
    queryFn: getIAMDashboard,
  });

  const { data: identitiesData, isLoading: identitiesLoading } = useQuery({
    queryKey: ["iam-identities", page, search, providerFilter, typeFilter, riskFilter],
    queryFn: () =>
      getIAMIdentities({
        page,
        page_size: pageSize,
        search: search || undefined,
        cloud_provider: providerFilter || undefined,
        identity_type: typeFilter || undefined,
        risk_level: riskFilter || undefined,
      }),
    enabled: activeTab === "identities",
  });

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ["iam-threats", page, severityFilter],
    queryFn: () =>
      getIAMThreats({
        page,
        page_size: pageSize,
        severity: severityFilter || undefined,
      }),
    enabled: activeTab === "threats",
  });

  const { data: attackPaths, isLoading: pathsLoading } = useQuery<AttackPath[]>({
    queryKey: ["iam-attack-paths"],
    queryFn: () => getIAMAttackPaths({}),
    enabled: activeTab === "attack-paths",
  });

  const [scanProvider, setScanProvider] = useState("aws");
  const scanMutation = useMutation({
    mutationFn: () => startIAMScan({ cloud_provider: scanProvider, scan_type: "full" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["iam-dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["iam-identities"] });
      queryClient.invalidateQueries({ queryKey: ["iam-threats"] });
      queryClient.invalidateQueries({ queryKey: ["iam-attack-paths"] });
    },
  });

  const handleTabChange = useCallback((tab: TabKey) => {
    setActiveTab(tab);
    setPage(1);
    setExpandedId(null);
  }, []);

  const identities: Identity[] = identitiesData?.items || [];
  const totalIdentities = identitiesData?.total || 0;
  const threats: Threat[] = threatsData?.items || [];
  const totalThreats = threatsData?.total || 0;
  const paths: AttackPath[] = attackPaths || [];

  const totalPages = activeTab === "identities"
    ? Math.ceil(totalIdentities / pageSize)
    : activeTab === "threats"
    ? Math.ceil(totalThreats / pageSize)
    : 1;

  /* ─── Scan Button ─── */
  const scanButton = (
    <div className="flex items-center gap-2">
      <select
        value={scanProvider}
        onChange={(e) => setScanProvider(e.target.value)}
        aria-label="Cloud provider to analyze"
        className="h-11 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
      >
        <option value="aws">AWS</option>
        <option value="azure">Azure</option>
        <option value="gcp">GCP</option>
      </select>
      <button
        onClick={() => scanMutation.mutate()}
        disabled={scanMutation.isPending}
        className="inline-flex items-center gap-2 px-5 h-11 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold text-sm transition-colors disabled:opacity-50"
      >
        {scanMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Scan className="w-4 h-4" />}
        {scanMutation.isPending ? "Analyzing..." : "Run IAM Scan"}
      </button>
    </div>
  );

  return (
    <PageLayout
      title="IAM Threat Intelligence"
      subtitle="Identity inventory, privilege analysis & threat detection"
      icon={ShieldAlert}
      actions={scanButton}
      breadcrumbs={[{ label: "Home", href: "/dashboard" }, { label: "IAM Intelligence" }]}
    >
      {/* Scan success banner */}
      {scanMutation.isSuccess && (
        <div className="mb-6 p-4 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 rounded-xl flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-600" />
          <p className="text-sm text-emerald-700 dark:text-emerald-400">
            IAM scan completed — {scanMutation.data?.identities_scanned} identities analyzed, {scanMutation.data?.threats_found} posture findings.
            {scanMutation.data?.summary?.note ? ` ${scanMutation.data.summary.note}` : ""}
          </p>
        </div>
      )}
      {scanMutation.isError && (
        <div className="mb-6 p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl text-sm text-amber-800 dark:text-amber-300">
          {(scanMutation.error as any)?.response?.data?.detail || "IAM scan failed."}{" "}
          <a href="/cloud-accounts" className="underline font-medium">Open Cloud Connectors</a>
        </div>
      )}

      {/* Tab Bar */}
      <div className="flex gap-1 p-1 bg-slate-100 dark:bg-slate-800/50 rounded-xl mb-6 max-w-fit">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => handleTabChange(tab.key)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-white dark:bg-slate-700 text-orange-600 dark:text-orange-400 shadow-sm"
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ─── Overview Tab ─── */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {statsLoading ? (
            <div className="flex justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>
          ) : stats ? (
            <>
              {/* Stat Cards Row 1 */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                {[
                  { label: "Total Identities", value: stats.total_identities, icon: Users, color: "text-orange-600", bg: "bg-orange-50 dark:bg-orange-950/30" },
                  { label: "Service Accounts", value: stats.service_accounts, icon: Bot, color: "text-violet-600", bg: "bg-violet-50 dark:bg-violet-950/30" },
                  { label: "Admin Users", value: stats.admin_users, icon: Key, color: "text-red-600", bg: "bg-red-50 dark:bg-red-950/30" },
                  { label: "MFA Disabled", value: stats.mfa_disabled, icon: Unlock, color: "text-orange-600", bg: "bg-orange-50 dark:bg-orange-950/30" },
                  { label: "Dormant (90d+)", value: stats.dormant_identities, icon: UserX, color: "text-amber-600", bg: "bg-amber-50 dark:bg-amber-950/30" },
                  { label: "Open Threats", value: stats.open_threats, icon: ShieldAlert, color: "text-red-600", bg: "bg-red-50 dark:bg-red-950/30" },
                ].map((s, i) => {
                  const Icon = s.icon;
                  return (
                    <div key={i} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-4">
                      <div className={`w-10 h-10 ${s.bg} rounded-xl flex items-center justify-center mb-3`}>
                        <Icon className={`w-5 h-5 ${s.color}`} />
                      </div>
                      <p className="text-2xl font-bold text-slate-900 dark:text-white">{s.value}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{s.label}</p>
                    </div>
                  );
                })}
              </div>

              {/* Risk Distribution + Threats Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution */}
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">Risk Distribution</h3>
                  <div className="space-y-3">
                    {Object.entries(stats.by_risk_level || {}).map(([level, count]) => (
                      <div key={level} className="flex items-center gap-3">
                        <span className="text-xs font-medium text-slate-500 dark:text-slate-400 w-16 uppercase">{level}</span>
                        <div className="flex-1 h-6 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${RISK_BAR_COLORS[level] || "bg-slate-400"} rounded-full transition-all`}
                            style={{ width: `${stats.total_identities ? (count / stats.total_identities) * 100 : 0}%` }}
                          />
                        </div>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 w-8 text-right">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat Summary */}
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">Threat Summary</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-red-50 dark:bg-red-950/30 rounded-xl p-4 text-center">
                      <p className="text-3xl font-bold text-red-600">{stats.critical_threats}</p>
                      <p className="text-xs text-red-500 mt-1">Critical</p>
                    </div>
                    <div className="bg-orange-50 dark:bg-orange-950/30 rounded-xl p-4 text-center">
                      <p className="text-3xl font-bold text-orange-600">{stats.high_threats}</p>
                      <p className="text-xs text-orange-500 mt-1">High</p>
                    </div>
                    <div className="bg-orange-50 dark:bg-orange-950/30 rounded-xl p-4 text-center">
                      <p className="text-3xl font-bold text-orange-600">{stats.attack_paths}</p>
                      <p className="text-xs text-orange-500 mt-1">Attack Paths</p>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4 text-center">
                      <p className="text-3xl font-bold text-slate-700 dark:text-slate-300">{stats.avg_risk_score}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Avg Risk Score</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* By Provider */}
              {Object.keys(stats.by_provider || {}).length > 0 && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-4">Identities by Cloud Provider</h3>
                  <div className="flex gap-4">
                    {Object.entries(stats.by_provider).map(([provider, count]) => (
                      <div key={provider} className="flex items-center gap-2 px-4 py-2 bg-slate-50 dark:bg-slate-800 rounded-xl">
                        <Cloud className="w-4 h-4 text-orange-500" />
                        <span className="text-sm font-medium text-slate-700 dark:text-slate-300 uppercase">{provider}</span>
                        <span className="text-sm font-bold text-slate-900 dark:text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Empty state */}
              {stats.total_identities === 0 && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-12 text-center">
                  <div className="w-16 h-16 bg-orange-50 dark:bg-orange-950/30 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <Scan className="w-8 h-8 text-orange-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">No IAM Data Yet</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">Run an IAM scan to discover cloud identities, detect threats, and map attack paths.</p>
                  <button
                    onClick={() => scanMutation.mutate()}
                    disabled={scanMutation.isPending}
                    className="inline-flex items-center gap-2 px-6 h-11 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold text-sm transition-colors"
                  >
                    <Scan className="w-4 h-4" />
                    Run First Scan
                  </button>
                </div>
              )}
            </>
          ) : null}
        </div>
      )}

      {/* ─── Identities Tab ─── */}
      {activeTab === "identities" && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search identities..."
                className="w-full h-10 pl-10 pr-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent"
              />
            </div>
            <select value={providerFilter} onChange={(e) => { setProviderFilter(e.target.value); setPage(1); }}
              className="h-10 px-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm">
              <option value="">All Providers</option>
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
            </select>
            <select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
              className="h-10 px-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm">
              <option value="">All Types</option>
              <option value="user">User</option>
              <option value="service_account">Service Account</option>
              <option value="role">Role</option>
              <option value="api_key">API Key</option>
            </select>
            <select value={riskFilter} onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }}
              className="h-10 px-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm">
              <option value="">All Risk</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Table */}
          {identitiesLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden max-h-[calc(100vh-320px)] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                  <tr className="border-b border-slate-100 dark:border-slate-800">
                    {["Identity", "Type", "Provider", "Risk Score", "Status", "MFA", "Permissions"].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {identities.map((ident) => {
                    const TypeIcon = TYPE_ICONS[ident.identity_type] || Users;
                    const expanded = expandedId === ident.id;
                    return (
                      <React.Fragment key={ident.id}>
                        <tr
                          onClick={() => setExpandedId(expanded ? null : ident.id)}
                          className="hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              {expanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
                              <span className="text-sm font-medium text-slate-900 dark:text-white">{ident.display_name || ident.external_id}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1.5">
                              <TypeIcon className="w-3.5 h-3.5 text-slate-400" />
                              <span className="text-xs text-slate-600 dark:text-slate-400">{ident.identity_type.replace("_", " ")}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-xs font-medium text-slate-600 dark:text-slate-400 uppercase">{ident.cloud_provider}</span>
                          </td>
                          <td className="px-4 py-3"><RiskBar score={ident.risk_score} /></td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                              ident.is_active
                                ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400"
                                : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"
                            }`}>
                              {ident.is_active ? "Active" : `Inactive ${ident.days_inactive}d`}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            {ident.mfa_enabled === null ? (
                              <span className="text-xs text-slate-400">N/A</span>
                            ) : ident.mfa_enabled ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                            ) : (
                              <XCircle className="w-4 h-4 text-red-500" />
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-sm font-mono text-slate-600 dark:text-slate-400">{ident.permissions_count}</span>
                          </td>
                        </tr>
                        {expanded && (
                          <tr>
                            <td colSpan={7} className="px-4 py-4 bg-slate-50 dark:bg-slate-800/30">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div>
                                  <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2">RISK FACTORS</p>
                                  {ident.risk_factors.length > 0 ? (
                                    <ul className="space-y-1">
                                      {ident.risk_factors.map((rf, i) => (
                                        <li key={i} className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-1">
                                          <AlertTriangle className="w-3 h-3 text-amber-500" />
                                          {rf.details} (score: {Math.round(rf.score)})
                                        </li>
                                      ))}
                                    </ul>
                                  ) : <p className="text-xs text-slate-400">No risk factors</p>}
                                </div>
                                <div>
                                  <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2">POLICIES</p>
                                  <div className="flex flex-wrap gap-1">
                                    {ident.attached_policies.slice(0, 5).map((p, i) => (
                                      <span key={i} className="px-2 py-0.5 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded text-xs">{p.name}</span>
                                    ))}
                                  </div>
                                </div>
                                <div>
                                  <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2">DETAILS</p>
                                  <div className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                                    <p>Credential Age: {ident.credential_age_days} days</p>
                                    <p>Console Access: {ident.has_console_access ? "Yes" : "No"}</p>
                                    <p>Programmatic: {ident.has_programmatic_access ? "Yes" : "No"}</p>
                                    <p>Admin: {ident.admin_access ? "⚠️ Yes" : "No"}</p>
                                  </div>
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
              {identities.length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400">No identities found. Run an IAM scan to discover cloud identities.</div>
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-1">
              <p className="text-xs text-slate-500 dark:text-slate-400">Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, totalIdentities)} of {totalIdentities}</p>
              <div className="flex gap-1">
                <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1} className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30"><ChevronLeft className="w-4 h-4" /></button>
                <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30"><ChevronRight className="w-4 h-4" /></button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─── Threats Tab ─── */}
      {activeTab === "threats" && (
        <div className="space-y-4">
          <div className="flex gap-3">
            <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              className="h-10 px-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm">
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>

          {threatsLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="space-y-3">
              {threats.map((t) => (
                <div key={t.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge level={t.severity} />
                        {t.mitre_tactic && (
                          <span className="text-xs font-mono text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded">{t.mitre_tactic}</span>
                        )}
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          t.status === "open" ? "bg-red-50 text-red-600 dark:bg-red-950/30" : "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/30"
                        }`}>{t.status}</span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{t.title}</h4>
                      {t.description && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t.description}</p>}
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-xs text-slate-400">Confidence</p>
                      <p className="text-sm font-bold text-slate-700 dark:text-slate-300">{Math.round(t.confidence * 100)}%</p>
                    </div>
                  </div>
                  {t.remediation_steps.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-100 dark:border-slate-800">
                      <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">Remediation</p>
                      <ul className="space-y-1">
                        {t.remediation_steps.map((step) => (
                          <li key={step.step} className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-1.5">
                            <span className="w-4 h-4 bg-slate-100 dark:bg-slate-800 rounded-full flex items-center justify-center text-[10px] font-bold text-slate-500 dark:text-slate-400">{step.step}</span>
                            {step.description}
                            {step.automated && <span className="text-[10px] bg-emerald-50 text-emerald-600 px-1.5 rounded">Auto</span>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
              {threats.length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                  No threats detected. Run an IAM scan to analyze your cloud identities.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── Attack Paths Tab ─── */}
      {activeTab === "attack-paths" && (
        <div className="space-y-4">
          {pathsLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="space-y-4">
              {paths.map((p) => (
                <div key={p.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge level={p.severity} />
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          p.complexity === "low" ? "bg-red-50 text-red-600" : p.complexity === "medium" ? "bg-amber-50 text-amber-600" : "bg-blue-50 text-blue-600"
                        }`}>
                          {p.complexity} complexity
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{p.title}</h4>
                      {p.description && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{p.description}</p>}
                    </div>
                    <RiskBar score={p.risk_score} />
                  </div>

                  {/* Path visualization */}
                  <div className="flex items-center gap-2 overflow-x-auto pb-2">
                    {p.path_steps.map((step, i) => (
                      <React.Fragment key={step.step_num}>
                        <div className="flex-shrink-0 bg-slate-50 dark:bg-slate-800 rounded-xl p-3 min-w-[140px]">
                          <p className="text-[10px] font-semibold text-slate-400 mb-1">STEP {step.step_num}</p>
                          <p className="text-xs font-medium text-slate-700 dark:text-slate-300">{step.action}</p>
                          <p className="text-[10px] text-slate-400 mt-0.5 truncate">{step.resource}</p>
                        </div>
                        {i < p.path_steps.length - 1 && (
                          <div className="flex-shrink-0 text-slate-300 dark:text-slate-600 dark:text-slate-300">→</div>
                        )}
                      </React.Fragment>
                    ))}
                    {p.target_resource && (
                      <>
                        <div className="flex-shrink-0 text-red-400">→</div>
                        <div className="flex-shrink-0 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-xl p-3 min-w-[140px]">
                          <p className="text-[10px] font-semibold text-red-400 mb-1">TARGET</p>
                          <p className="text-xs font-medium text-red-700 dark:text-red-400 truncate">{p.target_resource}</p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              ))}
              {paths.length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                  No attack paths discovered. Run an IAM scan to map privilege escalation paths.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </PageLayout>
  );
}
