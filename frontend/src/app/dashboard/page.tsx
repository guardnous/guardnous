"use client";

import React, { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Bug,
  Target,
  Activity,
  Zap,
  Eye,
  Server,
  GitBranch,
  CheckCircle2,
  ChevronRight,
  BarChart3,
  Lock,
  Cloud,
  Database,
  Key,
  Network,
  FileCode2,
  Users,
  Globe,
  Layers,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#94a3b8",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  info: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

const CATEGORY_COLORS: Record<string, string> = {
  secrets: "#ef4444",
  iam: "#8b5cf6",
  network: "#06b6d4",
  encryption: "#f97316",
  storage: "#3b82f6",
  compute: "#10b981",
  logging: "#eab308",
  iac: "#ec4899",
  sast: "#6366f1",
  monitoring: "#14b8a6",
  dependency: "#a855f7",
  container: "#0ea5e9",
  kubernetes: "#2563eb",
  database: "#d946ef",
  backup: "#84cc16",
  compliance: "#f43f5e",
  other: "#94a3b8",
};

/* Donuts read like a clock: the first slice starts at 12 o'clock and slices run clockwise. */
const DONUT = { startAngle: 90, endAngle: -270, innerRadius: 52, outerRadius: 72, paddingAngle: 0, strokeWidth: 1, minAngle: 3 } as const;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const MAX_CATEGORIES = 7;

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  secrets: <Key size={12} />,
  iam: <Users size={12} />,
  network: <Network size={12} />,
  encryption: <Lock size={12} />,
  storage: <Database size={12} />,
  compute: <Server size={12} />,
  logging: <Eye size={12} />,
  iac: <FileCode2 size={12} />,
  other: <Layers size={12} />,
};

interface DashboardData {
  risk_score: {
    overall: number;
    aws: number;
    gcp: number;
    azure: number;
    trend?: number | { date: string; score: number; findings: number }[];
  };
  severity_breakdown: Record<string, number>;
  cloud_breakdown?: Record<string, number>;
  category_breakdown?: Record<string, number>;
  recent_scans: {
    id: number;
    scan_type: string;
    status: string;
    risk_score: number;
    findings_count: number;
    file_name: string | null;
    created_at: string;
  }[];
  top_risks?: { id: number; title: string; severity: string; cloud_provider?: string; resource_name?: string }[];
  total_findings: number;
  total_scans: number;
  total_resources?: number;
  passed_checks?: number;
  failed_checks?: number;
}

/* ── Security Score Ring (SVG gauge) ─────────────────────── */
function ScoreRing({ riskScore, size = 120, label: customLabel }: { riskScore: number; size?: number; label?: string }) {
  const securityScore = Math.max(0, 100 - Math.min(riskScore, 100));
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = securityScore / 100;
  const offset = circumference * (1 - pct);
  const color = securityScore >= 80 ? "#10b981" : securityScore >= 50 ? "#f59e0b" : "#ef4444";
  // The word describes the score. "Critical" here read as "0 critical findings".
  const label = customLabel || (securityScore >= 80 ? "Good" : securityScore >= 50 ? "Fair" : securityScore >= 20 ? "Poor" : "At risk");
  const [showTooltip, setShowTooltip] = React.useState(false);

  return (
    <div className="relative" style={{ width: size, height: size }}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor"
          className="text-slate-100 dark:text-slate-700/50" strokeWidth={10} />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color}
          strokeWidth={10} strokeLinecap="round" strokeDasharray={circumference}
          strokeDashoffset={offset} className="transition-all duration-1000 ease-out" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-slate-900 dark:text-white">
          {securityScore}<span className="text-sm font-medium text-slate-500 dark:text-slate-400">/100</span>
        </span>
        <span className="text-[11px] font-medium uppercase tracking-wider" style={{ color }}>{label}</span>
      </div>
      {showTooltip && (
        <div className="absolute left-1/2 -translate-x-1/2 top-full mt-3 z-50 w-64 p-3 rounded-xl bg-slate-900 dark:bg-slate-700 text-white text-xs shadow-xl pointer-events-none">
          <p className="font-semibold mb-1.5">Security Score = 100 − Risk Score</p>
          <div className="space-y-1 text-slate-300">
            <p>Risk is calculated from open findings weighted by severity:</p>
            <p className="font-mono text-[10px]">Critical ×10 · High ×5 · Medium ×2 · Low ×1</p>
            <p>Risk rises in a straight line to 50 at a weight of 250, then more slowly, reaching 100 at 25,000. So the score still moves in a large backlog.</p>
            <p className="mt-1.5 text-white font-medium">Risk: {riskScore} → Security: {securityScore}/100</p>
          </div>
          <div className="absolute -top-1.5 left-1/2 -translate-x-1/2 w-3 h-3 bg-slate-900 dark:bg-slate-700 rotate-45" />
        </div>
      )}
    </div>
  );
}

/* ── Mini Ring (smaller, for cards) ──────────────────────── */
function MiniRing({ value, total, color, size = 56 }: { value: number; total: number; color: string; size?: number }) {
  const radius = (size - 6) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = total > 0 ? Math.min(value / total, 1) : 0;
  const offset = circumference * (1 - pct);

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor"
          className="text-slate-100 dark:text-slate-700/50" strokeWidth={5} />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color}
          strokeWidth={5} strokeLinecap="round" strokeDasharray={circumference}
          strokeDashoffset={offset} className="transition-all duration-700 ease-out" />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xs font-bold text-slate-900 dark:text-white">{value}</span>
      </div>
    </div>
  );
}

/* ── Severity Pill ──────────────────────────────────────── */
function SeverityPill({ severity, count }: { severity: string; count: number }) {
  const icons: Record<string, React.ReactNode> = {
    critical: <AlertOctagon size={12} />,
    high: <AlertTriangle size={12} />,
    medium: <Bug size={12} />,
    low: <Shield size={12} />,
  };
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-semibold ${SEVERITY_BG[severity] || SEVERITY_BG.info}`}>
      {icons[severity]} {count}
    </div>
  );
}

/* ── Compliance Framework display config ─────────────────── */
const FRAMEWORK_STYLE: Record<string, { icon: typeof ShieldCheck; color: string; label: string }> = {
  "CIS":      { icon: ShieldCheck, color: "#10b981", label: "CIS Benchmark" },
  "SOC2":     { icon: Lock,        color: "#3b82f6", label: "SOC 2 Type II" },
  "PCI-DSS":  { icon: Shield,      color: "#8b5cf6", label: "PCI DSS" },
  "HIPAA":    { icon: ShieldAlert,  color: "#ef4444", label: "HIPAA" },
  "ISO27001": { icon: Target,       color: "#f97316", label: "ISO 27001" },
};
const DEFAULT_STYLE = { icon: Shield, color: "#6b7280" };

export default function DashboardPage() {
  const router = useRouter();
  const { data, isLoading } = useQuery<DashboardData>({
    queryKey: ["dashboard"],
    queryFn: () => api.get("/dashboard").then((r) => r.data),
  });

  // Shown in the Open Findings card; needs findings:read, so a failure simply hides it
  const { data: slaSummary } = useQuery<{ open: { overdue: number } }>({
    queryKey: ["findings", "sla-summary"],
    queryFn: () => api.get("/findings/sla/summary").then((r) => r.data),
    retry: false,
  });

  const { data: frameworks } = useQuery<any[]>({
    queryKey: ["governance-frameworks"],
    queryFn: () => api.get("/governance/frameworks").then((r) => r.data),
  });

  const complianceItems = useMemo(() => {
    if (!frameworks?.length) return [];
    return frameworks.map((fw: any) => {
      const total = fw.total_controls || 0;
      const passed = fw.passed_controls || 0;
      const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
      const style = FRAMEWORK_STYLE[fw.name] || { ...DEFAULT_STYLE, label: fw.name };
      return { name: style.label || fw.name, pct, icon: style.icon, color: style.color, id: fw.id };
    });
  }, [frameworks]);

  if (isLoading || !data) {
    return (
      <PageLayout title="Dashboard" subtitle="Security posture at a glance">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-40 rounded-2xl animate-pulse glass" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          {[1, 2].map((i) => (
            <div key={i} className="h-80 rounded-2xl animate-pulse glass" />
          ))}
        </div>
      </PageLayout>
    );
  }

  const sev = data.severity_breakdown || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const totalFindings = data.total_findings;
  const severityData = SEVERITY_ORDER
    .map((name) => ({ name, value: (sev as Record<string, number>)[name] || 0 }))
    .filter((s) => s.value > 0);

  const cloudData = data.cloud_breakdown || { aws: 0, gcp: 0, azure: 0 };
  const totalCloud = Object.values(cloudData).reduce((a, b) => a + b, 0);

  // Category breakdown — synthesize from findings if not returned by API
  const catRaw = data.category_breakdown || {};
  const merged: Record<string, number> = {};
  for (const [name, value] of Object.entries(catRaw)) {
    if (value > 0) merged[name.toLowerCase()] = (merged[name.toLowerCase()] || 0) + value;
  }
  const sortedCategories = Object.entries(merged).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  // The ring and its legend show the same slices: the largest categories, and the rest as one "other".
  const tail = sortedCategories.slice(MAX_CATEGORIES).filter((c) => c.name !== "other");
  const categoryData = sortedCategories.length <= MAX_CATEGORIES + 1
    ? sortedCategories
    : [
        ...sortedCategories.slice(0, MAX_CATEGORIES).filter((c) => c.name !== "other"),
        { name: "other", value: tail.reduce((n, c) => n + c.value, 0) + (merged.other || 0) },
      ];
  const totalCategorised = categoryData.reduce((n, c) => n + c.value, 0);

  // Checks that passed and failed in the latest assessment of each repository and cloud account
  const passed = data.passed_checks || 0;
  const failed = data.failed_checks || 0;
  const totalChecks = passed + failed;
  const passRate = totalChecks > 0 ? Math.round((passed / totalChecks) * 100) : 0;

  return (
    <PageLayout title="Dashboard" subtitle="Security posture at a glance">

      {/* ═══════ ROW 1: Hero KPI Cards ═══════ */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">

        {/* Security Score */}
        <div className="sm:col-span-2 lg:col-span-1 glass rounded-2xl p-6 card-hover relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-orange-500/5 to-transparent rounded-bl-full" />
          <p className="text-[13px] font-medium text-slate-500 dark:text-slate-400 mb-4">Security Score</p>
          <div className="flex items-center justify-center">
            <ScoreRing riskScore={data.risk_score.overall} />
          </div>
        </div>

        {/* Open Findings */}
        <div className="glass rounded-2xl p-6 card-hover relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-red-500/5 to-transparent rounded-bl-full" />
          <div className="flex items-start justify-between mb-2">
            <p className="text-[13px] font-medium text-slate-500 dark:text-slate-400">Open Findings</p>
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-red-100 to-rose-50 dark:from-red-500/20 dark:to-rose-500/10 flex items-center justify-center">
              <ShieldAlert size={16} className="text-red-500" />
            </div>
          </div>
          <p className="text-4xl font-bold text-slate-900 dark:text-white tracking-tight">{totalFindings}</p>
          <div className="flex flex-wrap gap-1.5 mt-3">
            <SeverityPill severity="critical" count={sev.critical || 0} />
            <SeverityPill severity="high" count={sev.high || 0} />
            {(slaSummary?.open?.overdue ?? 0) > 0 && (
              <a
                href="/findings"
                className="inline-flex items-center rounded-md border border-red-200 bg-red-50 px-2 py-0.5 text-[11px] font-semibold text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300"
              >
                {slaSummary?.open.overdue} past SLA
              </a>
            )}
          </div>
        </div>

        {/* Scans Run */}
        <div className="glass rounded-2xl p-6 card-hover relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-blue-500/5 to-transparent rounded-bl-full" />
          <div className="flex items-start justify-between mb-2">
            <p className="text-[13px] font-medium text-slate-500 dark:text-slate-400">Scans Run</p>
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-100 to-sky-50 dark:from-blue-500/20 dark:to-sky-500/10 flex items-center justify-center">
              <Eye size={16} className="text-blue-500" />
            </div>
          </div>
          <p className="text-4xl font-bold text-slate-900 dark:text-white tracking-tight">{data.total_scans}</p>
          <div className="flex items-center gap-1.5 mt-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <span className="text-[12px] text-slate-400">
              {data.recent_scans?.filter((s) => s.status === "scanning").length || 0} running
            </span>
          </div>
        </div>

        {/* Pass Rate */}
        <div className="glass rounded-2xl p-6 card-hover relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-emerald-500/5 to-transparent rounded-bl-full" />
          <div className="flex items-start justify-between mb-2">
            <p className="text-[13px] font-medium text-slate-500 dark:text-slate-400">Check Pass Rate</p>
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-100 to-green-50 dark:from-emerald-500/20 dark:to-green-500/10 flex items-center justify-center">
              <CheckCircle2 size={16} className="text-emerald-500" />
            </div>
          </div>
          <p className="text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
            {totalChecks > 0 ? `${passRate}%` : "—"}
          </p>
          <div className="flex items-center gap-2 mt-3 text-[12px]">
            <span className="text-emerald-600 dark:text-emerald-400 font-medium">{passed} passed</span>
            <span className="text-slate-300 dark:text-slate-600">|</span>
            <span className="text-red-600 dark:text-red-400 font-medium">{failed} failed</span>
          </div>
          <p className="mt-2 text-[11px] leading-snug text-slate-500 dark:text-slate-400">
            {totalChecks > 0
              ? "Policy and cloud rule checks in the latest assessment of each repository and cloud account"
              : "No check results recorded yet"}
          </p>
        </div>
      </div>

      {/* ═══════ ROW 2: Severity Donut + Category Breakdown ═══════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        {/* Severity Distribution */}
        <div className="glass rounded-2xl p-7 card-hover">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <BarChart3 size={16} className="text-orange-500" />
              Severity Distribution
            </h3>
            <span className="text-[12px] text-slate-400 font-medium">{totalFindings} total</span>
          </div>
          <div className="flex items-center gap-6">
            <div className="w-44 h-44 flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData.length > 0 ? severityData : [{ name: "none", value: 1 }]}
                    cx="50%" cy="50%" dataKey="value" stroke="var(--card-bg, #fff)" isAnimationActive={false} {...DONUT}>
                    {(severityData.length > 0 ? severityData : [{ name: "none", value: 1 }]).map((entry) => (
                      <Cell key={entry.name} fill={entry.name === "none" ? "#e2e8f0" : (SEVERITY_COLORS[entry.name] || "#94a3b8")} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value, name) => [String(value), String(name).charAt(0).toUpperCase() + String(name).slice(1)]} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col gap-2.5 flex-1">
              {["critical", "high", "medium", "low", "info"].map((s) => {
                const count = sev[s] || 0;
                const exact = totalFindings > 0 ? (count / totalFindings) * 100 : 0;
                const pct = Math.round(exact);
                const pctLabel = exact > 0 && exact < 1 ? "<1%" : `${pct}%`;
                return (
                  <div key={s} className="group cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/30 -mx-2 px-2 py-1 rounded-lg transition-colors"
                    onClick={() => router.push(`/findings?severity=${s.toUpperCase()}`)}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[s] }} />
                        <span className="text-[13px] text-slate-600 dark:text-slate-300 capitalize group-hover:text-orange-500 transition-colors">{s}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-500 dark:text-slate-400">{pctLabel}</span>
                        <span className="text-[13px] font-semibold text-slate-900 dark:text-white w-8 text-right">{count}</span>
                        <ChevronRight size={12} className="text-slate-300 group-hover:text-orange-500 transition-colors" />
                      </div>
                    </div>
                    <div className="h-1 bg-slate-100 dark:bg-slate-700/50 rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-700" style={{ width: count > 0 ? `${Math.max(exact, 1)}%` : "0%", background: SEVERITY_COLORS[s] }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Findings by Category */}
        <div className="glass rounded-2xl p-7 card-hover">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Layers size={16} className="text-orange-500" />
              Issues by Category
            </h3>
          </div>
          {categoryData.length > 0 ? (
            <div className="flex items-center gap-6">
              <div className="w-44 h-44 flex-shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={categoryData} cx="50%" cy="50%" dataKey="value" stroke="var(--card-bg, #fff)"
                      isAnimationActive={false} {...DONUT}>
                      {categoryData.map((entry) => (
                        <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name] || CATEGORY_COLORS.other} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value, name) => [String(value), String(name).toUpperCase()]} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-col gap-2 flex-1">
                {categoryData.map((cat) => (
                  <div key={cat.name} onClick={() => router.push(cat.name === "other" ? "/findings" : `/findings?category=${cat.name}`)}
                    className="flex items-center justify-between cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/30 -mx-2 px-2 py-1 rounded-lg transition-colors group">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ background: CATEGORY_COLORS[cat.name] || CATEGORY_COLORS.other }} />
                      <span className="text-[13px] text-slate-600 dark:text-slate-300 uppercase group-hover:text-orange-500 transition-colors">{cat.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-500 dark:text-slate-400">
                        {(() => { const p = (cat.value / totalCategorised) * 100; return p > 0 && p < 1 ? "<1%" : `${Math.round(p)}%`; })()}
                      </span>
                      <span className="text-[13px] font-semibold text-slate-900 dark:text-white w-10 text-right">{cat.value}</span>
                      <ChevronRight size={12} className="text-slate-300 group-hover:text-orange-500 transition-colors" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-44 flex flex-col items-center justify-center text-slate-400">
              <Layers size={32} className="mb-3 opacity-30" />
              <p className="text-sm">Category data will appear after scans</p>
            </div>
          )}
        </div>
      </div>

      {/* ═══════ ROW 3: Cloud Provider Breakdown ═══════ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {[
          { name: "AWS", key: "aws", color: "#FF9900", icon: Cloud, perSev: { critical: 0, high: 0, medium: 0 } },
          { name: "Azure", key: "azure", color: "#0078D4", icon: Globe, perSev: { critical: 0, high: 0, medium: 0 } },
          { name: "GCP", key: "gcp", color: "#4285F4", icon: Server, perSev: { critical: 0, high: 0, medium: 0 } },
        ].map((cloud) => {
          const findings = (cloudData as Record<string, number>)[cloud.key] || 0;
          const Icon = cloud.icon;
          return (
            <div key={cloud.name} className="glass rounded-2xl p-6 card-hover relative overflow-hidden group cursor-pointer">
              <div className="absolute top-0 right-0 w-24 h-24 rounded-bl-full opacity-10 transition-opacity group-hover:opacity-20"
                style={{ background: cloud.color }} />
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2.5 mb-3">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${cloud.color}15` }}>
                      <Icon size={16} style={{ color: cloud.color }} />
                    </div>
                    <span className="text-[14px] font-semibold text-slate-700 dark:text-slate-200">{cloud.name}</span>
                  </div>
                  <p className="text-3xl font-bold text-slate-900 dark:text-white">{findings}</p>
                  <p className="text-[12px] text-slate-400 mt-1">
                    {findings === 0 ? "No issues detected" : `finding${findings !== 1 ? "s" : ""} detected`}
                  </p>
                </div>
                <MiniRing
                  value={findings}
                  total={Math.max(totalCloud, 1)}
                  color={findings === 0 ? "#10b981" : cloud.color}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* ═══════ ROW 4: Top Issues + Compliance ═══════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Top Critical Issues */}
        <div className="glass rounded-2xl overflow-hidden card-hover">
          <div className="px-6 py-5 border-b border-slate-100 dark:border-slate-700/30 flex items-center justify-between">
            <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Zap size={16} className="text-red-500" />
              Top Issues
            </h3>
            <a href="/findings" className="text-[12px] text-orange-500 hover:text-orange-600 font-medium flex items-center gap-1">
              View all <ChevronRight size={14} />
            </a>
          </div>
          <div className="divide-y divide-slate-50 dark:divide-slate-700/30">
            {(data.top_risks || []).length > 0 ? (
              data.top_risks!.slice(0, 5).map((risk, idx) => (
                <div key={idx} onClick={() => router.push(`/findings?highlight=${risk.id}`)} className="px-6 py-4 flex items-center gap-4 hover:bg-white/50 dark:hover:bg-slate-700/20 transition-colors cursor-pointer group">
                  <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${
                    risk.severity === "critical" ? "bg-red-500/10" : risk.severity === "high" ? "bg-orange-500/10" : "bg-amber-500/10"
                  }`}>
                    {risk.severity === "critical" ? <AlertOctagon size={16} className="text-red-500" /> :
                     risk.severity === "high" ? <AlertTriangle size={16} className="text-orange-500" /> :
                     <Bug size={16} className="text-amber-500" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-900 dark:text-white truncate group-hover:text-orange-500 transition-colors">{risk.title}</p>
                    <p className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-2">
                      {risk.resource_name && <span className="flex items-center gap-1"><GitBranch size={10} />{risk.resource_name}</span>}
                      {risk.cloud_provider && <span className="uppercase">{risk.cloud_provider}</span>}
                    </p>
                  </div>
                  <span className={`px-2.5 py-1 text-[11px] font-semibold rounded-lg border ${SEVERITY_BG[risk.severity] || SEVERITY_BG.info}`}>
                    {risk.severity}
                  </span>
                </div>
              ))
            ) : (
              <div className="px-6 py-16 text-center">
                <ShieldCheck size={40} className="mx-auto mb-3 text-emerald-400 opacity-50" />
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">No issues found</p>
                <p className="text-[12px] text-slate-400 mt-1">Run a scan to discover vulnerabilities</p>
              </div>
            )}
          </div>
        </div>

        {/* Compliance Posture */}
        <div className="glass rounded-2xl overflow-hidden card-hover">
          <div className="px-6 py-5 border-b border-slate-100 dark:border-slate-700/30 flex items-center justify-between">
            <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <CheckCircle2 size={16} className="text-emerald-500" />
              Compliance Posture
            </h3>
            <a href="/governance" className="text-[12px] text-orange-500 hover:text-orange-600 font-medium flex items-center gap-1">
              View all <ChevronRight size={14} />
            </a>
          </div>
          <div className="p-6 space-y-5">
            {complianceItems.length > 0 ? complianceItems.map((fw) => {
              const Icon = fw.icon;
              return (
                <div key={fw.name} onClick={() => router.push(`/governance?tab=frameworks&framework=${fw.id}`)} className="group cursor-pointer">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${fw.color}15` }}>
                        <Icon size={14} style={{ color: fw.color }} />
                      </div>
                      <span className="text-sm font-medium text-slate-700 dark:text-slate-200 group-hover:text-orange-500 transition-colors">{fw.name}</span>
                    </div>
                    <span className="text-sm font-bold" style={{ color: fw.pct >= 80 ? "#10b981" : fw.pct >= 50 ? "#f59e0b" : fw.color }}>{fw.pct}%</span>
                  </div>
                  <div className="h-2 bg-slate-100 dark:bg-slate-700/50 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700 ease-out" style={{ width: `${Math.max(fw.pct, 2)}%`, background: fw.color }} />
                  </div>
                </div>
              );
            }) : (
              <p className="text-center text-[12px] text-slate-400 pt-2">Run compliance scans to see posture data</p>
            )}
          </div>
        </div>
      </div>
    </PageLayout>
  );
}
