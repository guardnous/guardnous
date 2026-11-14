"use client";

import React, { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getSecurityPolicies,
  toggleSecurityPolicy,
  seedPolicies,
} from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  ShieldCheck,
  Shield,
  ShieldAlert,
  ShieldOff,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Loader2,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  BookOpen,
  Layers,
  Zap,
  Plus,
  RefreshCw,
} from "lucide-react";

/* ─────────────────────── Types ─────────────────────── */

interface PolicyRule {
  policy_id?: string;
  rule_id_prefixes?: string[];
  categories?: string[];
  resource_types?: string[];
  cloud_providers?: string[];
}

interface Policy {
  id: number;
  name: string;
  description: string;
  policy_type: string;
  severity: string;
  rules: PolicyRule[];
  is_enabled: boolean;
  is_enforced: boolean;
  is_builtin: boolean;
  target_repos: string[] | null;
  violations_count: number;
  last_evaluated: string | null;
  resources_in_scope: number;
  created_at: string;
}

/* ─────────────────────── Helpers ─────────────────────── */

type FilterTab = "all" | "enabled" | "disabled" | "custom";

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "text-red-600 dark:text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  high:     { color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium:   { color: "text-yellow-700 dark:text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low:      { color: "text-blue-600 dark:text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30" },
};

const CATEGORY_LABELS: Record<string, string> = {
  storage: "Storage",
  encryption: "Encryption",
  iam: "IAM",
  network: "Network",
  logging: "Logging",
  security: "Security",
  container: "Container",
  sast: "SAST",
  secrets: "Secrets",
  database: "Database",
};

function severityStyle(sev: string) {
  return SEVERITY_CONFIG[sev?.toLowerCase()] ?? SEVERITY_CONFIG.medium;
}

/** Number of match conditions: a policy matches findings by rule-ID prefix or by category. */
function ruleCount(rules: PolicyRule[] | undefined): number {
  if (!Array.isArray(rules)) return 0;
  return rules.reduce(
    (n, r) => n + (r.rule_id_prefixes?.length ?? 0) + (r.categories?.length ?? 0),
    0
  );
}

/* ─────────────────────── Component ─────────────────────── */

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<FilterTab>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  /* ── Data fetching ── */
  const { data: policiesData, isLoading, isError } = useQuery<Policy[]>({
    queryKey: ["security-policies"],
    queryFn: getSecurityPolicies,
  });

  const toggleMut = useMutation({
    mutationFn: (id: number) => toggleSecurityPolicy(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["security-policies"] }),
  });

  const seedMut = useMutation({
    mutationFn: seedPolicies,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["security-policies"] }),
  });

  const policies: Policy[] = useMemo(() => {
    if (!policiesData) return [];
    return Array.isArray(policiesData) ? policiesData : [];
  }, [policiesData]);

  /* ── Filtering ── */
  const filtered = useMemo(() => {
    let list = policies;
    if (activeTab === "enabled") list = list.filter((p) => p.is_enabled);
    if (activeTab === "disabled") list = list.filter((p) => !p.is_enabled);
    if (activeTab === "custom") list = list.filter((p) => !p.is_builtin);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q) ||
          p.policy_type?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [policies, activeTab, search]);

  /* ── Stats ── */
  const totalCount = policies.length;
  const enabledCount = policies.filter((p) => p.is_enabled).length;
  const customCount = policies.filter((p) => !p.is_builtin).length;

  const toggleExpand = useCallback((id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);

  /* ── Tabs ── */
  const tabs: { key: FilterTab; label: string; count: number }[] = [
    { key: "all", label: "All", count: totalCount },
    { key: "enabled", label: "Enabled", count: enabledCount },
    { key: "disabled", label: "Disabled", count: totalCount - enabledCount },
    { key: "custom", label: "Custom", count: customCount },
  ];

  /* ── Render ── */
  return (
    <PageLayout
      title="Security Policies"
      subtitle="Manage and enforce security policies across your organization"
      icon={ShieldCheck}
    >
      {/* ── Stats Bar ── */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[
          { label: "Total Policies", value: totalCount, icon: Shield, color: "text-blue-600 dark:text-blue-400" },
          { label: "Enabled", value: enabledCount, icon: CheckCircle2, color: "text-emerald-600 dark:text-emerald-400" },
          { label: "Custom", value: customCount, icon: Layers, color: "text-purple-600 dark:text-purple-400" },
        ].map((s) => (
          <div
            key={s.label}
            className="flex items-center gap-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm dark:border-white/[0.06] dark:bg-white/[0.02] dark:shadow-none dark:backdrop-blur-sm"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-100 dark:bg-white/[0.04]">
              <s.icon className={`h-5 w-5 ${s.color}`} />
            </div>
            <div>
              <p className="text-[13px] text-gray-500">{s.label}</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">{isLoading ? "—" : s.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Toolbar: Search + Seed ── */}
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search policies…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-4 text-[13px] text-gray-900 placeholder-gray-400 outline-none dark:border-white/[0.06] dark:bg-white/[0.03] dark:text-gray-300 dark:placeholder-gray-600 focus:border-orange-500/40 focus:ring-1 focus:ring-orange-500/20"
          />
        </div>
        <button
          onClick={() => seedMut.mutate()}
          disabled={seedMut.isPending}
          className="flex items-center gap-2 rounded-lg border border-orange-500/30 bg-orange-500/10 px-4 py-2 text-[13px] font-medium text-orange-600 dark:text-orange-400 transition hover:bg-orange-500/20 disabled:opacity-50"
        >
          {seedMut.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          Seed Built-in Policies
        </button>
      </div>

      {/* ── Filter Tabs ── */}
      <div className="mb-5 flex gap-1 rounded-lg border border-gray-200 bg-white p-1 dark:border-white/[0.06] dark:bg-white/[0.02]">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`flex items-center gap-1.5 rounded-md px-4 py-2 text-[13px] font-medium transition ${
              activeTab === t.key
                ? "bg-orange-500/15 text-orange-700 dark:text-orange-400"
                : "text-gray-600 hover:text-gray-900 dark:text-gray-500 dark:hover:text-gray-300"
            }`}
          >
            {t.label}
            <span
              className={`ml-1 rounded-full px-1.5 py-0.5 text-[11px] ${
                activeTab === t.key
                  ? "bg-orange-500/20 text-orange-800 dark:text-orange-400"
                  : "bg-gray-100 text-gray-600 dark:bg-white/[0.06] dark:text-gray-400"
              }`}
            >
              {isLoading ? "…" : t.count}
            </span>
          </button>
        ))}
      </div>

      {/* ── Loading / Error / Empty ── */}
      {isLoading && (
        <div className="flex items-center justify-center py-20 text-gray-500">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
          Loading policies…
        </div>
      )}
      {isError && (
        <div className="flex flex-col items-center justify-center py-20 text-gray-500">
          <XCircle className="mb-2 h-8 w-8 text-red-400/60" />
          <p className="text-[13px]">Failed to load policies.</p>
        </div>
      )}
      {!isLoading && !isError && filtered.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-gray-500">
          <ShieldOff className="mb-2 h-8 w-8 text-gray-600" />
          <p className="text-[13px]">
            {policies.length === 0
              ? 'No policies found. Click "Seed Built-in Policies" to get started.'
              : "No policies match your filters."}
          </p>
        </div>
      )}

      {/* ── Policy Cards Grid ── */}
      {!isLoading && !isError && filtered.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {filtered.map((policy) => {
            const sev = severityStyle(policy.severity);
            const rules = ruleCount(policy.rules);
            const expanded = expandedId === policy.id;

            return (
              <div
                key={policy.id}
                className="group rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition hover:border-gray-300 dark:border-white/[0.06] dark:bg-white/[0.02] dark:shadow-none dark:backdrop-blur-sm dark:hover:border-white/[0.10]"
              >
                {/* Header row */}
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-[14px] font-semibold text-gray-900 dark:text-white truncate">
                        {policy.name}
                      </h3>
                      {/* Severity badge */}
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize ${sev.bg} ${sev.border} ${sev.color}`}
                      >
                        {policy.severity?.toLowerCase()}
                      </span>
                      {/* Category badge */}
                      <span className="inline-flex items-center rounded-full border border-gray-200 bg-gray-50 px-2 py-0.5 text-[11px] font-medium text-gray-600 dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-gray-400">
                        {CATEGORY_LABELS[policy.policy_type?.toLowerCase()] ?? policy.policy_type}
                      </span>
                    </div>
                    <p className="mt-1.5 text-[12.5px] leading-relaxed text-gray-600 dark:text-gray-500 line-clamp-2">
                      {policy.description}
                    </p>
                  </div>

                  {/* Toggle switch */}
                  <button
                    onClick={() => toggleMut.mutate(policy.id)}
                    disabled={toggleMut.isPending}
                    className="mt-0.5 flex-shrink-0"
                    title={policy.is_enabled ? "Disable policy" : "Enable policy"}
                  >
                    {policy.is_enabled ? (
                      <ToggleRight className="h-7 w-7 text-emerald-600 transition hover:text-emerald-500 dark:text-emerald-400 dark:hover:text-emerald-300" />
                    ) : (
                      <ToggleLeft className="h-7 w-7 text-gray-400 transition hover:text-gray-600 dark:text-gray-600 dark:hover:text-gray-400" />
                    )}
                  </button>
                </div>

                {/* Meta row */}
                <div className="mt-3 flex items-center gap-4 text-[12px] text-gray-600 dark:text-gray-500">
                  <span className="flex items-center gap-1">
                    <BookOpen className="h-3.5 w-3.5" />
                    {rules} rule{rules !== 1 ? "s" : ""}
                  </span>
                  {policy.violations_count > 0 && (
                    <span className="flex items-center gap-1 text-red-600 dark:text-red-400/80">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      {policy.violations_count} violation{policy.violations_count !== 1 ? "s" : ""}
                    </span>
                  )}
                  <span className="flex items-center gap-1">
                    <Layers className="h-3.5 w-3.5" />
                    {policy.is_builtin ? "Built-in" : "Custom"}
                  </span>
                  {policy.is_enforced && (
                    <span
                      className="flex items-center gap-1 text-orange-600 dark:text-orange-400/80"
                      title="A CI scan that violates this policy fails"
                    >
                      <Zap className="h-3.5 w-3.5" />
                      Enforced
                    </span>
                  )}
                  {policy.is_enabled ? (
                    <span className="flex items-center gap-1 text-emerald-600 dark:text-emerald-500/70">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Active
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-gray-600">
                      <XCircle className="h-3.5 w-3.5" />
                      Disabled
                    </span>
                  )}
                </div>

                {/* Expand / Collapse rules */}
                <button
                  onClick={() => toggleExpand(policy.id)}
                  className="mt-3 flex w-full items-center gap-1 rounded-md border border-gray-200 bg-gray-50 px-3 py-1.5 text-[12px] text-gray-600 transition hover:border-gray-300 hover:text-gray-900 dark:border-white/[0.04] dark:bg-white/[0.02] dark:text-gray-500 dark:hover:border-white/[0.08] dark:hover:text-gray-300"
                >
                  {expanded ? (
                    <ChevronUp className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5" />
                  )}
                  {expanded ? "Hide Rules" : "View Rules"}
                </button>

                {/* Expanded rules panel */}
                {expanded && policy.rules?.length > 0 && (
                  <div className="mt-3 space-y-2 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-white/[0.04] dark:bg-black/20">
                    {policy.rules.map((rule, idx) => (
                      <div
                        key={idx}
                        className="rounded-md border border-gray-200 bg-white p-3 dark:border-white/[0.04] dark:bg-white/[0.02]"
                      >
                        {rule.policy_id && (
                          <p className="mb-1 text-[12px] font-medium text-orange-600 dark:text-orange-400/80">
                            {rule.policy_id}
                          </p>
                        )}
                        {rule.rule_id_prefixes && rule.rule_id_prefixes.length > 0 && (
                          <div className="mb-1.5 flex flex-wrap gap-1">
                            {rule.rule_id_prefixes.map((prefix) => (
                              <span
                                key={prefix}
                                className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px] font-mono text-gray-700 dark:bg-white/[0.05] dark:text-gray-400"
                              >
                                {prefix}
                              </span>
                            ))}
                          </div>
                        )}
                        {rule.categories && rule.categories.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {rule.categories.map((cat) => (
                              <span
                                key={cat}
                                className="rounded-full border border-gray-200 bg-white px-2 py-0.5 text-[10px] text-gray-600 dark:border-white/[0.06] dark:bg-white/[0.03] dark:text-gray-500"
                              >
                                {cat}
                              </span>
                            ))}
                          </div>
                        )}
                        {rule.resource_types && rule.resource_types.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {rule.resource_types.map((rt) => (
                              <span
                                key={rt}
                                className="rounded bg-blue-500/5 px-1.5 py-0.5 text-[10px] font-mono text-blue-700 dark:text-blue-400/60"
                              >
                                {rt}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </PageLayout>
  );
}
