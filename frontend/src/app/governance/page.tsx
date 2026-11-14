"use client";

import React, { useState, useCallback, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import PageLayout from "@/components/PageLayout";
import {
  getGovernanceDashboard,
  getComplianceFrameworks,
  seedFrameworks,
  evaluatePolicies,
  getFrameworkControls,
  getControlAffectedResources,
  getSecurityPolicies,
  createSecurityPolicy,
  updateSecurityPolicy,
  deleteSecurityPolicy,
  getGovernanceViolations,
  getViolationDetail,
  acceptViolation,
  reopenViolation,
  toggleFramework,
  runAssessment,
  getAssessments,
  seedGovernanceData,
  getRiskExceptions,
  createRiskException,
  updateRiskException,
  approveException,
  rejectException,
  getRepos,
} from "@/lib/api";
import {
  Shield,
  FileCheck,
  Scale,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Plus,
  Trash2,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  BookOpen,
  Lock,
  ShieldCheck,
  Gavel,
  ClipboardList,
  BarChart3,
  ThumbsUp,
  ThumbsDown,
  Clock,
  Search,
  X,
  ExternalLink,
  PlayCircle,
  GitBranch,
  Pencil,
  Eye,
  ToggleLeft,
  ToggleRight,
  Database,
  Info,
  ArrowRight,
  ShieldAlert,
} from "lucide-react";

/* ─── Types ─────────────────────────────────────────────── */
interface Framework {
  id: number;
  name: string;
  version: string;
  description: string | null;
  is_enabled: boolean;
  total_controls: number;
  passing_controls: number;
  failing_controls: number;
  not_applicable: number; // controls needing manual attestation
  not_assessed?: number;
  compliance_score: number | null;
  reference_url: string | null;
  last_assessed: string | null;
  created_at: string;
}

interface Control {
  id: number;
  framework_id: number;
  control_id: string;
  title: string;
  description: string | null;
  category: string;
  severity: string;
  status: string;
  evidence: string | null;
  last_assessed: string | null;
  reference_url: string | null;
  finding_categories: string[];
  failed_resources: number;
  passed_resources: number;
  total_resources: number;
}

interface AffectedResource {
  id: number | null;
  title: string;
  severity: string | null;
  category: string | null;
  resource_type: string;
  resource_name: string;
  file_path: string | null;
  line_number: number | null;
  file_link: string;
  rule_id: string | null;
  status: string;
}

interface Policy {
  id: number;
  name: string;
  description: string | null;
  policy_type: string;
  severity: string;
  rules: unknown; // list of finding rules, or an object with a cloud-resource condition
  is_enabled: boolean;
  is_enforced: boolean;
  violations_count: number;
  last_evaluated: string | null;
  resources_in_scope: number;
  target_repos: string[] | null;
  created_at: string;
}

interface Violation {
  id: number;
  policy_id: number;
  resource_type: string | null;
  resource_id: string | null;
  resource_name: string | null;
  cloud_provider: string | null;
  violation_details: Record<string, unknown>;
  severity: string;
  status: string;
  accepted_by: string | null;
  accepted_at: string | null;
  acceptance_reason: string | null;
  created_at: string;
}

interface RiskException {
  id: number;
  title: string;
  description: string | null;
  risk_type: string | null;
  reference_id: number | null;
  severity: string;
  justification: string;
  compensating_controls: string | null;
  status: string;
  requested_by: string;
  approved_by: string | null;
  policy_id?: number | null;
  resource_id?: string | null;
  expires_at: string | null;
  created_at: string;
}

interface DashboardStats {
  frameworks_count: number;
  avg_compliance_score: number | null;
  total_controls: number;
  passing_controls: number;
  failing_controls: number;
  not_assessed_controls?: number;
  manual_controls?: number;
  policies_count: number;
  active_policies: number;
  total_violations: number;
  open_violations: number;
  critical_violations: number;
  exceptions_pending: number;
  exceptions_approved: number;
  frameworks: Framework[];
}

/* ─── Helpers ───────────────────────────────────────────── */
const SEVERITY_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: "bg-red-50 dark:bg-red-950/30", text: "text-red-700 dark:text-red-400", dot: "bg-red-500" },
  high: { bg: "bg-orange-50 dark:bg-orange-950/30", text: "text-orange-700 dark:text-orange-400", dot: "bg-orange-500" },
  medium: { bg: "bg-amber-50 dark:bg-amber-950/30", text: "text-amber-700 dark:text-amber-400", dot: "bg-amber-500" },
  low: { bg: "bg-blue-50 dark:bg-blue-950/30", text: "text-blue-700 dark:text-blue-400", dot: "bg-blue-500" },
};

function SeverityBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-slate-400 text-xs">—</span>;
  const c = SEVERITY_COLORS[level] || SEVERITY_COLORS.low;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${c.bg} ${c.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {level.toUpperCase()}
    </span>
  );
}

/* A null score means "not assessed": show a dash, never 0% or 100%. */
function ScoreRing({ score, size = 64 }: { score: number | null | undefined; size?: number }) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  if (score == null) {
    return (
      <div className="relative" style={{ width: size, height: size }} title="Not assessed">
        <svg width={size} height={size}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={4} strokeDasharray="3 5" className="text-slate-300 dark:text-slate-700" />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-slate-400">—</span>
      </div>
    );
  }
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "text-emerald-500" : score >= 60 ? "text-amber-500" : "text-red-500";
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={4} className="text-slate-100 dark:text-slate-800" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={4} strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" className={color} />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-slate-900 dark:text-white">{Math.round(score)}%</span>
    </div>
  );
}

/* ─── Tabs ──────────────────────────────────────────────── */
type TabKey = "overview" | "frameworks" | "policies" | "violations" | "exceptions";

const TABS: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "overview", label: "Overview", icon: BarChart3 },
  { key: "frameworks", label: "Frameworks", icon: BookOpen },
  { key: "policies", label: "Policies", icon: Scale },
  { key: "violations", label: "Violations", icon: AlertTriangle },
  { key: "exceptions", label: "Exceptions", icon: Gavel },
];

/* ─── Component ─────────────────────────────────────────── */
export default function GovernancePage() {
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const paramTab = searchParams.get("tab") as TabKey | null;
  const paramFramework = searchParams.get("framework");
  const [activeTab, setActiveTab] = useState<TabKey>(paramTab && ["overview","frameworks","policies","violations","exceptions"].includes(paramTab) ? paramTab : "overview");
  const [expandedFrameworkId, setExpandedFrameworkId] = useState<number | null>(paramFramework ? Number(paramFramework) : null);
  const [expandedControlId, setExpandedControlId] = useState<number | null>(null);
  const [controlResources, setControlResources] = useState<{items: AffectedResource[]; total: number; description?: string; remediation_notes?: string} | null>(null);
  const [controlResourcesLoading, setControlResourcesLoading] = useState(false);
  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [showExceptionModal, setShowExceptionModal] = useState(false);
  const [editingException, setEditingException] = useState<RiskException | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 15;
  const [selectedViolation, setSelectedViolation] = useState<any | null>(null);
  const [violationDetailLoading, setViolationDetailLoading] = useState(false);
  const [showViolationModal, setShowViolationModal] = useState(false);
  const [acceptReason, setAcceptReason] = useState("");

  /* ── Queries ── */
  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["governance-dashboard"],
    queryFn: getGovernanceDashboard,
  });

  const { data: frameworks, isLoading: fwLoading } = useQuery<Framework[]>({
    queryKey: ["governance-frameworks"],
    queryFn: getComplianceFrameworks,
    enabled: activeTab === "overview" || activeTab === "frameworks",
  });

  const { data: policies, isLoading: polLoading } = useQuery<Policy[]>({
    queryKey: ["governance-policies"],
    queryFn: getSecurityPolicies,
    enabled: activeTab === "policies",
  });

  const { data: violationsData, isLoading: violLoading } = useQuery({
    queryKey: ["governance-violations", page],
    queryFn: () => getGovernanceViolations({ page, page_size: pageSize }),
    enabled: activeTab === "violations",
  });

  const { data: exceptions, isLoading: excLoading } = useQuery<RiskException[]>({
    queryKey: ["governance-exceptions"],
    queryFn: () => getRiskExceptions({}),
    enabled: activeTab === "exceptions",
  });

  const { data: controls, isLoading: ctrlLoading } = useQuery<Control[]>({
    queryKey: ["governance-controls", expandedFrameworkId],
    queryFn: () => getFrameworkControls(expandedFrameworkId!, {}),
    enabled: !!expandedFrameworkId,
  });

  const { data: assessmentsData } = useQuery({
    queryKey: ["governance-assessments"],
    queryFn: () => getAssessments({ page: 1, page_size: 5 }),
    enabled: activeTab === "overview",
  });

  /* ── Mutations ── */
  const seedMut = useMutation({
    mutationFn: seedFrameworks,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["governance-frameworks"] });
    },
  });

  const evalMut = useMutation({
    mutationFn: runAssessment,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["governance-frameworks"] });
      queryClient.invalidateQueries({ queryKey: ["governance-controls"] });
      queryClient.invalidateQueries({ queryKey: ["governance-assessments"] });
      queryClient.invalidateQueries({ queryKey: ["governance-violations"] });
    },
  });

  const seedEngineMut = useMutation({
    mutationFn: seedGovernanceData,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["governance-assessments"] });
    },
  });

  const toggleFwMut = useMutation({
    mutationFn: toggleFramework,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-frameworks"] });
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
    },
  });

  const acceptViolMut = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason: string }) => acceptViolation(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-violations"] });
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
      setShowViolationModal(false);
      setSelectedViolation(null);
    },
  });

  const reopenViolMut = useMutation({
    mutationFn: reopenViolation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-violations"] });
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
      setShowViolationModal(false);
      setSelectedViolation(null);
    },
  });

  const evalPoliciesMut = useMutation({
    mutationFn: evaluatePolicies,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-policies"] });
      queryClient.invalidateQueries({ queryKey: ["governance-violations"] });
      queryClient.invalidateQueries({ queryKey: ["governance-dashboard"] });
    },
  });

  const deletePolicyMut = useMutation({
    mutationFn: deleteSecurityPolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["governance-policies"] }),
  });

  const approveMut = useMutation({
    mutationFn: approveException,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["governance-exceptions"] }),
  });

  const rejectMut = useMutation({
    mutationFn: rejectException,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["governance-exceptions"] }),
  });

  const handleTabChange = useCallback((tab: TabKey) => {
    setActiveTab(tab);
    setPage(1);
    setExpandedFrameworkId(null);
    setExpandedControlId(null);
    setControlResources(null);
  }, []);

  const handleControlExpand = useCallback(async (ctrl: Control) => {
    if (expandedControlId === ctrl.id) {
      setExpandedControlId(null);
      setControlResources(null);
      return;
    }
    setExpandedControlId(ctrl.id);
    setControlResourcesLoading(true);
    try {
      const data = await getControlAffectedResources(ctrl.id, { page: 1, page_size: 50 });
      setControlResources(data);
    } catch {
      setControlResources({ items: [], total: 0 });
    } finally {
      setControlResourcesLoading(false);
    }
  }, [expandedControlId]);

  const violations: Violation[] = violationsData?.items || [];
  const totalViolations = violationsData?.total || 0;
  const totalPages = Math.ceil(totalViolations / pageSize);

  const handleViolationClick = useCallback(async (v: Violation) => {
    setViolationDetailLoading(true);
    setShowViolationModal(true);
    setAcceptReason("");
    try {
      const detail = await getViolationDetail(v.id);
      setSelectedViolation(detail);
    } catch {
      setSelectedViolation(v);
    } finally {
      setViolationDetailLoading(false);
    }
  }, []);

  /* ─── Action Buttons ─── */
  const actions = (
    <div className="flex items-center gap-3">
      <button
        onClick={() => evalMut.mutate({})}
        disabled={evalMut.isPending}
        className="inline-flex items-center gap-2 px-5 h-11 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-semibold text-sm transition-colors disabled:opacity-50"
      >
        {evalMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <PlayCircle className="w-4 h-4" />}
        {evalMut.isPending ? "Running Assessment..." : "Run Assessment"}
      </button>
      <button
        onClick={() => seedEngineMut.mutate()}
        disabled={seedEngineMut.isPending}
        className="inline-flex items-center gap-2 px-5 h-11 bg-violet-600 hover:bg-violet-700 text-white rounded-xl font-semibold text-sm transition-colors disabled:opacity-50"
      >
        {seedEngineMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />}
        {seedEngineMut.isPending ? "Loading..." : "Load Cloud Policies"}
      </button>
      <button
        onClick={() => seedMut.mutate()}
        disabled={seedMut.isPending}
        className="inline-flex items-center gap-2 px-5 h-11 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold text-sm transition-colors disabled:opacity-50"
      >
        {seedMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <BookOpen className="w-4 h-4" />}
        {seedMut.isPending ? "Loading..." : "Load Frameworks"}
      </button>
    </div>
  );

  return (
    <PageLayout
      title="Enterprise Governance"
      subtitle="Compliance frameworks, security policies & risk management"
      icon={Shield}
      actions={actions}
      breadcrumbs={[{ label: "Home", href: "/dashboard" }, { label: "Governance" }]}
    >
      {/* Seed success */}
      {seedMut.isSuccess && (
        <div className="mb-6 p-4 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 rounded-xl flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-600" />
          <p className="text-sm text-emerald-700 dark:text-emerald-400">Compliance frameworks seeded successfully — SOC2, ISO27001, PCI-DSS, HIPAA, CIS loaded.</p>
        </div>
      )}
      {seedEngineMut.isSuccess && (
        <div className="mb-6 p-4 bg-violet-50 dark:bg-violet-950/30 border border-violet-200 dark:border-violet-800 rounded-xl flex items-center gap-3">
          <Database className="w-5 h-5 text-violet-600" />
          <p className="text-sm text-violet-700 dark:text-violet-400">Built-in cloud-resource policies loaded. They are evaluated against resources synced from connected cloud accounts when you run an assessment.</p>
        </div>
      )}
      {evalMut.isSuccess && (
        <div className="mb-6 p-4 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 rounded-xl flex items-center gap-3">
          <ShieldCheck className="w-5 h-5 text-emerald-600" />
          <p className="text-sm text-emerald-700 dark:text-emerald-400">
            Assessment complete. {(evalMut.data as any)?.total_checks
              ? `Cloud resources: ${Math.round((evalMut.data as any).compliance_score)}% of checks passed (${(evalMut.data as any).passed} passed, ${(evalMut.data as any).failed} failed). `
              : `${(evalMut.data as any)?.note ?? "No cloud-resource checks ran."} `}
            {(evalMut.data as any)?.framework_compliance?.overall_score != null
              ? `Framework controls: ${(evalMut.data as any).framework_compliance.passing} passing, ${(evalMut.data as any).framework_compliance.failing} failing.`
              : "Framework controls are not assessed until a scan has completed."}
          </p>
        </div>
      )}

      {/* Tab Bar */}
      <div className="flex gap-1 p-1 bg-slate-100 dark:bg-slate-800/50 rounded-xl mb-6 max-w-fit overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => handleTabChange(tab.key)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
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

      {/* ─── Overview ─── */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {statsLoading ? (
            <div className="flex justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>
          ) : stats ? (
            <>
              {/* Stat Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
                {[
                  { label: "Compliance Score", value: stats.avg_compliance_score == null ? "Not assessed" : `${Math.round(stats.avg_compliance_score)}%`, icon: ShieldCheck, color: "text-emerald-600", bg: "bg-emerald-50 dark:bg-emerald-950/30" },
                  { label: "Frameworks", value: stats.frameworks_count, icon: BookOpen, color: "text-orange-600", bg: "bg-orange-50 dark:bg-orange-950/30" },
                  { label: "Automated Controls Passed", value: `${stats.passing_controls}/${stats.passing_controls + stats.failing_controls}`, icon: CheckCircle2, color: "text-emerald-600", bg: "bg-emerald-50 dark:bg-emerald-950/30" },
                  { label: "Open Violations", value: stats.open_violations, icon: AlertTriangle, color: "text-red-600", bg: "bg-red-50 dark:bg-red-950/30" },
                  { label: "Pending Exceptions", value: stats.exceptions_pending, icon: Clock, color: "text-amber-600", bg: "bg-amber-50 dark:bg-amber-950/30" },
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

              {/* Framework Score Cards */}
              {(frameworks || []).length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {(frameworks || []).map((fw) => (
                    <div key={fw.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{fw.name}</h4>
                            {fw.reference_url && (
                              <a href={fw.reference_url} target="_blank" rel="noopener noreferrer" className="text-orange-500 hover:text-orange-600" title="View official standard">
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            )}
                          </div>
                          <p className="text-xs text-slate-400">v{fw.version}</p>
                          <p className="text-xs mt-1">
                            {fw.last_assessed
                              ? <span className="text-emerald-600">Evaluated {new Date(fw.last_assessed).toLocaleDateString()}</span>
                              : <span className="text-amber-500">Not yet evaluated</span>}
                          </p>
                        </div>
                        <ScoreRing score={fw.compliance_score} size={56} />
                      </div>
                      <div className="flex gap-3 text-xs">
                        <span className="text-emerald-600">{fw.passing_controls} passed</span>
                        <span className="text-red-500">{fw.failing_controls} failed</span>
                        <span className="text-slate-400" title="Controls that scanning cannot evidence; attest these manually">{fw.not_applicable} manual</span>
                        {(fw.not_assessed ?? 0) > 0 && <span className="text-amber-500">{fw.not_assessed} not assessed</span>}
                      </div>
                      <div className="mt-3 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex">
                        <div className="bg-emerald-500 h-full" style={{ width: `${(fw.passing_controls / Math.max(fw.total_controls, 1)) * 100}%` }} />
                        <div className="bg-red-400 h-full" style={{ width: `${(fw.failing_controls / Math.max(fw.total_controls, 1)) * 100}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Assessment History */}
              {(assessmentsData?.items || assessmentsData?.assessments)?.length > 0 && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-orange-500" />
                    Recent Assessments
                  </h3>
                  <div className="space-y-2">
                    {(assessmentsData.items || assessmentsData.assessments).map((a: any) => (
                      <div key={a.id} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl">
                        <div className="flex items-center gap-3">
                          <ScoreRing score={a.total_checks ? a.compliance_score : null} size={36} />
                          <div>
                            <p className="text-sm font-medium text-slate-900 dark:text-white">
                              {a.total_checks && a.compliance_score != null
                                ? `${Math.round(a.compliance_score)}% of cloud-resource checks passed`
                                : "No cloud resources checked"}
                            </p>
                            <p className="text-xs text-slate-500">
                              {a.passed ?? 0} passed · {a.failed ?? 0} failed · {a.errors ?? 0} errors
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-xs text-slate-500">{a.triggered_by || "manual"}</p>
                          <p className="text-xs text-slate-400">{a.started_at ? new Date(a.started_at).toLocaleString() : "—"}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Empty state */}
              {stats.frameworks_count === 0 && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-12 text-center">
                  <div className="w-16 h-16 bg-orange-50 dark:bg-orange-950/30 rounded-2xl flex items-center justify-center mx-auto mb-4">
                    <BookOpen className="w-8 h-8 text-orange-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">No Compliance Frameworks</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">Seed frameworks to get started with SOC2, ISO27001, PCI-DSS, HIPAA, and CIS benchmarks.</p>
                  <button
                    onClick={() => seedMut.mutate()}
                    disabled={seedMut.isPending}
                    className="inline-flex items-center gap-2 px-6 h-11 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold text-sm"
                  >
                    <BookOpen className="w-4 h-4" />
                    Seed Frameworks
                  </button>
                </div>
              )}
            </>
          ) : null}
        </div>
      )}

      {/* ─── Frameworks ─── */}
      {activeTab === "frameworks" && (
        <div className="space-y-4">
          {fwLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="space-y-3">
              {(frameworks || []).map((fw) => {
                const expanded = expandedFrameworkId === fw.id;
                return (
                  <div key={fw.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <button
                      onClick={() => setExpandedFrameworkId(expanded ? null : fw.id)}
                      className="w-full flex items-center justify-between p-5 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
                    >
                      <div className="flex items-center gap-4">
                        <ScoreRing score={fw.compliance_score} size={48} />
                        <div className="text-left">
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{fw.name}</h4>
                            {fw.reference_url && (
                              <a href={fw.reference_url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-orange-500 hover:text-orange-600" title="View official standard">
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            )}
                          </div>
                          <p className="text-xs text-slate-400">v{fw.version} · {fw.total_controls} controls</p>
                          <p className="text-xs mt-0.5">
                            {fw.last_assessed
                              ? <span className="text-emerald-600">Evaluated {new Date(fw.last_assessed).toLocaleDateString()}</span>
                              : <span className="text-amber-500">Not yet evaluated</span>}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="flex gap-3 text-xs">
                          <span className="text-emerald-600 font-medium">{fw.passing_controls} passed</span>
                          <span className="text-red-500 font-medium">{fw.failing_controls} failed</span>
                        </div>
                        <button
                          onClick={(e) => { e.stopPropagation(); toggleFwMut.mutate(fw.id); }}
                          className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                          title={fw.is_enabled ? "Disable framework" : "Enable framework"}
                        >
                          {fw.is_enabled
                            ? <ToggleRight className="w-6 h-6 text-emerald-500" />
                            : <ToggleLeft className="w-6 h-6 text-slate-400" />}
                        </button>
                        {expanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                      </div>
                    </button>

                    {expanded && (
                      <div className="border-t border-slate-100 dark:border-slate-800">
                        {ctrlLoading ? (
                          <div className="flex justify-center py-8"><Loader2 className="w-5 h-5 animate-spin text-orange-500" /></div>
                        ) : (
                          <div className="max-h-[50vh] overflow-y-auto">
                          <table className="w-full">
                            <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                              <tr className="border-b border-slate-100 dark:border-slate-800">
                                {["Control ID", "Title", "Compliance", "Failed / Total", "Severity", "Status"].map((h) => (
                                  <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-50 dark:divide-slate-800/50">
                              {(controls || []).map((ctrl) => {
                                const isExpanded = expandedControlId === ctrl.id;
                                const total = ctrl.total_resources || 0;
                                const failed = ctrl.failed_resources || 0;
                                const passed = total - failed;
                                const passedPct = total > 0 ? (passed / total) * 100 : 100;
                                // Tri-state: all pass → green, all fail → red, partial → amber
                                const statusKind: "passed" | "partial" | "failed" | "na" =
                                  total === 0
                                    ? "na"
                                    : failed === 0
                                    ? "passed"
                                    : passed === 0
                                    ? "failed"
                                    : "partial";
                                const barColor =
                                  statusKind === "passed"
                                    ? "bg-emerald-500"
                                    : statusKind === "failed"
                                    ? "bg-red-500"
                                    : "bg-amber-500";
                                const badgeClass =
                                  statusKind === "passed"
                                    ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400"
                                    : statusKind === "failed"
                                    ? "bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-400"
                                    : statusKind === "partial"
                                    ? "bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-400"
                                    : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400";
                                const badgeIcon =
                                  statusKind === "passed" ? <CheckCircle2 className="w-3.5 h-3.5" />
                                  : statusKind === "failed" ? <XCircle className="w-3.5 h-3.5" />
                                  : statusKind === "partial" ? <AlertTriangle className="w-3.5 h-3.5" />
                                  : null;
                                const badgeLabel =
                                  statusKind === "passed" ? "PASSED"
                                  : statusKind === "failed" ? "FAILED"
                                  : statusKind === "partial" ? "PARTIAL"
                                  : "NOT ASSESSED";
                                return (
                                  <React.Fragment key={ctrl.id}>
                                    <tr
                                      onClick={() => handleControlExpand(ctrl)}
                                      className={`cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/20 ${isExpanded ? "bg-slate-50 dark:bg-slate-800/30" : ""}`}
                                    >
                                      <td className="px-4 py-3 text-xs font-mono text-slate-600 dark:text-slate-400 whitespace-nowrap">
                                        <div className="flex items-center gap-1.5">
                                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-400" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400" />}
                                          {ctrl.control_id}
                                        </div>
                                      </td>
                                      <td className="px-4 py-3 text-sm text-slate-900 dark:text-white max-w-xs truncate">{ctrl.title}</td>
                                      <td className="px-4 py-3" style={{ minWidth: 140 }}>
                                        <div className="w-full h-3 rounded-full overflow-hidden bg-slate-100 dark:bg-slate-800 flex">
                                          {total > 0 ? (
                                            <>
                                              <div className="h-full bg-emerald-500 transition-all" style={{ width: `${passedPct}%` }} />
                                              <div className="h-full bg-red-500 transition-all" style={{ width: `${100 - passedPct}%` }} />
                                            </>
                                          ) : (
                                            <div className="h-full bg-slate-300 dark:bg-slate-700 w-full" />
                                          )}
                                        </div>
                                      </td>
                                      <td className="px-4 py-3 text-xs font-medium text-slate-700 dark:text-slate-300 whitespace-nowrap">
                                        {failed > 0 ? (
                                          <span className="text-red-600 dark:text-red-400">{failed}</span>
                                        ) : (
                                          <span className="text-emerald-600 dark:text-emerald-400">0</span>
                                        )}
                                        <span className="text-slate-400"> / {total}</span>
                                      </td>
                                      <td className="px-4 py-3"><SeverityBadge level={ctrl.severity} /></td>
                                      <td className="px-4 py-3">
                                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold ${badgeClass}`}>
                                          {badgeIcon}
                                          {badgeLabel}
                                        </span>
                                      </td>
                                    </tr>
                                    {isExpanded && (
                                      <tr>
                                        <td colSpan={6} className="px-0 py-0">
                                          <div className="bg-slate-50 dark:bg-slate-800/40 border-y border-slate-200 dark:border-slate-700 p-5">
                                            {/* Control description */}
                                            {ctrl.description && (
                                              <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">{ctrl.description}</p>
                                            )}
                                            {/* Category badges */}
                                            <div className="flex flex-wrap gap-1.5 mb-4">
                                              {(ctrl.finding_categories || []).map((cat) => (
                                                <span key={cat} className="px-2 py-0.5 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded text-[10px] font-medium uppercase">{cat}</span>
                                              ))}
                                            </div>
                                            {/* Affected resources table */}
                                            {controlResourcesLoading ? (
                                              <div className="flex justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-orange-500" /></div>
                                            ) : controlResources && controlResources.items.length > 0 ? (
                                              <>
                                                <h5 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                                  Evaluated Resources ({controlResources.total})
                                                  {statusKind === "passed" && (
                                                    <span className="ml-2 text-emerald-600 dark:text-emerald-400 normal-case font-medium">— All compliant</span>
                                                  )}
                                                </h5>
                                                {controlResources.remediation_notes && statusKind !== "passed" && (
                                                  <p className="text-xs text-amber-600 dark:text-amber-400 mb-3 bg-amber-50 dark:bg-amber-950/20 rounded p-2">
                                                    <strong>Remediation:</strong> {controlResources.remediation_notes}
                                                  </p>
                                                )}
                                                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700 max-h-[320px] overflow-y-auto">
                                                  <table className="w-full text-sm">
                                                    <thead className="sticky top-0 z-10">
                                                      <tr className="bg-slate-100 dark:bg-slate-800">
                                                        {["Status", "Severity", "Category", "File / Resource", "Rule", "Title"].map((h) => (
                                                          <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase">{h}</th>
                                                        ))}
                                                      </tr>
                                                    </thead>
                                                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                                      {controlResources.items.map((r, ri) => {
                                                        const rPassed = r.status === "Passed";
                                                        return (
                                                        <tr key={`${r.status}-${r.file_path ?? r.resource_name ?? ri}-${r.id ?? ri}`} className="hover:bg-white dark:hover:bg-slate-800/60">
                                                          <td className="px-3 py-2">
                                                            {rPassed ? (
                                                              <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                                                                <CheckCircle2 className="w-3 h-3" /> Passed
                                                              </span>
                                                            ) : (
                                                              <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-400">
                                                                <XCircle className="w-3 h-3" /> Failed
                                                              </span>
                                                            )}
                                                          </td>
                                                          <td className="px-3 py-2"><SeverityBadge level={r.severity} /></td>
                                                          <td className="px-3 py-2 text-xs uppercase text-slate-500">{r.category}</td>
                                                          <td className="px-3 py-2 text-xs">
                                                            {r.file_link ? (
                                                              <a href={r.file_link} target="_blank" rel="noopener noreferrer" className="text-orange-600 dark:text-orange-400 hover:underline flex items-center gap-1">
                                                                {r.file_path || r.resource_name}
                                                                {r.line_number && <span className="text-slate-400">:{r.line_number}</span>}
                                                                <ExternalLink className="w-3 h-3 flex-shrink-0" />
                                                              </a>
                                                            ) : (
                                                              <span className="text-slate-600 dark:text-slate-400">{r.file_path || r.resource_name || "—"}</span>
                                                            )}
                                                          </td>
                                                          <td className="px-3 py-2 text-[10px] font-mono text-slate-500 max-w-[120px] truncate">{r.rule_id}</td>
                                                          <td className="px-3 py-2 text-xs text-slate-700 dark:text-slate-300 max-w-[200px] truncate">{r.title}</td>
                                                        </tr>
                                                        );
                                                      })}
                                                    </tbody>
                                                  </table>
                                                </div>
                                              </>
                                            ) : (
                                              <div className="text-center py-4 text-sm text-slate-400">
                                                No evaluated resources found for this control
                                              </div>
                                            )}
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
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {(frameworks || []).length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                  No frameworks yet. Click &quot;Seed Frameworks&quot; to load industry-standard compliance frameworks.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── Policies ─── */}
      {activeTab === "policies" && (
        <div className="space-y-4">
          <div className="flex justify-end gap-3">
            <button
              onClick={() => evalPoliciesMut.mutate()}
              disabled={evalPoliciesMut.isPending}
              className="inline-flex items-center gap-2 px-4 h-10 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-sm font-semibold disabled:opacity-50"
              title="Check open scan findings against all enabled finding-based policies"
            >
              {evalPoliciesMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <PlayCircle className="w-4 h-4" />}
              Evaluate Against Findings
            </button>
            <button
              onClick={() => setShowPolicyModal(true)}
              className="inline-flex items-center gap-2 px-4 h-10 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-sm font-semibold"
            >
              <Plus className="w-4 h-4" /> Add Policy
            </button>
          </div>
          {evalPoliciesMut.isSuccess && (
            <div className="p-3 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 rounded-xl text-sm text-emerald-700 dark:text-emerald-400">
              {(evalPoliciesMut.data as any)?.status === "no_policies"
                ? "No enabled policies to evaluate."
                : `Evaluated ${(evalPoliciesMut.data as any).policies_evaluated} policies against ${(evalPoliciesMut.data as any).total_findings} open findings: ${(evalPoliciesMut.data as any).violations_created} new violations, ${(evalPoliciesMut.data as any).exempted} exempted. ${(evalPoliciesMut.data as any).policies_skipped} cloud-resource policies are evaluated by Run Assessment.`}
            </div>
          )}
          {evalPoliciesMut.isError && (
            <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-xl text-sm text-red-700 dark:text-red-400">
              Policy evaluation failed. Please try again.
            </div>
          )}

          {polLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(policies || []).map((pol) => (
                <div key={pol.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        pol.is_enforced ? "bg-red-50 dark:bg-red-950/30" :
                        pol.severity === "high" || pol.severity === "critical" ? "bg-amber-50 dark:bg-amber-950/30" : "bg-blue-50 dark:bg-blue-950/30"
                      }`}>
                        {pol.is_enforced ? <Lock className="w-4 h-4 text-red-500" /> :
                         pol.severity === "high" || pol.severity === "critical" ? <AlertTriangle className="w-4 h-4 text-amber-500" /> :
                         <FileCheck className="w-4 h-4 text-blue-500" />}
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-slate-900 dark:text-white">{pol.name}</h4>
                        <p className="text-xs text-slate-400">{pol.policy_type} · {pol.is_enforced ? "Enforced" : "Monitor"} · {pol.severity}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={() => { setEditingPolicy(pol); setShowPolicyModal(true); }} className="p-1.5 text-slate-400 hover:text-orange-500 rounded-lg hover:bg-orange-50 dark:hover:bg-orange-950/30" title="Edit policy">
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => deletePolicyMut.mutate(pol.id)} className="p-1.5 text-slate-400 hover:text-red-500 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30" title="Delete policy">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  {pol.description && <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{pol.description}</p>}
                  {pol.target_repos && pol.target_repos.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {pol.target_repos.map((repo: string) => (
                        <span key={repo} className="inline-flex items-center gap-1 px-2 py-0.5 bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 rounded-md text-[10px] font-medium">
                          <GitBranch className="w-2.5 h-2.5" />{repo.split("/").pop()}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="flex items-center gap-3 text-xs">
                    <span className={pol.is_enabled ? "text-emerald-600" : "text-slate-400"}>{pol.is_enabled ? "Active" : "Inactive"}</span>
                    <span className="text-slate-400">{pol.target_repos && pol.target_repos.length > 0 ? `${pol.target_repos.length} repo(s)` : "All repos"}</span>
                    {pol.violations_count > 0 && (
                      <span className="text-red-500 font-medium">{pol.violations_count} violations</span>
                    )}
                  </div>
                </div>
              ))}
              {(policies || []).length === 0 && (
                <div className="col-span-2 py-12 text-center text-sm text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                  No policies created yet. Click &quot;Add Policy&quot; to define security policies.
                </div>
              )}
            </div>
          )}

          {/* Policy creation modal */}
          {showPolicyModal && <PolicyModal policy={editingPolicy} onClose={() => { setShowPolicyModal(false); setEditingPolicy(null); }} />}
        </div>
      )}

      {/* ─── Violations ─── */}
      {activeTab === "violations" && (
        <div className="space-y-4">
          {violLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden max-h-[calc(100vh-320px)] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                  <tr className="border-b border-slate-100 dark:border-slate-800">
                    {["Resource", "Type", "Severity", "Status", "Details", "Detected"].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {violations.map((v) => (
                    <tr key={v.id} onClick={() => handleViolationClick(v)} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 cursor-pointer group">
                      <td className="px-4 py-3 text-sm text-slate-900 dark:text-white">
                        <div className="flex items-center gap-2">
                          <span>{v.resource_name || v.resource_id || "Unknown"}</span>
                          <Eye className="w-3.5 h-3.5 text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{v.resource_type}</td>
                      <td className="px-4 py-3"><SeverityBadge level={v.severity} /></td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                          v.status === "open" ? "bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-400" :
                          v.status === "resolved" ? "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/30 dark:text-emerald-400" :
                          v.status === "accepted" ? "bg-amber-50 text-amber-600 dark:bg-amber-950/30 dark:text-amber-400" :
                          "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"
                        }`}>{v.status}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 max-w-[200px] truncate">{v.violation_details ? (v.violation_details.message || v.violation_details.detail || JSON.stringify(v.violation_details)) as string : "—"}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{new Date(v.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {violations.length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400">No violations recorded.</div>
              )}
            </div>
          )}

          {totalPages > 1 && (
            <div className="flex items-center justify-between px-1">
              <p className="text-xs text-slate-500 dark:text-slate-400">Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, totalViolations)} of {totalViolations}</p>
              <div className="flex gap-1">
                <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1} className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-30"><ChevronLeft className="w-4 h-4" /></button>
                <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages} className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-30"><ChevronRight className="w-4 h-4" /></button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─── Exceptions ─── */}
      {activeTab === "exceptions" && (
        <div className="space-y-4">
          {approveMut.isError && (
            <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-xl text-sm text-red-700 dark:text-red-400">
              {(approveMut.error as any)?.response?.data?.detail || "Could not approve the exception."}
            </div>
          )}
          <div className="flex justify-end">
            <button
              onClick={() => setShowExceptionModal(true)}
              className="inline-flex items-center gap-2 px-4 h-10 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-sm font-semibold"
            >
              <Plus className="w-4 h-4" /> Request Exception
            </button>
          </div>

          {excLoading ? (
            <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-orange-500" /></div>
          ) : (
            <div className="space-y-3">
              {(exceptions || []).map((exc) => (
                <div key={exc.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                          exc.status === "pending" ? "bg-amber-50 text-amber-600 dark:bg-amber-950/30 dark:text-amber-400" :
                          exc.status === "approved" ? "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/30 dark:text-emerald-400" :
                          "bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-400"
                        }`}>{exc.status.toUpperCase()}</span>
                        <SeverityBadge level={exc.severity} />
                      </div>
                      <p className="text-sm font-medium text-slate-900 dark:text-white">{exc.title}</p>
                      {exc.description && <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{exc.description}</p>}
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{exc.justification}</p>
                      <p className="text-xs text-slate-400 mt-2">Requested by {exc.requested_by} · {new Date(exc.created_at).toLocaleDateString()}</p>
                    </div>
                    <div className="flex gap-2 shrink-0 ml-4">
                      <button
                        onClick={() => { setEditingException(exc); setShowExceptionModal(true); }}
                        className="inline-flex items-center gap-1 px-3 h-8 bg-slate-50 hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-lg text-xs font-medium"
                      >
                        <Pencil className="w-3 h-3" /> Edit
                      </button>
                      {exc.status === "pending" && (
                        <>
                          <button
                            onClick={() => approveMut.mutate(exc.id)}
                            disabled={approveMut.isPending}
                            className="inline-flex items-center gap-1 px-3 h-8 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 rounded-lg text-xs font-medium"
                          >
                            <ThumbsUp className="w-3 h-3" /> Approve
                          </button>
                          <button
                            onClick={() => rejectMut.mutate(exc.id)}
                            disabled={rejectMut.isPending}
                            className="inline-flex items-center gap-1 px-3 h-8 bg-red-50 hover:bg-red-100 text-red-700 rounded-lg text-xs font-medium"
                          >
                            <ThumbsDown className="w-3 h-3" /> Reject
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {(exceptions || []).length === 0 && (
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                  No risk exceptions. Click &quot;Request Exception&quot; to submit one.
                </div>
              )}
            </div>
          )}

          {showExceptionModal && <ExceptionModal exception={editingException} onClose={() => { setShowExceptionModal(false); setEditingException(null); }} />}
        </div>
      )}
      {/* ─── Violation Detail Modal ─── */}
      {showViolationModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={() => { setShowViolationModal(false); setSelectedViolation(null); }}>
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 w-full max-w-2xl max-h-[85vh] overflow-y-auto shadow-2xl" onClick={(e) => e.stopPropagation()}>
            {violationDetailLoading ? (
              <div className="flex justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>
            ) : selectedViolation ? (
              <>
                <div className="p-6 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <ShieldAlert className="w-5 h-5 text-red-500" />
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white">Violation Detail</h3>
                      </div>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        {selectedViolation.policy_name || `Policy #${selectedViolation.policy_id}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge level={selectedViolation.severity || selectedViolation.policy_severity} />
                      <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                        selectedViolation.status === "open" ? "bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-400" :
                        selectedViolation.status === "resolved" ? "bg-emerald-50 text-emerald-600" :
                        selectedViolation.status === "accepted" ? "bg-amber-50 text-amber-600" :
                        "bg-slate-100 text-slate-500"
                      }`}>{selectedViolation.status?.toUpperCase()}</span>
                    </div>
                  </div>
                </div>
                <div className="p-6 space-y-5">
                  {/* Resource Info */}
                  <div>
                    <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Resource</h4>
                    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4 space-y-1.5">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Name</span>
                        <span className="text-slate-900 dark:text-white font-medium">{selectedViolation.resource_name || "—"}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Type</span>
                        <span className="text-slate-900 dark:text-white">{selectedViolation.resource_type || "—"}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Provider</span>
                        <span className="text-slate-900 dark:text-white">{selectedViolation.cloud_provider || "—"}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Resource ID</span>
                        <span className="text-slate-900 dark:text-white font-mono text-xs">{selectedViolation.resource_id || "—"}</span>
                      </div>
                    </div>
                  </div>

                  {/* Policy Description */}
                  {selectedViolation.policy_description && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Policy</h4>
                      <p className="text-sm text-slate-700 dark:text-slate-300">{selectedViolation.policy_description}</p>
                    </div>
                  )}

                  {/* Violation Details (evidence from JSON) */}
                  {selectedViolation.violation_details && Object.keys(selectedViolation.violation_details).length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Violation Evidence</h4>
                      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4">
                        <pre className="text-xs text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all font-mono">{JSON.stringify(selectedViolation.violation_details, null, 2)}</pre>
                      </div>
                    </div>
                  )}

                  {/* Assessment Evidence (from new engine) */}
                  {selectedViolation.assessment_evidence && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Assessment Evidence</h4>
                      <div className="space-y-2">
                        {(selectedViolation.assessment_evidence.evidence || []).map((ev: any, i: number) => (
                          <div key={i} className={`flex items-start gap-3 p-3 rounded-lg text-sm ${
                            ev.result === true ? "bg-emerald-50 dark:bg-emerald-950/20" : "bg-red-50 dark:bg-red-950/20"
                          }`}>
                            {ev.result ? <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" /> : <XCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />}
                            <div>
                              <p className={`font-medium ${ev.result ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}`}>{ev.message || `${ev.field} ${ev.operator} ${JSON.stringify(ev.expected)}`}</p>
                              <p className="text-xs text-slate-500 mt-0.5">Actual: <code className="bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded">{JSON.stringify(ev.actual)}</code></p>
                            </div>
                          </div>
                        ))}
                        {selectedViolation.assessment_evidence.remediation && (
                          <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-950/20 text-sm">
                            <p className="font-medium text-blue-700 dark:text-blue-400 flex items-center gap-1"><Info className="w-4 h-4" /> Remediation</p>
                            <p className="text-blue-600 dark:text-blue-300 mt-1">{selectedViolation.assessment_evidence.remediation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Resource Config (if available from new engine) */}
                  {selectedViolation.resource_detail?.config && (
                    <details className="group">
                      <summary className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider cursor-pointer flex items-center gap-1 select-none">
                        Resource Configuration <ChevronDown className="w-3.5 h-3.5 group-open:rotate-180 transition-transform" />
                      </summary>
                      <div className="mt-2 bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4">
                        <pre className="text-xs text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all font-mono max-h-60 overflow-y-auto">{JSON.stringify(selectedViolation.resource_detail.config, null, 2)}</pre>
                      </div>
                    </details>
                  )}

                  {/* Acceptance Info */}
                  {selectedViolation.status === "accepted" && (
                    <div className="bg-amber-50 dark:bg-amber-950/20 rounded-xl p-4">
                      <p className="text-sm font-medium text-amber-700 dark:text-amber-400">Risk Accepted</p>
                      <p className="text-xs text-amber-600 mt-1">By {selectedViolation.accepted_by} on {selectedViolation.accepted_at ? new Date(selectedViolation.accepted_at).toLocaleDateString() : "—"}</p>
                      {selectedViolation.acceptance_reason && <p className="text-xs text-amber-600 mt-1">Reason: {selectedViolation.acceptance_reason}</p>}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-3 pt-2">
                    {selectedViolation.status === "open" && (
                      <div className="flex-1 flex items-center gap-2">
                        <input
                          type="text"
                          placeholder="Risk acceptance reason..."
                          value={acceptReason}
                          onChange={(e) => setAcceptReason(e.target.value)}
                          className="flex-1 h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                        />
                        <button
                          onClick={() => acceptViolMut.mutate({ id: selectedViolation.id, reason: acceptReason })}
                          disabled={!acceptReason || acceptViolMut.isPending}
                          className="px-4 h-10 bg-amber-600 hover:bg-amber-700 text-white rounded-xl text-sm font-semibold disabled:opacity-50"
                        >
                          {acceptViolMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Accept Risk"}
                        </button>
                      </div>
                    )}
                    {selectedViolation.status === "accepted" && (
                      <button
                        onClick={() => reopenViolMut.mutate(selectedViolation.id)}
                        disabled={reopenViolMut.isPending}
                        className="px-4 h-10 bg-red-600 hover:bg-red-700 text-white rounded-xl text-sm font-semibold disabled:opacity-50"
                      >
                        {reopenViolMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Re-Open Violation"}
                      </button>
                    )}
                    <button onClick={() => { setShowViolationModal(false); setSelectedViolation(null); }} className="px-4 h-10 text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl ml-auto">
                      Close
                    </button>
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}
    </PageLayout>
  );
}

/* Finding domains a policy can match; mirrors backend services/governance/compliance.py */
const POLICY_FINDING_CATEGORIES = ["encryption", "network", "iam", "logging", "monitoring", "storage", "secrets", "cve", "sca", "sast", "iac"];

/* ─── Policy Modal ──────────────────────────────────────── */
function PolicyModal({ onClose, policy }: { onClose: () => void; policy?: Policy | null }) {
  const isEditing = !!policy;
  const queryClient = useQueryClient();
  const [name, setName] = useState(policy?.name || "");
  const [description, setDescription] = useState(policy?.description || "");
  const [policyType, setPolicyType] = useState(policy?.policy_type || "security");
  const [severity, setSeverity] = useState(policy?.severity || "medium");
  const [isEnforced, setIsEnforced] = useState(policy?.is_enforced || false);
  const [scopeMode, setScopeMode] = useState<"all" | "specific">(
    policy?.target_repos && policy.target_repos.length > 0 ? "specific" : "all"
  );
  const [selectedRepos, setSelectedRepos] = useState<string[]>(policy?.target_repos || []);

  const { data: repos } = useQuery({ queryKey: ["repos-for-policy"], queryFn: getRepos });
  const repoList: { full_name: string; enabled: boolean }[] = repos || [];

  const toggleRepoSelection = (repoName: string) => {
    setSelectedRepos((prev) =>
      prev.includes(repoName) ? prev.filter((r) => r !== repoName) : [...prev, repoName]
    );
  };

  // Cloud-resource policies carry a condition tree (object); those rules are kept as-is.
  const isCloudPolicy = !!policy && !Array.isArray(policy.rules) && typeof policy.rules === "object" && policy.rules !== null;
  const existingRules: any[] = Array.isArray(policy?.rules) ? (policy!.rules as any[]) : [];
  const [ruleCategories, setRuleCategories] = useState<string[]>(
    Array.from(new Set(existingRules.flatMap((r) => r?.categories || [])))
  );
  const [rulePrefixes, setRulePrefixes] = useState<string>(
    Array.from(new Set(existingRules.flatMap((r) => r?.rule_id_prefixes || []))).join(", ")
  );
  const prefixes = rulePrefixes.split(",").map((p) => p.trim()).filter(Boolean);
  const hasRules = isCloudPolicy || ruleCategories.length > 0 || prefixes.length > 0;

  const payload = {
    name, description, policy_type: policyType, severity, is_enabled: policy?.is_enabled ?? true, is_enforced: isEnforced,
    rules: isCloudPolicy ? policy!.rules : [{ categories: ruleCategories, rule_id_prefixes: prefixes }],
    target_repos: scopeMode === "specific" && selectedRepos.length > 0 ? selectedRepos : null,
  };

  const mut = useMutation({
    mutationFn: () => isEditing ? updateSecurityPolicy(policy!.id, payload) : createSecurityPolicy(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-policies"] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{isEditing ? "Edit Security Policy" : "New Security Policy"}</h3>
          <button onClick={onClose} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 focus:ring-2 focus:ring-orange-500" />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Description</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} className="w-full px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 focus:ring-2 focus:ring-orange-500 h-20 resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Type</label>
              <select value={policyType} onChange={(e) => setPolicyType(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800">
                <option value="security">Security</option>
                <option value="compliance">Compliance</option>
                <option value="access">Access</option>
                <option value="data">Data</option>
                <option value="network">Network</option>
                <option value="encryption">Encryption</option>
                <option value="iam">IAM</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={isEnforced} onChange={(e) => setIsEnforced(e.target.checked)} className="rounded border-slate-300 dark:border-slate-600 text-orange-600 focus:ring-orange-500" />
              <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Enforce policy (fail CI pipeline scans that violate it)</span>
            </label>
          </div>

          {/* What the policy matches */}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 block">Violated By</label>
            {isCloudPolicy ? (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                This is a cloud-resource policy. Its condition is evaluated against synced cloud resources by Run Assessment and cannot be edited here.
              </p>
            ) : (
              <>
                <p className="text-xs text-slate-400 mb-2">A scan finding violates this policy if it is in any selected category or its rule ID starts with any listed prefix.</p>
                <div className="flex flex-wrap gap-2 mb-3">
                  {POLICY_FINDING_CATEGORIES.map((cat) => {
                    const on = ruleCategories.includes(cat);
                    return (
                      <button
                        key={cat}
                        type="button"
                        onClick={() => setRuleCategories((prev) => on ? prev.filter((c) => c !== cat) : [...prev, cat])}
                        className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${on ? "bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}
                      >
                        {cat}
                      </button>
                    );
                  })}
                </div>
                <input
                  value={rulePrefixes}
                  onChange={(e) => setRulePrefixes(e.target.value)}
                  placeholder="Rule ID prefixes, comma-separated (e.g. CKV_AWS_19, AVD-AWS-0086)"
                  className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 focus:ring-2 focus:ring-orange-500"
                />
                {!hasRules && <p className="text-xs text-amber-600 mt-2">Select at least one category or enter a rule ID prefix.</p>}
              </>
            )}
          </div>

          {/* Repo scope selector */}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 block">Repository Scope</label>
            <div className="flex gap-3 mb-3">
              <button
                onClick={() => setScopeMode("all")}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${scopeMode === "all" ? "bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}
              >
                All Repositories
              </button>
              <button
                onClick={() => setScopeMode("specific")}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${scopeMode === "specific" ? "bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}
              >
                Specific Repositories
              </button>
            </div>
            {scopeMode === "specific" && (
              <div className="max-h-36 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-xl p-2 space-y-1">
                {repoList.length === 0 && (
                  <p className="text-xs text-slate-400 text-center py-2">No connected repositories. Add integrations first.</p>
                )}
                {repoList.map((repo) => (
                  <label key={repo.full_name} className="flex items-center gap-2 px-2 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedRepos.includes(repo.full_name)}
                      onChange={() => toggleRepoSelection(repo.full_name)}
                      className="rounded border-slate-300 dark:border-slate-600 text-orange-600 focus:ring-orange-500"
                    />
                    <span className="text-xs text-slate-700 dark:text-slate-300 truncate">{repo.full_name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 h-10 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 rounded-xl">Cancel</button>
          <button onClick={() => mut.mutate()} disabled={!name || !hasRules || mut.isPending} className="px-5 h-10 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-sm font-semibold disabled:opacity-50">
            {mut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : isEditing ? "Save Changes" : "Create Policy"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Exception Modal ───────────────────────────────────── */
function ExceptionModal({ exception, onClose }: { exception?: RiskException | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEditing = !!exception;
  const [title, setTitle] = useState(exception?.title || "");
  const [riskType, setRiskType] = useState(exception?.risk_type || "security_group");
  const [justification, setJustification] = useState(exception?.justification || "");
  const [severity, setSeverity] = useState(exception?.severity || "medium");
  const [compensatingControls, setCompensatingControls] = useState(exception?.compensating_controls || "");
  const [description, setDescription] = useState(exception?.description || "");
  // Scope: without a policy or resource the exception exempts nothing
  const [policyId, setPolicyId] = useState<string>(exception?.policy_id ? String(exception.policy_id) : "");
  const [resourceId, setResourceId] = useState(exception?.resource_id || "");
  const [expiresAt, setExpiresAt] = useState(exception?.expires_at ? exception.expires_at.slice(0, 10) : "");
  const { data: policyOptions } = useQuery<Policy[]>({ queryKey: ["governance-policies"], queryFn: getSecurityPolicies });
  const hasScope = !!policyId || !!resourceId.trim();

  const body = {
    title, description: description || null, risk_type: riskType, severity, justification,
    compensating_controls: compensatingControls || null,
    policy_id: policyId ? Number(policyId) : null,
    resource_id: resourceId.trim() || null,
    expires_at: expiresAt ? new Date(`${expiresAt}T23:59:59Z`).toISOString() : null,
  };

  const mut = useMutation({
    mutationFn: () => isEditing ? updateRiskException(exception!.id, body) : createRiskException(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["governance-exceptions"] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 w-full max-w-md shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{isEditing ? "Edit Exception" : "Request Risk Exception"}</h3>
          <button onClick={onClose} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Title</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Allow public S3 bucket for static assets" className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-orange-500" />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Risk Type</label>
            <select value={riskType} onChange={(e) => setRiskType(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white">
              <option value="security_group">Security Group</option>
              <option value="s3_bucket">S3 Bucket</option>
              <option value="iam_role">IAM Role</option>
              <option value="vm_instance">VM Instance</option>
              <option value="database">Database</option>
              <option value="encryption">Encryption</option>
              <option value="network">Network</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Applies To Policy</label>
            <select value={policyId} onChange={(e) => setPolicyId(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white">
              <option value="">Any policy</option>
              {(policyOptions || []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Applies To Resource</label>
            <input value={resourceId} onChange={(e) => setResourceId(e.target.value)} placeholder="Resource ID as shown on the violation (leave empty for all resources of the policy)" className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-orange-500" />
            {!hasScope && <p className="text-xs text-amber-600 mt-1">Choose a policy, a resource, or both.</p>}
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Expires On (optional)</label>
            <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white" />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Justification</label>
            <textarea value={justification} onChange={(e) => setJustification(e.target.value)} className="w-full px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-orange-500 h-20 resize-none" placeholder="Explain why this exception is needed..." />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Compensating Controls</label>
            <textarea value={compensatingControls} onChange={(e) => setCompensatingControls(e.target.value)} className="w-full px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-orange-500 h-16 resize-none" placeholder="Alternative security measures in place..." />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1 block">Severity</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full h-10 px-3 border border-slate-200 dark:border-slate-700 rounded-xl text-sm bg-white dark:bg-slate-800 text-slate-900 dark:text-white">
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 h-10 text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl">Cancel</button>
          <button onClick={() => mut.mutate()} disabled={!title || !justification || !hasScope || mut.isPending} className="px-5 h-10 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-sm font-semibold disabled:opacity-50">
            {mut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : isEditing ? "Save Changes" : "Submit Request"}
          </button>
        </div>
      </div>
    </div>
  );
}
