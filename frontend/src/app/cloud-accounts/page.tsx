"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Cloud,
  Plus,
  Trash2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Shield,
  Server,
  ChevronRight,
  ExternalLink,
  Wifi,
  WifiOff,
  Loader2,
  Eye,
  EyeOff,
  Info,
  Zap,
  FileUp,
  BookOpen,
  CheckSquare,
  Key,
  Globe,
  Building2,
  Lock,
} from "lucide-react";
import {
  listCloudAccounts,
  createCloudAccount,
  deleteCloudAccount,
  testCloudAccount,
  testCloudCredentials,
  syncCloudAccount,
  getCredentialSchema,
  getCloudAccountResources,
} from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import AwsKeylessConnect from "@/components/AwsKeylessConnect";
import ProviderLogo from "@/components/ProviderLogo";

/* ─── Provider metadata ─────────────────────────────────────────────── */

const PROVIDERS = [
  {
    id: "aws",
    name: "Amazon Web Services",
    shortName: "AWS",
    color: "from-amber-500 to-orange-600",
    bgColor: "bg-amber-500/10",
    borderColor: "border-amber-500/30",
    textColor: "text-amber-700 dark:text-amber-400",
    icon: "☁️",
    description: "Connect via cross-account IAM Role (recommended) or Access Keys for resource discovery",
    features: ["SecurityAudit policy", "Cross-account AssumeRole", "Multi-region discovery"],
  },
  {
    id: "azure",
    name: "Microsoft Azure",
    shortName: "Azure",
    color: "from-blue-500 to-cyan-600",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/30",
    textColor: "text-blue-700 dark:text-blue-400",
    icon: "⬡",
    description: "Connect via App Registration (Service Principal) with Reader role on your tenant",
    features: ["Tenant-level visibility", "Subscription scoping", "Azure AD integration"],
  },
  {
    id: "gcp",
    name: "Google Cloud Platform",
    shortName: "GCP",
    color: "from-red-500 to-yellow-500",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/30",
    textColor: "text-red-700 dark:text-red-400",
    icon: "◈",
    description: "Connect via Service Account with Viewer role for project or organization-level scanning",
    features: ["Project & Org level", "Cloud Asset Inventory", "IAM policy analysis"],
  },
];

/* ─── AWS default region options ─────────────────────────────────────── */
const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
  "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
  "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
];
const AZURE_REGIONS = [
  "eastus", "eastus2", "westus", "westus2", "westus3",
  "centralus", "northcentralus", "southcentralus",
  "westeurope", "northeurope", "uksouth", "ukwest",
  "southeastasia", "eastasia", "japaneast", "japanwest",
  "australiaeast", "australiasoutheast", "canadacentral", "brazilsouth",
];
const GCP_REGIONS = [
  "us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
  "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-north1",
  "asia-east1", "asia-southeast1", "asia-northeast1", "asia-south1",
  "australia-southeast1", "southamerica-east1",
];
const REGION_OPTIONS: Record<string, string[]> = { aws: AWS_REGIONS, azure: AZURE_REGIONS, gcp: GCP_REGIONS };

const PROVIDER_MAP = Object.fromEntries(PROVIDERS.map((p) => [p.id, p]));

const STATUS_CONFIG: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  connected: { icon: CheckCircle2, color: "text-emerald-400", label: "Connected" },
  pending: { icon: Clock, color: "text-amber-400", label: "Pending" },
  error: { icon: XCircle, color: "text-red-400", label: "Error" },
  disabled: { icon: WifiOff, color: "text-zinc-500", label: "Disabled" },
};

/* ─── Types ──────────────────────────────────────────────────────────── */

interface CloudAccountType {
  id: number;
  provider: string;
  name: string;
  account_identifier: string;
  status: string;
  last_error: string | null;
  last_synced_at: string | null;
  resources_count: number;
  sync_enabled: boolean;
  sync_interval_hours: number;
  resource_types_filter: string[];
  regions: string[];
  created_at: string;
  updated_at: string;
  has_credentials: boolean;
}

interface CredField {
  key: string;
  label: string;
  type: string;
  required: boolean;
  placeholder?: string;
  help?: string;
}

/* ─── Reusable Wizard Field ───────────────────────────────────────── */
function WizardField({
  label, required, placeholder, help, value, onChange, mono, isPassword,
  showPasswords, setShowPasswords, fieldKey,
}: {
  label: string; required?: boolean; placeholder?: string; help?: string;
  value: string; onChange: (v: string) => void; mono?: boolean; isPassword?: boolean;
  showPasswords?: Record<string, boolean>; setShowPasswords?: (v: Record<string, boolean>) => void; fieldKey?: string;
}) {
  const fk = fieldKey || label.toLowerCase().replace(/\s+/g, "_");
  const show = showPasswords?.[fk] ?? false;
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300 mb-1">
        {label}
        {required && <span className="text-red-400 ml-1">*</span>}
      </label>
      {help && <p className="text-xs text-slate-400 dark:text-zinc-500 mb-1.5">{help}</p>}
      <div className="relative">
        <input
          type={isPassword && !show ? "password" : "text"}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={`w-full px-4 py-2.5 bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 rounded-lg text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-zinc-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none ${
            isPassword ? "pr-10" : ""
          } ${mono ? "font-mono text-sm" : ""}`}
        />
        {isPassword && setShowPasswords && (
          <button
            type="button"
            onClick={() => setShowPasswords({ ...showPasswords, [fk]: !show })}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-zinc-500 hover:text-slate-600 dark:hover:text-zinc-300"
          >
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        )}
      </div>
    </div>
  );
}

/* ─── Main Page ──────────────────────────────────────────────────────── */

export default function CloudAccountsPage() {
  const qc = useQueryClient();
  const [showWizard, setShowWizard] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const [wizardStep, setWizardStep] = useState(0);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [showPasswords, setShowPasswords] = useState<Record<string, boolean>>({});
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [expandedAccount, setExpandedAccount] = useState<number | null>(null);
  const [awsAuthMethod, setAwsAuthMethod] = useState<"assume_role" | "access_key">("assume_role");
  const [showSetupGuide, setShowSetupGuide] = useState(true);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null);
  const [testingInline, setTestingInline] = useState(false);
  const [awsKeyless, setAwsKeyless] = useState(true);              // AWS: connect without keys unless the user opts out
  const [collapsedProviders, setCollapsedProviders] = useState<string[]>([]);

  const openProvider = (providerId: string) => {
    setSelectedProvider(providerId);
    setFormData({});
    setTestResult(null);
    setAwsKeyless(true);
    setWizardStep(1);
    setShowWizard(true);
  };

  // Fetch accounts
  const { data, isLoading } = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => listCloudAccounts(),
  });

  // Fetch credential schema when provider selected
  const { data: credSchema } = useQuery({
    queryKey: ["cred-schema", selectedProvider],
    queryFn: () => getCredentialSchema(selectedProvider!),
    enabled: !!selectedProvider,
  });

  // Fetch resources for expanded account
  const { data: resourcesData } = useQuery({
    queryKey: ["cloud-account-resources", expandedAccount],
    queryFn: () => getCloudAccountResources(expandedAccount!, { limit: 20 }),
    enabled: expandedAccount !== null,
  });

  // Mutations
  const createMut = useMutation({
    mutationFn: createCloudAccount,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      resetWizard();
    },
  });

  const deleteMut = useMutation({
    mutationFn: deleteCloudAccount,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      setDeleteConfirm(null);
    },
  });

  const testMut = useMutation({
    mutationFn: testCloudAccount,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cloud-accounts"] }),
  });

  const syncMut = useMutation({
    mutationFn: syncCloudAccount,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cloud-accounts"] }),
  });

  const accounts: CloudAccountType[] = data?.accounts || [];

  const resetWizard = () => {
    setShowWizard(false);
    setSelectedProvider(null);
    setWizardStep(0);
    setFormData({});
    setShowPasswords({});
    setAwsAuthMethod("assume_role");
    setAwsKeyless(true);
    setShowSetupGuide(true);
    setSelectedRegions([]);
    setTestResult(null);
    setTestingInline(false);
    qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
  };

  /* Build the account_identifier and credentials from provider-specific fields */
  const buildAccount = (): { accountId: string; credentials: Record<string, string> } => {
    let accountId = "";
    const credentials: Record<string, string> = {};

    if (selectedProvider === "aws") {
      accountId = formData.aws_account_id || "";
      if (awsAuthMethod === "assume_role") {
        if (formData.role_arn) credentials.role_arn = formData.role_arn;
        if (formData.external_id) credentials.external_id = formData.external_id;
      } else {
        if (formData.access_key_id) credentials.access_key_id = formData.access_key_id;
        if (formData.secret_access_key) credentials.secret_access_key = formData.secret_access_key;
      }
    } else if (selectedProvider === "azure") {
      accountId = formData.tenant_id || "";
      if (formData.tenant_id) credentials.tenant_id = formData.tenant_id;
      if (formData.client_id) credentials.client_id = formData.client_id;
      if (formData.client_secret) credentials.client_secret = formData.client_secret;
      if (formData.subscription_id) credentials.subscription_id = formData.subscription_id;
    } else if (selectedProvider === "gcp") {
      accountId = formData.project_id || "";
      if (formData.project_id) credentials.project_id = formData.project_id;
      if (formData.service_account_json) credentials.service_account_json = formData.service_account_json;
    }
    return { accountId, credentials };
  };

  const handleSubmit = () => {
    if (!selectedProvider) return;
    const { accountId, credentials } = buildAccount();

    createMut.mutate({
      provider: selectedProvider,
      name: formData._name || `${PROVIDER_MAP[selectedProvider]?.shortName} Account`,
      account_identifier: accountId,
      credentials,
      regions: selectedRegions,
    });
  };

  /* Inline test connection during wizard */
  const handleTestInline = async () => {
    if (!selectedProvider) return;
    setTestingInline(true);
    setTestResult(null);
    try {
      // Validated by the backend against the provider before the account is saved
      const result = await testCloudCredentials(selectedProvider, buildAccount().credentials);
      if (result.status === "connected") {
        setTestResult({ status: "success", message: "Credentials validated against the provider. Ready to connect." });
      } else {
        setTestResult({ status: "error", message: result.error || "Connection test failed. Check your credentials." });
      }
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setTestResult({ status: "error", message: typeof detail === "string" ? detail : "Connection test failed. Check your credentials." });
    } finally {
      setTestingInline(false);
    }
  };

  /* Check if the provider-specific required fields are filled */
  const isStep1Complete = (): boolean => {
    if (!selectedProvider) return false;
    if (!formData._name?.trim()) return false;
    if (selectedProvider === "aws") {
      if (!formData.aws_account_id?.trim()) return false;
      if (awsAuthMethod === "assume_role" && !formData.role_arn?.trim()) return false;
      if (awsAuthMethod === "access_key" && (!formData.access_key_id?.trim() || !formData.secret_access_key?.trim())) return false;
    } else if (selectedProvider === "azure") {
      if (!formData.tenant_id?.trim() || !formData.client_id?.trim() || !formData.client_secret?.trim() || !formData.subscription_id?.trim()) return false;
    } else if (selectedProvider === "gcp") {
      if (!formData.project_id?.trim() || !formData.service_account_json?.trim()) return false;
    }
    return true;
  };

  const toggleRegion = (r: string) => {
    setSelectedRegions((prev) => prev.includes(r) ? prev.filter((x) => x !== r) : [...prev, r]);
  };

  // Summary stats
  const connectedCount = accounts.filter((a) => a.status === "connected").length;
  const totalResources = accounts.reduce((s, a) => s + a.resources_count, 0);
  const providerCounts = accounts.reduce((m, a) => ({ ...m, [a.provider]: (m[a.provider] || 0) + 1 }), {} as Record<string, number>);

  return (
    <PageLayout
      title="Cloud Connectors"
      subtitle="Connect your cloud accounts for real-time resource discovery and compliance assessment"
      icon={Cloud}
    >
      <div className="space-y-6">

      {/* One card per cloud; a card opens that cloud's connection dialog. */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {PROVIDERS.map((p) => {
          const count = providerCounts[p.id] || 0;
          return (
            <button
              key={p.id}
              onClick={() => openProvider(p.id)}
              className="group glass flex flex-col rounded-xl border border-slate-200 p-5 text-left transition-all hover:border-orange-500/60 hover:shadow-md dark:border-zinc-800"
            >
              <div className="flex items-start justify-between">
                <ProviderLogo provider={p.id} size="lg" />
                <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                  count
                    ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                    : "bg-slate-100 text-slate-700 dark:bg-zinc-800 dark:text-zinc-200"
                }`}>
                  {count ? `${count} connected` : "Not connected"}
                </span>
              </div>
              <div className="mt-4 text-base font-semibold text-slate-900 dark:text-white">{p.name}</div>
              <p className="mt-1 flex-1 text-sm leading-relaxed text-slate-600 dark:text-zinc-300">{p.description}</p>
              <span className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-orange-700 dark:text-orange-300">
                <Plus size={15} /> {count ? "Connect another account" : "Connect"}
              </span>
            </button>
          );
        })}
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Connected", value: connectedCount, icon: Wifi, color: "text-emerald-400" },
          { label: "Total Accounts", value: accounts.length, icon: Cloud, color: "text-blue-400" },
          { label: "Resources Discovered", value: totalResources, icon: Server, color: "text-purple-400" },
          { label: "Providers", value: Object.keys(providerCounts).length, icon: Shield, color: "text-orange-400" },
        ].map((stat) => (
          <div key={stat.label} className="glass rounded-xl p-4 border border-slate-200 dark:border-zinc-800">
            <div className="flex items-center gap-2 text-slate-500 dark:text-zinc-400 text-sm mb-1">
              <stat.icon size={14} className={stat.color} />
              {stat.label}
            </div>
            <div className="text-2xl font-bold text-slate-900 dark:text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Accounts List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="animate-spin text-orange-400" size={32} />
        </div>
      ) : accounts.length === 0 ? (
        <p className="py-10 text-center text-sm text-slate-600 dark:text-zinc-300">
          No cloud account is connected yet. Choose a cloud above to connect one.
        </p>
      ) : (
        <div className="space-y-4">
          {PROVIDERS.filter((p) => providerCounts[p.id]).map((group) => {
            const open = !collapsedProviders.includes(group.id);
            const own = accounts.filter((a) => a.provider === group.id);
            return (
              <section key={group.id} className="glass overflow-hidden rounded-xl border border-slate-200 dark:border-zinc-800">
                <button
                  onClick={() => setCollapsedProviders((prev) => open ? [...prev, group.id] : prev.filter((x) => x !== group.id))}
                  aria-expanded={open}
                  className="flex w-full items-center gap-3 p-4 text-left hover:bg-slate-50 dark:hover:bg-zinc-800/40"
                >
                  <ChevronRight size={18} className={`text-slate-500 transition-transform dark:text-zinc-300 ${open ? "rotate-90" : ""}`} />
                  <ProviderLogo provider={group.id} size="sm" />
                  <span className="flex-1 font-semibold text-slate-900 dark:text-white">{group.name}</span>
                  <span className="text-sm text-slate-600 dark:text-zinc-300">
                    {own.length} {own.length === 1 ? "account" : "accounts"} · {own.reduce((s, a) => s + a.resources_count, 0)} resources
                  </span>
                </button>
                {open && (
        <div className="space-y-3 border-t border-slate-200 p-3 dark:border-zinc-800">
          {own.map((acct) => {
            const prov = PROVIDER_MAP[acct.provider];
            const statusCfg = STATUS_CONFIG[acct.status] || STATUS_CONFIG.pending;
            const StatusIcon = statusCfg.icon;
            const isExpanded = expandedAccount === acct.id;

            return (
              <div
                key={acct.id}
                className={`glass border rounded-xl overflow-hidden transition-all ${
                  isExpanded ? "border-orange-500/40" : "border-slate-200 dark:border-zinc-800 hover:border-slate-300 dark:hover:border-zinc-700"
                }`}
              >
                {/* Main row */}
                <div
                  className="flex items-center gap-4 p-4 cursor-pointer"
                  onClick={() => setExpandedAccount(isExpanded ? null : acct.id)}
                >
                  {/* Provider icon */}
                  <ProviderLogo provider={acct.provider} />

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold truncate text-slate-900 dark:text-white">{acct.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${prov?.bgColor} ${prov?.textColor} font-medium`}>
                        {prov?.shortName || acct.provider.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-sm text-slate-500 dark:text-zinc-400 flex items-center gap-3 mt-0.5">
                      <span className="font-mono text-xs">{acct.account_identifier}</span>
                      <span className="text-slate-300 dark:text-zinc-600">•</span>
                      <span>{acct.resources_count} resources</span>
                      {acct.last_synced_at && (
                        <>
                          <span className="text-slate-300 dark:text-zinc-600">•</span>
                          <span>
                            Synced {new Date(acct.last_synced_at).toLocaleDateString()}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Status */}
                  <div className={`flex items-center gap-1.5 text-sm ${statusCfg.color}`}>
                    <StatusIcon size={16} />
                    {statusCfg.label}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => testMut.mutate(acct.id)}
                      disabled={testMut.isPending}
                      className="p-2 text-slate-400 dark:text-zinc-400 hover:text-emerald-400 hover:bg-emerald-400/10 rounded-lg transition-colors"
                      title="Test Connection"
                    >
                      {testMut.isPending ? (
                        <Loader2 size={16} className="animate-spin" />
                      ) : (
                        <Zap size={16} />
                      )}
                    </button>
                    <button
                      onClick={() => syncMut.mutate(acct.id)}
                      disabled={syncMut.isPending}
                      className="p-2 text-slate-400 dark:text-zinc-400 hover:text-blue-400 hover:bg-blue-400/10 rounded-lg transition-colors"
                      title="Sync Resources"
                    >
                      <RefreshCw size={16} className={syncMut.isPending ? "animate-spin" : ""} />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(acct.id)}
                      className="p-2 text-slate-400 dark:text-zinc-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                      title="Delete"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>

                  <ChevronRight
                    size={16}
                    className={`text-slate-400 dark:text-zinc-500 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                  />
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-slate-200 dark:border-zinc-800 p-4 bg-slate-50/50 dark:bg-zinc-950/50 space-y-4">
                    {/* Error banner */}
                    {acct.last_error && (
                      <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-600 dark:text-red-300">
                        <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
                        <span>{acct.last_error}</span>
                      </div>
                    )}

                    {/* Config grid */}
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <div className="text-slate-500 dark:text-zinc-500 mb-1">Sync Schedule</div>
                        <div className="font-medium text-slate-800 dark:text-zinc-200">
                          {acct.sync_enabled ? `Every ${acct.sync_interval_hours}h` : "Disabled"}
                        </div>
                      </div>
                      <div>
                        <div className="text-slate-500 dark:text-zinc-500 mb-1">Regions</div>
                        <div className="font-medium text-slate-800 dark:text-zinc-200">
                          {acct.regions.length ? acct.regions.join(", ") : "All regions"}
                        </div>
                      </div>
                      <div>
                        <div className="text-slate-500 dark:text-zinc-500 mb-1">Credentials</div>
                        <div className="font-medium">
                          {acct.has_credentials ? (
                            <span className="text-emerald-400">✓ Stored (encrypted)</span>
                          ) : (
                            <span className="text-red-400">✗ Not configured</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Resources preview */}
                    {resourcesData && resourcesData.resources?.length > 0 && (
                      <div>
                        <div className="text-sm text-slate-500 dark:text-zinc-400 mb-2">
                          Recent Resources ({resourcesData.total} total)
                        </div>
                        <div className="space-y-1">
                          {resourcesData.resources.slice(0, 5).map((r: any) => (
                            <div
                              key={r.id}
                              className="flex items-center gap-3 p-2 bg-slate-100 dark:bg-zinc-900/60 rounded-lg text-sm"
                            >
                              <span className="text-xs font-mono px-2 py-0.5 bg-slate-200 dark:bg-zinc-800 rounded text-slate-600 dark:text-zinc-300">
                                {r.resource_type}
                              </span>
                              <span className="truncate text-slate-800 dark:text-zinc-200">{r.resource_name}</span>
                              <span className="text-slate-400 dark:text-zinc-500 ml-auto text-xs">{r.region}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
                )}
              </section>
            );
          })}
        </div>
      )}

      {/* ─── Enterprise Connection Wizard Modal ────────────────────── */}
      {showWizard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl">
            {/* Header with progress */}
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-zinc-800">
              <div className="flex items-center gap-3">
                {selectedProvider && <ProviderLogo provider={selectedProvider} />}
                <div>
                  <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                    Connect {PROVIDER_MAP[selectedProvider || ""]?.name || "a cloud account"}
                  </h2>
                  <p className="text-slate-600 dark:text-zinc-300 text-sm mt-0.5">
                    {wizardStep === 2 ? "Select regions and confirm" : "Give GuardNous read access to this cloud"}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                {/* Step indicators (the manual, two-step flow only) */}
                {!(selectedProvider === "aws" && awsKeyless) && (
                  <div className="flex items-center gap-2">
                    {[1, 2].map((s) => (
                      <div key={s} className={`w-2.5 h-2.5 rounded-full transition-colors ${
                        s === wizardStep ? "bg-orange-500" : s < wizardStep ? "bg-emerald-500" : "bg-slate-300 dark:bg-zinc-700"
                      }`} />
                    ))}
                  </div>
                )}
                <button onClick={resetWizard} aria-label="Close" className="p-2 text-slate-600 dark:text-zinc-300 hover:text-slate-700 dark:hover:text-zinc-200 hover:bg-slate-100 dark:hover:bg-zinc-800 rounded-lg">
                  ✕
                </button>
              </div>
            </div>

            <div className="p-6">
              {/* ── Step 0: Provider Selection ───────────────────────────── */}
              {/* ── AWS without keys (default for AWS) ───────────────────── */}
              {wizardStep === 1 && selectedProvider === "aws" && awsKeyless && (
                <div className="space-y-4">
                  <AwsKeylessConnect />
                  <button
                    onClick={() => setAwsKeyless(false)}
                    className="text-sm text-slate-700 underline underline-offset-2 hover:text-slate-900 dark:text-zinc-200 dark:hover:text-white"
                  >
                    Use an IAM role ARN or access keys instead
                  </button>
                </div>
              )}

              {/* ── Step 1: Provider-Specific Account + Credentials ──── */}
              {wizardStep === 1 && selectedProvider && !(selectedProvider === "aws" && awsKeyless) && (
                <div className="space-y-5">
                  {selectedProvider === "aws" && (
                    <button
                      onClick={() => setAwsKeyless(true)}
                      className="text-sm text-slate-700 underline underline-offset-2 hover:text-slate-900 dark:text-zinc-200 dark:hover:text-white"
                    >
                      ← Connect without access keys (recommended)
                    </button>
                  )}
                  {/* Account Name (universal) */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300 mb-1.5">
                      <Building2 size={14} className="inline mr-1.5 -mt-0.5" />
                      Account Name
                    </label>
                    <input
                      type="text"
                      placeholder={`e.g., Production ${PROVIDER_MAP[selectedProvider]?.shortName}`}
                      value={formData._name || ""}
                      onChange={(e) => setFormData({ ...formData, _name: e.target.value })}
                      className="w-full px-4 py-2.5 bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 rounded-lg text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-zinc-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none"
                    />
                  </div>

                  {/* ── AWS-specific fields ─────────────────────────────── */}
                  {selectedProvider === "aws" && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300 mb-1.5">
                          AWS Account ID <span className="text-red-400">*</span>
                        </label>
                        <p className="text-xs text-slate-400 dark:text-zinc-500 mb-1.5">12-digit AWS account number</p>
                        <input
                          type="text"
                          placeholder="123456789012"
                          maxLength={12}
                          value={formData.aws_account_id || ""}
                          onChange={(e) => setFormData({ ...formData, aws_account_id: e.target.value.replace(/\D/g, "").slice(0, 12) })}
                          className="w-full px-4 py-2.5 bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 rounded-lg text-slate-900 dark:text-white font-mono text-sm placeholder:text-slate-400 dark:placeholder:text-zinc-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none"
                        />
                      </div>

                      {/* Auth method toggle */}
                      <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300 mb-2">
                          <Key size={14} className="inline mr-1.5 -mt-0.5" />
                          Authentication Method
                        </label>
                        <div className="grid grid-cols-2 gap-3">
                          <button
                            onClick={() => setAwsAuthMethod("assume_role")}
                            className={`p-3 border rounded-lg text-left transition-all ${
                              awsAuthMethod === "assume_role"
                                ? "border-orange-500 bg-orange-500/5 dark:bg-orange-500/10"
                                : "border-slate-200 dark:border-zinc-700 hover:border-slate-300 dark:hover:border-zinc-600"
                            }`}
                          >
                            <div className="font-medium text-sm text-slate-900 dark:text-white">IAM Role (Recommended)</div>
                            <div className="text-xs text-slate-500 dark:text-zinc-400 mt-0.5">Cross-account AssumeRole — no static keys</div>
                          </button>
                          <button
                            onClick={() => setAwsAuthMethod("access_key")}
                            className={`p-3 border rounded-lg text-left transition-all ${
                              awsAuthMethod === "access_key"
                                ? "border-orange-500 bg-orange-500/5 dark:bg-orange-500/10"
                                : "border-slate-200 dark:border-zinc-700 hover:border-slate-300 dark:hover:border-zinc-600"
                            }`}
                          >
                            <div className="font-medium text-sm text-slate-900 dark:text-white">Access Keys</div>
                            <div className="text-xs text-slate-500 dark:text-zinc-400 mt-0.5">Static IAM credentials — rotate regularly</div>
                          </button>
                        </div>
                      </div>

                      {/* Collapsible setup guide */}
                      <div className="border border-blue-500/20 rounded-lg overflow-hidden">
                        <button
                          onClick={() => setShowSetupGuide(!showSetupGuide)}
                          className="w-full flex items-center gap-2 p-3 bg-blue-500/5 dark:bg-blue-500/10 text-left"
                        >
                          <BookOpen size={14} className="text-blue-400" />
                          <span className="text-sm font-medium text-blue-700 dark:text-blue-300 flex-1">Setup Instructions</span>
                          <ChevronRight size={14} className={`text-blue-400 transition-transform ${showSetupGuide ? "rotate-90" : ""}`} />
                        </button>
                        {showSetupGuide && (
                          <div className="p-3 bg-blue-500/5 dark:bg-blue-900/20 border-t border-blue-500/10 text-sm text-blue-700 dark:text-blue-200 space-y-1.5">
                            {awsAuthMethod === "assume_role" ? (
                              <>
                                <p className="font-medium">Create a cross-account IAM Role:</p>
                                <ol className="list-decimal list-inside space-y-1 text-xs">
                                  <li>Go to IAM → Roles → Create Role</li>
                                  <li>Choose "Another AWS Account" and enter GuardNous Account ID</li>
                                  <li>Attach policies: <code className="px-1 py-0.5 bg-blue-500/10 rounded">SecurityAudit</code> and <code className="px-1 py-0.5 bg-blue-500/10 rounded">ViewOnlyAccess</code></li>
                                  <li>Set an External ID for additional security (optional)</li>
                                  <li>Copy the Role ARN</li>
                                </ol>
                              </>
                            ) : (
                              <>
                                <p className="font-medium">Create an IAM User with programmatic access:</p>
                                <ol className="list-decimal list-inside space-y-1 text-xs">
                                  <li>Go to IAM → Users → Create User</li>
                                  <li>Enable "Access key - Programmatic access"</li>
                                  <li>Attach policies: <code className="px-1 py-0.5 bg-blue-500/10 rounded">SecurityAudit</code> and <code className="px-1 py-0.5 bg-blue-500/10 rounded">ViewOnlyAccess</code></li>
                                  <li>Save the Access Key ID and Secret Access Key securely</li>
                                </ol>
                                <p className="text-xs text-amber-600 dark:text-amber-300 mt-2">⚠ Static keys are less secure. Rotate them every 90 days.</p>
                              </>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Credential fields based on auth method */}
                      {awsAuthMethod === "assume_role" ? (
                        <>
                          <WizardField
                            label="IAM Role ARN" required
                            placeholder="arn:aws:iam::123456789012:role/GuardNousReadOnly"
                            help="Cross-account role with SecurityAudit + ViewOnlyAccess"
                            value={formData.role_arn || ""}
                            onChange={(v) => setFormData({ ...formData, role_arn: v })}
                            mono
                          />
                          <WizardField
                            label="External ID"
                            placeholder="guardnous-external-id"
                            help="Optional. Adds extra security to the AssumeRole trust policy"
                            value={formData.external_id || ""}
                            onChange={(v) => setFormData({ ...formData, external_id: v })}
                            mono
                          />
                        </>
                      ) : (
                        <>
                          <WizardField
                            label="Access Key ID" required
                            placeholder="AKIAIOSFODNN7EXAMPLE"
                            value={formData.access_key_id || ""}
                            onChange={(v) => setFormData({ ...formData, access_key_id: v })}
                            mono
                          />
                          <WizardField
                            label="Secret Access Key" required isPassword
                            placeholder=""
                            value={formData.secret_access_key || ""}
                            onChange={(v) => setFormData({ ...formData, secret_access_key: v })}
                            showPasswords={showPasswords} setShowPasswords={setShowPasswords} fieldKey="secret_access_key"
                            mono
                          />
                        </>
                      )}
                    </>
                  )}

                  {/* ── Azure-specific fields ──────────────────────────── */}
                  {selectedProvider === "azure" && (
                    <>
                      {/* Collapsible setup guide */}
                      <div className="border border-blue-500/20 rounded-lg overflow-hidden">
                        <button
                          onClick={() => setShowSetupGuide(!showSetupGuide)}
                          className="w-full flex items-center gap-2 p-3 bg-blue-500/5 dark:bg-blue-500/10 text-left"
                        >
                          <BookOpen size={14} className="text-blue-400" />
                          <span className="text-sm font-medium text-blue-700 dark:text-blue-300 flex-1">Setup Instructions — App Registration</span>
                          <ChevronRight size={14} className={`text-blue-400 transition-transform ${showSetupGuide ? "rotate-90" : ""}`} />
                        </button>
                        {showSetupGuide && (
                          <div className="p-3 bg-blue-500/5 dark:bg-blue-900/20 border-t border-blue-500/10 text-sm text-blue-700 dark:text-blue-200 space-y-1.5">
                            <p className="font-medium">Create an App Registration (Service Principal):</p>
                            <ol className="list-decimal list-inside space-y-1 text-xs">
                              <li>Go to <strong>Azure Active Directory → App Registrations → New Registration</strong></li>
                              <li>Name it "GuardNous Security Scanner" and register</li>
                              <li>Copy the <strong>Application (Client) ID</strong> and <strong>Directory (Tenant) ID</strong></li>
                              <li>Go to <strong>Certificates & Secrets → New Client Secret</strong> — copy the value</li>
                              <li>Go to the target <strong>Subscription → Access Control (IAM) → Add Role Assignment</strong></li>
                              <li>Assign the <strong>Reader</strong> role to the App Registration</li>
                            </ol>
                          </div>
                        )}
                      </div>

                      {/* Tenant + Subscription side by side */}
                      <div className="grid grid-cols-2 gap-4">
                        <WizardField
                          label="Tenant (Directory) ID" required
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          help="Azure AD Tenant — found in Azure Active Directory → Overview"
                          value={formData.tenant_id || ""}
                          onChange={(v) => setFormData({ ...formData, tenant_id: v })}
                          mono
                        />
                        <WizardField
                          label="Subscription ID" required
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          help="Target subscription to scan"
                          value={formData.subscription_id || ""}
                          onChange={(v) => setFormData({ ...formData, subscription_id: v })}
                          mono
                        />
                      </div>

                      <WizardField
                        label="Application (Client) ID" required
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        help="From App Registration → Overview"
                        value={formData.client_id || ""}
                        onChange={(v) => setFormData({ ...formData, client_id: v })}
                        mono
                      />
                      <WizardField
                        label="Client Secret" required isPassword
                        placeholder=""
                        help="From App Registration → Certificates & Secrets"
                        value={formData.client_secret || ""}
                        onChange={(v) => setFormData({ ...formData, client_secret: v })}
                        showPasswords={showPasswords} setShowPasswords={setShowPasswords} fieldKey="client_secret"
                        mono
                      />
                    </>
                  )}

                  {/* ── GCP-specific fields ────────────────────────────── */}
                  {selectedProvider === "gcp" && (
                    <>
                      {/* Collapsible setup guide */}
                      <div className="border border-blue-500/20 rounded-lg overflow-hidden">
                        <button
                          onClick={() => setShowSetupGuide(!showSetupGuide)}
                          className="w-full flex items-center gap-2 p-3 bg-blue-500/5 dark:bg-blue-500/10 text-left"
                        >
                          <BookOpen size={14} className="text-blue-400" />
                          <span className="text-sm font-medium text-blue-700 dark:text-blue-300 flex-1">Setup Instructions — Service Account</span>
                          <ChevronRight size={14} className={`text-blue-400 transition-transform ${showSetupGuide ? "rotate-90" : ""}`} />
                        </button>
                        {showSetupGuide && (
                          <div className="p-3 bg-blue-500/5 dark:bg-blue-900/20 border-t border-blue-500/10 text-sm text-blue-700 dark:text-blue-200 space-y-1.5">
                            <p className="font-medium">Create a Service Account with Viewer role:</p>
                            <ol className="list-decimal list-inside space-y-1 text-xs">
                              <li>Go to <strong>IAM & Admin → Service Accounts → Create Service Account</strong></li>
                              <li>Name it "guardnous-scanner" and grant the <strong>Viewer</strong> role</li>
                              <li>Optionally add <strong>Cloud Asset Viewer</strong> for inventory data</li>
                              <li>Go to <strong>Keys → Add Key → Create new key → JSON</strong></li>
                              <li>Download the JSON key file and paste its contents below</li>
                            </ol>
                            <p className="text-xs text-slate-500 dark:text-zinc-400 mt-2">💡 For organization-level scanning, grant Viewer at the organization level instead of the project.</p>
                          </div>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <WizardField
                          label="Project ID" required
                          placeholder="my-project-123456"
                          help="GCP Project ID — found in Console → Project selector"
                          value={formData.project_id || ""}
                          onChange={(v) => setFormData({ ...formData, project_id: v })}
                          mono
                        />
                        <WizardField
                          label="Organization ID"
                          placeholder="123456789012"
                          help="Optional — for org-level scanning"
                          value={formData.gcp_org_id || ""}
                          onChange={(v) => setFormData({ ...formData, gcp_org_id: v })}
                          mono
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300 mb-1.5">
                          Service Account Key (JSON) <span className="text-red-400">*</span>
                        </label>
                        <p className="text-xs text-slate-400 dark:text-zinc-500 mb-1.5">Paste the JSON key file contents or drag & drop the file</p>
                        <div className="relative">
                          <textarea
                            placeholder='{"type": "service_account", "project_id": "...", ...}'
                            value={formData.service_account_json || ""}
                            onChange={(e) => setFormData({ ...formData, service_account_json: e.target.value })}
                            rows={5}
                            className="w-full px-4 py-2.5 bg-slate-100 dark:bg-zinc-800 border border-slate-300 dark:border-zinc-700 rounded-lg text-slate-900 dark:text-white font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-zinc-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none resize-none"
                            onDrop={(e) => {
                              e.preventDefault();
                              const file = e.dataTransfer.files[0];
                              if (file) {
                                const reader = new FileReader();
                                reader.onload = (ev) => {
                                  setFormData({ ...formData, service_account_json: ev.target?.result as string || "" });
                                };
                                reader.readAsText(file);
                              }
                            }}
                            onDragOver={(e) => e.preventDefault()}
                          />
                          <label className="absolute bottom-3 right-3 flex items-center gap-1.5 px-3 py-1.5 bg-slate-200 dark:bg-zinc-700 rounded-md cursor-pointer hover:bg-slate-300 dark:hover:bg-zinc-600 transition-colors">
                            <FileUp size={12} className="text-slate-600 dark:text-zinc-300" />
                            <span className="text-xs text-slate-600 dark:text-zinc-300">Upload JSON</span>
                            <input
                              type="file"
                              accept=".json"
                              className="hidden"
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (file) {
                                  const reader = new FileReader();
                                  reader.onload = (ev) => {
                                    setFormData({ ...formData, service_account_json: ev.target?.result as string || "" });
                                  };
                                  reader.readAsText(file);
                                }
                              }}
                            />
                          </label>
                        </div>
                      </div>
                    </>
                  )}

                  {/* Inline test connection result */}
                  {testResult && (
                    <div className={`flex items-center gap-2 p-3 rounded-lg text-sm ${
                      testResult.status === "success"
                        ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                        : "bg-red-500/10 border border-red-500/20 text-red-700 dark:text-red-300"
                    }`}>
                      {testResult.status === "success" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                      {testResult.message}
                    </div>
                  )}

                  {/* Error */}
                  {createMut.isError && (
                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-600 dark:text-red-300">
                      {(() => {
                        const detail = (createMut.error as any)?.response?.data?.detail;
                        if (typeof detail === "string") return detail;
                        if (detail && typeof detail === "object") {
                          if (Array.isArray(detail)) return detail.map((d: any) => d.msg || String(d)).join("; ");
                          if (detail.errors) return Array.isArray(detail.errors) ? detail.errors.join("; ") : String(detail.errors);
                          return JSON.stringify(detail);
                        }
                        return (createMut.error as any)?.message || "Failed to connect account";
                      })()}
                    </div>
                  )}

                  <div className="flex justify-between pt-4 border-t border-slate-200 dark:border-zinc-800">
                    <button
                      onClick={resetWizard}
                      className="px-4 py-2 text-slate-600 dark:text-zinc-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={handleTestInline}
                        disabled={!isStep1Complete() || testingInline}
                        className="flex items-center gap-2 px-4 py-2.5 border border-emerald-500/40 text-emerald-600 dark:text-emerald-400 rounded-lg font-medium hover:bg-emerald-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                      >
                        {testingInline ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
                        Test Connection
                      </button>
                      <button
                        onClick={() => setWizardStep(2)}
                        disabled={!isStep1Complete()}
                        className="px-6 py-2.5 bg-orange-500 text-white rounded-lg font-medium hover:bg-orange-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      >
                        Next →
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* ── Step 2: Region Scope + Confirm ──────────────────────── */}
              {wizardStep === 2 && selectedProvider && (
                <div className="space-y-5">
                  {/* Summary card */}
                  <div className="p-4 bg-slate-50 dark:bg-zinc-800/50 border border-slate-200 dark:border-zinc-700 rounded-lg">
                    <div className="flex items-center gap-3 mb-3">
                      <ProviderLogo provider={selectedProvider} />
                      <div>
                        <div className="font-semibold text-slate-900 dark:text-white">{formData._name || "Cloud Account"}</div>
                        <div className="text-xs text-slate-500 dark:text-zinc-400 font-mono">
                          {selectedProvider === "aws" && formData.aws_account_id}
                          {selectedProvider === "azure" && formData.tenant_id}
                          {selectedProvider === "gcp" && formData.project_id}
                        </div>
                      </div>
                      <div className="ml-auto flex items-center gap-1.5 text-sm text-emerald-500">
                        <Lock size={12} />
                        <span className="text-xs">Credentials encrypted</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="text-slate-500 dark:text-zinc-400">
                        <span className="font-medium text-slate-700 dark:text-zinc-300">Auth: </span>
                        {selectedProvider === "aws" ? (awsAuthMethod === "assume_role" ? "IAM Role (AssumeRole)" : "Access Keys") : selectedProvider === "azure" ? "Service Principal" : "Service Account"}
                      </div>
                      <div className="text-slate-500 dark:text-zinc-400">
                        <span className="font-medium text-slate-700 dark:text-zinc-300">Provider: </span>
                        {PROVIDER_MAP[selectedProvider]?.name}
                      </div>
                    </div>
                  </div>

                  {/* Region selection */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-slate-700 dark:text-zinc-300">
                        <Globe size={14} className="inline mr-1.5 -mt-0.5" />
                        Scan Regions
                      </label>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setSelectedRegions(REGION_OPTIONS[selectedProvider] || [])}
                          className="text-xs text-orange-500 hover:text-orange-600"
                        >
                          Select All
                        </button>
                        <span className="text-xs text-slate-300 dark:text-zinc-600">|</span>
                        <button
                          onClick={() => setSelectedRegions([])}
                          className="text-xs text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:hover:text-zinc-200"
                        >
                          Clear
                        </button>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 dark:text-zinc-500 mb-3">
                      Select specific regions to scan, or leave empty to scan all available regions.
                    </p>
                    <div className="grid grid-cols-4 gap-1.5 max-h-40 overflow-y-auto p-2 bg-slate-50 dark:bg-zinc-800/50 border border-slate-200 dark:border-zinc-700 rounded-lg">
                      {(REGION_OPTIONS[selectedProvider] || []).map((r) => (
                        <button
                          key={r}
                          onClick={() => toggleRegion(r)}
                          className={`px-2 py-1.5 text-xs rounded-md transition-colors text-left font-mono ${
                            selectedRegions.includes(r)
                              ? "bg-orange-500/15 text-orange-700 dark:text-orange-300 border border-orange-500/30"
                              : "text-slate-600 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-700/50 border border-transparent"
                          }`}
                        >
                          {selectedRegions.includes(r) && "✓ "}{r}
                        </button>
                      ))}
                    </div>
                    <p className="text-xs text-slate-400 dark:text-zinc-500 mt-1.5">
                      {selectedRegions.length === 0
                        ? "All regions will be scanned"
                        : `${selectedRegions.length} region${selectedRegions.length > 1 ? "s" : ""} selected`}
                    </p>
                  </div>

                  {/* Error */}
                  {createMut.isError && (
                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-600 dark:text-red-300">
                      {(() => {
                        const detail = (createMut.error as any)?.response?.data?.detail;
                        if (typeof detail === "string") return detail;
                        if (detail && typeof detail === "object") {
                          if (Array.isArray(detail)) return detail.map((d: any) => d.msg || String(d)).join("; ");
                          return JSON.stringify(detail);
                        }
                        return (createMut.error as any)?.message || "Failed to connect account";
                      })()}
                    </div>
                  )}

                  <div className="flex justify-between pt-4 border-t border-slate-200 dark:border-zinc-800">
                    <button
                      onClick={() => setWizardStep(1)}
                      className="px-4 py-2 text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                      ← Back
                    </button>
                    <button
                      onClick={handleSubmit}
                      disabled={createMut.isPending}
                      className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-orange-500 to-amber-600 text-white rounded-lg font-medium hover:from-orange-600 hover:to-amber-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/20"
                    >
                      {createMut.isPending ? (
                        <Loader2 size={16} className="animate-spin" />
                      ) : (
                        <Shield size={16} />
                      )}
                      Connect & Start Discovery
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ─── Delete Confirmation Modal ───────────────────────────────── */}
      {deleteConfirm !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-lg font-bold text-red-600 dark:text-red-400 mb-2">Delete Cloud Account?</h3>
            <p className="text-sm text-slate-500 dark:text-zinc-400 mb-4">
              This will permanently remove this cloud account and all its discovered resources.
              Assessment history will be preserved.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-slate-500 dark:text-zinc-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMut.mutate(deleteConfirm)}
                disabled={deleteMut.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
              >
                {deleteMut.isPending ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </PageLayout>
  );
}

/* ─── Empty State ────────────────────────────────────────────────────── */

