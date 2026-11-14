"use client";

import React, { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import PageLayout from "@/components/PageLayout";
import {
  connectPAT,
  getIntegrationStatus,
  getAllIntegrations,
  getRepos,
  toggleRepo,
  disconnectIntegration,
  getCapabilities,
  triggerRepoScan,
  syncRepos,
  updateIntegrationSettings,
  removeRepository,
} from "@/lib/api";
import {
  GitBranch,
  Link2,
  Unlink,
  Search,
  CheckCircle2,
  XCircle,
  Loader2,
  Settings,
  RefreshCw,
  Eye,
  EyeOff,
  Lock,
  Globe2,
  GitPullRequest,
  Zap,
  ChevronRight,
  ChevronLeft,
  AlertTriangle,
  Play,
  Shield,
  X,
  Plus,
  Check,
  ArrowRight,
  ExternalLink,
  ToggleLeft,
  ToggleRight,
  Trash2,
  ScanLine,
  FolderGit2,
  Radio,
  BookOpen,
  Copy,
  Clock,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

/* ─────────────────────────── Types ─────────────────────────── */

type VcsType = "github" | "gitlab" | "bitbucket" | "azure_devops";

interface RepositoryInfo {
  full_name: string;
  name: string;
  private: boolean;
  default_branch: string;
  language: string;
  enabled: boolean;
  last_scan_at?: string;
  last_scan_status?: string;
}

interface IntegrationStatus {
  id: number;
  vcs_type: string;
  auth_method: string;
  account_name: string;
  account_url: string;
  avatar_url: string;
  is_active: boolean;
  repositories: RepositoryInfo[];
  scan_on_push: boolean;
  scan_on_pr: boolean;
  auto_fix_prs?: boolean;
  created_at: string;
  last_synced_at?: string;
}

interface CapabilitiesResponse {
  providers: Record<string, { methods: string[] }>;
}

interface ScanResult {
  id: number;
  status: string;
  findings_count: number;
  files_scanned: number;
  files_total: number;
  risk_score: number;
  error_message: string | null;
}

interface ProviderField {
  key: string;
  label: string;
  placeholder: string;
  required: boolean;
  type?: "text" | "password" | "url";
  helpText?: string;
}

interface ProviderInfo {
  id: VcsType;
  name: string;
  description: string;
  tokenUrl: string;
  tokenSteps: string[];
  scopes: string;
  tokenLabel: string;
  tokenPlaceholder: string;
  fields: ProviderField[];
}

/* ───────────────────────────── Constants ───────────────────────── */

const PROVIDERS: ProviderInfo[] = [
  {
    id: "github",
    name: "GitHub",
    description: "Connect repositories for automated security scanning and PR checks",
    tokenUrl: "https://github.com/settings/tokens/new",
    tokenSteps: [
      "Go to GitHub → Settings → Developer settings",
      "Select Personal access tokens → Tokens (classic)",
      'Click "Generate new token (classic)"',
      "Select scopes: repo, read:org, workflow",
      "Generate and copy the token",
    ],
    scopes: "repo, read:org, workflow",
    tokenLabel: "Personal Access Token",
    tokenPlaceholder: "ghp_xxxxxxxxxxxxxxxxxxxx",
    fields: [],
  },
  {
    id: "gitlab",
    name: "GitLab",
    description: "Integrate for pipeline-aware scanning and merge request analysis",
    tokenUrl: "https://gitlab.com/-/profile/personal_access_tokens",
    tokenSteps: [
      "Go to GitLab → Preferences → Access Tokens",
      'Click "Add new token"',
      "Name your token and set expiry date",
      "Select scopes: api, read_repository",
      "Create and copy the token",
    ],
    scopes: "api, read_repository",
    tokenLabel: "Personal Access Token",
    tokenPlaceholder: "glpat-xxxxxxxxxxxxxxxxxxxx",
    fields: [
      {
        key: "base_url",
        label: "GitLab Instance URL",
        placeholder: "https://gitlab.example.com",
        required: false,
        type: "url",
        helpText: "Leave blank for GitLab.com. Required for self-hosted instances.",
      },
    ],
  },
  {
    id: "bitbucket",
    name: "Bitbucket",
    description: "Connect for repository scanning and pull request security checks",
    tokenUrl: "https://bitbucket.org/account/settings/app-passwords/",
    tokenSteps: [
      "Go to Bitbucket → Personal settings → App passwords",
      'Click "Create app password"',
      "Give it a descriptive label",
      "Select permissions: Repositories (Read), Pull requests (Read & Write)",
      "Create and copy the password",
    ],
    scopes: "Repositories: Read, Pull requests: Read & Write",
    tokenLabel: "App Password",
    tokenPlaceholder: "ATBB_xxxxxxxxxxxxxxxxxxxx",
    fields: [
      {
        key: "username",
        label: "Bitbucket Username",
        placeholder: "your-username",
        required: true,
        type: "text",
        helpText: "Your Bitbucket username (not email). Found under Personal settings.",
      },
    ],
  },
  {
    id: "azure_devops",
    name: "Azure DevOps",
    description: "Integrate with Azure Repos for pipeline-triggered scans and build validation",
    tokenUrl: "https://dev.azure.com",
    tokenSteps: [
      "Go to Azure DevOps → User Settings (top-right icon)",
      "Select Personal access tokens",
      'Click "New Token"',
      "Set organization, expiration, and scopes: Code (Read & Write), Build (Read)",
      "Create and copy the token",
    ],
    scopes: "Code: Read & Write, Build: Read",
    tokenLabel: "Personal Access Token",
    tokenPlaceholder: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    fields: [
      {
        key: "base_url",
        label: "Organization Name",
        placeholder: "my-organization",
        required: true,
        type: "text",
        helpText: "Your Azure DevOps org name from https://dev.azure.com/{org}",
      },
    ],
  },
];

const LANGUAGE_COLORS: Record<string, string> = {
  TypeScript: "bg-blue-500",
  JavaScript: "bg-yellow-400",
  Python: "bg-emerald-500",
  Go: "bg-cyan-500",
  Rust: "bg-orange-600",
  Java: "bg-red-500",
  Ruby: "bg-red-600",
  "C#": "bg-purple-500",
  PHP: "bg-orange-500",
  Swift: "bg-orange-500",
  Kotlin: "bg-violet-500",
  C: "bg-slate-50 dark:bg-slate-8000",
  "C++": "bg-pink-500",
  Shell: "bg-green-600",
  HCL: "bg-violet-600",
  Dockerfile: "bg-sky-500",
};

type WizardStep = "provider" | "auth" | "connecting" | "success";

/* ────────────────────── SVG Brand Logos ─────────────────────── */

/* The providers' own logos (files in /public/logos), on a white tile so their
   brand colours are the same in both themes. */
const PROVIDER_LOGO_FILE: Record<VcsType, string> = {
  github: "/logos/github.svg",
  gitlab: "/logos/gitlab.svg",
  bitbucket: "/logos/bitbucket.svg",
  azure_devops: "/logos/azure-devops.svg",
};

const makeLogo = (id: VcsType): React.FC<{ className?: string }> => {
  const Logo = ({ className }: { className?: string }) => (
    /* eslint-disable-next-line @next/next/no-img-element */
    <img src={PROVIDER_LOGO_FILE[id]} alt="" className={`${className ?? ""} object-contain`} />
  );
  Logo.displayName = `${id}Logo`;
  return Logo;
};

const PROVIDER_LOGO_MAP: Record<VcsType, React.FC<{ className?: string }>> = {
  github: makeLogo("github"),
  gitlab: makeLogo("gitlab"),
  bitbucket: makeLogo("bitbucket"),
  azure_devops: makeLogo("azure_devops"),
};

const TILE = "bg-white border border-slate-200 dark:border-gray-600";
const PROVIDER_BG: Record<VcsType, string> = { github: TILE, gitlab: TILE, bitbucket: TILE, azure_devops: TILE };

function ProviderIcon({ provider, size = "md" }: { provider: ProviderInfo; size?: "sm" | "md" | "lg" }) {
  const cls = size === "sm" ? "w-9 h-9" : size === "lg" ? "w-14 h-14" : "w-11 h-11";
  const iconCls = size === "sm" ? "w-5 h-5" : size === "lg" ? "w-8 h-8" : "w-6 h-6";
  const Logo = PROVIDER_LOGO_MAP[provider.id];
  return (
    <div className={`${cls} ${PROVIDER_BG[provider.id]} rounded-xl flex items-center justify-center shadow-sm`} role="img" aria-label={provider.name}>
      <Logo className={iconCls} />
    </div>
  );
}

/* ────────────────────── Skeleton Loader ─────────────────────── */

function CardSkeleton() {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 p-6 animate-pulse">
      <div className="flex items-start gap-4">
        <div className="w-11 h-11 rounded-xl bg-slate-200 dark:bg-gray-600" />
        <div className="flex-1 space-y-3">
          <div className="h-5 w-32 bg-slate-200 dark:bg-gray-600 rounded-lg" />
          <div className="h-4 w-full bg-slate-100 dark:bg-gray-700 rounded-lg" />
        </div>
      </div>
    </div>
  );
}

function TableSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="bg-white dark:bg-gray-800 rounded-xl border border-slate-200 dark:border-gray-700 p-4 animate-pulse flex items-center gap-4">
          <div className="w-5 h-5 rounded bg-slate-200 dark:bg-gray-600" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-48 bg-slate-200 dark:bg-gray-600 rounded" />
            <div className="h-3 w-24 bg-slate-100 rounded" />
          </div>
          <div className="h-6 w-16 bg-slate-100 dark:bg-gray-700 rounded-full" />
          <div className="h-8 w-20 bg-slate-100 dark:bg-gray-700 rounded-lg" />
        </div>
      ))}
    </div>
  );
}

/* ────────────────────── Scan Toast ──────────────────────────── */

function ScanToast({ result, onClose }: { result: ScanResult; onClose: () => void }) {
  const isError = result.status === "failed";
  return (
    <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-bottom-4 fade-in">
      <div
        className={`flex items-start gap-3 p-4 rounded-2xl border dark:border-gray-700 shadow-lg max-w-sm ${
          isError
            ? "bg-red-50 border-red-200"
            : "bg-emerald-50 border-emerald-200"
        }`}
      >
        {isError ? (
          <AlertTriangle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
        ) : (
          <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
        )}
        <div className="flex-1 min-w-0">
          <p
            className={`text-sm font-semibold ${isError ? "text-red-700" : "text-emerald-700"}`}
          >
            {isError ? "Scan Failed" : "Scan Complete"}
          </p>
          {isError ? (
            <p className="text-xs text-red-600 mt-0.5">
              {result.error_message || "An error occurred"}
            </p>
          ) : (
            <p className="text-xs text-emerald-600 mt-0.5">
              {result.findings_count} finding{result.findings_count !== 1 ? "s" : ""} in{" "}
              {result.files_scanned} file{result.files_scanned !== 1 ? "s" : ""}
            </p>
          )}
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 dark:text-gray-500 dark:text-gray-400 hover:text-slate-600 dark:text-gray-400 shrink-0"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

/* ────────────────────── Disconnect Modal ───────────────────── */

function DisconnectModal({
  providerName,
  onConfirm,
  onCancel,
  isLoading,
}: {
  providerName: string;
  onConfirm: () => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm" onClick={onCancel} />
      <div className="relative bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-2xl dark:shadow-black/20 max-w-md w-full p-8">
        <div className="w-14 h-14 rounded-2xl bg-red-50 flex items-center justify-center mx-auto mb-5">
          <Unlink className="w-7 h-7 text-red-500" />
        </div>
        <h3 className="text-xl font-semibold text-slate-900 dark:text-white text-center mb-2">
          Disconnect {providerName}?
        </h3>
        <p className="text-sm text-slate-500 dark:text-gray-400 text-center mb-8">
          This will remove the integration and stop all automated scans. Repository
          data will be retained but no new scans will run.
        </p>
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 h-12 rounded-xl border border-slate-200 dark:border-gray-600 text-slate-700 dark:text-gray-300 font-semibold hover:bg-slate-50 dark:hover:bg-gray-700 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className="flex-1 h-12 rounded-xl bg-red-600 hover:bg-red-700 text-white font-semibold transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
          >
            {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
            Disconnect
          </button>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────── Toggle Switch ──────────────────────── */

function ToggleSwitch({
  enabled,
  onChange,
  disabled,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={() => !disabled && onChange(!enabled)}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 shrink-0 rounded-full transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 disabled:opacity-50 ${
        enabled ? "bg-orange-500" : "bg-slate-200"
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white dark:bg-gray-200 shadow ring-0 transition duration-200 ease-in-out ${
          enabled ? "translate-x-5" : "translate-x-0.5"
        } mt-0.5`}
      />
    </button>
  );
}

/* ═══════════════════════════════════════════════════════════════
   WIZARD COMPONENT
   ═══════════════════════════════════════════════════════════════ */

function AddIntegrationWizard({ onClose, onSuccess, initialProvider }: { onClose: () => void; onSuccess: () => void; initialProvider?: ProviderInfo | null }) {
  const [step, setStep] = useState<WizardStep>(initialProvider ? "auth" : "provider");
  const [selectedProvider, setSelectedProvider] = useState<ProviderInfo | null>(initialProvider ?? null);
  const [token, setToken] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [showToken, setShowToken] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [connectedResult, setConnectedResult] = useState<IntegrationStatus | null>(null);

  const queryClient = useQueryClient();

  const connectMutation = useMutation({
    mutationFn: connectPAT,
    onSuccess: (data: IntegrationStatus) => {
      setConnectedResult(data);
      setStep("success");
      queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
      queryClient.invalidateQueries({ queryKey: ["repos"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      setConnectError(err.response?.data?.detail || err.message || "Connection failed");
      setStep("auth");
    },
  });

  const canConnect = (): boolean => {
    if (!selectedProvider || !token.trim()) return false;
    for (const field of selectedProvider.fields) {
      if (field.required && !fieldValues[field.key]?.trim()) return false;
    }
    return true;
  };

  const handleConnect = () => {
    if (!canConnect()) return;
    setConnectError(null);
    setStep("connecting");
    const body: Record<string, string> = {
      vcs_type: selectedProvider!.id,
      token: token.trim(),
    };
    for (const field of selectedProvider!.fields) {
      const val = fieldValues[field.key]?.trim();
      if (val) body[field.key] = val;
    }
    connectMutation.mutate(body as any);
  };

  const handleSelectProvider = (p: ProviderInfo) => {
    setSelectedProvider(p);
    setToken("");
    setFieldValues({});
    setConnectError(null);
    setStep("auth");
  };

  const stepIndex = step === "provider" ? 0 : step === "auth" ? 1 : step === "connecting" ? 2 : 3;
  const stepLabels = ["Choose Provider", "Authenticate", "Connecting", "Connected"];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm" onClick={step !== "connecting" ? onClose : undefined} />
      <div className="relative bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-2xl dark:shadow-black/20 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-slate-100 dark:border-gray-700 px-8 py-5 rounded-t-2xl flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Add Integration</h2>
            <p className="text-sm text-slate-500 dark:text-gray-400 mt-0.5">Connect your version control system</p>
          </div>
          {step !== "connecting" && (
            <button onClick={onClose} className="w-9 h-9 rounded-xl hover:bg-slate-100 flex items-center justify-center text-slate-400 dark:text-gray-500 dark:text-gray-400 hover:text-slate-600 dark:text-gray-400 transition-colors">
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Step Indicator */}
        <div className="px-8 pt-6 pb-2">
          <div className="flex items-center gap-1">
            {stepLabels.map((label, i) => (
              <React.Fragment key={label}>
                <div className="flex items-center gap-2">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold transition-all ${
                      i < stepIndex
                        ? "bg-emerald-500 text-white"
                        : i === stepIndex
                          ? "bg-orange-500 text-white"
                          : "bg-slate-100 text-slate-400 dark:text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    {i < stepIndex ? <Check className="w-3.5 h-3.5" /> : i + 1}
                  </div>
                  <span
                    className={`text-xs font-medium hidden sm:block ${
                      i === stepIndex ? "text-slate-900 dark:text-white" : "text-slate-400 dark:text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    {label}
                  </span>
                </div>
                {i < stepLabels.length - 1 && (
                  <div
                    className={`flex-1 h-px mx-2 ${
                      i < stepIndex ? "bg-emerald-300" : "bg-slate-200"
                    }`}
                  />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="px-8 py-6">
          {/* Step 1: Choose Provider */}
          {step === "provider" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => handleSelectProvider(p)}
                  className="group bg-white dark:bg-gray-700/50 rounded-2xl border border-slate-200 dark:border-gray-600 p-5 text-left hover:border-orange-300 dark:hover:border-orange-500 hover:shadow-md transition-all duration-200"
                >
                  <div className="flex items-start gap-4">
                    <ProviderIcon provider={p} size="lg" />
                    <div className="flex-1 min-w-0">
                      <h3 className="text-base font-semibold text-slate-900 dark:text-white group-hover:text-orange-500 transition-colors">
                        {p.name}
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-gray-400 mt-1 leading-relaxed">
                        {p.description}
                      </p>
                    </div>
                    <ChevronRight className="w-5 h-5 text-slate-300 group-hover:text-orange-400 transition-colors shrink-0 mt-1" />
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Step 2: Authentication */}
          {step === "auth" && selectedProvider && (
            <div className="space-y-6">
              {/* Provider recap */}
              <div className="flex items-center gap-3 p-4 bg-slate-50 dark:bg-slate-800 rounded-xl">
                <ProviderIcon provider={selectedProvider} size="sm" />
                <div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-white">{selectedProvider.name}</p>
                  <p className="text-xs text-slate-500 dark:text-gray-400">{selectedProvider.tokenLabel}</p>
                </div>
                <button
                  onClick={() => setStep("provider")}
                  className="ml-auto text-xs text-orange-500 hover:text-orange-600 font-medium"
                >
                  Change
                </button>
              </div>

              {/* Error banner */}
              {connectError && (
                <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-200 rounded-xl">
                  <XCircle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-red-700">Connection Failed</p>
                    <p className="text-xs text-red-600 mt-0.5">{connectError}</p>
                  </div>
                </div>
              )}

              {/* Instructions */}
              <div className="bg-orange-50 border border-orange-100 rounded-xl p-5">
                <h4 className="text-sm font-semibold text-orange-900 flex items-center gap-2 mb-3">
                  <BookOpen className="w-4 h-4" />
                  How to generate a token
                </h4>
                <ol className="space-y-2">
                  {selectedProvider.tokenSteps.map((s, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-xs text-orange-800">
                      <span className="w-5 h-5 rounded-full bg-orange-200 text-orange-700 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      {s}
                    </li>
                  ))}
                </ol>
                <div className="mt-3 pt-3 border-t border-orange-200 flex items-center justify-between">
                  <p className="text-[11px] text-orange-700">
                    Required scopes: <span className="font-mono font-semibold">{selectedProvider.scopes}</span>
                  </p>
                  <a
                    href={selectedProvider.tokenUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-orange-500 hover:text-orange-600 font-semibold flex items-center gap-1"
                  >
                    Open {selectedProvider.name}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>

              {/* Dynamic provider fields */}
              {selectedProvider.fields.map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2">
                    {field.label}
                    {field.required && <span className="text-red-500 ml-1">*</span>}
                  </label>
                  <input
                    type={field.type || "text"}
                    value={fieldValues[field.key] || ""}
                    onChange={(e) => setFieldValues((prev) => ({ ...prev, [field.key]: e.target.value }))}
                    placeholder={field.placeholder}
                    className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-gray-600 text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-gray-500 dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-all"
                  />
                  {field.helpText && (
                    <p className="text-xs text-slate-400 dark:text-gray-500 dark:text-gray-400 mt-1.5">{field.helpText}</p>
                  )}
                </div>
              ))}

              {/* Token input */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2">
                  {selectedProvider.tokenLabel}
                  <span className="text-red-500 ml-1">*</span>
                </label>
                <div className="relative">
                  <input
                    type={showToken ? "text" : "password"}
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder={selectedProvider.tokenPlaceholder}
                    className="w-full h-12 px-4 pr-20 rounded-xl border border-slate-200 dark:border-gray-600 text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-gray-500 dark:bg-gray-700 font-mono focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-all"
                    onKeyDown={(e) => e.key === "Enter" && canConnect() && handleConnect()}
                  />
                  <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setShowToken(!showToken)}
                      className="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 dark:text-gray-500 dark:text-gray-400 hover:text-slate-600 dark:text-gray-400 transition-colors"
                    >
                      {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setStep("provider")}
                  className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:text-gray-300 font-medium transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                  Back
                </button>
                <button
                  onClick={handleConnect}
                  disabled={!canConnect()}
                  className="h-12 px-8 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  Connect
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Step 3: Connecting */}
          {step === "connecting" && selectedProvider && (
            <div className="py-12 flex flex-col items-center text-center">
              <div className="relative mb-6">
                <ProviderIcon provider={selectedProvider} size="lg" />
                <div className="absolute -bottom-1 -right-1 w-7 h-7 bg-white dark:bg-gray-700 rounded-full flex items-center justify-center shadow-md">
                  <Loader2 className="w-4 h-4 text-orange-500 animate-spin" />
                </div>
              </div>
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                Connecting to {selectedProvider.name}...
              </h3>
              <p className="text-sm text-slate-500 dark:text-gray-400 max-w-sm">
                Validating your token and discovering repositories. This usually takes a few seconds.
              </p>
              <div className="mt-8 flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-orange-500 animate-bounce [animation-delay:-0.3s]" />
                <div className="w-2 h-2 rounded-full bg-orange-500 animate-bounce [animation-delay:-0.15s]" />
                <div className="w-2 h-2 rounded-full bg-orange-500 animate-bounce" />
              </div>
            </div>
          )}

          {/* Step 4: Success */}
          {step === "success" && selectedProvider && connectedResult && (
            <div className="py-8 flex flex-col items-center text-center">
              <div className="w-16 h-16 rounded-2xl bg-emerald-50 flex items-center justify-center mb-5">
                <CheckCircle2 className="w-9 h-9 text-emerald-500" />
              </div>
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                Successfully Connected!
              </h3>
              <p className="text-sm text-slate-500 dark:text-gray-400 mb-6 max-w-sm">
                Your {selectedProvider.name} account{" "}
                <span className="font-semibold text-slate-700 dark:text-gray-300">
                  {connectedResult.account_name}
                </span>{" "}
                is now linked to GuardNous.
              </p>
              <div className="grid grid-cols-2 gap-4 w-full max-w-xs mb-8">
                <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-4">
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {connectedResult.repositories?.length ?? 0}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-gray-400 mt-1">Repos Found</p>
                </div>
                <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-4">
                  <p className="text-2xl font-bold text-emerald-600">Active</p>
                  <p className="text-xs text-slate-500 dark:text-gray-400 mt-1">Status</p>
                </div>
              </div>
              <button
                onClick={() => {
                  onSuccess();
                  onClose();
                }}
                className="h-12 px-8 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors flex items-center gap-2"
              >
                <FolderGit2 className="w-4 h-4" />
                View Repositories
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN PAGE COMPONENT
   ═══════════════════════════════════════════════════════════════ */

export default function IntegrationsPage() {
  const queryClient = useQueryClient();

  /* ── Local state ── */
  const [showWizard, setShowWizard] = useState(false);
  const [wizardInitialProvider, setWizardInitialProvider] = useState<ProviderInfo | null>(null);
  const [search, setSearch] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [showDisconnect, setShowDisconnect] = useState(false);
  const [scanToast, setScanToast] = useState<ScanResult | null>(null);
  const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());
  const [filterEnabled, setFilterEnabled] = useState<"all" | "enabled" | "disabled">("all");
  const [scanningRepos, setScanningRepos] = useState<Set<string>>(new Set());
  const [reposCollapsed, setReposCollapsed] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ repoName: string } | null>(null);
  const [deleteInput, setDeleteInput] = useState("");

  /* ── Queries ── */
  const statusQuery = useQuery<IntegrationStatus>({
    queryKey: ["integrationStatus"],
    queryFn: getIntegrationStatus,
    retry: 1,
  });

  const allIntegrationsQuery = useQuery<IntegrationStatus[]>({
    queryKey: ["allIntegrations"],
    queryFn: getAllIntegrations,
    retry: 1,
  });

  const connectedProviders = useMemo(() => {
    const map = new Map<string, IntegrationStatus>();
    (allIntegrationsQuery.data ?? []).forEach((int) => {
      if (int.is_active) map.set(int.vcs_type, int);
    });
    // Also include the single status if allIntegrations didn't load yet
    if (statusQuery.data?.is_active) {
      map.set(statusQuery.data.vcs_type, statusQuery.data);
    }
    return map;
  }, [allIntegrationsQuery.data, statusQuery.data]);

  const reposQuery = useQuery<RepositoryInfo[]>({
    queryKey: ["repos"],
    queryFn: getRepos,
    enabled: !!statusQuery.data?.is_active,
  });

  const capabilitiesQuery = useQuery<CapabilitiesResponse>({
    queryKey: ["capabilities"],
    queryFn: getCapabilities,
  });

  const integration = statusQuery.data;
  const repos = reposQuery.data ?? [];
  const hasIntegration = !!integration?.is_active;

  /* ── Mutations ── */
  const toggleMutation = useMutation({
    mutationFn: toggleRepo,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["repos"] });
      queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
    },
  });

  const syncMutation = useMutation({
    mutationFn: syncRepos,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["repos"] });
    },
  });

  const settingsMutation = useMutation({
    mutationFn: updateIntegrationSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: disconnectIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
      queryClient.invalidateQueries({ queryKey: ["repos"] });
      setShowDisconnect(false);
      setShowSettings(false);
    },
  });

  const scanMutation = useMutation({
    mutationFn: (repoFullName: string) =>
      triggerRepoScan({ repository_full_name: repoFullName, scan_types: ["full"] }),
    onSuccess: (data: ScanResult) => {
      setScanToast(data);
      setTimeout(() => setScanToast(null), 6000);
    },
    onSettled: (_d, _e, repoFullName) => {
      setScanningRepos((prev) => {
        const next = new Set(prev);
        next.delete(repoFullName);
        return next;
      });
    },
  });

  const removeMutation = useMutation({
    mutationFn: (fullName: string) => removeRepository(fullName),
    onSuccess: () => {
      setDeleteConfirm(null);
      setDeleteInput("");
      queryClient.invalidateQueries({ queryKey: ["repos"] });
      queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = axiosErr?.response?.data?.detail || axiosErr?.message || "Failed to delete repository";
      alert(msg);
    },
  });

  /* ── Handlers ── */
  const handleRemoveRepo = useCallback(
    (fullName: string) => {
      setDeleteConfirm({ repoName: fullName });
      setDeleteInput("");
    },
    []
  );

  const confirmDelete = useCallback(() => {
    if (deleteConfirm && deleteInput === deleteConfirm.repoName) {
      removeMutation.mutate(deleteConfirm.repoName);
    }
  }, [deleteConfirm, deleteInput, removeMutation]);

  const handleToggle = useCallback(
    (fullName: string, enabled: boolean) => {
      toggleMutation.mutate({ full_name: fullName, enabled });
    },
    [toggleMutation]
  );

  const handleScan = useCallback(
    (fullName: string) => {
      setScanningRepos((prev) => new Set(prev).add(fullName));
      scanMutation.mutate(fullName);
    },
    [scanMutation]
  );

  const [bulkInProgress, setBulkInProgress] = useState(false);

  const handleBulkEnable = useCallback(
    async (enable: boolean) => {
      const targets = selectedRepos.size > 0 ? Array.from(selectedRepos) : repos.map((r) => r.full_name);
      if (targets.length === 0) return;
      setBulkInProgress(true);
      try {
        for (const fn of targets) {
          await new Promise<void>((resolve, reject) => {
            toggleMutation.mutate(
              { full_name: fn, enabled: enable },
              { onSuccess: () => resolve(), onError: (e) => reject(e) }
            );
          });
        }
      } finally {
        setBulkInProgress(false);
        setSelectedRepos(new Set());
      }
    },
    [selectedRepos, repos, toggleMutation]
  );

  const handleBulkScan = useCallback(async () => {
    const targets = selectedRepos.size > 0 ? Array.from(selectedRepos) : repos.filter((r) => r.enabled).map((r) => r.full_name);
    if (targets.length === 0) return;
    setBulkInProgress(true);
    try {
      for (const fn of targets) {
        handleScan(fn);
        await new Promise((r) => setTimeout(r, 300));
      }
    } finally {
      setBulkInProgress(false);
      setSelectedRepos(new Set());
    }
  }, [selectedRepos, repos, handleScan]);

  const toggleSelectRepo = useCallback((fn: string) => {
    setSelectedRepos((prev) => {
      const next = new Set(prev);
      if (next.has(fn)) next.delete(fn);
      else next.add(fn);
      return next;
    });
  }, []);

  /* ── Derived (must be above toggleSelectAll) ── */
  const filteredRepos = useMemo(() => {
    let list = repos;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) =>
          r.full_name.toLowerCase().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          (r.language && r.language.toLowerCase().includes(q))
      );
    }
    if (filterEnabled === "enabled") list = list.filter((r) => r.enabled);
    if (filterEnabled === "disabled") list = list.filter((r) => !r.enabled);
    return list;
  }, [repos, search, filterEnabled]);

  const allFilteredSelected = useMemo(
    () => filteredRepos.length > 0 && filteredRepos.every((r) => selectedRepos.has(r.full_name)),
    [filteredRepos, selectedRepos],
  );

  const toggleSelectAll = useCallback(() => {
    if (allFilteredSelected) {
      // Deselect only the currently filtered repos, keep others selected
      setSelectedRepos((prev) => {
        const next = new Set(prev);
        filteredRepos.forEach((r) => next.delete(r.full_name));
        return next;
      });
    } else {
      // Add all filtered repos to selection (keep existing selections)
      setSelectedRepos((prev) => {
        const next = new Set(prev);
        filteredRepos.forEach((r) => next.add(r.full_name));
        return next;
      });
    }
  }, [allFilteredSelected, filteredRepos]);

  const providerForIntegration = integration
    ? PROVIDERS.find((p) => p.id === integration.vcs_type) ?? PROVIDERS[0]
    : null;

  const enabledCount = repos.filter((r) => r.enabled).length;

  /* ── Render ── */
  return (
    <PageLayout
      title="VCS Integrations"
      subtitle="Connect your version control systems to enable automated security scanning"
      icon={Link2}
      actions={
        hasIntegration ? (
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="h-10 px-4 rounded-xl border border-slate-200 dark:border-gray-600 text-slate-700 dark:text-gray-300 font-medium text-sm hover:bg-slate-50 dark:hover:bg-gray-700 transition-colors flex items-center gap-2"
            >
              <Settings className="w-4 h-4" />
              <span className="hidden sm:inline">Settings</span>
            </button>
            <button
              onClick={() => { setWizardInitialProvider(null); setShowWizard(true); }}
              className="h-10 px-5 bg-orange-500 hover:bg-orange-600 text-white font-semibold text-sm rounded-xl transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              <span className="hidden sm:inline">Add Integration</span>
            </button>
          </div>
        ) : undefined
      }
    >
      {/* ──────────────────── Settings Panel ──────────────────── */}
      {showSettings && integration && providerForIntegration && (
        <div className="mb-8 bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-sm dark:shadow-black/10 overflow-hidden">
          <div className="px-6 py-5 border-b border-slate-100 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Settings className="w-5 h-5 text-slate-400 dark:text-gray-500 dark:text-gray-400" />
              <h3 className="text-base font-semibold text-slate-900 dark:text-white">Integration Settings</h3>
            </div>
            <button
              onClick={() => setShowSettings(false)}
              className="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 dark:text-gray-500 dark:text-gray-400 hover:text-slate-600 dark:text-gray-400"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="p-6 space-y-5">
            {/* Scan on Push */}
            <div className="flex items-center justify-between py-1">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-orange-50 flex items-center justify-center">
                  <Zap className="w-4 h-4 text-orange-500" />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">Scan on Push</p>
                  <p className="text-xs text-slate-500 dark:text-gray-400">Automatically scan when code is pushed</p>
                </div>
              </div>
              <ToggleSwitch
                enabled={integration.scan_on_push}
                onChange={(v) => settingsMutation.mutate({ scan_on_push: v })}
                disabled={settingsMutation.isPending}
              />
            </div>
            {/* Scan on PR */}
            <div className="flex items-center justify-between py-1">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-purple-50 flex items-center justify-center">
                  <GitPullRequest className="w-4 h-4 text-purple-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">Scan on Pull Request</p>
                  <p className="text-xs text-slate-500 dark:text-gray-400">Run scans on new and updated PRs</p>
                </div>
              </div>
              <ToggleSwitch
                enabled={integration.scan_on_pr}
                onChange={(v) => settingsMutation.mutate({ scan_on_pr: v })}
                disabled={settingsMutation.isPending}
              />
            </div>
            {/* Auto-fix PRs */}
            <div className="flex items-center justify-between py-1">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-emerald-50 flex items-center justify-center">
                  <Shield className="w-4 h-4 text-emerald-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">Auto-fix PRs</p>
                  <p className="text-xs text-slate-500 dark:text-gray-400">Automatically create fix PRs for detected vulnerabilities</p>
                </div>
              </div>
              <ToggleSwitch
                enabled={integration.auto_fix_prs ?? false}
                onChange={(v) => settingsMutation.mutate({ auto_fix_prs: v })}
                disabled={settingsMutation.isPending}
              />
            </div>

            {/* Connected Account Info */}
            <div className="pt-4 border-t border-slate-100">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <ProviderIcon provider={providerForIntegration} size="sm" />
                  <div>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">
                      {integration.account_name}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-gray-400">
                      Connected {new Date(integration.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowDisconnect(true)}
                  className="h-9 px-4 rounded-lg border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 text-sm font-medium hover:bg-red-50 dark:hover:bg-red-900/30 transition-colors flex items-center gap-2"
                >
                  <Unlink className="w-3.5 h-3.5" />
                  Disconnect
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ──────────────── Loading State ────────────────── */}
      {statusQuery.isLoading && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <CardSkeleton />
            <CardSkeleton />
            <CardSkeleton />
            <CardSkeleton />
          </div>
        </div>
      )}

      {/* ──────────────── Provider Grid (always visible) ──────── */}
      {!statusQuery.isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {PROVIDERS.map((p) => {
            const Logo = PROVIDER_LOGO_MAP[p.id];
            const isConnected = connectedProviders.has(p.id);
            const connectedInt = connectedProviders.get(p.id);
            return (
              <button
                key={p.id}
                onClick={() => {
                  if (isConnected) {
                    // Already connected — show repo manager
                    setShowSettings(true);
                  } else {
                    setWizardInitialProvider(p);
                    setShowWizard(true);
                  }
                }}
                className={`group bg-white dark:bg-gray-800 rounded-2xl border shadow-sm hover:shadow-md transition-all duration-200 p-8 text-left flex flex-col items-center gap-5 ${
                  isConnected
                    ? "border-emerald-300 dark:border-emerald-600 hover:border-emerald-400"
                    : "border-slate-200 dark:border-gray-700 hover:border-orange-300 dark:hover:border-orange-500"
                }`}
              >
                <div className="relative">
                  <div className={`w-16 h-16 ${PROVIDER_BG[p.id]} rounded-2xl flex items-center justify-center text-white shadow-md group-hover:scale-105 transition-transform`}>
                    <Logo className="w-9 h-9" />
                  </div>
                  {isConnected && (
                    <div className="absolute -top-1 -right-1 w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center shadow-sm border-2 border-white dark:border-gray-800">
                      <CheckCircle2 className="w-4 h-4 text-white" />
                    </div>
                  )}
                </div>
                <div className="text-center">
                  <h4 className="text-base font-semibold text-slate-900 dark:text-white mb-1.5">{p.name}</h4>
                  <p className="text-sm text-slate-500 dark:text-gray-400 leading-relaxed">{p.description}</p>
                </div>
                {isConnected ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Connected{connectedInt?.account_name ? ` · ${connectedInt.account_name}` : ""}
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-orange-500 opacity-0 group-hover:opacity-100 transition-opacity mt-1">
                    <Plus className="w-3.5 h-3.5" />
                    Connect
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* ═══════════════ Connected State — Repo Manager ═══════════ */}
      {hasIntegration && integration && providerForIntegration && (
        <div className="space-y-6">
          {/* Connected Account Card */}
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-sm dark:shadow-black/10 p-6">
            <div
              className="flex flex-col sm:flex-row sm:items-center gap-4 cursor-pointer select-none"
              onClick={() => setReposCollapsed((c) => !c)}
            >
              <div className="flex items-center gap-4 flex-1 min-w-0">
                <ProviderIcon provider={providerForIntegration} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2.5">
                    <h3 className="text-base font-semibold text-slate-900 dark:text-white truncate">
                      {integration.account_name}
                    </h3>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-700">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      Active
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-gray-400 mt-0.5">
                    {providerForIntegration.name} · {repos.length} repositories · {enabledCount} scanning
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={(e) => { e.stopPropagation(); syncMutation.mutate(); }}
                  disabled={syncMutation.isPending}
                  className="h-9 px-3.5 rounded-lg border border-slate-200 dark:border-gray-600 text-slate-600 dark:text-gray-300 text-sm font-medium hover:bg-slate-50 dark:hover:bg-gray-700 transition-colors flex items-center gap-2 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? "animate-spin" : ""}`} />
                  Sync
                </button>
                {reposCollapsed ? (
                  <ChevronDown className="w-5 h-5 text-slate-400 dark:text-gray-500" />
                ) : (
                  <ChevronUp className="w-5 h-5 text-slate-400 dark:text-gray-500" />
                )}
              </div>
            </div>

            {/* Stats row */}
            <div className={`grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-5 border-t border-slate-100 ${reposCollapsed ? "hidden" : ""}`}>
              <div className="bg-slate-50 dark:bg-slate-800 rounded-xl px-4 py-3">
                <p className="text-lg font-bold text-slate-900 dark:text-white">{repos.length}</p>
                <p className="text-[11px] text-slate-500 dark:text-gray-400 font-medium">Total Repos</p>
              </div>
              <div className="bg-emerald-50 rounded-xl px-4 py-3">
                <p className="text-lg font-bold text-emerald-700">{enabledCount}</p>
                <p className="text-[11px] text-emerald-600 font-medium">Scanning</p>
              </div>
              <div className="bg-slate-50 dark:bg-slate-800 rounded-xl px-4 py-3">
                <p className="text-lg font-bold text-slate-900 dark:text-white">
                  {repos.filter((r) => r.last_scan_status === "completed").length}
                </p>
                <p className="text-[11px] text-slate-500 dark:text-gray-400 font-medium">Scanned</p>
              </div>
              <div className="bg-slate-50 dark:bg-slate-800 rounded-xl px-4 py-3">
                <p className="text-lg font-bold text-slate-900 dark:text-white">
                  {repos.filter((r) => r.private).length}
                </p>
                <p className="text-[11px] text-slate-500 dark:text-gray-400 font-medium">Private</p>
              </div>
            </div>
          </div>

          {/* Repository Manager */}
          {!reposCollapsed && (
          <div className="bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-sm dark:shadow-black/10 overflow-hidden">
            {/* Toolbar */}
            <div className="px-6 py-4 border-b border-slate-100">
              <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="relative flex-1 max-w-sm">
                    <Search className="w-4 h-4 text-slate-400 dark:text-gray-500 dark:text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Search repositories..."
                      className="w-full h-10 pl-10 pr-4 rounded-xl border border-slate-200 dark:border-gray-600 text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-gray-500 dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-all"
                    />
                  </div>
                  {/* Filter tabs */}
                  <div className="hidden sm:flex items-center bg-slate-100 rounded-lg p-0.5">
                    {(["all", "enabled", "disabled"] as const).map((f) => (
                      <button
                        key={f}
                        onClick={() => setFilterEnabled(f)}
                        className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                          filterEnabled === f
                            ? "bg-white dark:bg-gray-700 text-slate-900 dark:text-white shadow-sm"
                            : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:text-gray-300"
                        }`}
                      >
                        {f === "all" ? `All (${repos.length})` : f === "enabled" ? `Enabled (${enabledCount})` : `Disabled (${repos.length - enabledCount})`}
                      </button>
                    ))}
                  </div>
                </div>
                {/* Bulk actions */}
                <div className="flex items-center gap-2">
                  {selectedRepos.size > 0 && (
                    <span className="text-xs text-slate-500 dark:text-gray-400 mr-1">
                      {selectedRepos.size} selected
                    </span>
                  )}
                  <button
                    onClick={() => handleBulkEnable(true)}
                    disabled={bulkInProgress}
                    className="h-9 px-3 rounded-lg border border-slate-200 dark:border-gray-600 text-xs font-medium text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors hidden sm:flex items-center gap-1.5"
                  >
                    {bulkInProgress ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    Enable{selectedRepos.size > 0 ? " Selected" : " All"}
                  </button>
                  <button
                    onClick={() => handleBulkEnable(false)}
                    disabled={bulkInProgress}
                    className="h-9 px-3 rounded-lg border border-slate-200 dark:border-gray-600 text-xs font-medium text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors hidden sm:flex items-center gap-1.5"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    Disable{selectedRepos.size > 0 ? " Selected" : " All"}
                  </button>
                  <button
                    onClick={handleBulkScan}
                    disabled={bulkInProgress}
                    className="h-9 px-3.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
                  >
                    {bulkInProgress ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    Scan{selectedRepos.size > 0 ? ` (${selectedRepos.size})` : " Enabled"}
                  </button>
                </div>
              </div>
            </div>

            {/* Repos loading */}
            {reposQuery.isLoading && (
              <div className="p-6">
                <TableSkeleton />
              </div>
            )}

            {/* Repos empty */}
            {reposQuery.isSuccess && repos.length === 0 && (
              <div className="p-12 text-center">
                <FolderGit2 className="w-10 h-10 text-slate-300 dark:text-gray-600 dark:text-gray-300 mx-auto mb-4" />
                <h4 className="text-base font-semibold text-slate-900 dark:text-white mb-2">No Repositories Found</h4>
                <p className="text-sm text-slate-500 dark:text-gray-400 mb-6 max-w-sm mx-auto">
                  We didn&apos;t find any repositories. Try syncing to refresh the list.
                </p>
                <button
                  onClick={() => syncMutation.mutate()}
                  disabled={syncMutation.isPending}
                  className="h-10 px-5 bg-orange-500 hover:bg-orange-600 text-white font-semibold text-sm rounded-xl transition-colors inline-flex items-center gap-2"
                >
                  <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? "animate-spin" : ""}`} />
                  Sync Repositories
                </button>
              </div>
            )}

            {/* Repos filtered empty */}
            {reposQuery.isSuccess && repos.length > 0 && filteredRepos.length === 0 && (
              <div className="p-10 text-center">
                <Search className="w-8 h-8 text-slate-300 dark:text-gray-600 dark:text-gray-300 mx-auto mb-3" />
                <h4 className="text-sm font-semibold text-slate-700 dark:text-gray-300">No matching repositories</h4>
                <p className="text-xs text-slate-500 dark:text-gray-400 mt-1">Try adjusting your search or filter</p>
              </div>
            )}

            {/* Repo list */}
            {reposQuery.isSuccess && filteredRepos.length > 0 && (
              <div className="divide-y divide-slate-100 dark:divide-gray-700 max-h-[500px] overflow-y-auto">
                {/* Table header */}
                <div className="px-6 py-3 bg-slate-50 dark:bg-slate-800/80 dark:bg-gray-700/50 flex items-center gap-4 text-[11px] font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
                  <div className="w-5 flex items-center justify-center">
                    <input
                      type="checkbox"
                      checked={allFilteredSelected}
                      onChange={toggleSelectAll}
                      className="w-4 h-4 rounded border-slate-300 dark:border-gray-500 text-orange-500 focus:ring-orange-500 cursor-pointer"
                    />
                  </div>
                  <div className="flex-1">Repository</div>
                  <div className="w-20 hidden md:block text-center">Language</div>
                  <div className="w-24 hidden lg:block text-center">Branch</div>
                  <div className="w-24 hidden lg:block text-center">Last Scan</div>
                  <div className="w-20 text-center">Scanning</div>
                  <div className="w-24 text-center">Actions</div>
                </div>

                {filteredRepos.map((repo) => {
                  const isScanning = scanningRepos.has(repo.full_name);
                  const langColor = repo.language ? LANGUAGE_COLORS[repo.language] || "bg-slate-400" : null;

                  return (
                    <div
                      key={repo.full_name}
                      className={`px-6 py-3.5 flex items-center gap-4 hover:bg-slate-50 dark:bg-slate-800/60 dark:hover:bg-gray-700/40 transition-colors ${
                        selectedRepos.has(repo.full_name) ? "bg-orange-50/40 dark:bg-orange-900/20" : ""
                      }`}
                    >
                      {/* Checkbox */}
                      <div className="w-5 flex items-center justify-center">
                        <input
                          type="checkbox"
                          checked={selectedRepos.has(repo.full_name)}
                          onChange={() => toggleSelectRepo(repo.full_name)}
                          className="w-4 h-4 rounded border-slate-300 dark:border-gray-500 text-orange-500 focus:ring-orange-500 cursor-pointer"
                        />
                      </div>

                      {/* Repo info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                            {repo.name}
                          </p>
                          {repo.private ? (
                            <Lock className="w-3 h-3 text-slate-400 dark:text-gray-500 dark:text-gray-400 shrink-0" />
                          ) : (
                            <Globe2 className="w-3 h-3 text-slate-400 dark:text-gray-500 dark:text-gray-400 shrink-0" />
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 dark:text-gray-500 dark:text-gray-400 truncate mt-0.5">
                          {repo.full_name}
                        </p>
                      </div>

                      {/* Language */}
                      <div className="w-20 hidden md:flex items-center justify-center">
                        {repo.language ? (
                          <span className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-gray-400">
                            <span className={`w-2 h-2 rounded-full ${langColor}`} />
                            {repo.language}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-300 dark:text-gray-600 dark:text-gray-300">—</span>
                        )}
                      </div>

                      {/* Branch */}
                      <div className="w-24 hidden lg:flex items-center justify-center">
                        <span className="inline-flex items-center gap-1 text-xs text-slate-500 dark:text-gray-400 bg-slate-100 dark:bg-gray-700 px-2 py-0.5 rounded-md font-mono">
                          <GitBranch className="w-3 h-3" />
                          {repo.default_branch}
                        </span>
                      </div>

                      {/* Last Scan */}
                      <div className="w-24 hidden lg:flex items-center justify-center">
                        {repo.last_scan_at ? (
                          <span className="text-xs text-slate-500 dark:text-gray-400 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(repo.last_scan_at).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-300">Never</span>
                        )}
                      </div>

                      {/* Toggle */}
                      <div className="w-20 flex items-center justify-center">
                        <ToggleSwitch
                          enabled={repo.enabled}
                          onChange={(v) => handleToggle(repo.full_name, v)}
                          disabled={toggleMutation.isPending}
                        />
                      </div>

                      {/* Scan button */}
                      <div className="w-24 flex items-center justify-center">
                        <button
                          onClick={() => handleScan(repo.full_name)}
                          disabled={isScanning || !repo.enabled}
                          className={`h-8 px-3 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                            repo.enabled
                              ? "bg-orange-50 text-orange-700 hover:bg-orange-100"
                              : "bg-slate-50 dark:bg-slate-800 text-slate-400 dark:text-gray-500 dark:text-gray-400 cursor-not-allowed"
                          } disabled:opacity-50`}
                        >
                          {isScanning ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Play className="w-3 h-3" />
                          )}
                          {isScanning ? "..." : "Scan"}
                        </button>
                      </div>

                      {/* Remove button */}
                      <div className="w-10 flex items-center justify-center">
                        <button
                          onClick={() => handleRemoveRepo(repo.full_name)}
                          disabled={removeMutation.isPending}
                          title="Remove repository and all scan data"
                          className="h-8 w-8 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors flex items-center justify-center disabled:opacity-50"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Footer */}
            {reposQuery.isSuccess && repos.length > 0 && (
              <div className="px-6 py-3 bg-slate-50 dark:bg-slate-800/80 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 dark:text-gray-400">
                <span>
                  Showing {filteredRepos.length} of {repos.length} repositories
                </span>
                <span>
                  {enabledCount} enabled for scanning
                </span>
              </div>
            )}
          </div>
          )}
        </div>
      )}

      {/* ──────────────── Modals ──────────────────────── */}
      {showWizard && (
        <AddIntegrationWizard
          initialProvider={wizardInitialProvider}
          onClose={() => { setShowWizard(false); setWizardInitialProvider(null); }}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ["integrationStatus"] });
            queryClient.invalidateQueries({ queryKey: ["repos"] });
          }}
        />
      )}

      {showDisconnect && integration && providerForIntegration && (
        <DisconnectModal
          providerName={providerForIntegration.name}
          onConfirm={() => disconnectMutation.mutate()}
          onCancel={() => setShowDisconnect(false)}
          isLoading={disconnectMutation.isPending}
        />
      )}

      {scanToast && (
        <ScanToast result={scanToast} onClose={() => setScanToast(null)} />
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full mx-4 overflow-hidden">
            <div className="px-6 pt-6 pb-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                  <Trash2 className="w-5 h-5 text-red-600 dark:text-red-400" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Delete Repository</h3>
              </div>
              <p className="text-sm text-slate-600 dark:text-gray-300 mb-1">
                This will permanently remove <strong className="text-slate-900 dark:text-white">{deleteConfirm.repoName}</strong> and all associated scan data and findings. This action cannot be undone.
              </p>
              <p className="text-sm text-slate-500 dark:text-gray-400 mb-4">
                Type <code className="px-1.5 py-0.5 bg-slate-100 dark:bg-gray-700 rounded text-xs font-mono text-red-600 dark:text-red-400">{deleteConfirm.repoName}</code> to confirm:
              </p>
              <input
                type="text"
                value={deleteInput}
                onChange={(e) => setDeleteInput(e.target.value)}
                placeholder={deleteConfirm.repoName}
                className="w-full px-3 py-2 border border-slate-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none"
                autoFocus
                onKeyDown={(e) => { if (e.key === "Enter") confirmDelete(); }}
              />
            </div>
            <div className="px-6 py-4 bg-slate-50 dark:bg-gray-800/80 border-t border-slate-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => { setDeleteConfirm(null); setDeleteInput(""); }}
                className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-slate-300 dark:border-gray-600 rounded-lg hover:bg-slate-50 dark:hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleteInput !== deleteConfirm.repoName || removeMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {removeMutation.isPending ? "Deleting…" : "Delete Repository"}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
