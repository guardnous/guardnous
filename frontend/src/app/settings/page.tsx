"use client";

import React, { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Settings,
  Sparkles,
  Cloud,
  Brain,
  Server,
  Eye,
  EyeOff,
  Check,
  X,
  Loader2,
  Bell,
  ChevronDown,
  Send,
  Mail,
  Shield,
  AlertCircle,
  Smartphone,
  KeyRound,
  Copy,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Building2,
  Users,
  Crown,
  Calendar,
  Database,
  Activity,
} from "lucide-react";
import PageLayout from "@/components/PageLayout";
import {
  getAgentConfig, updateAgentConfig, testAgentConfig,
  getGeneralSettings, updateGeneralSettings,
  getNotificationPrefs, updateNotificationPrefs,
  getSmtpSettings, updateSmtpSettings, testSmtpConnection,
  setup2FA, confirm2FASetup, disable2FA, regenerateBackupCodes,
  fetchOrgDashboard,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";

/* ── Types ── */
interface ProviderField {
  key: string;
  label: string;
  placeholder: string;
  help?: string;
  required?: boolean;
  type?: "text" | "password" | "select";
}

interface ProviderOption {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  bgSelected: string;
  borderSelected: string;
  models: string[];
  fields: ProviderField[];
  requiresApiKey: boolean;
}

type TabId = "ai-provider" | "general" | "notifications" | "security" | "organization";

interface Tab {
  id: TabId;
  label: string;
}

/* ── Constants ── */
const TABS: Tab[] = [
  { id: "ai-provider", label: "AI Provider" },
  { id: "general", label: "General" },
  { id: "notifications", label: "Notifications" },
  { id: "security", label: "Security" },
  { id: "organization", label: "Organization" },
];

const PROVIDERS: ProviderOption[] = [
  {
    id: "openai",
    label: "OpenAI",
    description: "GPT-4o, GPT-4o mini, GPT-4 Turbo",
    icon: <Sparkles size={22} />,
    color: "text-emerald-500",
    bgSelected: "bg-orange-50 dark:bg-orange-500/10",
    borderSelected: "border-orange-500",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
    requiresApiKey: true,
    fields: [
      { key: "api_key", label: "API Key", placeholder: "sk-...", required: true, type: "password" },
      { key: "base_url", label: "Base URL", placeholder: "https://api.openai.com/v1", help: "Optional. Override for OpenAI-compatible gateways or proxies." },
    ],
  },
  {
    id: "azure_foundry",
    label: "Azure AI Foundry",
    description: "Azure-hosted GPT and Claude models via AI Foundry",
    icon: <Cloud size={22} />,
    color: "text-blue-500",
    bgSelected: "bg-orange-50 dark:bg-orange-500/10",
    borderSelected: "border-orange-500",
    models: [],
    requiresApiKey: true,
    fields: [
      { key: "api_key", label: "API Key", placeholder: "Enter your Azure AI Foundry API key", required: true, type: "password" },
      { key: "base_url", label: "Endpoint URL", placeholder: "https://<resource>.cognitiveservices.azure.com", required: true, help: "For GPT: https://<resource>.cognitiveservices.azure.com — For Claude: https://<resource>.services.ai.azure.com/anthropic" },
      { key: "model", label: "Deployment Name", placeholder: "gpt-4.1 or claude-opus-4-5", required: true, help: "The deployment name (e.g. gpt-4.1, gpt-4o, claude-opus-4-5)." },
      { key: "api_version", label: "API Version", placeholder: "2024-12-01-preview", help: "Azure API version (GPT only, ignored for Claude). Defaults to 2024-12-01-preview." },
    ],
  },
  {
    id: "anthropic",
    label: "Anthropic",
    description: "Claude 4 Sonnet, Claude 3.5 Sonnet, Claude 3 Opus",
    icon: <Brain size={22} />,
    color: "text-purple-500",
    bgSelected: "bg-orange-50 dark:bg-orange-500/10",
    borderSelected: "border-orange-500",
    models: [
      "claude-sonnet-4-20250514",
      "claude-3-5-sonnet-latest",
      "claude-3-opus-latest",
      "claude-3-haiku-20240307",
    ],
    requiresApiKey: true,
    fields: [
      { key: "api_key", label: "API Key", placeholder: "sk-ant-...", required: true, type: "password" },
      { key: "base_url", label: "Base URL", placeholder: "https://api.anthropic.com/v1", help: "Optional. Override for Anthropic-compatible proxies." },
    ],
  },
  {
    id: "ollama",
    label: "Ollama",
    description: "Self-hosted local models — no API key needed",
    icon: <Server size={22} />,
    color: "text-orange-500",
    bgSelected: "bg-orange-50 dark:bg-orange-500/10",
    borderSelected: "border-orange-500",
    models: ["llama3.1", "llama3", "mistral", "codellama", "deepseek-coder"],
    requiresApiKey: false,
    fields: [
      { key: "base_url", label: "Base URL", placeholder: "http://localhost:11434/v1", required: true, help: "URL of your running Ollama instance." },
    ],
  },
];

/* ── Timezone list ── */
const TIMEZONES = [
  "UTC", "America/New_York", "America/Chicago", "America/Denver",
  "America/Los_Angeles", "America/Sao_Paulo", "Europe/London", "Europe/Paris",
  "Europe/Berlin", "Asia/Dubai", "Asia/Kolkata", "Asia/Shanghai",
  "Asia/Tokyo", "Asia/Singapore", "Australia/Sydney", "Pacific/Auckland",
];
const DATE_FORMATS = ["YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY", "DD-MMM-YYYY"];
const RISK_THRESHOLDS = [
  { value: "critical", label: "Critical Only" },
  { value: "high", label: "High & Above" },
  { value: "medium", label: "Medium & Above" },
  { value: "low", label: "All Severities" },
];

/* ── Toggle helper ── */
function Toggle({ checked, onChange, label, desc }: { checked: boolean; onChange: (v: boolean) => void; label: string; desc?: string }) {
  return (
    <div className="flex items-center justify-between py-3">
      <div>
        <p className="text-sm font-medium text-slate-900 dark:text-white">{label}</p>
        {desc && <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{desc}</p>}
      </div>
      <button type="button" onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? "bg-blue-600" : "bg-slate-300 dark:bg-slate-700"}`}>
        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${checked ? "translate-x-6" : "translate-x-1"}`} />
      </button>
    </div>
  );
}

/* ── SelectField helper ── */
function SelectField({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{label}</label>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

/* ── NumberField helper ── */
function NumberField({ label, value, onChange, min, max, suffix }: { label: string; value: number; onChange: (v: number) => void; min: number; max: number; suffix?: string }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{label}</label>
      <div className="flex items-center gap-2">
        <input type="number" value={value} min={min} max={max} onChange={(e) => onChange(Number(e.target.value))}
          className="w-32 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
        {suffix && <span className="text-sm text-slate-500 dark:text-slate-400">{suffix}</span>}
      </div>
    </div>
  );
}

const NO_PERMISSION = "You do not have permission to change this";

function isForbidden(err: unknown): boolean {
  return (err as { response?: { status?: number } } | null)?.response?.status === 403;
}

function SaveError({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <span className="text-sm text-red-600 dark:text-red-400">
      {isForbidden(error) ? NO_PERMISSION : "Could not save"}
    </span>
  );
}

/* ── General Settings Tab ── */
function GeneralSettingsTab() {
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState({
    platform_name: "GuardNous",
    timezone: "UTC",
    date_format: "YYYY-MM-DD",
    session_timeout: 30,
    dark_mode_default: "system",
    data_retention_days: 90,
    enforce_2fa: false,
    auto_remediation: false,
    risk_threshold: "high",
    scan_concurrency: 3,
    log_level: "INFO",
  });

  const { data, isLoading } = useQuery({ queryKey: ["generalSettings"], queryFn: getGeneralSettings });
  useEffect(() => { if (data) setForm(data); }, [data]);

  const mutation = useMutation({
    mutationFn: updateGeneralSettings,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["generalSettings"] }); setSaved(true); setTimeout(() => setSaved(false), 3000); },
  });

  const upd = (k: string, v: unknown) => setForm((p) => ({ ...p, [k]: v }));

  if (isLoading) return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 flex items-center justify-center py-16">
      <Loader2 className="animate-spin text-slate-400" size={24} />
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Platform Identity */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Platform Identity</h3>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Platform Name</label>
          <input type="text" value={form.platform_name} onChange={(e) => upd("platform_name", e.target.value)}
            className="w-full max-w-md rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-orange-500" />
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Used in email notifications and page titles</p>
        </div>
      </div>

      {/* Date & Time */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Date &amp; Time</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SelectField label="Timezone" value={form.timezone} onChange={(v) => upd("timezone", v)}
            options={TIMEZONES.map((tz) => ({ value: tz, label: tz.replace(/_/g, " ") }))} />
          <SelectField label="Date Format" value={form.date_format} onChange={(v) => upd("date_format", v)}
            options={DATE_FORMATS.map((f) => ({ value: f, label: f }))} />
        </div>
      </div>

      {/* Security & Session */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Security &amp; Session</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <NumberField label="Session Timeout" value={form.session_timeout} onChange={(v) => upd("session_timeout", v)} min={5} max={480} suffix="minutes" />
          <NumberField label="Data Retention" value={form.data_retention_days} onChange={(v) => upd("data_retention_days", v)} min={7} max={3650} suffix="days" />
        </div>
        <div className="border-t border-slate-200 dark:border-slate-800 pt-3">
          <Toggle label="Enforce Two-Factor Authentication" desc="Require all users to enable 2FA on their accounts" checked={form.enforce_2fa} onChange={(v) => upd("enforce_2fa", v)} />
        </div>
      </div>

      {/* Scanning & Remediation */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Scanning &amp; Remediation</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <SelectField label="Risk Alert Threshold" value={form.risk_threshold} onChange={(v) => upd("risk_threshold", v)} options={RISK_THRESHOLDS} />
          <NumberField label="Max Concurrent Scans" value={form.scan_concurrency} onChange={(v) => upd("scan_concurrency", v)} min={1} max={20} />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SelectField label="Default Theme" value={form.dark_mode_default} onChange={(v) => upd("dark_mode_default", v)}
            options={[{ value: "system", label: "System Default" }, { value: "light", label: "Light" }, { value: "dark", label: "Dark" }]} />
        </div>
        <div className="border-t border-slate-200 dark:border-slate-800 pt-3 mt-4">
          <Toggle label="Auto-Remediation" desc="Automatically apply safe fixes for known vulnerabilities" checked={form.auto_remediation} onChange={(v) => upd("auto_remediation", v)} />
        </div>
      </div>

      {/* Logging */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-4">Logging</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SelectField label="Log Level" value={form.log_level} onChange={(v) => upd("log_level", v)}
            options={[
              { value: "DEBUG", label: "Debug — All messages" },
              { value: "VERBOSE", label: "Verbose — Detailed operational" },
              { value: "INFO", label: "Info — Standard events" },
              { value: "WARNING", label: "Warning — Potential issues" },
              { value: "ERROR", label: "Error — Failures only" },
              { value: "CRITICAL", label: "Critical — Severe failures" },
            ]} />
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">Controls which log entries are persisted to the database. Lower levels capture more detail but increase storage usage.</p>
      </div>

      {/* Save */}
      <div className="flex items-center justify-end gap-3">
        {saved && <span className="flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400"><Check size={16} /> Settings saved</span>}
        <SaveError error={mutation.error} />
        <button onClick={() => mutation.mutate(form)} disabled={mutation.isPending}
          className="px-5 py-2.5 rounded-xl bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2 transition-colors">
          {mutation.isPending ? <Loader2 className="animate-spin" size={16} /> : <Check size={16} />}
          Save Settings
        </button>
      </div>
    </div>
  );
}

/* ── Notification Preferences Tab ── */

/* ── SMTP Configuration Card ── */
function SmtpConfigCard() {
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [form, setForm] = useState({
    smtp_enabled: false,
    smtp_host: "",
    smtp_port: 587,
    smtp_user: "",
    smtp_password: "",
    smtp_from_email: "",
    smtp_from_name: "GuardNous",
    smtp_use_tls: true,
  });
  const [passwordPlaceholder, setPasswordPlaceholder] = useState(false);

  const { data, isLoading, error: loadError } = useQuery({ queryKey: ["smtpSettings"], queryFn: getSmtpSettings });
  useEffect(() => {
    if (data) {
      setForm({
        smtp_enabled: data.smtp_enabled ?? false,
        smtp_host: data.smtp_host ?? "",
        smtp_port: data.smtp_port ?? 587,
        smtp_user: data.smtp_user ?? "",
        smtp_password: "",
        smtp_from_email: data.smtp_from_email ?? "",
        smtp_from_name: data.smtp_from_name ?? "GuardNous",
        smtp_use_tls: data.smtp_use_tls ?? true,
      });
      setPasswordPlaceholder(data.smtp_password_set ?? false);
    }
  }, [data]);

  const mutation = useMutation({
    mutationFn: updateSmtpSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["smtpSettings"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    },
  });

  const handleSave = () => {
    const payload: Record<string, unknown> = { ...form };
    if (!payload.smtp_password) delete payload.smtp_password;
    mutation.mutate(payload);
  };

  const handleTest = async () => {
    if (!testEmail) return;
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testSmtpConnection(testEmail);
      setTestResult(res);
    } catch (err) {
      setTestResult({ status: "error", message: isForbidden(err) ? NO_PERMISSION : "Request failed" });
    } finally {
      setTesting(false);
    }
  };

  const upd = (k: string, v: unknown) => setForm((p) => ({ ...p, [k]: v }));
  const inputCls = "w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

  if (isLoading) return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 flex items-center justify-center py-16">
      <Loader2 className="animate-spin text-slate-400" size={24} />
    </div>
  );

  // The notifications tab already says so; do not show an editable form with made-up defaults.
  if (isForbidden(loadError)) return null;

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
      <div className="flex items-center gap-3 mb-1">
        <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/50">
          <Mail className="text-blue-600 dark:text-blue-400" size={18} />
        </div>
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">SMTP Configuration</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">Configure your mail server to send email notifications</p>
        </div>
      </div>

      <div className="mt-4">
        <Toggle label="Enable SMTP" desc="Turn on email delivery for notifications and alerts" checked={form.smtp_enabled} onChange={(v) => upd("smtp_enabled", v)} />
      </div>

      {form.smtp_enabled && (
        <div className="mt-4 space-y-4 border-t border-slate-200 dark:border-slate-800 pt-4">
          {/* Server Settings */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">SMTP Host</label>
              <input type="text" value={form.smtp_host} onChange={(e) => upd("smtp_host", e.target.value)}
                placeholder="smtp.gmail.com" className={inputCls} />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Port</label>
              <input type="number" value={form.smtp_port} onChange={(e) => upd("smtp_port", parseInt(e.target.value) || 587)}
                placeholder="587" className={inputCls} />
            </div>
          </div>

          {/* Auth */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Username</label>
              <input type="text" value={form.smtp_user} onChange={(e) => upd("smtp_user", e.target.value)}
                placeholder="your-email@gmail.com" className={inputCls} />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Password / App Password</label>
              <div className="relative">
                <input type={showPassword ? "text" : "password"} value={form.smtp_password}
                  onChange={(e) => { upd("smtp_password", e.target.value); setPasswordPlaceholder(false); }}
                  placeholder={passwordPlaceholder ? "••••••••  (saved)" : "Enter SMTP password"}
                  className={inputCls + " pr-10"} />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          {/* From */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">From Email</label>
              <input type="email" value={form.smtp_from_email} onChange={(e) => upd("smtp_from_email", e.target.value)}
                placeholder="noreply@yourcompany.com" className={inputCls} />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">From Name</label>
              <input type="text" value={form.smtp_from_name} onChange={(e) => upd("smtp_from_name", e.target.value)}
                placeholder="GuardNous" className={inputCls} />
            </div>
          </div>

          {/* TLS */}
          <Toggle label="Use TLS/STARTTLS" desc="Encrypt SMTP traffic (recommended — required for port 587)" checked={form.smtp_use_tls} onChange={(v) => upd("smtp_use_tls", v)} />

          {/* Save Button */}
          <div className="flex items-center gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
            {saved && <span className="flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400"><Check size={16} /> SMTP settings saved</span>}
            <SaveError error={mutation.error} />
            <button onClick={handleSave} disabled={mutation.isPending}
              className="px-4 py-2 rounded-xl bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2 transition-colors">
              {mutation.isPending ? <Loader2 className="animate-spin" size={16} /> : <Check size={16} />}
              Save SMTP Settings
            </button>
          </div>

          {/* Test Section */}
          <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
            <h4 className="text-sm font-semibold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
              <Send size={14} className="text-blue-500" /> Send Test Email
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Save settings first, then send a test to verify delivery.</p>
            <div className="flex gap-2">
              <input type="email" value={testEmail} onChange={(e) => setTestEmail(e.target.value)}
                placeholder="recipient@example.com"
                className={inputCls + " flex-1"} />
              <button onClick={handleTest} disabled={testing || !testEmail}
                className="px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-700 disabled:opacity-50 flex items-center gap-2 whitespace-nowrap transition-colors">
                {testing ? <Loader2 className="animate-spin" size={16} /> : <Send size={16} />}
                Send Test
              </button>
            </div>
            {testResult && (
              <div className={`mt-3 flex items-start gap-2 text-sm rounded-lg p-3 ${testResult.status === "ok" ? "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800" : "bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800"}`}>
                {testResult.status === "ok" ? <Check size={16} className="mt-0.5 shrink-0" /> : <AlertCircle size={16} className="mt-0.5 shrink-0" />}
                <span>{testResult.message}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function NotificationPrefsTab() {
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState({
    email_enabled: true, email_critical: true, email_high: true, email_medium: false, email_low: false,
    email_digest: "daily",
    in_app_enabled: true, in_app_scans: true, in_app_findings: true, in_app_compliance: true, in_app_system: true,
    slack_webhook: "", slack_enabled: false,
    teams_webhook: "", teams_enabled: false,
  });

  const { data, isLoading, error: loadError } = useQuery({ queryKey: ["notificationPrefs"], queryFn: getNotificationPrefs });
  useEffect(() => { if (data) setForm(data); }, [data]);

  const mutation = useMutation({
    mutationFn: updateNotificationPrefs,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["notificationPrefs"] }); setSaved(true); setTimeout(() => setSaved(false), 3000); },
  });

  const upd = (k: string, v: unknown) => setForm((p) => ({ ...p, [k]: v }));

  if (isLoading) return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 flex items-center justify-center py-16">
      <Loader2 className="animate-spin text-slate-400" size={24} />
    </div>
  );

  if (isForbidden(loadError)) return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 text-sm text-slate-500 dark:text-slate-400">
      {NO_PERMISSION}
    </div>
  );

  return (
    <div className="space-y-6">
      {/* SMTP Configuration */}
      <SmtpConfigCard />

      {/* Email Notifications */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">Email Notifications</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">Configure which events trigger email alerts</p>
        <Toggle label="Enable Email Notifications" desc="Master switch for all email alerts" checked={form.email_enabled} onChange={(v) => upd("email_enabled", v)} />
        {form.email_enabled && (
          <div className="mt-2 space-y-0 border-t border-slate-200 dark:border-slate-800 pt-2">
            <Toggle label="Critical Findings" desc="Severity ≥ 9.0" checked={form.email_critical} onChange={(v) => upd("email_critical", v)} />
            <Toggle label="High Findings" desc="Severity ≥ 7.0" checked={form.email_high} onChange={(v) => upd("email_high", v)} />
            <Toggle label="Medium Findings" desc="Severity ≥ 4.0" checked={form.email_medium} onChange={(v) => upd("email_medium", v)} />
            <Toggle label="Low Findings" desc="Severity < 4.0" checked={form.email_low} onChange={(v) => upd("email_low", v)} />
            <div className="pt-2">
              <SelectField label="Email Digest Frequency" value={form.email_digest} onChange={(v) => upd("email_digest", v)}
                options={[{ value: "realtime", label: "Real-time" }, { value: "daily", label: "Daily Digest" }, { value: "weekly", label: "Weekly Summary" }, { value: "off", label: "Off" }]} />
            </div>
          </div>
        )}
      </div>

      {/* In-App Notifications */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">In-App Notifications</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">Notification bell and toast alerts in the platform</p>
        <Toggle label="Enable In-App Notifications" desc="Master switch for bell icon alerts" checked={form.in_app_enabled} onChange={(v) => upd("in_app_enabled", v)} />
        {form.in_app_enabled && (
          <div className="mt-2 space-y-0 border-t border-slate-200 dark:border-slate-800 pt-2">
            <Toggle label="Scan Completions" desc="Notify when assessments finish" checked={form.in_app_scans} onChange={(v) => upd("in_app_scans", v)} />
            <Toggle label="New Findings" desc="Alert on new vulnerabilities discovered" checked={form.in_app_findings} onChange={(v) => upd("in_app_findings", v)} />
            <Toggle label="Compliance Violations" desc="Policy & compliance breach alerts" checked={form.in_app_compliance} onChange={(v) => upd("in_app_compliance", v)} />
            <Toggle label="System Events" desc="Platform health & maintenance notices" checked={form.in_app_system} onChange={(v) => upd("in_app_system", v)} />
          </div>
        )}
      </div>

      {/* Integrations (Slack & Teams) */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">Channel Integrations</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">Send alerts to Slack or Microsoft Teams</p>

        <Toggle label="Slack Notifications" desc="Forward alerts to a Slack channel" checked={form.slack_enabled} onChange={(v) => upd("slack_enabled", v)} />
        {form.slack_enabled && (
          <div className="mt-2 mb-4">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Slack Webhook URL</label>
            <input type="url" value={form.slack_webhook} onChange={(e) => upd("slack_webhook", e.target.value)} placeholder="https://hooks.slack.com/services/..."
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
          </div>
        )}

        <div className="border-t border-slate-200 dark:border-slate-800 pt-3">
          <Toggle label="Microsoft Teams Notifications" desc="Forward alerts to a Teams channel" checked={form.teams_enabled} onChange={(v) => upd("teams_enabled", v)} />
          {form.teams_enabled && (
            <div className="mt-2">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Teams Webhook URL</label>
              <input type="url" value={form.teams_webhook} onChange={(e) => upd("teams_webhook", e.target.value)} placeholder="https://outlook.office.com/webhook/..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500" />
            </div>
          )}
        </div>
      </div>

      {/* Save */}
      <div className="flex items-center justify-end gap-3">
        {saved && <span className="flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400"><Check size={16} /> Preferences saved</span>}
        <SaveError error={mutation.error} />
        <button onClick={() => mutation.mutate(form)} disabled={mutation.isPending}
          className="px-5 py-2.5 rounded-xl bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2 transition-colors">
          {mutation.isPending ? <Loader2 className="animate-spin" size={16} /> : <Check size={16} />}
          Save Preferences
        </button>
      </div>
    </div>
  );
}

/* ── Security (2FA) Tab ── */
function SecurityTab() {
  const { user, refreshUser } = useAuth();
  const [step, setStep] = useState<"idle" | "setup" | "codes">("idle");
  const [qrCode, setQrCode] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [otpCode, setOtpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");
  const [copied, setCopied] = useState(false);

  const is2FAEnabled = user?.totp_enabled ?? false;

  const handleSetup = async () => {
    setError(""); setLoading(true);
    try {
      const res = await setup2FA();
      setQrCode(res.qr_code);
      setTotpUri(res.totp_uri);
      setBackupCodes(res.backup_codes);
      setStep("setup");
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      setError(axErr.response?.data?.detail || "Failed to start 2FA setup");
    } finally { setLoading(false); }
  };

  const handleConfirm = async () => {
    if (otpCode.length !== 6) { setError("Enter a valid 6-digit code"); return; }
    setError(""); setLoading(true);
    try {
      await confirm2FASetup(otpCode);
      await refreshUser();
      setStep("codes");
      setSuccess("Two-factor authentication enabled!");
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      setError(axErr.response?.data?.detail || "Invalid code");
    } finally { setLoading(false); }
  };

  const handleDisable = async () => {
    if (!confirm("Are you sure? This will remove 2FA from your account.")) return;
    setError(""); setLoading(true);
    try {
      await disable2FA();
      await refreshUser();
      setStep("idle");
      setSuccess("Two-factor authentication disabled");
      setQrCode(""); setTotpUri(""); setBackupCodes([]);
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      setError(axErr.response?.data?.detail || "Failed to disable 2FA");
    } finally { setLoading(false); }
  };

  const handleRegenCodes = async () => {
    setError(""); setLoading(true);
    try {
      const res = await regenerateBackupCodes();
      setBackupCodes(res.backup_codes);
      setStep("codes");
      setSuccess("Backup codes regenerated — save them now!");
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      setError(axErr.response?.data?.detail || "Failed to regenerate codes");
    } finally { setLoading(false); }
  };

  const copyAllCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 p-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-xl bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center">
            <Shield className="w-5 h-5 text-orange-600 dark:text-orange-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Two-Factor Authentication</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">Add an extra layer of security to your account</p>
          </div>
          <div className="ml-auto">
            {is2FAEnabled ? (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 text-sm font-medium">
                <ShieldCheck className="w-4 h-4" /> Enabled
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 text-sm font-medium">
                <ShieldOff className="w-4 h-4" /> Disabled
              </span>
            )}
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3 mt-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-400">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
          </div>
        )}
        {success && (
          <div className="flex items-center gap-2 p-3 mt-4 rounded-xl bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 text-sm text-emerald-700 dark:text-emerald-400">
            <Check className="w-4 h-4 flex-shrink-0" />{success}
          </div>
        )}

        {/* Idle — show enable or manage */}
        {step === "idle" && (
          <div className="mt-6 flex flex-wrap gap-3">
            {!is2FAEnabled ? (
              <button onClick={handleSetup} disabled={loading}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white text-sm font-medium shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-50 flex items-center gap-2 transition-all">
                {loading ? <Loader2 className="animate-spin w-4 h-4" /> : <Smartphone className="w-4 h-4" />}
                Enable 2FA
              </button>
            ) : (
              <>
                <button onClick={handleRegenCodes} disabled={loading}
                  className="px-5 py-2.5 rounded-xl bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2 transition-colors">
                  <RefreshCw className="w-4 h-4" /> Regenerate Backup Codes
                </button>
                <button onClick={handleDisable} disabled={loading}
                  className="px-5 py-2.5 rounded-xl bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 text-sm font-medium hover:bg-red-100 dark:hover:bg-red-900/40 disabled:opacity-50 flex items-center gap-2 transition-colors">
                  <ShieldOff className="w-4 h-4" /> Disable 2FA
                </button>
              </>
            )}
          </div>
        )}

        {/* Setup step — QR + code entry */}
        {step === "setup" && (
          <div className="mt-6 space-y-6">
            <div className="bg-slate-50 dark:bg-slate-900 rounded-xl p-6">
              <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-4">1. Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)</p>
              <div className="flex justify-center mb-4">
                <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-sm">
                  {qrCode && <img src={`data:image/png;base64,${qrCode}`} alt="2FA QR Code" width={200} height={200} />}
                </div>
              </div>
              {totpUri && (
                <p className="text-xs text-slate-400 text-center break-all">
                  <span className="font-medium text-slate-500">Manual key:</span>{" "}
                  <code className="bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded">{totpUri.match(/secret=([A-Z2-7]+)/)?.[1] ?? ""}</code>
                </p>
              )}
            </div>

            {backupCodes.length > 0 && (
              <div className="bg-amber-50 dark:bg-amber-900/20 rounded-xl p-6 border border-amber-200 dark:border-amber-800">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-300">🔑 Backup Codes — save these somewhere safe!</p>
                  <button onClick={copyAllCodes} className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400 hover:text-amber-800 transition-colors">
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? "Copied!" : "Copy all"}
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {backupCodes.map((code, i) => (
                    <code key={i} className="px-3 py-1.5 bg-white dark:bg-slate-800 rounded-lg text-sm font-mono text-amber-900 dark:text-amber-200 border border-amber-200 dark:border-amber-700 text-center">
                      {code}
                    </code>
                  ))}
                </div>
              </div>
            )}

            <div className="bg-slate-50 dark:bg-slate-900 rounded-xl p-6">
              <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">2. Enter the 6-digit code from your app to confirm</p>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="000000"
                  className="w-40 h-12 text-center text-xl font-mono tracking-[0.5em] rounded-xl border-2 border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-white transition-colors"
                />
                <button onClick={handleConfirm} disabled={loading || otpCode.length !== 6}
                  className="px-5 py-3 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-50 flex items-center gap-2 transition-all">
                  {loading ? <Loader2 className="animate-spin w-4 h-4" /> : <KeyRound className="w-4 h-4" />}
                  Verify &amp; Enable
                </button>
                <button onClick={() => { setStep("idle"); setError(""); }}
                  className="px-4 py-3 rounded-xl text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 border border-slate-200 dark:border-slate-700 transition-colors">
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Codes display (after enable or regen) */}
        {step === "codes" && (
          <div className="mt-6 space-y-4">
            {backupCodes.length > 0 && (
              <div className="bg-amber-50 dark:bg-amber-900/20 rounded-xl p-6 border border-amber-200 dark:border-amber-800">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-300">🔑 Your Backup Codes</p>
                  <button onClick={copyAllCodes} className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400 hover:text-amber-800 transition-colors">
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? "Copied!" : "Copy all"}
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {backupCodes.map((code, i) => (
                    <code key={i} className="px-3 py-1.5 bg-white dark:bg-slate-800 rounded-lg text-sm font-mono text-amber-900 dark:text-amber-200 border border-amber-200 dark:border-amber-700 text-center">
                      {code}
                    </code>
                  ))}
                </div>
                <p className="text-xs text-amber-600 dark:text-amber-500 mt-3">Each code can only be used once. Store them securely.</p>
              </div>
            )}
            <button onClick={() => { setStep("idle"); setSuccess(""); }}
              className="px-5 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm font-medium hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors">
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Organization Tab ── */
function OrganizationTab() {
  const { user, isAdmin } = useAuth();
  const { data: orgData, isLoading } = useQuery({
    queryKey: ["org-dashboard"],
    queryFn: fetchOrgDashboard,
  });

  const org = orgData ?? {};
  const orgName = org.organization_name ?? user?.organization_name ?? "—";
  const planTier = org.plan_tier ?? org.plan ?? "free";
  const usersUsed = org.users_count ?? org.total_users ?? 0;
  const usersMax = org.users_limit ?? org.max_users ?? 50;
  const reposUsed = org.repos_count ?? org.total_repos ?? 0;
  const reposMax = org.repos_limit ?? org.max_repos ?? 25;
  const createdAt = org.created_at ?? (user as any)?.created_at ?? null;

  const PLAN_BADGE: Record<string, string> = {
    free: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400",
    pro: "bg-orange-100 dark:bg-orange-950/50 text-orange-700 dark:text-orange-400",
    team: "bg-blue-100 dark:bg-blue-950/50 text-blue-700 dark:text-blue-400",
    enterprise: "bg-purple-100 dark:bg-purple-950/50 text-purple-700 dark:text-purple-400",
  };

  if (isLoading) return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 flex items-center justify-center py-16">
      <Loader2 className="animate-spin text-slate-400" size={24} />
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Organization Info */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-orange-50 dark:bg-orange-950/50">
            <Building2 className="text-orange-600 dark:text-orange-400" size={18} />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-white">Organization Details</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Information about your organization</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Organization Name</label>
            <p className="text-lg font-semibold text-slate-900 dark:text-white">{orgName}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Plan</label>
            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium capitalize ${PLAN_BADGE[planTier] ?? PLAN_BADGE.free}`}>
              <Crown size={13} />
              {planTier}
            </span>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Your Role</label>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium capitalize bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 ring-1 ring-orange-600/20">
              <Shield size={13} />
              {user?.role ?? "member"}
            </span>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Created</label>
            <div className="flex items-center gap-1.5 text-sm text-slate-900 dark:text-white">
              <Calendar size={14} className="text-slate-400" />
              {createdAt ? new Date(createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" }) : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* Usage Stats */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/50">
            <Activity className="text-blue-600 dark:text-blue-400" size={18} />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-white">Usage &amp; Limits</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Current resource usage against your plan limits</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Users usage */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                <Users size={15} className="text-orange-500" />
                Users
              </div>
              <span className="text-sm font-semibold text-slate-900 dark:text-white">{usersUsed} / {usersMax}</span>
            </div>
            <div className="h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${(usersUsed / usersMax) > 0.9 ? "bg-red-500" : "bg-orange-500"}`}
                style={{ width: `${Math.min((usersUsed / usersMax) * 100, 100)}%` }}
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">{Math.round((usersUsed / usersMax) * 100)}% used</p>
          </div>

          {/* Repos usage */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300">
                <Database size={15} className="text-blue-500" />
                Repositories
              </div>
              <span className="text-sm font-semibold text-slate-900 dark:text-white">{reposUsed} / {reposMax}</span>
            </div>
            <div className="h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${(reposUsed / reposMax) > 0.9 ? "bg-red-500" : "bg-blue-500"}`}
                style={{ width: `${Math.min((reposUsed / reposMax) * 100, 100)}%` }}
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">{Math.round((reposUsed / reposMax) * 100)}% used</p>
          </div>
        </div>
      </div>

      {/* Admin notice */}
      {!isAdmin && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50 text-sm text-amber-700 dark:text-amber-400">
          <AlertCircle size={16} />
          Only organization admins can modify these settings. Contact your admin for changes.
        </div>
      )}
    </div>
  );
}

/* ── Component ── */
export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabId>("ai-provider");
  const [selectedProvider, setSelectedProvider] = useState("openai");
  const [showKey, setShowKey] = useState(false);
  /* Dynamic field values — keyed by field key (api_key, base_url, model, api_version) */
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  /* Model select (separate since Azure uses the "model" field for deployment name) */
  const [model, setModel] = useState("");
  const [testResult, setTestResult] = useState<{
    status: "ok" | "error";
    latency_ms?: number;
    error?: string;
  } | null>(null);
  const [saveMessage, setSaveMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const { data: config, isLoading } = useQuery({
    queryKey: ["agent-config"],
    queryFn: getAgentConfig,
  });

  const providerMeta =
    PROVIDERS.find((p) => p.id === selectedProvider) || PROVIDERS[0];

  /* Whether this provider uses a model dropdown (not Azure — Azure's "model" field = deployment name, shown as a text input) */
  const hasModelDropdown = !providerMeta.fields.some((f) => f.key === "model");

  useEffect(() => {
    if (config) {
      const pid = config.provider || "openai";
      setSelectedProvider(pid);
      setModel(config.model || "");
      setFieldValues({
        base_url: config.base_url || "",
        api_version: config.api_version || "",
        model: config.model || "",
      });
    }
  }, [config]);

  useEffect(() => {
    if (hasModelDropdown && (!model || !providerMeta.models.includes(model))) {
      setModel(providerMeta.models[0]);
    }
  }, [selectedProvider, model, providerMeta.models, hasModelDropdown]);

  const setField = (key: string, value: string) =>
    setFieldValues((prev) => ({ ...prev, [key]: value }));

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Record<string, string | undefined> = {
        provider: selectedProvider,
        model: hasModelDropdown ? model : fieldValues.model,
      };
      if (fieldValues.api_key) body.api_key = fieldValues.api_key;
      if (fieldValues.base_url) body.base_url = fieldValues.base_url;
      if (fieldValues.api_version) body.api_version = fieldValues.api_version;
      return updateAgentConfig(body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-config"] });
      setSaveMessage({ type: "success", text: "Configuration saved successfully" });
      setFieldValues((prev) => ({ ...prev, api_key: "" }));
      setTimeout(() => setSaveMessage(null), 4000);
    },
    onError: (err: Error) => {
      setSaveMessage({
        type: "error",
        text: err.message || "Failed to save configuration",
      });
      setTimeout(() => setSaveMessage(null), 4000);
    },
  });

  const testMutation = useMutation({
    mutationFn: () => {
      const body: Record<string, string | undefined> = {
        provider: selectedProvider,
        model: hasModelDropdown ? model : fieldValues.model,
      };
      if (fieldValues.api_key) body.api_key = fieldValues.api_key;
      if (fieldValues.base_url) body.base_url = fieldValues.base_url;
      if (fieldValues.api_version) body.api_version = fieldValues.api_version;
      console.log("[TestConnection] sending body:", JSON.stringify(body));
      return testAgentConfig(body);
    },
    onSuccess: (data) => {
      console.log("[TestConnection] success response:", JSON.stringify(data));
      setTestResult({
        status: data.ok ? "ok" : "error",
        latency_ms: data.latency_ms,
        error: data.error,
      });
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
      const detail = axiosErr?.response?.data?.detail || axiosErr?.message || "Connection test failed";
      console.error("[TestConnection] error:", detail, err);
      setTestResult({ status: "error", error: detail });
    },
  });

  const handleSelectProvider = (id: string) => {
    setSelectedProvider(id);
    setFieldValues({});
    setModel("");
    setTestResult(null);
    setSaveMessage(null);
  };

  return (
    <PageLayout
      title="Settings"
      subtitle="Configure AI providers and platform preferences"
      icon={Settings}
    >
      {/* ── Tab Navigation ── */}
      <div className="border-b border-slate-200 dark:border-slate-800 mb-8">
        <nav className="flex gap-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-3 text-sm font-medium rounded-t-xl transition-colors relative ${
                activeTab === tab.id
                  ? "text-orange-600 dark:text-orange-400 bg-white dark:bg-slate-900 border border-b-0 border-slate-200 dark:border-slate-800"
                  : "text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
            >
              {tab.label}
              {activeTab === tab.id && (
                <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-orange-600 dark:bg-orange-400" />
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── AI Provider Tab ── */}
      {activeTab === "ai-provider" && (
        <div className="space-y-8">
          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="animate-spin text-slate-400" size={28} />
            </div>
          ) : (
            <>
              {/* Provider Selection Cards */}
              <div>
                <h2 className="text-base font-semibold text-slate-900 dark:text-white mb-4">
                  Select Provider
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                  {PROVIDERS.map((provider) => {
                    const isSelected = selectedProvider === provider.id;
                    return (
                      <button
                        key={provider.id}
                        onClick={() => handleSelectProvider(provider.id)}
                        className={`text-left rounded-2xl border-2 p-5 transition-all ${
                          isSelected
                            ? `${provider.borderSelected} ${provider.bgSelected}`
                            : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-slate-300 dark:hover:border-slate-700"
                        }`}
                      >
                        <div
                          className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${
                            isSelected
                              ? "bg-orange-100 dark:bg-orange-500/20 text-orange-600 dark:text-orange-400"
                              : `bg-slate-100 dark:bg-slate-800 ${provider.color}`
                          }`}
                        >
                          {provider.icon}
                        </div>
                        <p className="font-semibold text-slate-900 dark:text-white text-sm">
                          {provider.label}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                          {provider.description}
                        </p>
                        {isSelected && (
                          <div className="mt-3 flex items-center gap-1.5 text-xs font-medium text-orange-600 dark:text-orange-400">
                            <Check size={14} />
                            Selected
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Configuration Form */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                <h2 className="text-base font-semibold text-slate-900 dark:text-white mb-6">
                  {providerMeta.label} Configuration
                </h2>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Dynamic provider fields */}
                  {providerMeta.fields.map((field) => {
                    const isPassword = field.type === "password";
                    const isWide = isPassword; // API key spans full width
                    const value = fieldValues[field.key] || "";
                    const placeholder =
                      field.key === "api_key" && config?.provider === selectedProvider && config?.has_api_key
                        ? "••••••••  (leave blank to keep existing)"
                        : field.placeholder;

                    return (
                      <div key={field.key} className={isWide ? "md:col-span-2" : ""}>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                          {field.label}
                          {field.required && (
                            <span className="text-red-400 ml-1">*</span>
                          )}
                        </label>
                        <div className="relative">
                          <input
                            type={isPassword && !showKey ? "password" : "text"}
                            value={value}
                            onChange={(e) => setField(field.key, e.target.value)}
                            placeholder={placeholder}
                            className="w-full h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 pr-12 text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
                          />
                          {isPassword && (
                            <button
                              type="button"
                              onClick={() => setShowKey(!showKey)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition"
                            >
                              {showKey ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                          )}
                        </div>
                        {field.help && (
                          <p className="mt-1.5 text-xs text-slate-400 dark:text-slate-500">
                            {field.help}
                          </p>
                        )}
                      </div>
                    );
                  })}

                  {/* Model dropdown — only for providers that don't define model as a text field */}
                  {hasModelDropdown && (
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                        Model
                      </label>
                      <div className="relative">
                        <select
                          value={model}
                          onChange={(e) => setModel(e.target.value)}
                          className="w-full h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 pr-10 text-sm text-slate-900 dark:text-white appearance-none focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
                        >
                          {providerMeta.models.map((m) => (
                            <option key={m} value={m}>
                              {m}
                            </option>
                          ))}
                        </select>
                        <ChevronDown
                          size={16}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none"
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Test Result Banner */}
                {testResult && (
                  <div
                    className={`mt-6 flex items-center gap-3 rounded-xl px-4 py-3 text-sm ${
                      testResult.status === "ok"
                        ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20"
                        : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20"
                    }`}
                  >
                    {testResult.status === "ok" ? (
                      <>
                        <Check size={18} className="shrink-0" />
                        <span>
                          Connection successful — latency{" "}
                          <span className="font-semibold">
                            {testResult.latency_ms}ms
                          </span>
                        </span>
                      </>
                    ) : (
                      <>
                        <X size={18} className="shrink-0" />
                        <span>{testResult.error || "Connection failed"}</span>
                      </>
                    )}
                  </div>
                )}

                {/* Save Message Banner */}
                {saveMessage && (
                  <div
                    className={`mt-4 flex items-center gap-3 rounded-xl px-4 py-3 text-sm ${
                      saveMessage.type === "success"
                        ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20"
                        : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20"
                    }`}
                  >
                    {saveMessage.type === "success" ? (
                      <Check size={18} className="shrink-0" />
                    ) : (
                      <X size={18} className="shrink-0" />
                    )}
                    <span>{saveMessage.text}</span>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex items-center gap-3 mt-8">
                  <button
                    onClick={() => {
                      setTestResult(null);
                      testMutation.mutate();
                    }}
                    disabled={testMutation.isPending}
                    className="h-12 px-6 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition disabled:opacity-50 flex items-center gap-2"
                  >
                    {testMutation.isPending ? (
                      <Loader2 size={16} className="animate-spin" />
                    ) : (
                      <Sparkles size={16} />
                    )}
                    Test Connection
                  </button>
                  <button
                    onClick={() => {
                      setSaveMessage(null);
                      saveMutation.mutate();
                    }}
                    disabled={saveMutation.isPending}
                    className="h-12 px-6 rounded-xl bg-orange-600 hover:bg-orange-700 text-white text-sm font-semibold transition disabled:opacity-50 flex items-center gap-2"
                  >
                    {saveMutation.isPending ? (
                      <Loader2 size={16} className="animate-spin" />
                    ) : (
                      <Check size={16} />
                    )}
                    Save Configuration
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── General Tab ── */}
      {activeTab === "general" && <GeneralSettingsTab />}

      {/* ── Notifications Tab ── */}
      {activeTab === "notifications" && <NotificationPrefsTab />}

      {/* ── Security Tab ── */}
      {activeTab === "security" && <SecurityTab />}
      {activeTab === "organization" && <OrganizationTab />}
    </PageLayout>
  );
}
