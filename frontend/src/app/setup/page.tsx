"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { completeSetup, getGeneralSettings } from "@/lib/api";
import {
  ShieldCheck,
  Globe,
  Cpu,
  Bell,
  Mail,
  CheckCircle,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  Clock,
} from "lucide-react";

const STEPS = [
  { id: 1, title: "Platform Identity", icon: Globe, desc: "Name & language" },
  { id: 2, title: "Date & Time", icon: Clock, desc: "Format & timezone" },
  { id: 3, title: "AI Provider", icon: Cpu, desc: "Connect your LLM" },
  { id: 4, title: "Notifications", icon: Bell, desc: "Alert preferences" },
  { id: 5, title: "Email (SMTP)", icon: Mail, desc: "Optional" },
];

const TIMEZONES = [
  "UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
  "Europe/London", "Europe/Berlin", "Europe/Paris", "Asia/Kolkata",
  "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney", "America/Sao_Paulo",
];

const DATE_FORMATS = [
  { value: "YYYY-MM-DD", label: "2026-10-25 (ISO)" },
  { value: "MM/DD/YYYY", label: "10/25/2026 (US)" },
  { value: "DD/MM/YYYY", label: "25/10/2026 (EU)" },
  { value: "DD-MMM-YYYY", label: "25-Oct-2026" },
];

const AI_PROVIDERS = [
  { id: "mock", label: "Built-in (offline)", description: "Local heuristic reasoning — no API key needed", requiresKey: false, defaultModel: "" },
  { id: "openai", label: "OpenAI", description: "GPT-4o, GPT-4o-mini", requiresKey: true, defaultModel: "gpt-4o-mini" },
  { id: "azure", label: "Azure OpenAI", description: "Enterprise Azure-hosted deployments", requiresKey: true, defaultModel: "" },
  { id: "anthropic", label: "Anthropic (Claude)", description: "Claude 3.5 Sonnet", requiresKey: true, defaultModel: "claude-3-5-sonnet-latest" },
  { id: "ollama", label: "Ollama (self-hosted)", description: "Local open models", requiresKey: false, defaultModel: "llama3.1" },
];

export default function SetupWizardPage() {
  const router = useRouter();
  const { user, refreshUser } = useAuth();
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  // Form state
  const [platformName, setPlatformName] = useState("GuardNous");
  const [language, setLanguage] = useState("en");
  const [timezone, setTimezone] = useState("UTC");
  const [dateFormat, setDateFormat] = useState("YYYY-MM-DD");

  const [aiProvider, setAiProvider] = useState("mock");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [aiBaseUrl, setAiBaseUrl] = useState("");

  const [emailDigest, setEmailDigest] = useState("daily");
  const [emailCritical, setEmailCritical] = useState(true);
  const [emailHigh, setEmailHigh] = useState(true);
  const [emailMedium, setEmailMedium] = useState(false);

  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState(587);
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [smtpFromEmail, setSmtpFromEmail] = useState("");
  const [smtpFromName, setSmtpFromName] = useState("");
  const [smtpUseTls, setSmtpUseTls] = useState(true);

  // If setup already completed, redirect to dashboard
  useEffect(() => {
    if (user && user.setup_completed !== false) {
      router.replace("/");
    }
  }, [user, router]);

  // Load existing general settings (in case of partial setup)
  useEffect(() => {
    getGeneralSettings()
      .then((s: Record<string, string>) => {
        if (s.platform_name && s.platform_name !== "GuardNous") setPlatformName(s.platform_name);
        if (s.timezone) setTimezone(s.timezone);
        if (s.date_format) setDateFormat(s.date_format);
        if (s.language) setLanguage(s.language);
      })
      .catch(() => {});
  }, []);

  const selectedProvider = AI_PROVIDERS.find((p) => p.id === aiProvider);

  const handleComplete = async () => {
    setSubmitting(true);
    setError("");
    try {
      await completeSetup({
        platform_name: platformName,
        timezone,
        date_format: dateFormat,
        language,
        ai_provider: aiProvider !== "mock" ? aiProvider : undefined,
        ai_api_key: aiApiKey || undefined,
        ai_model: aiModel || undefined,
        ai_base_url: aiBaseUrl || undefined,
        email_digest: emailDigest,
        email_critical: emailCritical,
        email_high: emailHigh,
        email_medium: emailMedium,
        smtp_host: smtpHost || undefined,
        smtp_port: smtpPort,
        smtp_user: smtpUser || undefined,
        smtp_password: smtpPassword || undefined,
        smtp_from_email: smtpFromEmail || undefined,
        smtp_from_name: smtpFromName || platformName,
        smtp_use_tls: smtpUseTls,
      });
      if (refreshUser) await refreshUser();
      router.replace("/");
    } catch (e: unknown) {
      const forbidden = (e as { response?: { status?: number } } | null)?.response?.status === 403;
      const msg = forbidden
        ? "You do not have permission to change this"
        : e instanceof Error ? e.message : "Setup failed";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const canProceed = () => {
    if (step === 1) return platformName.trim().length > 0;
    if (step === 3 && selectedProvider?.requiresKey) return aiApiKey.trim().length > 0;
    return true;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-orange-50/30 dark:from-gray-900 dark:to-gray-800 flex flex-col">
      {/* Header */}
      <header className="flex items-center gap-3 px-8 py-6">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center">
          <ShieldCheck size={24} className="text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-gray-900 dark:text-white">
            Welcome to {platformName || "GuardNous"}
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Let&apos;s configure your platform in a few quick steps
          </p>
        </div>
      </header>

      {/* Progress bar */}
      <div className="px-8">
        <div className="flex items-center gap-1 max-w-3xl mx-auto">
          {STEPS.map((s, i) => (
            <React.Fragment key={s.id}>
              <button
                onClick={() => setStep(s.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                  step === s.id
                    ? "bg-orange-500 text-white shadow-md"
                    : step > s.id
                    ? "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"
                    : "bg-gray-100 text-gray-400 dark:bg-gray-800 dark:text-gray-500"
                }`}
              >
                {step > s.id ? (
                  <CheckCircle size={16} />
                ) : (
                  <s.icon size={16} />
                )}
                <span className="hidden sm:inline">{s.title}</span>
                <span className="sm:hidden">{s.id}</span>
              </button>
              {i < STEPS.length - 1 && (
                <div
                  className={`flex-1 h-0.5 ${
                    step > s.id ? "bg-orange-400" : "bg-gray-200 dark:bg-gray-700"
                  }`}
                />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Step content */}
      <div className="flex-1 flex items-start justify-center px-8 py-8">
        <div className="w-full max-w-2xl bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-200 dark:border-gray-700 p-8">
          {/* Step 1 — Platform Identity */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Globe size={20} className="text-orange-500" />
                  Platform Identity
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Set your platform name and language. This appears across the UI, emails, and reports.
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Platform Name *
                </label>
                <input
                  type="text"
                  value={platformName}
                  onChange={(e) => setPlatformName(e.target.value)}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  placeholder="e.g. GuardNous, Acme Security"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Language
                </label>
                <select
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                >
                  <option value="en">English</option>
                  <option value="es">Español</option>
                  <option value="fr">Français</option>
                  <option value="de">Deutsch</option>
                  <option value="ja">日本語</option>
                  <option value="zh">中文</option>
                </select>
              </div>
            </div>
          )}

          {/* Step 2 — Date & Time */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Clock size={20} className="text-orange-500" />
                  Date &amp; Time Settings
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Configure how dates and times are displayed across the platform.
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Timezone
                </label>
                <select
                  value={timezone}
                  onChange={(e) => setTimezone(e.target.value)}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                >
                  {TIMEZONES.map((tz) => (
                    <option key={tz} value={tz}>{tz}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Date Format
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {DATE_FORMATS.map((df) => (
                    <button
                      key={df.value}
                      onClick={() => setDateFormat(df.value)}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        dateFormat === df.value
                          ? "border-orange-500 bg-orange-50 dark:bg-orange-900/20 ring-2 ring-orange-500"
                          : "border-gray-200 dark:border-gray-600 hover:border-orange-300"
                      }`}
                    >
                      <div className="text-sm font-medium text-gray-900 dark:text-white">{df.label}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{df.value}</div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 3 — AI Provider */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Cpu size={20} className="text-orange-500" />
                  AI Provider
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Connect an LLM provider for AI-powered security analysis. You can skip this and configure later.
                </p>
              </div>
              <div className="grid gap-3">
                {AI_PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => {
                      setAiProvider(p.id);
                      if (p.defaultModel) setAiModel(p.defaultModel);
                    }}
                    className={`p-4 rounded-lg border text-left transition-all ${
                      aiProvider === p.id
                        ? "border-orange-500 bg-orange-50 dark:bg-orange-900/20 ring-2 ring-orange-500"
                        : "border-gray-200 dark:border-gray-600 hover:border-orange-300"
                    }`}
                  >
                    <div className="font-medium text-gray-900 dark:text-white">{p.label}</div>
                    <div className="text-xs text-gray-500 mt-0.5">{p.description}</div>
                  </button>
                ))}
              </div>
              {selectedProvider?.requiresKey && (
                <div className="space-y-4 pt-2 border-t border-gray-100 dark:border-gray-700">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      API Key *
                    </label>
                    <input
                      type="password"
                      value={aiApiKey}
                      onChange={(e) => setAiApiKey(e.target.value)}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                      placeholder="sk-..."
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Model
                      </label>
                      <input
                        type="text"
                        value={aiModel}
                        onChange={(e) => setAiModel(e.target.value)}
                        className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                        placeholder={selectedProvider.defaultModel || "model name"}
                      />
                    </div>
                    {(aiProvider === "openai" || aiProvider === "azure" || aiProvider === "ollama") && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                          Base URL
                        </label>
                        <input
                          type="text"
                          value={aiBaseUrl}
                          onChange={(e) => setAiBaseUrl(e.target.value)}
                          className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                          placeholder="https://api.openai.com/v1"
                        />
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4 — Notifications */}
          {step === 4 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Bell size={20} className="text-orange-500" />
                  Notification Preferences
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Choose which severity levels trigger email alerts and how often you receive digests.
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email Digest Frequency
                </label>
                <select
                  value={emailDigest}
                  onChange={(e) => setEmailDigest(e.target.value)}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                >
                  <option value="realtime">Real-time (every finding)</option>
                  <option value="daily">Daily digest</option>
                  <option value="weekly">Weekly digest</option>
                  <option value="off">Off</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                  Email alert severity levels
                </label>
                <div className="space-y-3">
                  {[
                    { label: "Critical", desc: "Immediate threats, active exploits", value: emailCritical, setter: setEmailCritical, dot: "bg-red-500" },
                    { label: "High", desc: "Significant vulnerabilities", value: emailHigh, setter: setEmailHigh, dot: "bg-orange-500" },
                    { label: "Medium", desc: "Misconfigurations, best-practice violations", value: emailMedium, setter: setEmailMedium, dot: "bg-yellow-500" },
                  ].map((item) => (
                    <label
                      key={item.label}
                      className="flex items-center justify-between p-3 rounded-lg border border-gray-200 dark:border-gray-600 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50"
                    >
                      <div className="flex items-start gap-2">
                        <span className={`inline-block w-2 h-2 rounded-full mt-1.5 ${item.dot}`} />
                        <div>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">{item.label}</span>
                          <p className="text-xs text-gray-500">{item.desc}</p>
                        </div>
                      </div>
                      <input
                        type="checkbox"
                        checked={item.value}
                        onChange={(e) => item.setter(e.target.checked)}
                        className="rounded border-gray-300 text-orange-500 focus:ring-orange-500 h-4 w-4"
                      />
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 5 — SMTP */}
          {step === 5 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <Mail size={20} className="text-orange-500" />
                  Email Delivery (SMTP)
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Optional — configure SMTP to send email reports, alerts, and user invitations.
                  You can skip this and set it up later in Settings.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">SMTP Host</label>
                  <input type="text" value={smtpHost} onChange={(e) => setSmtpHost(e.target.value)}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                    placeholder="smtp.gmail.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Port</label>
                  <input type="number" value={smtpPort} onChange={(e) => setSmtpPort(Number(e.target.value))}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Username</label>
                  <input type="text" value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                    placeholder="user@company.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Password</label>
                  <input type="password" value={smtpPassword} onChange={(e) => setSmtpPassword(e.target.value)}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">From Email</label>
                  <input type="email" value={smtpFromEmail} onChange={(e) => setSmtpFromEmail(e.target.value)}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                    placeholder="noreply@company.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">From Name</label>
                  <input type="text" value={smtpFromName} onChange={(e) => setSmtpFromName(e.target.value)}
                    className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500"
                    placeholder={platformName} />
                </div>
                <div className="col-span-2">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={smtpUseTls} onChange={(e) => setSmtpUseTls(e.target.checked)}
                      className="rounded border-gray-300 text-orange-500 focus:ring-orange-500 h-4 w-4" />
                    <span className="text-sm text-gray-700 dark:text-gray-300">Use TLS encryption</span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              {error}
            </div>
          )}

          {/* Navigation */}
          <div className="flex items-center justify-between mt-8 pt-6 border-t border-gray-100 dark:border-gray-700">
            <button
              onClick={() => setStep(Math.max(1, step - 1))}
              disabled={step === 1}
              className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ArrowLeft size={16} />
              Back
            </button>

            <div className="flex items-center gap-3">
              {step < STEPS.length ? (
                <>
                  {step >= 3 && (
                    <button
                      onClick={() => setStep(step + 1)}
                      className="text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                    >
                      Skip
                    </button>
                  )}
                  <button
                    onClick={() => setStep(step + 1)}
                    disabled={!canProceed()}
                    className="flex items-center gap-1 px-5 py-2.5 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg shadow-sm disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    Next
                    <ArrowRight size={16} />
                  </button>
                </>
              ) : (
                <button
                  onClick={handleComplete}
                  disabled={submitting}
                  className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white text-sm font-semibold rounded-lg shadow-md disabled:opacity-50 transition-all"
                >
                  {submitting ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                      Saving…
                    </>
                  ) : (
                    <>
                      <Sparkles size={16} />
                      Complete Setup
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
