"use client";

import React, { useState, useMemo, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import {
  Shield,
  AlertCircle,
  CheckCircle,
  Eye,
  EyeOff,
  Building2,
  Users,
  Lock,
  Fingerprint,
  Globe,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  Crown,
  Zap,
  Check,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const BENEFITS = [
  { icon: Building2, label: "Multi-Organization Architecture", desc: "Isolate teams with organization-level separation" },
  { icon: Users, label: "Enterprise RBAC", desc: "Granular roles, groups & permissions" },
  { icon: Lock, label: "Zero-Trust Security", desc: "End-to-end encrypted scanning" },
  { icon: Fingerprint, label: "SSO & MFA Ready", desc: "Okta, Azure AD, SAML 2.0" },
  { icon: Globe, label: "Global Compliance", desc: "SOC 2, ISO 27001, GDPR" },
];

const PLANS = [
  {
    id: "free",
    name: "Free",
    price: "$0",
    period: "forever",
    icon: Zap,
    features: ["Up to 5 repos", "Basic scanning", "Community support"],
    gradient: "from-slate-50 to-slate-100",
    border: "border-slate-200",
    badge: null,
  },
  {
    id: "professional",
    name: "Professional",
    price: "$49",
    period: "/month",
    icon: Sparkles,
    features: ["Unlimited repos", "Advanced CVE intel", "Priority support"],
    gradient: "from-orange-50 to-orange-100",
    border: "border-orange-300",
    badge: "Popular",
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Custom",
    period: "contact us",
    icon: Crown,
    features: ["SSO & SAML", "Dedicated CSM", "SLA guarantee"],
    gradient: "from-amber-50 to-orange-50",
    border: "border-amber-300",
    badge: null,
  },
] as const;

type PlanId = (typeof PLANS)[number]["id"];

const STEP_LABELS = ["Organization", "Admin Account", "Review & Create"] as const;

/* ------------------------------------------------------------------ */
/*  Password helpers                                                   */
/* ------------------------------------------------------------------ */

interface PwdCheck {
  label: string;
  met: boolean;
}

function getPasswordChecks(pw: string): PwdCheck[] {
  return [
    { label: "8+ characters", met: pw.length >= 8 },
    { label: "Uppercase letter", met: /[A-Z]/.test(pw) },
    { label: "Lowercase letter", met: /[a-z]/.test(pw) },
    { label: "Number", met: /\d/.test(pw) },
    { label: "Special character", met: /[^A-Za-z0-9]/.test(pw) },
  ];
}

function getStrength(checks: PwdCheck[]): { percent: number; label: string; color: string } {
  const met = checks.filter((c) => c.met).length;
  if (met <= 2) return { percent: 20, label: "Weak", color: "bg-red-500" };
  if (met <= 3) return { percent: 50, label: "Fair", color: "bg-amber-500" };
  if (met <= 4) return { percent: 75, label: "Good", color: "bg-orange-500" };
  return { percent: 100, label: "Strong", color: "bg-emerald-500" };
}

function extractDomain(email: string): string {
  const parts = email.split("@");
  return parts.length === 2 && parts[1].includes(".") ? parts[1] : "";
}

/* ------------------------------------------------------------------ */
/*  Axios error message extractor                                      */
/* ------------------------------------------------------------------ */

function parseApiError(err: unknown): string {
  if (
    typeof err === "object" &&
    err !== null &&
    "response" in err
  ) {
    const resp = (err as { response?: { data?: { detail?: string }; status?: number } }).response;
    const detail = resp?.data?.detail ?? "";
    const status = resp?.status ?? 0;
    if (status === 400 && /domain.*already/i.test(detail)) {
      const match = detail.match(/domain '([^']+)'/i);
      const d = match ? match[1] : "this domain";
      return `Organization for domain '${d}' already exists. Please ask your admin to invite you.`;
    }
    if (status === 400 && /email.*already|already.*registered/i.test(detail)) {
      return "This email is already registered. Try signing in instead.";
    }
    if (detail) return detail;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong. Please try again.";
}

/* ------------------------------------------------------------------ */
/*  Page Component                                                     */
/* ------------------------------------------------------------------ */

export default function RegisterPage() {
  const router = useRouter();

  /* ----- form state ----- */
  const [step, setStep] = useState(1);
  const [orgName, setOrgName] = useState("");
  const [selectedPlan, setSelectedPlan] = useState<PlanId>("free");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  /* ----- ui state ----- */
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [agreedToTerms, setAgreedToTerms] = useState(false);

  /* ----- domain (editable, auto-filled from email) ----- */
  const [domain, setDomain] = useState("");
  const [domainEdited, setDomainEdited] = useState(false);

  // Auto-fill domain from email unless user has manually edited it
  useEffect(() => {
    if (!domainEdited && email) {
      const extracted = extractDomain(email);
      if (extracted) setDomain(extracted);
    }
  }, [email, domainEdited]);

  /* ----- derived ----- */
  const pwdChecks = useMemo(() => getPasswordChecks(password), [password]);
  const pwdStrength = useMemo(() => getStrength(pwdChecks), [pwdChecks]);
  const allPwdMet = pwdChecks.every((c) => c.met);

  /* ----- navigation ----- */
  const goNext = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      if (step === 1) {
        if (!orgName.trim()) {
          setError("Organization name is required");
          return;
        }
        setStep(2);
      } else if (step === 2) {
        if (!fullName.trim() || !email.trim()) {
          setError("Full name and work email are required");
          return;
        }
        if (!allPwdMet) {
          setError("Password does not meet all requirements");
          return;
        }
        if (password !== confirmPassword) {
          setError("Passwords do not match");
          return;
        }
        setStep(3);
      }
    },
    [step, orgName, fullName, email, allPwdMet, password, confirmPassword],
  );

  const goBack = useCallback(() => {
    setError("");
    setStep((s) => Math.max(1, s - 1));
  }, []);

  /* ----- submit ----- */
  const handleCreate = useCallback(async () => {
    setError("");
    setLoading(true);
    try {
      await api.post("/auth/register", {
        email,
        password,
        full_name: fullName,
        organization_name: orgName,
        tenant_name: orgName,
        domain: domain || undefined,
      });

      setSuccess(true);

      // Redirect to login after a brief success message
      setTimeout(() => {
        router.push("/login?registered=true");
      }, 2000);
    } catch (err: unknown) {
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  }, [email, password, fullName, orgName, router]);

  /* ---------------------------------------------------------------- */
  /*  Input class helper                                               */
  /* ---------------------------------------------------------------- */

  const inputClass =
    "w-full h-12 px-4 rounded-xl border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition text-sm";

  /* ================================================================ */
  /*  RENDER                                                           */
  /* ================================================================ */

  return (
    <div className="min-h-screen grid grid-cols-1 lg:grid-cols-2">
      {/* ============================================================ */}
      {/*  LEFT PANEL — Features Showcase                               */}
      {/* ============================================================ */}
      <div className="hidden lg:flex relative bg-gradient-to-br from-slate-900 via-slate-800 to-orange-950 flex-col justify-center px-16 overflow-hidden">
        {/* Animated gradient blobs */}
        <div className="absolute top-[-120px] right-[-80px] w-[400px] h-[400px] bg-orange-500/15 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-[-80px] left-[-60px] w-[300px] h-[300px] bg-orange-600/10 rounded-full blur-2xl animate-pulse [animation-delay:2s]" />

        <div className="relative z-10">
          {/* Brand */}
          <div className="w-16 h-16 rounded-2xl bg-white/10 backdrop-blur-sm flex items-center justify-center mb-8 ring-1 ring-white/20">
            <Shield className="w-9 h-9 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">GuardNous</h1>
          <p className="text-lg text-orange-200 mb-12">
            Enterprise Cloud Security Platform
          </p>

          {/* Benefits */}
          <div className="space-y-5">
            {BENEFITS.map((b) => {
              const Icon = b.icon;
              return (
                <div key={b.label} className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-white/10 backdrop-blur-sm flex items-center justify-center shrink-0 ring-1 ring-white/10">
                    <Icon className="w-5 h-5 text-orange-300" />
                  </div>
                  <div>
                    <p className="text-white font-semibold text-sm">{b.label}</p>
                    <p className="text-slate-400 text-sm">{b.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Stats footer */}
          <div className="mt-14 pt-8 border-t border-white/10 flex items-center gap-8">
            <div>
              <p className="text-2xl font-bold text-white">Free</p>
              <p className="text-slate-400 text-xs">To Get Started</p>
            </div>
            <div className="w-px h-10 bg-white/10" />
            <div>
              <p className="text-2xl font-bold text-white">∞</p>
              <p className="text-slate-400 text-xs">Repos Supported</p>
            </div>
            <div className="w-px h-10 bg-white/10" />
            <div>
              <p className="text-2xl font-bold text-white">100%</p>
              <p className="text-slate-400 text-xs">Self-Hosted</p>
            </div>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/*  RIGHT PANEL — Wizard Form                                    */}
      {/* ============================================================ */}
      <div className="flex items-center justify-center bg-slate-50 px-6 py-12">
        <div className="w-full max-w-lg">
          {/* Mobile brand header */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-slate-900">GuardNous</span>
          </div>

          {/* Card */}
          <div className="bg-white rounded-2xl shadow-xl p-8">
            {/* ---- Step Indicator ---- */}
            <div className="flex items-center gap-2 mb-8">
              {STEP_LABELS.map((label, i) => {
                const num = i + 1;
                const isActive = step === num;
                const isDone = step > num;
                return (
                  <React.Fragment key={label}>
                    {i > 0 && (
                      <div
                        className={`flex-1 h-0.5 rounded transition-colors ${
                          isDone ? "bg-orange-500" : "bg-slate-200"
                        }`}
                      />
                    )}
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                          isDone
                            ? "bg-orange-500 text-white"
                            : isActive
                              ? "bg-orange-500 text-white ring-4 ring-orange-100"
                              : "bg-slate-100 text-slate-400"
                        }`}
                      >
                        {isDone ? <Check className="w-4 h-4" /> : num}
                      </span>
                      <span
                        className={`text-xs font-medium hidden sm:inline ${
                          isActive || isDone ? "text-slate-700" : "text-slate-400"
                        }`}
                      >
                        {label}
                      </span>
                    </div>
                  </React.Fragment>
                );
              })}
            </div>

            {/* ---- Error Banner ---- */}
            {error && (
              <div className="flex items-start gap-2.5 p-3.5 mb-6 rounded-xl bg-red-50 text-red-700 text-sm border border-red-100">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* ========================================================== */}
            {/*  STEP 1 — Organization Setup                                */}
            {/* ========================================================== */}
            {step === 1 && (
              <form onSubmit={goNext} className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-slate-900 mb-1">
                    Create Your Organization
                  </h2>
                  <p className="text-slate-500 text-sm">
                    Set up a dedicated workspace for your team
                  </p>
                </div>

                {/* Org name */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">
                    Organization Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    required
                    placeholder="Acme Corp"
                    className={inputClass}
                    autoFocus
                  />
                </div>

                {/* Domain field (editable, auto-filled from email) */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">
                    Domain
                  </label>
                  <div className="relative">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => { setDomain(e.target.value); setDomainEdited(true); }}
                      placeholder="example.com"
                      className={inputClass + " pl-10"}
                    />
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    Auto-filled from admin email. Edit if your organization uses a different domain.
                  </p>
                </div>

                {/* Plan selection */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-3">
                    Select a Plan
                  </label>
                  <div className="grid grid-cols-3 gap-3">
                    {PLANS.map((plan) => {
                      const Icon = plan.icon;
                      const active = selectedPlan === plan.id;
                      return (
                        <button
                          type="button"
                          key={plan.id}
                          onClick={() => setSelectedPlan(plan.id)}
                          className={`relative p-3 rounded-xl border-2 text-left transition-all ${
                            active
                              ? "border-orange-500 bg-orange-50 ring-2 ring-orange-200"
                              : `${plan.border} bg-gradient-to-b ${plan.gradient} hover:border-orange-300`
                          }`}
                        >
                          {plan.badge && (
                            <span className="absolute -top-2.5 left-1/2 -translate-x-1/2 text-[10px] font-bold bg-orange-500 text-white px-2.5 py-0.5 rounded-full">
                              {plan.badge}
                            </span>
                          )}
                          <Icon className={`w-5 h-5 mb-2 ${active ? "text-orange-500" : "text-slate-500"}`} />
                          <p className="text-sm font-semibold text-slate-900">{plan.name}</p>
                          <p className="text-xs text-slate-500">
                            {plan.price}{" "}
                            <span className="text-slate-400">{plan.period}</span>
                          </p>
                        </button>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-xs text-slate-400">
                    All plans start free during beta. Upgrade anytime.
                  </p>
                </div>

                <button
                  type="submit"
                  className="w-full h-12 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  Continue
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>
            )}

            {/* ========================================================== */}
            {/*  STEP 2 — Admin Account                                     */}
            {/* ========================================================== */}
            {step === 2 && (
              <form onSubmit={goNext} className="space-y-5">
                <div>
                  <h2 className="text-2xl font-bold text-slate-900 mb-1">
                    Admin Account
                  </h2>
                  <p className="text-slate-500 text-sm">
                    You&apos;ll be the first admin of{" "}
                    <span className="font-medium text-slate-700">{orgName}</span>
                  </p>
                </div>

                {/* Full name */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">
                    Full Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    required
                    placeholder="Jane Doe"
                    className={inputClass}
                    autoFocus
                  />
                </div>

                {/* Work email */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">
                    Work Email <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="you@company.com"
                    className={inputClass}
                  />
                  {domain && (
                    <p className="mt-1.5 text-xs text-orange-500 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5" />
                      Domain claim: <span className="font-medium">{domain}</span>
                    </p>
                  )}
                </div>

                {/* Password */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">
                    Password <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      placeholder="Create a strong password"
                      className={`${inputClass} pr-11`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition"
                    >
                      {showPassword ? <EyeOff className="w-4.5 h-4.5" /> : <Eye className="w-4.5 h-4.5" />}
                    </button>
                  </div>

                  {/* Strength meter */}
                  {password.length > 0 && (
                    <div className="mt-3 space-y-2">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-slate-100 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-300 ${pwdStrength.color}`}
                            style={{ width: `${pwdStrength.percent}%` }}
                          />
                        </div>
                        <span className="text-xs font-medium text-slate-500 w-12 text-right">
                          {pwdStrength.label}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                        {pwdChecks.map((c) => (
                          <div key={c.label} className="flex items-center gap-1.5 text-xs">
                            {c.met ? (
                              <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                            ) : (
                              <div className="w-3.5 h-3.5 rounded-full border border-slate-300" />
                            )}
                            <span className={c.met ? "text-slate-600" : "text-slate-400"}>
                              {c.label}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Confirm password */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">
                    Confirm Password <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirm ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      placeholder="••••••••"
                      className={`${inputClass} pr-11`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirm((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition"
                    >
                      {showConfirm ? <EyeOff className="w-4.5 h-4.5" /> : <Eye className="w-4.5 h-4.5" />}
                    </button>
                  </div>
                  {confirmPassword.length > 0 && password !== confirmPassword && (
                    <p className="mt-1.5 text-xs text-red-500">Passwords do not match</p>
                  )}
                </div>

                {/* Nav buttons */}
                <div className="flex gap-3 pt-1">
                  <button
                    type="button"
                    onClick={goBack}
                    className="h-12 px-5 border border-slate-200 text-slate-700 font-medium rounded-xl transition-colors hover:bg-slate-50 flex items-center gap-2"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Back
                  </button>
                  <button
                    type="submit"
                    className="flex-1 h-12 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                  >
                    Continue
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </form>
            )}

            {/* ========================================================== */}
            {/*  STEP 3 — Review & Create  /  Success                       */}
            {/* ========================================================== */}
            {step === 3 && !success && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-slate-900 mb-1">
                    Review &amp; Create
                  </h2>
                  <p className="text-slate-500 text-sm">
                    Confirm your details before we set everything up
                  </p>
                </div>

                {/* Summary grid */}
                <div className="rounded-xl border border-slate-200 divide-y divide-slate-100 overflow-hidden">
                  <SummaryRow label="Organization" value={orgName} />
                  <SummaryRow label="Domain" value={domain || "—"} />
                  <SummaryRow
                    label="Plan"
                    value={PLANS.find((p) => p.id === selectedPlan)?.name ?? "Free"}
                  />
                  <SummaryRow label="Admin Name" value={fullName} />
                  <SummaryRow label="Admin Email" value={email} />
                </div>

                {/* Terms of Service checkbox */}
                <label className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={agreedToTerms}
                    onChange={(e) => setAgreedToTerms(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-slate-300 text-orange-500 focus:ring-orange-500 cursor-pointer"
                  />
                  <span className="text-sm text-slate-600 leading-snug">
                    I agree to the{" "}
                    <a href="/terms" className="text-orange-500 hover:text-orange-600 font-medium underline underline-offset-2">
                      Terms of Service
                    </a>{" "}
                    and{" "}
                    <a href="/privacy" className="text-orange-500 hover:text-orange-600 font-medium underline underline-offset-2">
                      Privacy Policy
                    </a>
                  </span>
                </label>

                {/* Nav buttons */}
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={goBack}
                    className="h-12 px-5 border border-slate-200 text-slate-700 font-medium rounded-xl transition-colors hover:bg-slate-50 flex items-center gap-2"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Back
                  </button>
                  <button
                    type="button"
                    onClick={handleCreate}
                    disabled={loading || !agreedToTerms}
                    className="flex-1 h-12 bg-orange-500 hover:bg-orange-600 disabled:opacity-60 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Creating…
                      </>
                    ) : (
                      <>
                        <Building2 className="w-4 h-4" />
                        Create Organization
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* ---------- Success State ---------- */}
            {step === 3 && success && (
              <div className="text-center py-6 space-y-6">
                {/* Confetti-style burst */}
                <div className="relative mx-auto w-20 h-20">
                  <div className="absolute inset-0 bg-emerald-100 rounded-full animate-ping opacity-30" />
                  <div className="relative w-20 h-20 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-full flex items-center justify-center shadow-lg shadow-emerald-500/25">
                    <CheckCircle className="w-10 h-10 text-white" />
                  </div>
                  {/* Decorative dots */}
                  <span className="absolute -top-2 -right-1 w-3 h-3 bg-amber-400 rounded-full animate-bounce [animation-delay:0.1s]" />
                  <span className="absolute -top-1 -left-2 w-2 h-2 bg-orange-400 rounded-full animate-bounce [animation-delay:0.3s]" />
                  <span className="absolute -bottom-1 -right-2 w-2.5 h-2.5 bg-pink-400 rounded-full animate-bounce [animation-delay:0.2s]" />
                  <span className="absolute -bottom-2 left-0 w-2 h-2 bg-sky-400 rounded-full animate-bounce [animation-delay:0.4s]" />
                </div>

                <div>
                  <h2 className="text-2xl font-bold text-slate-900 mb-2">
                    You&apos;re All Set! 🎉
                  </h2>
                  <p className="text-slate-500 text-sm">
                    <span className="font-medium text-slate-700">{orgName}</span>{" "}
                    has been created. Redirecting you to sign in…
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => router.push("/login?registered=true")}
                  className="w-full h-12 bg-orange-500 hover:bg-orange-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  Go to Sign In
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* ---- Footer links ---- */}
            {!success && (
              <div className="mt-6 space-y-2 text-center text-sm text-slate-500">
                <p>
                  Already have an account?{" "}
                  <Link
                    href="/login"
                    className="text-orange-500 hover:text-orange-600 font-medium"
                  >
                    Sign in
                  </Link>
                </p>
                <p>
                  Have an invite?{" "}
                  <Link
                    href="/invite"
                    className="text-orange-500 hover:text-orange-600 font-medium"
                  >
                    Accept invitation
                  </Link>
                </p>
              </div>
            )}
          </div>

          {/* Legal */}
          <p className="mt-6 text-center text-xs text-slate-400">
            By creating an organization you agree to our Terms of Service and
            Privacy Policy.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm font-medium text-slate-900">{value}</span>
    </div>
  );
}
