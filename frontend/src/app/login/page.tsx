"use client";

import React, { Suspense, useState, useRef, useEffect, useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import { useAuth } from "@/lib/auth";
import { checkFirstRunSetup, API_URL } from "@/lib/api";
import {
  Shield,
  Eye,
  EyeOff,
  AlertCircle,
  Cloud,
  Lock,
  Zap,
  Loader2,
  Smartphone,
  KeyRound,
  Copy,
  Check,
  ArrowLeft,
  Mail,
} from "lucide-react";

const FEATURES = [
  { icon: Cloud, label: "Multi-Cloud Security", desc: "AWS, Azure, GCP scanning in one unified view" },
  { icon: Zap, label: "Real-Time Scanning", desc: "14-stage enterprise security pipeline" },
  { icon: Lock, label: "Self-Hosted & Private", desc: "Your data never leaves your infrastructure" },
];

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center bg-slate-50"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" /></div>}>
      <LoginContent />
    </Suspense>
  );
}

function LoginContent() {
  const { login, mfaChallenge, verifyMfa, clearMfa } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const justRegistered = searchParams.get("registered") === "true";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [remember, setRemember] = useState(false);

  // Forgot password state
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotLoading, setForgotLoading] = useState(false);
  const [forgotSuccess, setForgotSuccess] = useState(false);
  const [forgotError, setForgotError] = useState("");

  // 2FA state
  const [otpDigits, setOtpDigits] = useState<string[]>(["", "", "", "", "", ""]);
  const otpRefs = useRef<(HTMLInputElement | null)[]>([]);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [mfaVerifying, setMfaVerifying] = useState(false);
  const verifyingRef = useRef(false);

  // Redirect to first-run setup if no admin exists yet
  useEffect(() => {
    checkFirstRunSetup()
      .then((s) => { if (!s.is_setup_complete) router.replace("/first-run"); })
      .catch(() => {});
  }, [router]);

  // After MFA challenge, redirect to dashboard on successful verify
  useEffect(() => {
    if (!mfaChallenge) return;
  }, [mfaChallenge]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const needsMfa = await login(email, password, remember);
      if (!needsMfa) {
        router.push("/dashboard");
      }
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      const msg = axErr.response?.data?.detail || (err instanceof Error ? err.message : "Invalid email or password");
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError("");
    setForgotLoading(true);
    try {
      await fetch(`${API_URL}/api/v1/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: forgotEmail }),
      });
      setForgotSuccess(true);
    } catch {
      setForgotError("Something went wrong. Please try again.");
    } finally {
      setForgotLoading(false);
    }
  };

  const handleOtpChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newDigits = [...otpDigits];
    newDigits[index] = value.slice(-1);
    setOtpDigits(newDigits);
    if (value && index < 5) otpRefs.current[index + 1]?.focus();
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !otpDigits[index] && index > 0) {
      otpRefs.current[index - 1]?.focus();
    }
  };

  const handleOtpPaste = (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (text.length === 6) {
      setOtpDigits(text.split(""));
      otpRefs.current[5]?.focus();
      e.preventDefault();
    }
  };

  const handleVerifyOtp = async () => {
    // Ref-based guard prevents double-submit even if React state hasn't flushed yet
    if (verifyingRef.current) return;
    const code = otpDigits.join("");
    if (code.length !== 6) { setError("Enter all 6 digits"); return; }
    verifyingRef.current = true;
    setMfaVerifying(true);
    setError("");
    setLoading(true);
    try {
      await verifyMfa(code, remember);
      router.push("/dashboard");
    } catch (err: unknown) {
      const axErr = err as { response?: { data?: { detail?: string } } };
      setError(axErr.response?.data?.detail || "Invalid code — please try again");
      setOtpDigits(["", "", "", "", "", ""]);
      otpRefs.current[0]?.focus();
    } finally {
      verifyingRef.current = false;
      setMfaVerifying(false);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      {/* Left Branding Panel */}
      <div className="hidden lg:flex lg:w-[45%] relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex-col justify-center px-16 overflow-hidden">
        {/* Decorative elements */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-orange-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-orange-500/5 rounded-full blur-2xl" />

        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-8">
            <img src="/logo.svg" alt="GuardNous" className="w-14 h-14 drop-shadow-[0_4px_12px_rgba(249,115,22,0.35)]" />
            <div>
              <h1 className="text-3xl font-bold text-white">GuardNous</h1>
              <p className="text-sm text-slate-400">Enterprise Security Platform</p>
            </div>
          </div>

          <p className="text-lg text-slate-300 leading-relaxed mb-12 max-w-md">
            Comprehensive infrastructure security scanning with CVE intelligence, compliance monitoring, and real-time threat detection.
          </p>

          <div className="space-y-6">
            {FEATURES.map((f) => {
              const Icon = f.icon;
              return (
                <div key={f.label} className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-5 h-5 text-orange-400" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold">{f.label}</h3>
                    <p className="text-sm text-slate-400">{f.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Bottom gradient bar */}
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-orange-500 via-orange-400 to-amber-500" />
      </div>

      {/* Right Panel */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 bg-slate-50 dark:bg-slate-900">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 justify-center mb-10">
            <img src="/logo.svg" alt="GuardNous" className="w-12 h-12 drop-shadow-[0_4px_12px_rgba(249,115,22,0.35)]" />
            <h1 className="text-2xl font-bold text-slate-800 dark:text-white">GuardNous</h1>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-xl shadow-slate-200/50 dark:shadow-slate-900/50 p-8">

            {/* Registration success banner */}
            {justRegistered && (
              <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 text-sm text-emerald-700 dark:text-emerald-400">
                <Check className="w-4 h-4 flex-shrink-0" />
                Organization created successfully! Sign in with your credentials.
              </div>
            )}

            {/* ── MFA SETUP REQUIRED (org enforced, first time) ── */}
            {mfaChallenge?.mfa_setup_required ? (
              <>
                <div className="mb-6">
                  <div className="flex items-center gap-2 mb-2">
                    <Smartphone className="w-6 h-6 text-orange-500" />
                    <h2 className="text-2xl font-bold text-slate-800 dark:text-white">Set Up 2FA</h2>
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Your organization requires two-factor authentication. Scan the QR code with your authenticator app.</p>
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-400">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                  </div>
                )}

                {mfaChallenge.qr_code && (
                  <div className="flex justify-center mb-4">
                    <div className="p-3 bg-white rounded-xl border border-slate-200">
                      <img src={`data:image/png;base64,${mfaChallenge.qr_code}`} alt="2FA QR Code" width={200} height={200} />
                    </div>
                  </div>
                )}

                {mfaChallenge.totp_uri && (
                  <p className="text-xs text-slate-400 text-center mb-6 break-all">
                    <span className="font-medium text-slate-500">Manual key:</span>{" "}
                    {mfaChallenge.totp_uri.match(/secret=([A-Z2-7]+)/)?.[1] ?? ""}
                  </p>
                )}

                <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 text-center">Enter the 6-digit code from your app</p>
                <div className="flex justify-center gap-2 mb-6" onPaste={handleOtpPaste}>
                  {otpDigits.map((d, i) => (
                    <input
                      key={i}
                      ref={(el) => { otpRefs.current[i] = el; }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={d}
                      onChange={(e) => handleOtpChange(i, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(i, e)}
                      className="w-12 h-14 text-center text-xl font-bold rounded-xl border-2 border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-white transition-colors"
                    />
                  ))}
                </div>

                <button
                  onClick={handleVerifyOtp}
                  disabled={loading || mfaVerifying || otpDigits.join("").length !== 6}
                  className="w-full h-12 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-60 transition-all flex items-center justify-center gap-2"
                >
                  {loading || mfaVerifying ? <Loader2 className="w-5 h-5 animate-spin" /> : <><KeyRound className="w-4 h-4" /> Verify &amp; Sign In</>}
                </button>
              </>

            ) : mfaChallenge?.mfa_required ? (
              /* ── MFA VERIFICATION (user has 2FA already set up) ── */
              <>
                <div className="mb-6">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-6 h-6 text-orange-500" />
                    <h2 className="text-2xl font-bold text-slate-800 dark:text-white">Two-Factor Auth</h2>
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Enter the 6-digit code from your authenticator app</p>
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-3 mb-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-400">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                  </div>
                )}

                <div className="flex justify-center gap-2 mb-6" onPaste={handleOtpPaste}>
                  {otpDigits.map((d, i) => (
                    <input
                      key={i}
                      ref={(el) => { otpRefs.current[i] = el; }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={d}
                      onChange={(e) => handleOtpChange(i, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(i, e)}
                      className="w-12 h-14 text-center text-xl font-bold rounded-xl border-2 border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-white transition-colors"
                    />
                  ))}
                </div>

                <button
                  onClick={handleVerifyOtp}
                  disabled={loading || mfaVerifying || otpDigits.join("").length !== 6}
                  className="w-full h-12 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-60 transition-all flex items-center justify-center gap-2 mb-4"
                >
                  {loading || mfaVerifying ? <Loader2 className="w-5 h-5 animate-spin" /> : "Verify"}
                </button>

                <button
                  onClick={() => { clearMfa(); setError(""); setOtpDigits(["","","","","",""]); }}
                  className="w-full text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
                >
                  ← Back to sign in
                </button>
              </>

            ) : !showForgotPassword ? (
              /* ── NORMAL LOGIN FORM ── */
              <>
                <div className="mb-8">
                  <h2 className="text-2xl font-bold text-slate-800 dark:text-white">Welcome back</h2>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Sign in to your account to continue</p>
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-3 mb-6 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-400">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />{error}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Email</label>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      placeholder="you@company.com"
                      className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-slate-200 transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Password</label>
                    <div className="relative">
                      <input
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        placeholder="••••••••"
                        className="w-full h-12 px-4 pr-12 rounded-xl border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-slate-200 transition-colors"
                      />
                      <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <div
                        onClick={() => setRemember(!remember)}
                        className={`w-5 h-5 rounded-md border-2 flex items-center justify-center transition-colors ${
                          remember ? "bg-orange-500 border-orange-500" : "border-slate-300 dark:border-slate-600"
                        }`}
                      >
                        {remember && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>}
                      </div>
                      <span className="text-sm text-slate-600 dark:text-slate-400">Remember me</span>
                    </label>
                    <button
                      type="button"
                      onClick={() => { setShowForgotPassword(true); setForgotEmail(email); setForgotSuccess(false); setForgotError(""); }}
                      className="text-sm text-orange-600 hover:text-orange-700 dark:text-orange-400 dark:hover:text-orange-300 font-medium transition-colors"
                    >
                      Forgot password?
                    </button>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full h-12 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-60 transition-all flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Sign in"}
                  </button>
                </form>
              </>
            ) : (
              /* ── FORGOT PASSWORD FORM ── */
              <div className="space-y-5">
                <button
                  onClick={() => setShowForgotPassword(false)}
                  className="flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" /> Back to login
                </button>

                <div className="text-center space-y-1">
                  <div className="w-12 h-12 rounded-full bg-orange-100 dark:bg-orange-500/20 flex items-center justify-center mx-auto mb-3">
                    <Mail className="w-6 h-6 text-orange-600 dark:text-orange-400" />
                  </div>
                  <h2 className="text-xl font-bold text-slate-800 dark:text-white">Reset your password</h2>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Enter your email and we&apos;ll send you a reset link
                  </p>
                </div>

                {forgotSuccess ? (
                  <div className="rounded-xl bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/30 p-4 text-center space-y-2">
                    <Check className="w-8 h-8 text-green-600 dark:text-green-400 mx-auto" />
                    <p className="text-sm font-medium text-green-800 dark:text-green-300">
                      If an account exists with that email, you&apos;ll receive a password reset link shortly.
                    </p>
                    <button
                      onClick={() => setShowForgotPassword(false)}
                      className="text-sm text-orange-600 hover:text-orange-700 dark:text-orange-400 dark:hover:text-orange-300 font-medium mt-2"
                    >
                      Return to login
                    </button>
                  </div>
                ) : (
                  <form onSubmit={handleForgotPassword} className="space-y-4">
                    {forgotError && (
                      <div className="flex items-center gap-2 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-xl px-4 py-3 text-red-700 dark:text-red-300 text-sm">
                        <AlertCircle className="w-4 h-4 shrink-0" /> {forgotError}
                      </div>
                    )}
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Email address</label>
                      <input
                        type="email"
                        value={forgotEmail}
                        onChange={(e) => setForgotEmail(e.target.value)}
                        required
                        autoFocus
                        placeholder="you@company.com"
                        className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-slate-200 transition-colors"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={forgotLoading}
                      className="w-full h-12 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-60 transition-all flex items-center justify-center gap-2"
                    >
                      {forgotLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Send reset link"}
                    </button>
                  </form>
                )}
              </div>
            )}
          </div>

          {!mfaChallenge && (
            <div className="text-center text-sm text-slate-500 dark:text-slate-400 mt-6 space-y-2">
              <p>
                Want to set up your organization?{" "}
                <Link href="/register" className="text-orange-500 hover:text-orange-600 font-medium transition-colors">
                  Create Tenant
                </Link>
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
