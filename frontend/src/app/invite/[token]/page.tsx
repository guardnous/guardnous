"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import Link from "next/link";
import api from "@/lib/api";
import {
  Shield,
  AlertCircle,
  CheckCircle,
  Eye,
  EyeOff,
  UserPlus,
  Building2,
  Lock,
  Sparkles,
  Users,
  Loader2,
} from "lucide-react";

interface InviteData {
  email: string;
  full_name: string;
  role: string;
  tenant_name: string;
  organization_name: string;
  expires_at: string;
}

const BENEFITS = [
  { icon: UserPlus, label: "Seamless Onboarding", desc: "Pre-configured role & permissions from day one" },
  { icon: Building2, label: "Team Workspace", desc: "Collaborate within your organization's secure tenancy" },
  { icon: Lock, label: "Enterprise Security", desc: "Zero-trust architecture with end-to-end encryption" },
  { icon: Users, label: "Role-Based Access", desc: "Granular permissions tailored to your responsibilities" },
  { icon: Sparkles, label: "Instant Insights", desc: "Access dashboards, scans & reports immediately" },
];

const formatRole = (slug: string) =>
  slug
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

const getPasswordStrength = (pw: string): { score: number; label: string; color: string } => {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  if (score <= 1) return { score, label: "Weak", color: "bg-red-500" };
  if (score <= 2) return { score, label: "Fair", color: "bg-orange-500" };
  if (score <= 3) return { score, label: "Good", color: "bg-yellow-500" };
  if (score <= 4) return { score, label: "Strong", color: "bg-emerald-500" };
  return { score, label: "Excellent", color: "bg-emerald-600" };
};

export default function InviteAcceptPage() {
  const router = useRouter();
  const params = useParams();
  const token = params.token as string;

  const [invite, setInvite] = useState<InviteData | null>(null);
  const [pageLoading, setPageLoading] = useState(true);
  const [pageError, setPageError] = useState("");

  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  const fetchInvite = useCallback(async () => {
    try {
      const res = await api.get(`/users/invite/${token}`);
      const data: InviteData = res.data;
      setInvite(data);
      if (data.full_name) setFullName(data.full_name);
    } catch (err: unknown) {
      if (
        err &&
        typeof err === "object" &&
        "response" in err &&
        (err as { response: { status: number } }).response?.status === 410
      ) {
        setPageError("This invitation has expired. Please ask your admin to send a new one.");
      } else {
        setPageError("This invitation link is invalid or has already been used.");
      }
    } finally {
      setPageLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchInvite();
  }, [fetchInvite]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    if (!fullName.trim()) {
      setFormError("Full name is required");
      return;
    }
    if (password.length < 8) {
      setFormError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirmPassword) {
      setFormError("Passwords do not match");
      return;
    }

    setSubmitting(true);
    try {
      await api.post("/users/invite/accept", {
        token,
        password,
        full_name: fullName.trim(),
      });
      setSuccess(true);
      setTimeout(() => router.push("/login"), 2000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to accept invitation. Please try again.";
      setFormError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const strength = getPasswordStrength(password);

  if (pageLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <Loader2 className="w-10 h-10 text-orange-500 animate-spin mx-auto mb-4" />
          <p className="text-slate-500 text-sm">Validating your invitation…</p>
        </div>
      </div>
    );
  }

  if (pageError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 px-6">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-xl border border-slate-200 p-8 text-center">
          <div className="w-16 h-16 rounded-full bg-red-50 flex items-center justify-center mx-auto mb-5">
            <AlertCircle className="w-8 h-8 text-red-500" />
          </div>
          <h2 className="text-xl font-bold text-slate-800 mb-2">Invitation Unavailable</h2>
          <p className="text-slate-500 text-sm mb-6">{pageError}</p>
          <Link
            href="/login"
            className="inline-flex items-center justify-center h-11 px-6 rounded-xl bg-orange-500 text-white text-sm font-medium hover:bg-orange-600 transition-colors"
          >
            Go to Login
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex">
      {/* Left Branding Panel */}
      <div className="hidden lg:flex lg:w-[45%] relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex-col justify-center px-16 overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-orange-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-orange-500/5 rounded-full blur-2xl" />

        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center shadow-xl shadow-orange-500/25">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">GuardNous</h1>
              <p className="text-sm text-slate-400">Enterprise Security Platform</p>
            </div>
          </div>

          <p className="text-lg text-slate-300 leading-relaxed mb-12 max-w-md">
            Welcome aboard! You&apos;ve been invited to join a team on GuardNous.
            Set up your account to start collaborating.
          </p>

          <div className="space-y-6">
            {BENEFITS.map((b) => {
              const Icon = b.icon;
              return (
                <div key={b.label} className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-white/10 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-5 h-5 text-orange-400" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold">{b.label}</h3>
                    <p className="text-sm text-slate-400">{b.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-orange-500 via-orange-400 to-amber-500" />
      </div>

      {/* Right Form Panel */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 bg-slate-50">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 justify-center mb-10">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center shadow-xl shadow-orange-500/25">
              <Shield className="w-7 h-7 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-slate-800">GuardNous</h1>
          </div>

          <div className="bg-white rounded-2xl border border-slate-200 shadow-xl shadow-slate-200/50 p-8">
            {success ? (
              <div className="text-center py-8 animate-fade-in">
                <div className="w-16 h-16 rounded-full bg-emerald-50 flex items-center justify-center mx-auto mb-5">
                  <CheckCircle className="w-8 h-8 text-emerald-500" />
                </div>
                <h2 className="text-2xl font-bold text-slate-800 mb-2">Account Created!</h2>
                <p className="text-slate-500 text-sm">Redirecting to login…</p>
              </div>
            ) : (
              <>
                <div className="mb-6">
                  <h2 className="text-2xl font-bold text-slate-800">Accept Invitation</h2>
                  <p className="text-sm text-slate-500 mt-1">
                    Set up your account to join the team
                  </p>
                </div>

                {/* Invitation details card */}
                {invite && (
                  <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 mb-6 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Team</span>
                      <span className="text-sm font-semibold text-slate-800">
                        {invite.organization_name}
                        {invite.tenant_name && (
                          <span className="text-slate-400 font-normal"> / {invite.tenant_name}</span>
                        )}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Role</span>
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-orange-100 text-orange-700">
                        {formatRole(invite.role)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Email</span>
                      <span className="text-sm text-slate-700">{invite.email}</span>
                    </div>
                  </div>
                )}

                {formError && (
                  <div className="flex items-center gap-2 p-3 mb-5 rounded-xl bg-red-50 border border-red-200 text-sm text-red-700">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    {formError}
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-5">
                  {/* Full Name */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Full Name
                    </label>
                    <input
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      required
                      placeholder="Jane Doe"
                      className="w-full px-4 h-12 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 text-slate-800 transition-colors"
                    />
                  </div>

                  {/* Email (read-only) */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Email
                    </label>
                    <input
                      type="email"
                      value={invite?.email ?? ""}
                      disabled
                      className="w-full px-4 h-12 rounded-xl border border-slate-200 bg-slate-100 text-sm text-slate-500 cursor-not-allowed"
                    />
                  </div>

                  {/* Password */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        placeholder="••••••••"
                        className="w-full px-4 h-12 pr-12 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 text-slate-800 transition-colors"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                      >
                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                    {/* Strength meter */}
                    {password.length > 0 && (
                      <div className="mt-2">
                        <div className="flex gap-1">
                          {[1, 2, 3, 4, 5].map((i) => (
                            <div
                              key={i}
                              className={`h-1 flex-1 rounded-full transition-colors ${
                                i <= strength.score ? strength.color : "bg-slate-200"
                              }`}
                            />
                          ))}
                        </div>
                        <p className="text-xs text-slate-500 mt-1">
                          Strength: <span className="font-medium">{strength.label}</span>
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Confirm Password */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <input
                        type={showConfirm ? "text" : "password"}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        placeholder="••••••••"
                        className="w-full px-4 h-12 pr-12 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 text-slate-800 transition-colors"
                      />
                      <button
                        type="button"
                        onClick={() => setShowConfirm(!showConfirm)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                      >
                        {showConfirm ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full h-12 rounded-xl bg-orange-500 text-white font-medium text-sm hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                  >
                    {submitting ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Creating account…
                      </>
                    ) : (
                      "Create Account & Join"
                    )}
                  </button>
                </form>

                <p className="mt-6 text-center text-sm text-slate-500">
                  Already have an account?{" "}
                  <Link href="/login" className="text-orange-500 hover:text-orange-600 font-medium transition-colors">
                    Sign in
                  </Link>
                </p>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
