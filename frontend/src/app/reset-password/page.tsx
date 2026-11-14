"use client";

import React, { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Shield, Eye, EyeOff, AlertCircle, Loader2, Check } from "lucide-react";
import { API_URL } from "@/lib/api";

function ResetPasswordContent() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") || "";
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!token) {
      setError("Invalid or missing reset link. Please request a new one.");
      return;
    }

    if (password.length < 8) { setError("Password must be at least 8 characters"); return; }
    if (!/[A-Z]/.test(password)) { setError("Password must contain an uppercase letter"); return; }
    if (!/[a-z]/.test(password)) { setError("Password must contain a lowercase letter"); return; }
    if (!/\d/.test(password)) { setError("Password must contain a digit"); return; }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) { setError("Password must contain a special character"); return; }
    if (password !== confirmPassword) { setError("Passwords do not match"); return; }

    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || "Failed to reset password. The link may have expired.");
        return;
      }
      setSuccess(true);
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-orange-50/30 to-slate-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Shield className="w-8 h-8 text-orange-500" />
            <h1 className="text-2xl font-bold bg-gradient-to-r from-orange-500 to-orange-600 bg-clip-text text-transparent">
              GuardNous
            </h1>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl border border-slate-200/60 dark:border-slate-700/60 p-8">
          {success ? (
            <div className="text-center space-y-4">
              <div className="w-14 h-14 rounded-full bg-green-100 dark:bg-green-500/20 flex items-center justify-center mx-auto">
                <Check className="w-7 h-7 text-green-600 dark:text-green-400" />
              </div>
              <h2 className="text-xl font-bold text-slate-800 dark:text-white">Password reset!</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Your password has been successfully reset. You can now sign in with your new password.
              </p>
              <Link
                href="/login"
                className="inline-block mt-4 px-6 py-3 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 transition-all"
              >
                Go to login
              </Link>
            </div>
          ) : (
            <>
              <div className="text-center mb-6">
                <h2 className="text-xl font-bold text-slate-800 dark:text-white">Set new password</h2>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  Choose a strong password for your account
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-xl px-4 py-3 text-red-700 dark:text-red-300 text-sm mb-4">
                  <AlertCircle className="w-4 h-4 shrink-0" /> {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">New password</label>
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
                  <p className="text-xs text-slate-400 mt-1">8+ characters, uppercase, lowercase, digit, special character</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Confirm password</label>
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    placeholder="••••••••"
                    className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-700/50 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/40 focus:border-orange-500 dark:text-slate-200 transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full h-12 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 text-white font-semibold shadow-lg shadow-orange-500/25 hover:shadow-orange-500/40 disabled:opacity-60 transition-all flex items-center justify-center gap-2"
                >
                  {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Reset password"}
                </button>
              </form>
            </>
          )}
        </div>

        <div className="text-center mt-6">
          <Link href="/login" className="text-sm text-slate-500 hover:text-orange-500 transition-colors">
            ← Back to login
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center bg-slate-50"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" /></div>}>
      <ResetPasswordContent />
    </Suspense>
  );
}
