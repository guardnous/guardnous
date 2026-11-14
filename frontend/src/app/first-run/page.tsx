"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { checkFirstRunSetup, initializeSetup } from "@/lib/api";
import {
  ShieldCheck,
  User,
  Building2,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  AlertCircle,
  Eye,
  EyeOff,
  Loader2,
} from "lucide-react";

export default function FirstRunSetupPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  // Step 1: Admin account
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // Step 2: Tenant & Org
  const [tenantName, setTenantName] = useState("");
  const [orgName, setOrgName] = useState("");

  // Check if setup is already done
  useEffect(() => {
    checkFirstRunSetup()
      .then((status) => {
        if (status.is_setup_complete) {
          router.replace("/login");
        } else {
          setLoading(false);
        }
      })
      .catch(() => setLoading(false));
  }, [router]);

  const validateStep1 = () => {
    if (!fullName.trim()) return "Full name is required";
    if (!email.trim()) return "Email is required";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "Invalid email format";
    if (password.length < 8) return "Password must be at least 8 characters";
    if (password !== confirmPassword) return "Passwords do not match";
    return null;
  };

  const validateStep2 = () => {
    if (!tenantName.trim()) return "Company name is required";
    if (!orgName.trim()) return "Organization name is required";
    return null;
  };

  const handleNext = () => {
    const err = validateStep1();
    if (err) {
      setError(err);
      return;
    }
    setError("");
    setStep(2);
  };

  const handleSubmit = async () => {
    const err = validateStep2();
    if (err) {
      setError(err);
      return;
    }

    setSubmitting(true);
    setError("");
    try {
      const result = await initializeSetup({
        admin_email: email,
        admin_password: password,
        admin_full_name: fullName,
        tenant_name: tenantName,
        organization_name: orgName,
      });

      if (result.access_token) {
        localStorage.setItem("token", result.access_token);
      }
      setSuccess(true);
      setTimeout(() => router.replace("/"), 2000);
    } catch (e: unknown) {
      if (e && typeof e === "object" && "response" in e) {
        const axErr = e as { response?: { data?: { detail?: string } } };
        setError(axErr.response?.data?.detail || "Setup failed. Please try again.");
      } else {
        setError("Setup failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-gray-900">
        <Loader2 className="h-8 w-8 animate-spin text-orange-500" />
      </div>
    );
  }

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-orange-50/30 dark:from-gray-900 dark:to-gray-800">
        <div className="text-center space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
            <CheckCircle className="h-8 w-8 text-green-600" />
          </div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Setup Complete!</h2>
          <p className="text-gray-500 dark:text-gray-400">Redirecting to your dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-orange-50/30 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="mx-auto w-14 h-14 rounded-xl bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center mb-4">
            <ShieldCheck size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Welcome to GuardNous
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Let&apos;s set up your platform in 2 quick steps
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-3 mb-8">
          {[
            { num: 1, label: "Admin Account", icon: User },
            { num: 2, label: "Company", icon: Building2 },
          ].map(({ num, label, icon: Icon }) => (
            <div key={num} className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
                  step >= num
                    ? "bg-orange-500 text-white"
                    : "bg-gray-200 dark:bg-gray-700 text-gray-500"
                }`}
              >
                {step > num ? <CheckCircle size={16} /> : num}
              </div>
              <span className={`text-sm hidden sm:inline ${step >= num ? "text-gray-900 dark:text-white font-medium" : "text-gray-400"}`}>
                {label}
              </span>
              {num === 1 && (
                <div className={`w-12 h-0.5 mx-1 ${step > 1 ? "bg-orange-500" : "bg-gray-200 dark:bg-gray-700"}`} />
              )}
            </div>
          ))}
        </div>

        {/* Card */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-200 dark:border-gray-700 p-8">
          {error && (
            <div className="mb-6 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 flex items-start gap-2">
              <AlertCircle size={18} className="text-red-500 mt-0.5 flex-shrink-0" />
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          {step === 1 && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                  Create Admin Account
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  This will be the platform super-administrator
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Jane Doe"
                  className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@yourcompany.com"
                  className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Minimum 8 characters"
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter password"
                  className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                />
              </div>

              <button
                onClick={handleNext}
                className="w-full py-2.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-medium flex items-center justify-center gap-2 transition-colors"
              >
                Next: Company Details <ArrowRight size={18} />
              </button>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                  Company Details
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Set up your tenant and primary organization
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Company / Tenant Name
                </label>
                <input
                  type="text"
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  placeholder="e.g. Acme Corp"
                  className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                />
                <p className="text-xs text-gray-400 mt-1">
                  This is your top-level account. You can add more organizations later.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. Engineering, Security Team"
                  className="w-full px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Your first team or business unit. More can be added later.
                </p>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => { setStep(1); setError(""); }}
                  className="px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 font-medium flex items-center gap-2 transition-colors"
                >
                  <ArrowLeft size={18} /> Back
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="flex-1 py-2.5 rounded-lg bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white font-medium flex items-center justify-center gap-2 transition-colors"
                >
                  {submitting ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <>Complete Setup <CheckCircle size={18} /></>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          GuardNous — Open-Source Cloud Security Platform
        </p>
      </div>
    </div>
  );
}
