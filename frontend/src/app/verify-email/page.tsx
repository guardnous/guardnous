"use client";

import React, { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { verifyEmail } from "@/lib/api";
import { CheckCircle, XCircle, Loader2, ShieldCheck } from "lucide-react";

function VerifyEmailContent() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const [status, setStatus] = useState<"loading" | "verified" | "already" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMsg("No verification token provided.");
      return;
    }

    verifyEmail(token)
      .then((res) => {
        if (res.status === "already_verified") {
          setStatus("already");
        } else {
          setStatus("verified");
        }
      })
      .catch((err) => {
        setStatus("error");
        setErrorMsg(
          err?.response?.data?.detail || "Verification failed. The link may have expired."
        );
      });
  }, [token]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-950">
      <div className="w-full max-w-md mx-auto px-4">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-gradient-to-r from-orange-500 to-orange-600 shadow-lg mb-4">
            <ShieldCheck size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Guard<span className="text-orange-500">Nous</span>
          </h1>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-100 dark:border-gray-700 p-8 text-center">
          {status === "loading" && (
            <>
              <Loader2 size={48} className="mx-auto text-orange-500 animate-spin mb-4" />
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                Verifying your email…
              </h2>
              <p className="text-gray-500 dark:text-gray-400">
                Please wait while we confirm your email address.
              </p>
            </>
          )}

          {status === "verified" && (
            <>
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 dark:bg-green-900/30 mb-4">
                <CheckCircle size={36} className="text-green-600 dark:text-green-400" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                Email Verified!
              </h2>
              <p className="text-gray-500 dark:text-gray-400 mb-6">
                Your email has been successfully verified. You can now access all features.
              </p>
              <a
                href="/login"
                className="inline-flex items-center px-6 py-2.5 rounded-lg bg-gradient-to-r from-orange-500 to-orange-600 text-white font-medium hover:from-orange-600 hover:to-orange-700 transition-all shadow-md"
              >
                Go to Login
              </a>
            </>
          )}

          {status === "already" && (
            <>
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 mb-4">
                <CheckCircle size={36} className="text-blue-600 dark:text-blue-400" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                Already Verified
              </h2>
              <p className="text-gray-500 dark:text-gray-400 mb-6">
                Your email was already verified. No further action needed.
              </p>
              <a
                href="/login"
                className="inline-flex items-center px-6 py-2.5 rounded-lg bg-gradient-to-r from-orange-500 to-orange-600 text-white font-medium hover:from-orange-600 hover:to-orange-700 transition-all shadow-md"
              >
                Go to Login
              </a>
            </>
          )}

          {status === "error" && (
            <>
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 dark:bg-red-900/30 mb-4">
                <XCircle size={36} className="text-red-600 dark:text-red-400" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                Verification Failed
              </h2>
              <p className="text-gray-500 dark:text-gray-400 mb-6">
                {errorMsg}
              </p>
              <a
                href="/login"
                className="inline-flex items-center px-6 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 font-medium hover:bg-gray-50 dark:hover:bg-gray-700 transition-all"
              >
                Back to Login
              </a>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
          <Loader2 size={32} className="text-orange-500 animate-spin" />
        </div>
      }
    >
      <VerifyEmailContent />
    </Suspense>
  );
}
