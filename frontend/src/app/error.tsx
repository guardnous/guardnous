"use client";
import { useEffect, useState } from "react";
import { AlertTriangle, RotateCcw, Home, ChevronDown, ChevronUp, Bug } from "lucide-react";
import Link from "next/link";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    console.error("Application error:", error);
  }, [error]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900 flex items-center justify-center p-6">
      <div className="text-center max-w-lg">
        <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-amber-50 dark:bg-amber-900/20 mb-8 border border-amber-200 dark:border-amber-800">
          <AlertTriangle className="w-12 h-12 text-amber-500 dark:text-amber-400" />
        </div>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-3">
          Something didn&apos;t load correctly
        </h1>
        <p className="text-slate-500 dark:text-slate-400 mb-6 text-base leading-relaxed">
          This page encountered an unexpected error. Try refreshing — if the
          problem persists, please{" "}
          <a
            href="https://github.com/AquaNous/GuardNous/issues/new"
            target="_blank"
            rel="noopener noreferrer"
            className="text-orange-600 dark:text-orange-400 hover:underline font-medium"
          >
            report an issue
          </a>
          .
        </p>

        {/* Expandable error details */}
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors mb-6"
        >
          <Bug size={14} />
          {showDetails ? "Hide" : "Show"} error details
          {showDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showDetails && (
          <div className="mb-6 p-4 bg-slate-100 dark:bg-slate-800/60 rounded-xl text-left border border-slate-200 dark:border-slate-700">
            <p className="text-sm font-mono text-red-600 dark:text-red-400 break-all">
              {error.message || "Unknown error"}
            </p>
            {error.digest && (
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-2 font-mono">
                Digest: {error.digest}
              </p>
            )}
          </div>
        )}

        <div className="flex items-center justify-center gap-3">
          <button
            onClick={reset}
            className="inline-flex items-center gap-2 px-6 h-11 bg-orange-600 hover:bg-orange-700 text-white font-semibold rounded-xl transition-colors shadow-sm"
          >
            <RotateCcw className="w-4 h-4" />
            Try Again
          </button>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-6 h-11 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-semibold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          >
            <Home className="w-4 h-4" />
            Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
