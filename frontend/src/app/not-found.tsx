"use client";
import Link from "next/link";
import { ShieldOff, Home, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900 flex items-center justify-center p-6">
      <div className="text-center max-w-lg">
        <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-orange-100 dark:bg-orange-900/30 mb-8">
          <ShieldOff className="w-12 h-12 text-orange-600 dark:text-orange-400" />
        </div>
        <h1 className="text-7xl font-bold text-slate-900 dark:text-white mb-4">404</h1>
        <h2 className="text-2xl font-semibold text-slate-700 dark:text-slate-300 mb-4">
          Page Not Found
        </h2>
        <p className="text-slate-500 dark:text-slate-400 mb-8 text-lg">
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
          Check the URL or navigate back to the dashboard.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-6 h-12 bg-orange-600 hover:bg-orange-700 text-white font-semibold rounded-xl transition-colors"
          >
            <Home className="w-5 h-5" />
            Go to Dashboard
          </Link>
          <button
            onClick={() => window.history.back()}
            className="inline-flex items-center gap-2 px-6 h-12 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-semibold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            Go Back
          </button>
        </div>
      </div>
    </div>
  );
}
