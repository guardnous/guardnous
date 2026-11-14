"use client";

import React, { useState } from "react";
import { usePathname } from "next/navigation";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "@/lib/auth";
import { ToastProvider } from "@/lib/toast";
import TopBar from "@/components/TopBar";
import Sidebar from "@/components/Sidebar";
import "./globals.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

// Pages that should never show the authenticated shell (sidebar + topbar)
const AUTH_PAGES = ["/login", "/register", "/invite", "/verify-email", "/first-run"];
// Pages that bypass the setup-wizard redirect (the wizard itself + auth pages)
const SETUP_BYPASS = ["/login", "/register", "/invite", "/setup", "/first-run", "/verify-email"];

function AuthenticatedLayout({ children }: { children: React.ReactNode }) {
  const { token, user, isLoading } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  // Auth pages always render without shell, even if token exists
  const isAuthPage = AUTH_PAGES.some((p) => pathname.startsWith(p));
  const isBypassPage = SETUP_BYPASS.some((p) => pathname.startsWith(p));

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="flex flex-col items-center gap-3">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500" />
          <p className="text-sm text-gray-400 animate-fade-in">Loading…</p>
        </div>
      </div>
    );
  }

  if (!token || isAuthPage) {
    return <>{children}</>;
  }

  // Redirect admins to /setup if first-login wizard hasn't been completed
  const isAdmin = user && ["admin", "super_admin", "superadmin", "owner", "platform_admin"].includes(user.role);
  if (isAdmin && user.setup_completed === false && !isBypassPage) {
    if (typeof window !== "undefined") {
      window.location.href = "/setup";
    }
    return null;
  }

  // Setup page renders without sidebar shell
  if (pathname.startsWith("/setup")) {
    return <>{children}</>;
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-gray-900">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  );
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <title>GuardNous — Defend What Matters</title>
        <meta name="description" content="Open-source cloud security & IaC posture management platform" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta property="og:title" content="GuardNous — Defend What Matters" />
        <meta property="og:description" content="Open-source cloud security & IaC posture management platform" />
        <meta property="og:type" content="website" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
      </head>
      <body>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            <ToastProvider>
              <AuthenticatedLayout>{children}</AuthenticatedLayout>
            </ToastProvider>
          </AuthProvider>
        </QueryClientProvider>
      </body>
    </html>
  );
}
