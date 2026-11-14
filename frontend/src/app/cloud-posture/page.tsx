"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Loader2, RefreshCw } from "lucide-react";
import PageLayout from "@/components/PageLayout";
import ProviderLogo, { CLOUD_PROVIDERS } from "@/components/ProviderLogo";
import { evaluateCloudPosture, getCloudPosture } from "@/lib/api";

/* ── Types ── */

type SeverityKey = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface AccountRow {
  id: number;
  name: string;
  provider: string;
  account: string;
  status: string;
  last_error: string | null;
  last_synced_at: string | null;
  last_evaluated: string | null;
  scan_id: number | null;
  resources: number;
  checks: number;
  passed: number;
  failed: number;
  not_checked: number;
  open_findings: number;
  by_severity: Record<SeverityKey, number>;
}

interface Overview {
  connected_accounts: AccountRow[];
  open_findings: number;
  by_severity: Record<SeverityKey, number>;
  rules: unknown[];
}

/* ── Helpers ── */

const card = "rounded-xl border border-gray-200 bg-white dark:border-white/[0.08] dark:bg-[#0f1420]";
const muted = "text-gray-600 dark:text-gray-400";
const strong = "text-gray-900 dark:text-gray-100";

const SEVERITIES: { key: SeverityKey; label: string; style: string }[] = [
  { key: "CRITICAL", label: "Critical", style: "text-red-800 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20" },
  { key: "HIGH", label: "High", style: "text-orange-800 border-orange-300 bg-orange-50 dark:text-orange-300 dark:border-orange-800/40 dark:bg-orange-900/20" },
  { key: "MEDIUM", label: "Medium", style: "text-amber-800 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800/40 dark:bg-amber-900/20" },
  { key: "LOW", label: "Low", style: "text-blue-800 border-blue-300 bg-blue-50 dark:text-blue-300 dark:border-blue-800/40 dark:bg-blue-900/20" },
];

const formatTime = (value: string | null) => (value ? new Date(value).toLocaleString() : "never");

/* ── One cloud account in the list ── */

function AccountLink({ account }: { account: AccountRow }) {
  const checked = account.scan_id !== null;
  return (
    <li className="border-t border-gray-200 dark:border-white/[0.06]">
      <Link
        href={`/cloud-posture/${account.id}`}
        className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3.5 hover:bg-gray-50 dark:hover:bg-white/[0.03]"
      >
        <div className="min-w-[220px] flex-1">
          <p className={`font-mono text-sm font-semibold ${strong}`}>{account.account}</p>
          <p className={`text-xs ${muted}`}>
            {account.name}
            {account.status !== "connected" ? ` · ${account.status}` : ""}
          </p>
        </div>
        {checked ? (
          <>
            <p className={`w-56 text-xs ${muted}`}>
              <span className={strong}>{account.resources}</span> resources ·{" "}
              <span className={strong}>{account.passed}</span> passed, <span className={strong}>{account.failed}</span> failed
              {account.not_checked > 0 ? `, ${account.not_checked} not checked` : ""}
            </p>
            <div className="flex w-72 flex-wrap gap-1.5">
              {account.open_findings === 0 ? (
                <span className={`text-xs ${muted}`}>No open findings</span>
              ) : (
                SEVERITIES.filter((s) => account.by_severity[s.key] > 0).map((s) => (
                  <span key={s.key} className={`rounded border px-2 py-0.5 text-[11px] ${s.style}`}>
                    {account.by_severity[s.key]} {s.label}
                  </span>
                ))
              )}
            </div>
            <p className={`w-44 text-xs ${muted}`}>Checked {formatTime(account.last_evaluated)}</p>
          </>
        ) : (
          <p className={`flex-1 text-xs ${account.last_error ? "text-red-700 dark:text-red-300" : muted}`}>
            {account.last_error || (account.provider === "aws" ? "Not checked yet — open to sync it" : "Posture rules exist for AWS only today")}
          </p>
        )}
        <ChevronRight className="h-4 w-4 shrink-0 text-gray-500 dark:text-gray-400" />
      </Link>
    </li>
  );
}

/* ── Page ── */

export default function CloudPosturePage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<Overview>({ queryKey: ["cloud-posture"], queryFn: () => getCloudPosture() });
  const evaluate = useMutation({
    mutationFn: evaluateCloudPosture,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cloud-posture"] }),
  });
  const [closed, setClosed] = useState<string[]>([]);

  const layout = (children: React.ReactNode) => (
    <PageLayout title="Cloud Posture" subtitle="Security rules checked against the resources in your connected cloud accounts">
      {children}
    </PageLayout>
  );

  if (isLoading) return layout(<p className={`text-sm ${muted}`}>Loading…</p>);
  if (isError || !data) return layout(<p className="text-sm text-red-700 dark:text-red-300">Cloud posture could not be loaded.</p>);

  const accounts = data.connected_accounts;
  if (accounts.length === 0) {
    return layout(
      <div className={`${card} p-6`}>
        <h2 className={`text-sm font-semibold ${strong}`}>No cloud account is connected</h2>
        <p className={`mt-2 max-w-2xl text-sm ${muted}`}>
          Connect a cloud account and GuardNous will read its configuration and check it against {data.rules.length} rules:
          public buckets, open ports, missing MFA, unencrypted databases, logging gaps and more. Access is read-only.
        </p>
        <Link href="/cloud-accounts" className="mt-4 inline-block rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500">
          Open Cloud Connectors
        </Link>
      </div>,
    );
  }

  // Known clouds first, in a fixed order; then anything else that has accounts.
  const known: string[] = CLOUD_PROVIDERS.map((p) => p.id);
  const providers = [...known, ...Array.from(new Set(accounts.map((a) => a.provider))).filter((p) => !known.includes(p))]
    .filter((p) => accounts.some((a) => a.provider === p));

  return layout(
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-4">
        {SEVERITIES.map((s) => (
          <div key={s.key} className={`${card} p-4`}>
            <p className={`text-xs ${muted}`}>{s.label} findings, all accounts</p>
            <p className={`mt-1 text-2xl font-semibold ${strong}`}>{data.by_severity[s.key] ?? 0}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className={`text-sm ${muted}`}>Open a cloud, then an account, to see its findings, exposure and rules.</p>
        <button
          type="button"
          disabled={evaluate.isPending}
          onClick={() => evaluate.mutate()}
          className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-800 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.05]"
        >
          {evaluate.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Re-check synced data
        </button>
      </div>

      {providers.map((provider) => {
        const own = accounts.filter((a) => a.provider === provider);
        const open = !closed.includes(provider);
        const findings = own.reduce((n, a) => n + a.open_findings, 0);
        const name = CLOUD_PROVIDERS.find((p) => p.id === provider)?.name ?? provider.toUpperCase();
        return (
          <section key={provider} className={`${card} overflow-hidden`} aria-label={name}>
            <button
              type="button"
              aria-expanded={open}
              onClick={() => setClosed((prev) => (open ? [...prev, provider] : prev.filter((p) => p !== provider)))}
              className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50 dark:hover:bg-white/[0.03]"
            >
              <ChevronRight className={`h-4 w-4 shrink-0 text-gray-500 transition-transform dark:text-gray-400 ${open ? "rotate-90" : ""}`} />
              <ProviderLogo provider={provider} size="sm" />
              <span className={`flex-1 text-sm font-semibold ${strong}`}>{name}</span>
              <span className={`text-xs ${muted}`}>
                {own.length} {own.length === 1 ? "account" : "accounts"} · {findings} open {findings === 1 ? "finding" : "findings"}
              </span>
            </button>
            {open && <ul>{own.map((a) => <AccountLink key={a.id} account={a} />)}</ul>}
          </section>
        );
      })}
    </div>,
  );
}
