"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { ArrowLeft, ChevronDown, ChevronRight, Loader2, RefreshCw, Undo2, Wrench } from "lucide-react";
import PageLayout from "@/components/PageLayout";
import ProviderLogo, { providerName } from "@/components/ProviderLogo";
import { evaluateCloudPosture, getCloudPosture, rollbackCloudChange, startAgentRun, syncCloudAccount } from "@/lib/api";

/* ── Types ── */

interface FailingResource {
  finding_id: number;
  name: string;
  detail: string;
  status: string;
  region: string | null;
  account: string | null;
}

interface RuleRow {
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  resource_type: string;
  cis_aws_1_4: string | null;
  remediation: string;
  can_auto_fix: boolean;
  failing: number;
  passing: number;
  not_checked: number;
  resources: FailingResource[];
}

interface Evaluated {
  scan_id: number;
  account: string;
  last_evaluated: string | null;
  risk_score: number | null;
  resources: number;
  checks: number;
  passed: number;
  failed: number;
  not_checked: number;
  not_checked_examples: string[];
}

interface Named {
  name: string;
  region?: string | null;
  open_to_internet?: string[];
  public_ip?: string;
  engine?: string;
  dns_name?: string;
  waf?: string | null;
  attached_to_an_instance?: boolean | null;
}

interface Exposure {
  instances_reachable_from_internet: Named[];
  public_databases: Named[];
  internet_facing_load_balancers: Named[];
  public_kubernetes_endpoints: Named[];
  open_security_groups: Named[];
  buckets_without_public_access_block: string[];
}

interface Change {
  id: number;
  finding_id: number | null;
  run_id: number | null;
  rule_id: string;
  action: string;
  resource_name: string;
  status: string;
  approved_by: string | null;
  rolled_back_by: string | null;
  created_at: string | null;
}

interface AccountSummary {
  id: number;
  name: string;
  provider: string;
  account: string;
  status: string;
  last_error: string | null;
  last_synced_at: string | null;
  regions: string[];
  scan_id: number | null;
}

interface Posture {
  account: AccountSummary | null;
  connected_accounts: AccountSummary[];
  evaluated: Evaluated[];
  open_findings: number;
  by_severity: Record<string, number>;
  rules: RuleRow[];
  exposure: Exposure | null;
  changes: Change[];
}

type ApiError = { response?: { data?: { detail?: unknown } } };

/* ── Helpers ── */

const card = "rounded-xl border border-gray-200 bg-white dark:border-white/[0.08] dark:bg-[#0f1420]";
const muted = "text-gray-600 dark:text-gray-400";
const heading = "text-sm font-semibold text-gray-900 dark:text-gray-100";
const strong = "text-gray-900 dark:text-gray-100";

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "text-red-800 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20",
  HIGH: "text-orange-800 border-orange-300 bg-orange-50 dark:text-orange-300 dark:border-orange-800/40 dark:bg-orange-900/20",
  MEDIUM: "text-amber-800 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800/40 dark:bg-amber-900/20",
  LOW: "text-blue-800 border-blue-300 bg-blue-50 dark:text-blue-300 dark:border-blue-800/40 dark:bg-blue-900/20",
};

function Severity({ value }: { value: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[11px] ${SEVERITY_STYLE[value] ?? SEVERITY_STYLE.LOW}`}>
      {value.charAt(0) + value.slice(1).toLowerCase()}
    </span>
  );
}

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function errorText(err: unknown, fallback: string): string {
  const detail = (err as ApiError)?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
}

/* ── Rule row ── */

function Rule({ rule }: { rule: RuleRow }) {
  const [open, setOpen] = useState(false);
  const [started, setStarted] = useState<Record<number, number>>({});
  const fix = useMutation({
    mutationFn: (findingId: number) =>
      startAgentRun({
        agent_id: "remediation_agent",
        goal: `Fix cloud posture finding ${findingId} (${rule.rule_id}) in the cloud account with remediate_cloud_finding.`,
      }).then((run: { id: number }) => ({ findingId, runId: run.id })),
    onSuccess: ({ findingId, runId }) => setStarted((s) => ({ ...s, [findingId]: runId })),
  });
  const failing = rule.failing > 0;

  return (
    <li className="border-b border-gray-200 last:border-0 dark:border-white/[0.06]">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-gray-50 dark:hover:bg-white/[0.03]"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-gray-500" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-gray-500" />}
        <span className="w-20 shrink-0"><Severity value={rule.severity} /></span>
        <span className={`min-w-0 flex-1 truncate text-sm ${strong}`}>{rule.title}</span>
        {rule.cis_aws_1_4 && <span className={`hidden shrink-0 text-[11px] sm:inline ${muted}`}>CIS {rule.cis_aws_1_4}</span>}
        <span className={`w-28 shrink-0 text-right text-xs ${failing ? "font-semibold text-red-700 dark:text-red-300" : muted}`}>
          {failing ? `${rule.failing} failing` : rule.passing > 0 ? `${rule.passing} passing` : rule.not_checked > 0 ? "Not checked" : "Nothing to check"}
        </span>
      </button>
      {open && (
        <div className="space-y-3 px-4 pb-4 pl-11 text-sm">
          <p className={muted}>
            <code>{rule.rule_id}</code> · checks <code>{rule.resource_type}</code> · {rule.passing} passing, {rule.failing} failing
            {rule.not_checked > 0 ? `, ${rule.not_checked} could not be checked (the setting was not readable)` : ""}
          </p>
          <p className={strong}><span className="font-medium">How to fix:</span> {rule.remediation}</p>
          {rule.resources.length > 0 && (
            <ul className="space-y-2">
              {rule.resources.map((r) => (
                <li key={r.finding_id} className="rounded-lg border border-gray-200 p-3 dark:border-white/[0.06]">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className={`font-medium ${strong}`}>{r.name}</p>
                      <p className={`text-xs ${muted}`}>
                        {[r.account, r.region].filter(Boolean).join(" · ")} · finding #{r.finding_id}
                        {r.status !== "open" ? ` · ${r.status.replace("_", " ")}` : ""}
                      </p>
                      <p className={`mt-1 text-xs ${strong}`}>{r.detail}</p>
                    </div>
                    {rule.can_auto_fix && (
                      started[r.finding_id] ? (
                        <Link href="/agent-runs" className="text-xs text-blue-700 underline dark:text-blue-300">
                          Run #{started[r.finding_id]} started — approve it in Agent Runs
                        </Link>
                      ) : (
                        <button
                          type="button"
                          disabled={fix.isPending}
                          onClick={() => fix.mutate(r.finding_id)}
                          className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-800 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.04]"
                        >
                          <Wrench className="h-3.5 w-3.5" /> Fix in AWS…
                        </button>
                      )
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {fix.isError && <p className="text-xs text-red-700 dark:text-red-300">{errorText(fix.error, "The fix could not be started.")}</p>}
          {rule.can_auto_fix && rule.resources.length > 0 && (
            <p className={`text-xs ${muted}`}>
              “Fix in AWS” asks an agent to prepare the change. Nothing changes until a second person approves the exact change in Agent Runs.
            </p>
          )}
        </div>
      )}
    </li>
  );
}

/* ── Exposure ── */

function ExposureList({ title, items, render }: { title: string; items: Named[]; render: (n: Named) => string }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className={`text-xs font-semibold ${strong}`}>{title} ({items.length})</h3>
      <ul className="mt-1 space-y-1">
        {items.slice(0, 20).map((n, i) => (
          <li key={`${n.name}-${i}`} className={`text-xs ${strong}`}>
            <span className="font-medium">{n.name}</span> <span className={muted}>{render(n)}</span>
          </li>
        ))}
        {items.length > 20 && <li className={`text-xs ${muted}`}>and {items.length - 20} more</li>}
      </ul>
    </div>
  );
}

/* ── Page ── */

export default function CloudAccountPosturePage() {
  const accountId = Number(useParams<{ id: string }>().id);
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<Posture>({
    queryKey: ["cloud-posture", accountId],
    queryFn: () => getCloudPosture(accountId),
    enabled: Number.isFinite(accountId),
    retry: false,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["cloud-posture"] });
  const evaluate = useMutation({ mutationFn: evaluateCloudPosture, onSuccess: refresh });
  const sync = useMutation({ mutationFn: () => syncCloudAccount(accountId) });
  const rollback = useMutation({ mutationFn: rollbackCloudChange, onSuccess: refresh });
  const [showPassing, setShowPassing] = useState(false);
  const account = data?.account;

  const layout = (children: React.ReactNode) => (
    <PageLayout
      title={account ? account.name : "Cloud account"}
      subtitle={account ? `${providerName(account.provider)} account ${account.account}` : "Cloud posture of one account"}
    >
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <Link href="/cloud-posture" className={`inline-flex items-center gap-1.5 text-sm ${strong} hover:underline`}>
          <ArrowLeft className="h-4 w-4" /> All cloud accounts
        </Link>
        {account && (
          <div className="flex items-center gap-3">
            <ProviderLogo provider={account.provider} size="sm" />
            <span className={`text-xs ${muted}`}>
              {account.status === "connected" ? "Connected" : account.status} · last synced {formatTime(account.last_synced_at)}
            </span>
            <button
              type="button"
              disabled={sync.isPending || sync.isSuccess}
              onClick={() => sync.mutate()}
              className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-800 hover:bg-gray-50 disabled:opacity-60 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.05]"
            >
              {sync.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
              {sync.isSuccess ? "Sync started — refresh in a minute" : "Sync from the cloud now"}
            </button>
          </div>
        )}
      </div>
      {children}
    </PageLayout>
  );

  if (isLoading) return layout(<p className={`text-sm ${muted}`}>Loading…</p>);
  if (isError || !data || !account) {
    return layout(<p className="text-sm text-red-700 dark:text-red-300">This cloud account was not found.</p>);
  }

  if (data.evaluated.length === 0) {
    return layout(
      <div className={`${card} p-6`}>
        <h2 className={heading}>Connected, but not checked yet</h2>
        <p className={`mt-2 max-w-2xl text-sm ${muted}`}>
          {account.provider === "aws"
            ? `Sync this account and GuardNous will check its configuration against ${data.rules.length} rules: public buckets, open ports, missing MFA, unencrypted databases, logging gaps and more. Access is read-only.`
            : `Resources of ${providerName(account.provider)} accounts are synced, but posture rules exist for AWS only today.`}
        </p>
        {account.last_error && <p className="mt-2 text-sm text-red-700 dark:text-red-300">{account.last_error}</p>}
      </div>,
    );
  }

  const failing = data.rules.filter((r) => r.failing > 0);
  const rest = data.rules.filter((r) => r.failing === 0);
  const notChecked = data.evaluated.reduce((n, e) => n + e.not_checked, 0);
  const exposure = data.exposure;
  const exposed = exposure
    ? exposure.instances_reachable_from_internet.length + exposure.public_databases.length +
      exposure.public_kubernetes_endpoints.length + exposure.buckets_without_public_access_block.length
    : 0;

  return layout(
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-4">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
          <div key={sev} className={`${card} p-4`}>
            <p className={`text-xs ${muted}`}>{sev.charAt(0) + sev.slice(1).toLowerCase()} findings</p>
            <p className={`mt-1 text-2xl font-semibold ${strong}`}>{data.by_severity[sev] ?? 0}</p>
          </div>
        ))}
      </div>

      <section className={`${card} p-5`} aria-label="Accounts">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className={heading}>Last check</h2>
          <button
            type="button"
            disabled={evaluate.isPending}
            onClick={() => evaluate.mutate()}
            className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-800 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.04]"
          >
            {evaluate.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Re-check synced data
          </button>
        </div>
        <ul className="mt-3 space-y-2">
          {data.evaluated.map((e) => (
            <li key={e.scan_id} className={`text-sm ${strong}`}>
              <span className="font-medium">{e.resources} resources</span>{" "}
              <span className={muted}>
                · {e.checks} checks: {e.passed} passed, {e.failed} failed
                {e.not_checked > 0 ? `, ${e.not_checked} not checked` : ""} · last checked {formatTime(e.last_evaluated)}
                {account.regions.length > 0 ? ` · regions: ${account.regions.join(", ")}` : ""}
              </span>{" "}
              <Link href={`/scans/${e.scan_id}`} className="text-xs underline">Pipeline and timings</Link>
            </li>
          ))}
        </ul>
        {notChecked > 0 && (
          <details className="mt-3">
            <summary className={`cursor-pointer text-xs ${strong}`}>
              {notChecked} checks could not be run because GuardNous was not allowed to read a setting
            </summary>
            <ul className={`mt-1 list-disc pl-5 text-xs ${muted}`}>
              {data.evaluated.flatMap((e) => e.not_checked_examples).slice(0, 10).map((x) => <li key={x}>{x}</li>)}
            </ul>
          </details>
        )}
        <p className={`mt-3 text-xs ${muted}`}>
          “Re-check” runs the rules on data from the last sync. “Sync from the cloud now” reads the account again first.
        </p>
      </section>

      {exposure && (
        <section className={`${card} p-5`} aria-label="Internet exposure">
          <h2 className={heading}>Reachable from the internet</h2>
          {exposed === 0 && exposure.internet_facing_load_balancers.length === 0 && exposure.open_security_groups.length === 0 ? (
            <p className={`mt-2 text-sm ${muted}`}>Nothing in the synced resources is exposed to the internet.</p>
          ) : (
            <div className="mt-3 grid gap-4 md:grid-cols-2">
              <ExposureList title="Running instances with a public address behind open ports" items={exposure.instances_reachable_from_internet}
                render={(n) => `${n.public_ip ?? ""} · ${(n.open_to_internet ?? []).join(", ")}`} />
              <ExposureList title="Publicly accessible databases" items={exposure.public_databases} render={(n) => n.engine ?? ""} />
              <ExposureList title="Kubernetes API endpoints open to everyone" items={exposure.public_kubernetes_endpoints} render={(n) => n.region ?? ""} />
              <ExposureList title="Buckets without a public access block"
                items={exposure.buckets_without_public_access_block.map((name) => ({ name }))} render={() => ""} />
              <ExposureList title="Internet-facing load balancers" items={exposure.internet_facing_load_balancers}
                render={(n) => (n.waf ? `WAF: ${n.waf}` : "no WAF")} />
              <ExposureList title="Security groups open to the internet" items={exposure.open_security_groups}
                render={(n) => `${(n.open_to_internet ?? []).join(", ")}${n.attached_to_an_instance === false ? " · not attached to any instance" : ""}`} />
            </div>
          )}
        </section>
      )}

      <section className={card} aria-label="Rules">
        <h2 className={`border-b border-gray-200 px-5 py-3 dark:border-white/[0.06] ${heading}`}>
          {failing.length === 0 ? "No rule is failing" : `Failing rules (${failing.length})`}
        </h2>
        {failing.length > 0 && <ul>{failing.map((r) => <Rule key={r.rule_id} rule={r} />)}</ul>}
        <button
          type="button"
          onClick={() => setShowPassing(!showPassing)}
          aria-expanded={showPassing}
          className={`w-full border-t border-gray-200 px-5 py-3 text-left text-sm dark:border-white/[0.06] ${strong} hover:bg-gray-50 dark:hover:bg-white/[0.03]`}
        >
          {showPassing ? "Hide" : "Show"} the other {rest.length} rules (passing, not checked, or nothing to check)
        </button>
        {showPassing && <ul className="border-t border-gray-200 dark:border-white/[0.06]">{rest.map((r) => <Rule key={r.rule_id} rule={r} />)}</ul>}
      </section>

      {data.changes.length > 0 && (
        <section className={`${card} p-5`} aria-label="Changes made in the cloud">
          <h2 className={heading}>Changes GuardNous made in your cloud</h2>
          <ul className="mt-3 space-y-2">
            {data.changes.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-gray-200 p-3 dark:border-white/[0.06]">
                <div className="min-w-0">
                  <p className={`text-sm font-medium ${strong}`}>{c.action}: {c.resource_name}</p>
                  <p className={`text-xs ${muted}`}>
                    {formatTime(c.created_at)}
                    {c.approved_by ? ` · approved by ${c.approved_by}` : ""}
                    {c.run_id ? ` · agent run #${c.run_id}` : ""}
                    {c.status === "rolled_back" ? ` · rolled back by ${c.rolled_back_by ?? "unknown"}` : ""}
                  </p>
                </div>
                {c.status === "applied" && (
                  <button
                    type="button"
                    disabled={rollback.isPending}
                    onClick={() => {
                      if (window.confirm(`Put ${c.resource_name} back to how it was before this change?`)) rollback.mutate(c.id);
                    }}
                    className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-800 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.04]"
                  >
                    <Undo2 className="h-3.5 w-3.5" /> Roll back
                  </button>
                )}
              </li>
            ))}
          </ul>
          {rollback.isError && (
            <p className="mt-2 text-xs text-red-700 dark:text-red-300">{errorText(rollback.error, "The change could not be rolled back.")}</p>
          )}
        </section>
      )}
    </div>,
  );
}
