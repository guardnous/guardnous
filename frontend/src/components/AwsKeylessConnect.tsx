"use client";

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Download, ExternalLink, KeyRound, Loader2, X } from "lucide-react";
import {
  connectAwsKeyless,
  deleteCloudAccount,
  downloadAwsKeylessTemplate,
  getAwsFederation,
  getAwsKeylessSetup,
  listCloudAccounts,
  syncCloudAccount,
  testCloudAccount,
} from "@/lib/api";

interface Setup {
  account_id: string;
  role_arn: string;
  stack_name: string;
  issuer: string;
  access: string;
  template_filename: string;
  cli_command: string;
  console_url: string;
  quick_create_url: string | null;
}

interface Account {
  id: number;
  provider: string;
  name: string;
  account_identifier: string;
  status: string;
  keyless?: boolean;
}

type ApiError = { response?: { data?: { detail?: unknown } } };

const POLL_MS = 8000;

const card = "rounded-xl border border-gray-200 bg-white p-5 dark:border-white/[0.08] dark:bg-[#0f1420]";
const muted = "text-gray-600 dark:text-gray-400";
const strong = "text-gray-900 dark:text-gray-100";
const inputCls =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:outline-none dark:border-white/[0.08] dark:bg-[#161c2b] dark:text-gray-100 dark:placeholder-gray-400";
const secondaryBtn =
  "inline-flex items-center gap-1.5 rounded-lg border border-gray-300 px-3 py-2 text-xs font-medium text-gray-800 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.12] dark:text-gray-200 dark:hover:bg-white/[0.04]";
const primaryBtn =
  "inline-flex items-center gap-1.5 rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white hover:bg-blue-800 disabled:opacity-50";

function errorText(err: unknown, fallback: string): string {
  const detail = (err as ApiError)?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-blue-700 text-xs font-semibold text-white">{n}</span>
      <div className="min-w-0 flex-1">
        <p className={`text-sm font-medium ${strong}`}>{title}</p>
        <div className="mt-2">{children}</div>
      </div>
    </li>
  );
}

/* ── Waiting for the stack ── */

function Pending({ account, onDone }: { account: Account; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<"waiting" | "connected">("waiting");
  const [lastError, setLastError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [copied, setCopied] = useState(false);
  const busy = useRef(false);
  const { data: setup } = useQuery<Setup>({
    queryKey: ["aws-keyless-setup", account.id],
    queryFn: () => getAwsKeylessSetup(account.id),
  });

  const check = async () => {
    if (busy.current) return;
    busy.current = true;
    setChecking(true);
    try {
      const result = await testCloudAccount(account.id);
      if (result.status === "connected") {
        setState("connected");
        await syncCloudAccount(account.id).catch(() => undefined);
        queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
        queryClient.invalidateQueries({ queryKey: ["cloud-posture"] });
      } else {
        setLastError(result.error ?? "AWS did not accept the connection yet.");
      }
    } catch (err) {
      setLastError(errorText(err, "The check could not be run."));
    } finally {
      busy.current = false;
      setChecking(false);
    }
  };

  useEffect(() => {
    if (state !== "waiting") return;
    const timer = setInterval(check, POLL_MS);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state, account.id]);

  const cancel = useMutation({
    mutationFn: () => deleteCloudAccount(account.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
      queryClient.invalidateQueries({ queryKey: ["aws-keyless-accounts"] });
      onDone();
    },
  });

  if (state === "connected") {
    return (
      <div className="rounded-lg border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-800/40 dark:bg-emerald-900/20">
        <p className="flex items-center gap-2 text-sm font-medium text-emerald-900 dark:text-emerald-200">
          <Check className="h-4 w-4" /> AWS account {account.account_identifier} is connected. No access key was created or stored.
        </p>
        <p className="mt-1 text-sm text-emerald-900 dark:text-emerald-200">
          The first sync has started. Results appear in{" "}
          <Link href="/cloud-posture" className="underline">Cloud Posture</Link> in a minute or two.
        </p>
        <button type="button" onClick={onDone} className={`mt-3 ${secondaryBtn}`}>Done</button>
      </div>
    );
  }
  if (!setup) return <p className={`text-sm ${muted}`}>Loading…</p>;

  return (
    <div>
      <p className={`text-sm ${strong}`}>
        Finish connecting AWS account <span className="font-semibold">{setup.account_id}</span> ({setup.access}).
      </p>
      <ol className="mt-4 space-y-5">
        <Step n={1} title="Deploy one CloudFormation stack in that account">
          {setup.quick_create_url ? (
            <a href={setup.quick_create_url} target="_blank" rel="noopener noreferrer" className={primaryBtn}>
              <ExternalLink className="h-4 w-4" /> Launch stack in AWS
            </a>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => downloadAwsKeylessTemplate(account.id, setup.template_filename)} className={primaryBtn}>
                  <Download className="h-4 w-4" /> Download template
                </button>
                <a href={setup.console_url} target="_blank" rel="noopener noreferrer" className={secondaryBtn}>
                  <ExternalLink className="h-3.5 w-3.5" /> Open CloudFormation
                </a>
              </div>
              <p className={`text-xs ${muted}`}>
                In CloudFormation choose “Upload a template file”, pick the downloaded file, keep every value as it is,
                tick the box acknowledging that IAM resources are created, and create the stack. Or run this where the AWS CLI is signed in to that account:
              </p>
              <div className="flex items-start gap-2">
                <code className="block flex-1 overflow-x-auto whitespace-pre rounded-lg bg-gray-100 p-3 text-[11px] text-gray-900 dark:bg-black/30 dark:text-gray-200">
                  {setup.cli_command}
                </code>
                <button
                  type="button"
                  aria-label="Copy command"
                  onClick={() => navigator.clipboard.writeText(setup.cli_command).then(() => setCopied(true))}
                  className={secondaryBtn}
                >
                  {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
          )}
          <p className={`mt-3 text-xs ${muted}`}>
            The stack creates an identity provider for <code>{setup.issuer}</code> and the role <code>{setup.role_arn}</code>.
            It creates no user and no access key. Deleting the stack disconnects GuardNous.
          </p>
        </Step>
        <Step n={2} title="GuardNous connects by itself when the stack is ready">
          <p className={`flex items-center gap-2 text-sm ${strong}`} role="status">
            <Loader2 className="h-4 w-4 animate-spin" /> Waiting for the stack… checking every few seconds.
          </p>
          {lastError && <p className={`mt-2 text-xs ${muted}`}>Last answer from AWS: {lastError}</p>}
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" disabled={checking} onClick={check} className={secondaryBtn}>Check now</button>
            <button
              type="button"
              disabled={cancel.isPending}
              onClick={() => cancel.mutate()}
              className={secondaryBtn}
            >
              <X className="h-3.5 w-3.5" /> Cancel this connection
            </button>
          </div>
        </Step>
      </ol>
    </div>
  );
}

/* ── Panel ── */

export default function AwsKeylessConnect() {
  const queryClient = useQueryClient();
  const [accountId, setAccountId] = useState("");
  const [allowFixes, setAllowFixes] = useState(false);
  const [active, setActive] = useState<Account | null>(null);
  const { data: federation } = useQuery<{ available: boolean; issuer: string | null; reason: string | null }>({
    queryKey: ["aws-federation"],
    queryFn: getAwsFederation,
  });
  const { data: listing } = useQuery<{ accounts: Account[] }>({
    queryKey: ["aws-keyless-accounts"],
    queryFn: () => listCloudAccounts({ provider: "aws" }),
  });
  const unfinished = (listing?.accounts ?? []).find((a) => a.keyless && a.status !== "connected");
  const current = active ?? unfinished ?? null;

  const connect = useMutation({
    mutationFn: () => connectAwsKeyless({ account_id: accountId.trim(), allow_fixes: allowFixes }),
    onSuccess: (data: { account: Account }) => {
      setActive(data.account);
      setAccountId("");
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
      queryClient.invalidateQueries({ queryKey: ["aws-keyless-accounts"] });
    },
  });
  const valid = /^\d{12}$/.test(accountId.trim());

  return (
    <section className={card} aria-label="Connect AWS without access keys">
      <h2 className={`flex items-center gap-2 text-sm font-semibold ${strong}`}>
        <KeyRound className="h-4 w-4 text-blue-700 dark:text-blue-300" />
        Connect AWS without access keys
      </h2>

      {current ? (
        <div className="mt-4">
          <Pending
            key={current.id}
            account={current}
            onDone={() => {
              setActive(null);
              queryClient.invalidateQueries({ queryKey: ["aws-keyless-accounts"] });
            }}
          />
        </div>
      ) : federation && !federation.available ? (
        <p className={`mt-2 max-w-3xl text-sm ${muted}`}>Not available on this installation yet. {federation.reason}</p>
      ) : (
        <form
          className="mt-2"
          onSubmit={(e) => {
            e.preventDefault();
            connect.mutate();
          }}
        >
          <p className={`max-w-3xl text-sm ${muted}`}>
            Enter the account ID and deploy one CloudFormation stack. AWS then trusts short-lived tokens signed by GuardNous;
            nothing secret is created, copied or stored.
          </p>
          <div className="mt-4 flex flex-wrap items-end gap-3">
            <div className="w-56">
              <label htmlFor="aws-account-id" className={`mb-1 block text-xs font-medium ${muted}`}>AWS account ID</label>
              <input
                id="aws-account-id"
                className={inputCls}
                inputMode="numeric"
                placeholder="12 digits"
                value={accountId}
                onChange={(e) => setAccountId(e.target.value.replace(/\D/g, "").slice(0, 12))}
              />
            </div>
            <button type="submit" disabled={!valid || connect.isPending} className={primaryBtn}>
              {connect.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Connect
            </button>
          </div>
          <label className={`mt-3 flex items-start gap-2 text-sm ${strong}`}>
            <input type="checkbox" className="mt-1" checked={allowFixes} onChange={(e) => setAllowFixes(e.target.checked)} />
            <span>
              Also let GuardNous make the fixes it offers
              <span className={`block text-xs ${muted}`}>
                Off = read-only. On = the role may also block S3 public access, remove internet SSH/RDP rules, and turn on EBS default
                encryption and KMS rotation. Each fix still needs a person’s approval.
              </span>
            </span>
          </label>
          {connect.isError && (
            <p className="mt-3 text-sm text-red-700 dark:text-red-300">{errorText(connect.error, "The connection could not be started.")}</p>
          )}
        </form>
      )}
    </section>
  );
}
