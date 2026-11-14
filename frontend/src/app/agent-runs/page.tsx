"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Check, ChevronDown, ChevronRight, Loader2, Play, ShieldQuestion, X } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import PageLayout from "@/components/PageLayout";
import {
  cancelAgentRun,
  decideAgentApproval,
  getAgentApprovals,
  getAgentList,
  getAgentRun,
  getAgentRuns,
  getAgentUsage,
  startAgentRun,
} from "@/lib/api";

/* ── Types ── */

interface Run {
  id: number;
  agent_id: string;
  agent_name: string;
  goal: string;
  status: string;
  requested_by: string | null;
  provider: string | null;
  model: string | null;
  step_count: number;
  max_steps: number;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number | null;
  pending_approvals: number;
  error: string | null;
  created_at: string | null;
  finished_at: string | null;
}

interface Step {
  seq: number;
  kind: string;
  tool_name: string | null;
  risk: string | null;
  arguments: Record<string, unknown> | null;
  output: string | null;
  status: string;
  duration_ms: number | null;
  input_tokens: number;
  output_tokens: number;
}

interface Approval {
  id: number;
  run_id: number;
  agent_id: string | null;
  goal: string | null;
  tool_name: string;
  risk: string;
  arguments: Record<string, unknown> | null;
  summary: string | null;
  preview: string | null;
  reasoning: string | null;
  status: string;
  requested_by: string | null;
  decided_by: string | null;
  decision_note: string | null;
  created_at: string | null;
  expires_at: string | null;
  can_decide: boolean;
  blocked_reason: string | null;
}

interface RunDetail extends Run {
  result: string | null;
  steps: Step[];
  approvals: Approval[];
  children: Run[];
}

interface Usage {
  tokens_this_month: number;
  monthly_budget: number;
  estimated_cost_usd: number | null;
  runs_this_month: number;
  model_configured: boolean;
  provider: string;
  model: string;
}

interface AgentInfo {
  id: string;
  name: string;
  description: string;
}

type ApiError = { response?: { data?: { detail?: unknown } } };

/* ── Helpers ── */

const ACTIVE = ["queued", "running", "awaiting_approval"];

const STATUS_STYLE: Record<string, string> = {
  queued: "text-gray-700 border-gray-300 bg-gray-50 dark:text-gray-300 dark:border-gray-700 dark:bg-white/[0.04]",
  running: "text-blue-700 border-blue-300 bg-blue-50 dark:text-blue-300 dark:border-blue-800/40 dark:bg-blue-900/20",
  awaiting_approval: "text-amber-800 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800/40 dark:bg-amber-900/20",
  completed: "text-emerald-700 border-emerald-300 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/40 dark:bg-emerald-900/20",
  failed: "text-red-700 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20",
  cancelled: "text-gray-700 border-gray-300 bg-gray-50 dark:text-gray-300 dark:border-gray-700 dark:bg-white/[0.04]",
  ok: "text-emerald-700 border-emerald-300 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/40 dark:bg-emerald-900/20",
  error: "text-red-700 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20",
  denied: "text-amber-800 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800/40 dark:bg-amber-900/20",
};

const STATUS_TEXT: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  awaiting_approval: "Waiting for approval",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
  ok: "Done",
  error: "Error",
  denied: "Not allowed",
  approved: "Approved",
  rejected: "Rejected",
  expired: "Expired",
};

const RISK_TEXT: Record<string, string> = {
  internal_write: "Changes GuardNous data",
  external_write: "Changes an external system",
};

function Badge({ status }: { status: string }) {
  return (
    <span className={`inline-block whitespace-nowrap rounded border px-2 py-0.5 text-[11px] ${STATUS_STYLE[status] ?? STATUS_STYLE.queued}`}>
      {STATUS_TEXT[status] ?? status}
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

function prettyJson(text: string | null): string {
  if (!text) return "";
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

const card = "rounded-xl border border-gray-200 bg-white dark:border-white/[0.08] dark:bg-[#0f1420]";
const inputCls =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-blue-500 focus:outline-none dark:border-white/[0.08] dark:bg-[#161c2b] dark:text-gray-100 dark:placeholder-gray-500";
const labelCls = "mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400";
const muted = "text-gray-600 dark:text-gray-400";
const heading = "text-sm font-semibold text-gray-900 dark:text-gray-100";

function Answer({ text }: { text: string }) {
  const cell = "border border-gray-300 px-2 py-1 text-left align-top dark:border-white/[0.12]";
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h4 className="mb-2 mt-4 text-base font-semibold first:mt-0">{children}</h4>,
        h2: ({ children }) => <h4 className="mb-2 mt-4 text-base font-semibold first:mt-0">{children}</h4>,
        h3: ({ children }) => <h5 className="mb-1 mt-3 text-sm font-semibold first:mt-0">{children}</h5>,
        p: ({ children }) => <p className="mb-2 leading-relaxed last:mb-0">{children}</p>,
        ul: ({ children }) => <ul className="mb-2 list-disc space-y-1 pl-5">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 list-decimal space-y-1 pl-5">{children}</ol>,
        a: ({ children, href }) => (
          <a href={href} target="_blank" rel="noopener noreferrer" className="text-blue-700 underline dark:text-blue-300">{children}</a>
        ),
        code: ({ children }) => <code className="rounded bg-gray-200 px-1 py-0.5 text-[12px] dark:bg-white/[0.08]">{children}</code>,
        pre: ({ children }) => <pre className="mb-2 overflow-x-auto rounded-lg bg-gray-200 p-3 text-[12px] dark:bg-black/30">{children}</pre>,
        table: ({ children }) => <div className="mb-2 overflow-x-auto"><table className="border-collapse text-[13px]">{children}</table></div>,
        th: ({ children }) => <th className={`${cell} font-semibold`}>{children}</th>,
        td: ({ children }) => <td className={cell}>{children}</td>,
        hr: () => <hr className="my-3 border-gray-300 dark:border-white/[0.1]" />,
      }}
    >
      {text}
    </ReactMarkdown>
  );
}

function Diff({ text }: { text: string }) {
  return (
    <pre className="mt-2 max-h-96 overflow-auto rounded-lg bg-gray-100 p-3 text-[11px] leading-relaxed dark:bg-black/30">
      {text.split("\n").map((line, i) => {
        const tone = line.startsWith("+") && !line.startsWith("+++")
          ? "text-emerald-800 dark:text-emerald-300"
          : line.startsWith("-") && !line.startsWith("---")
            ? "text-red-800 dark:text-red-300"
            : "text-gray-800 dark:text-gray-300";
        return <span key={i} className={`block ${tone}`}>{line || " "}</span>;
      })}
    </pre>
  );
}

/* ── New run ── */

function NewRun({ usage, onStarted }: { usage?: Usage; onStarted: (id: number) => void }) {
  const queryClient = useQueryClient();
  const [goal, setGoal] = useState("");
  const [agentId, setAgentId] = useState("");
  const { data: agents = [] } = useQuery<AgentInfo[]>({ queryKey: ["agent-list"], queryFn: getAgentList });
  const start = useMutation({
    mutationFn: () => startAgentRun({ goal: goal.trim(), agent_id: agentId || undefined }),
    onSuccess: (run: Run) => {
      setGoal("");
      queryClient.invalidateQueries({ queryKey: ["agent-runs"] });
      queryClient.invalidateQueries({ queryKey: ["agent-usage"] });
      onStarted(run.id);
    },
  });
  const noModel = usage ? !usage.model_configured : false;
  const chosen = agents.find((a) => a.id === agentId);

  return (
    <form
      className={`${card} p-5`}
      onSubmit={(e) => {
        e.preventDefault();
        start.mutate();
      }}
    >
      <h2 className={heading}>Give an agent a task</h2>
      <p className={`mt-1 text-xs ${muted}`}>
        The agent works in the background and keeps going if you leave this page. Anything that changes data waits for approval first.
      </p>
      {noModel && (
        <p className="mt-3 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800/40 dark:bg-amber-900/20 dark:text-amber-200">
          No language model is configured, so agents cannot run. Add a provider and API key in{" "}
          <Link href="/settings" className="underline">Settings</Link>.
        </p>
      )}
      <div className="mt-4 grid gap-4 md:grid-cols-[240px_1fr]">
        <div>
          <label className={labelCls} htmlFor="run-agent">Agent</label>
          <select id="run-agent" className={inputCls} value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">General assistant</option>
            {agents.filter((a) => a.id !== "general").map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
          {chosen && <p className={`mt-1 text-[11px] ${muted}`}>{chosen.description}</p>}
        </div>
        <div>
          <label className={labelCls} htmlFor="run-goal">Task</label>
          <textarea
            id="run-goal"
            className={`${inputCls} min-h-[76px]`}
            placeholder="e.g. Review the open CRITICAL findings and tell me which three to fix first, with the evidence."
            value={goal}
            maxLength={4000}
            onChange={(e) => setGoal(e.target.value)}
          />
        </div>
      </div>
      {start.isError && (
        <p className="mt-3 text-xs text-red-700 dark:text-red-300">{errorText(start.error, "The run could not be started.")}</p>
      )}
      <div className="mt-4 flex justify-end">
        <button
          type="submit"
          disabled={start.isPending || noModel || goal.trim().length < 5}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {start.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          Start run
        </button>
      </div>
    </form>
  );
}

/* ── Approvals ── */

function ApprovalCard({ approval, showRun }: { approval: Approval; showRun?: (id: number) => void }) {
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");
  const decide = useMutation({
    mutationFn: (approve: boolean) => decideAgentApproval(approval.id, { approve, note: note.trim() }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-approvals"] });
      queryClient.invalidateQueries({ queryKey: ["agent-runs"] });
      queryClient.invalidateQueries({ queryKey: ["agent-run", approval.run_id] });
    },
  });
  const pending = approval.status === "pending";

  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50/60 p-4 dark:border-amber-800/40 dark:bg-amber-900/10">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-sm font-medium text-gray-900 dark:text-gray-100">{approval.summary ?? approval.tool_name}</p>
          <p className={`mt-1 text-[11px] ${muted}`}>
            {RISK_TEXT[approval.risk] ?? approval.risk} · tool <code>{approval.tool_name}</code> · requested by{" "}
            {approval.requested_by ?? "unknown"}
            {pending && approval.expires_at ? ` · expires ${formatTime(approval.expires_at)}` : ""}
          </p>
        </div>
        {showRun && (
          <button type="button" onClick={() => showRun(approval.run_id)} className="text-xs text-blue-700 underline dark:text-blue-300">
            Open run #{approval.run_id}
          </button>
        )}
      </div>
      {approval.reasoning && (
        <p className="mt-2 border-l-2 border-amber-300 pl-3 text-xs text-gray-700 dark:border-amber-800/60 dark:text-gray-300">
          Agent: {approval.reasoning}
        </p>
      )}
      {approval.preview && (
        <details className="mt-2" open={pending}>
          <summary className="cursor-pointer text-xs font-medium text-gray-800 dark:text-gray-200">Exactly what will change</summary>
          <Diff text={approval.preview} />
        </details>
      )}
      {!pending && (
        <p className={`mt-2 text-xs ${muted}`}>
          {STATUS_TEXT[approval.status] ?? approval.status}
          {approval.decided_by ? ` by ${approval.decided_by}` : ""}
          {approval.decision_note ? ` — ${approval.decision_note}` : ""}
        </p>
      )}
      {pending && approval.can_decide && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            className={`${inputCls} max-w-sm`}
            placeholder="Note (required to reject)"
            aria-label="Decision note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <button
            type="button"
            disabled={decide.isPending}
            onClick={() => decide.mutate(true)}
            className="inline-flex items-center gap-1 rounded-lg bg-emerald-700 px-3 py-2 text-xs font-medium text-white hover:bg-emerald-800 disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" /> Approve
          </button>
          <button
            type="button"
            disabled={decide.isPending || !note.trim()}
            onClick={() => decide.mutate(false)}
            className="inline-flex items-center gap-1 rounded-lg border border-red-300 px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800/50 dark:text-red-300 dark:hover:bg-red-900/20"
          >
            <X className="h-3.5 w-3.5" /> Reject
          </button>
        </div>
      )}
      {pending && !approval.can_decide && approval.blocked_reason && (
        <p className={`mt-2 text-xs ${muted}`}>You cannot decide this: {approval.blocked_reason}</p>
      )}
      {decide.isError && (
        <p className="mt-2 text-xs text-red-700 dark:text-red-300">{errorText(decide.error, "The decision could not be saved.")}</p>
      )}
    </div>
  );
}

/* ── Run detail ── */

function StepRow({ step }: { step: Step }) {
  const [open, setOpen] = useState(false);
  const title =
    step.kind === "model"
      ? "Model"
      : step.kind === "delegation"
        ? `Delegated to ${String(step.arguments?.target_agent ?? "another agent")}`
        : step.tool_name ?? "Tool";
  return (
    <li className="border-b border-gray-200 last:border-0 dark:border-white/[0.06]">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-gray-50 dark:hover:bg-white/[0.03]"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 text-gray-500" /> : <ChevronRight className="h-3.5 w-3.5 text-gray-500" />}
        <span className={`w-6 text-xs ${muted}`}>{step.seq}</span>
        <span className="flex-1 truncate text-sm text-gray-900 dark:text-gray-100">
          {step.kind === "model" ? title : <code>{title}</code>}
          {step.risk && step.risk !== "read" && <span className={`ml-2 text-[11px] ${muted}`}>{RISK_TEXT[step.risk]}</span>}
        </span>
        <span className={`text-[11px] ${muted}`}>
          {step.kind === "model" ? `${(step.input_tokens + step.output_tokens).toLocaleString()} tokens` : ""}
          {step.duration_ms != null ? ` ${(step.duration_ms / 1000).toFixed(1)}s` : ""}
        </span>
        <Badge status={step.status} />
      </button>
      {open && (
        <div className="space-y-2 px-4 pb-3 pl-14">
          {step.arguments && Object.keys(step.arguments).length > 0 && (
            <pre className="overflow-x-auto rounded-lg bg-gray-100 p-3 text-[11px] text-gray-800 dark:bg-black/30 dark:text-gray-300">
              {JSON.stringify(step.arguments, null, 2)}
            </pre>
          )}
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-gray-100 p-3 text-[11px] text-gray-800 dark:bg-black/30 dark:text-gray-300">
            {prettyJson(step.output) || "(no output)"}
          </pre>
        </div>
      )}
    </li>
  );
}

function RunPanel({ runId, onClose, onOpen }: { runId: number; onClose: () => void; onOpen: (id: number) => void }) {
  const queryClient = useQueryClient();
  const { data: run, isLoading, isError } = useQuery<RunDetail>({
    queryKey: ["agent-run", runId],
    queryFn: () => getAgentRun(runId),
    refetchInterval: (query) => (query.state.data && !ACTIVE.includes(query.state.data.status) ? false : 2000),
  });
  const cancel = useMutation({
    mutationFn: () => cancelAgentRun(runId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-run", runId] });
      queryClient.invalidateQueries({ queryKey: ["agent-runs"] });
      queryClient.invalidateQueries({ queryKey: ["agent-approvals"] });
    },
  });

  if (isLoading) return <div className={`${card} p-6 text-sm ${muted}`}>Loading run…</div>;
  if (isError || !run) return <div className={`${card} p-6 text-sm text-red-700 dark:text-red-300`}>This run could not be loaded.</div>;

  const waiting = run.approvals.filter((a) => a.status === "pending");
  const decided = run.approvals.filter((a) => a.status !== "pending");

  return (
    <section className={card} aria-label={`Run ${run.id}`}>
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-200 p-5 dark:border-white/[0.06]">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className={heading}>Run #{run.id} · {run.agent_name}</h2>
            <Badge status={run.status} />
          </div>
          <p className="mt-2 whitespace-pre-wrap text-sm text-gray-800 dark:text-gray-200">{run.goal}</p>
          <p className={`mt-2 text-[11px] ${muted}`}>
            Started {formatTime(run.created_at)} by {run.requested_by ?? "unknown"}
            {run.model ? ` · ${run.provider}/${run.model}` : ""} · {run.step_count} of {run.max_steps} model calls ·{" "}
            {(run.input_tokens + run.output_tokens).toLocaleString()} tokens
            {run.estimated_cost_usd != null ? ` · about $${run.estimated_cost_usd.toFixed(4)}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {ACTIVE.includes(run.status) && (
            <button
              type="button"
              disabled={cancel.isPending}
              onClick={() => cancel.mutate()}
              className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-white/[0.1] dark:text-gray-300 dark:hover:bg-white/[0.04]"
            >
              <Ban className="h-3.5 w-3.5" /> Stop run
            </button>
          )}
          <button type="button" onClick={onClose} aria-label="Close run" className="text-gray-500 hover:text-gray-800 dark:hover:text-gray-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {run.error && (
        <p className="mx-5 mt-4 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800/40 dark:bg-red-900/20 dark:text-red-200">
          {run.error}
        </p>
      )}

      {waiting.length > 0 && (
        <div className="space-y-3 p-5 pb-0">
          <h3 className={heading}>Waiting for a decision</h3>
          {waiting.map((a) => <ApprovalCard key={a.id} approval={a} />)}
        </div>
      )}

      {run.result && (
        <div className="p-5 pb-0">
          <h3 className={heading}>Answer</h3>
          <div className="mt-2 rounded-lg bg-gray-50 p-4 text-sm text-gray-900 dark:bg-white/[0.03] dark:text-gray-100">
            <Answer text={run.result} />
          </div>
        </div>
      )}

      <div className="p-5">
        <h3 className={heading}>What the agent did</h3>
        {run.steps.length === 0 ? (
          <p className={`mt-2 text-sm ${muted}`}>{run.status === "queued" ? "Waiting for a worker to pick this up." : "No steps recorded."}</p>
        ) : (
          <ol className="mt-2 rounded-lg border border-gray-200 dark:border-white/[0.06]">
            {run.steps.map((s) => <StepRow key={s.seq} step={s} />)}
          </ol>
        )}
      </div>

      {run.children.length > 0 && (
        <div className="px-5 pb-5">
          <h3 className={heading}>Delegated to other agents</h3>
          <ul className="mt-2 space-y-1">
            {run.children.map((c) => (
              <li key={c.id} className="flex items-center gap-2 text-sm">
                <button type="button" onClick={() => onOpen(c.id)} className="text-blue-700 underline dark:text-blue-300">
                  Run #{c.id} · {c.agent_name}
                </button>
                <Badge status={c.status} />
              </li>
            ))}
          </ul>
        </div>
      )}

      {decided.length > 0 && (
        <div className="space-y-3 px-5 pb-5">
          <h3 className={heading}>Decisions</h3>
          {decided.map((a) => <ApprovalCard key={a.id} approval={a} />)}
        </div>
      )}
    </section>
  );
}

/* ── Page ── */

export default function AgentRunsPage() {
  const [openRun, setOpenRun] = useState<number | null>(null);
  const { data: usage } = useQuery<Usage>({ queryKey: ["agent-usage"], queryFn: getAgentUsage, refetchInterval: 15000 });
  const { data: runs = [], isLoading } = useQuery<Run[]>({
    queryKey: ["agent-runs"],
    queryFn: () => getAgentRuns(),
    refetchInterval: 4000,
  });
  const { data: approvals = [] } = useQuery<Approval[]>({
    queryKey: ["agent-approvals"],
    queryFn: () => getAgentApprovals("pending"),
    refetchInterval: 4000,
  });

  return (
    <PageLayout title="Agent Runs" subtitle="Background tasks for AI agents, with every step recorded and every change approved">
      <div className="space-y-6">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className={`${card} p-4`}>
            <p className={`text-xs ${muted}`}>Model</p>
            <p className="mt-1 text-sm font-medium text-gray-900 dark:text-gray-100">
              {usage ? (usage.model_configured ? `${usage.provider} / ${usage.model}` : "Not configured") : "—"}
            </p>
          </div>
          <div className={`${card} p-4`}>
            <p className={`text-xs ${muted}`}>Tokens used this month</p>
            <p className="mt-1 text-sm font-medium text-gray-900 dark:text-gray-100">
              {usage ? usage.tokens_this_month.toLocaleString() : "—"}
              {usage && usage.monthly_budget > 0 ? ` of ${usage.monthly_budget.toLocaleString()}` : ""}
              {usage && usage.estimated_cost_usd != null ? ` · about $${usage.estimated_cost_usd.toFixed(2)}` : ""}
            </p>
          </div>
          <div className={`${card} p-4`}>
            <p className={`text-xs ${muted}`}>Runs this month</p>
            <p className="mt-1 text-sm font-medium text-gray-900 dark:text-gray-100">{usage ? usage.runs_this_month : "—"}</p>
          </div>
        </div>

        <NewRun usage={usage} onStarted={setOpenRun} />

        {approvals.length > 0 && (
          <section className={`${card} p-5`} aria-label="Pending approvals">
            <h2 className={`flex items-center gap-2 ${heading}`}>
              <ShieldQuestion className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              Waiting for a decision ({approvals.length})
            </h2>
            <div className="mt-3 space-y-3">
              {approvals.map((a) => <ApprovalCard key={a.id} approval={a} showRun={setOpenRun} />)}
            </div>
          </section>
        )}

        {openRun != null && <RunPanel key={openRun} runId={openRun} onClose={() => setOpenRun(null)} onOpen={setOpenRun} />}

        <section className={card} aria-label="Runs">
          <h2 className={`border-b border-gray-200 px-5 py-3 dark:border-white/[0.06] ${heading}`}>Runs</h2>
          {isLoading ? (
            <p className={`p-5 text-sm ${muted}`}>Loading…</p>
          ) : runs.length === 0 ? (
            <p className={`p-5 text-sm ${muted}`}>No runs yet. Give an agent a task above.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className={`text-left text-xs ${muted}`}>
                    <th className="px-5 py-2 font-medium">Run</th>
                    <th className="px-3 py-2 font-medium">Task</th>
                    <th className="px-3 py-2 font-medium">Status</th>
                    <th className="px-3 py-2 font-medium">Tokens</th>
                    <th className="px-3 py-2 font-medium">Started</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r) => (
                    <tr
                      key={r.id}
                      className={`border-t border-gray-200 dark:border-white/[0.06] ${openRun === r.id ? "bg-blue-50 dark:bg-blue-900/10" : ""}`}
                    >
                      <td className="whitespace-nowrap px-5 py-2.5">
                        <button type="button" onClick={() => setOpenRun(r.id)} className="text-blue-700 underline dark:text-blue-300">
                          #{r.id}
                        </button>
                        <span className={`ml-2 text-xs ${muted}`}>{r.agent_name}</span>
                      </td>
                      <td className="max-w-md truncate px-3 py-2.5 text-gray-900 dark:text-gray-100" title={r.goal}>{r.goal}</td>
                      <td className="px-3 py-2.5"><Badge status={r.status} /></td>
                      <td className={`whitespace-nowrap px-3 py-2.5 text-xs ${muted}`}>{(r.input_tokens + r.output_tokens).toLocaleString()}</td>
                      <td className={`whitespace-nowrap px-3 py-2.5 text-xs ${muted}`}>{formatTime(r.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </PageLayout>
  );
}
