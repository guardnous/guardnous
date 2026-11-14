"use client";

import React, { useId, useState } from "react";
import { ArrowRight, ChevronDown, ChevronRight } from "lucide-react";
import { agentLabel } from "./planLayout";

export interface AgentHandoff {
  from: string;
  fromName: string;
  to: string;
  toName: string;
  /** Short context passed with the handoff, as sent by the server. */
  summary: string;
  step?: number;
}

/** Read an `agent_handoff` stream event: `{from, from_name, to, to_name, task, step}`. */
export function parseHandoff(event: Record<string, unknown>): AgentHandoff | null {
  const from = typeof event.from === "string" ? event.from : "";
  const to = typeof event.to === "string" ? event.to : "";
  if (!from || !to) return null;
  const summary = typeof event.task === "string" ? event.task : typeof event.summary === "string" ? event.summary : "";
  return {
    from,
    fromName: agentLabel(event.from_name, from),
    to,
    toName: agentLabel(event.to_name, to),
    summary,
    step: typeof event.step === "number" ? event.step : undefined,
  };
}

interface HandoffVisualizationProps {
  handoffs: AgentHandoff[];
  /** True once the answer has finished streaming. */
  complete: boolean;
}

/**
 * Delegations between agents during one answer: who handed work to whom, and
 * the short context that went with it. Renders nothing when there are none.
 */
export function HandoffVisualization({ handoffs, complete }: HandoffVisualizationProps) {
  const panelId = useId();
  const [userOpen, setUserOpen] = useState<boolean | null>(null);

  if (handoffs.length === 0) return null;

  const open = userOpen ?? !complete;
  const count = `${handoffs.length} ${handoffs.length === 1 ? "handoff" : "handoffs"}`;

  return (
    <section
      aria-label="Agent handoffs"
      className="rounded-xl border border-slate-200 bg-white/80 backdrop-blur dark:border-slate-700 dark:bg-slate-800/70"
    >
      <button
        type="button"
        onClick={() => setUserOpen(!open)}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-xs font-medium text-slate-700 hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500 dark:text-slate-200 dark:hover:bg-slate-700/50"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
        )}
        <span>Handoffs: {count}</span>
        <span className="ml-auto text-[11px] font-normal text-slate-500 dark:text-slate-400">
          {open ? "Hide" : "Show"}
        </span>
      </button>

      {open && (
        <ol id={panelId} className="space-y-2 border-t border-slate-200 p-3 dark:border-slate-700">
          {handoffs.map((handoff, index) => (
            <li
              key={`${index}-${handoff.from}-${handoff.to}`}
              /* The entrance runs once when a row arrives during the answer; rows opened later appear at once. */
              className={`rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 dark:border-slate-600 dark:bg-slate-900 ${
                complete ? "" : "animate-fade-in-up motion-reduce:animate-none"
              }`}
            >
              <p className="flex min-w-0 items-center gap-1.5 text-xs font-semibold text-slate-800 dark:text-slate-100">
                <span className="truncate" title={handoff.fromName}>
                  {handoff.fromName}
                </span>
                <ArrowRight className="h-3.5 w-3.5 flex-shrink-0 text-orange-600 dark:text-orange-400" aria-hidden="true" />
                <span className="sr-only">hands off to</span>
                <span className="truncate" title={handoff.toName}>
                  {handoff.toName}
                </span>
                {handoff.step !== undefined && (
                  <span className="ml-auto flex-shrink-0 text-[11px] font-normal text-slate-500 dark:text-slate-400">
                    Step {handoff.step}
                  </span>
                )}
              </p>
              {handoff.summary && (
                <p className="mt-0.5 line-clamp-2 text-[11px] text-slate-600 dark:text-slate-300" title={handoff.summary}>
                  {handoff.summary}
                </p>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
