"use client";

import React, { useId, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Circle, Loader2, MinusCircle } from "lucide-react";
import { layoutPlan, planSummary, type PlanStep } from "./planLayout";

interface PlanVisualizationProps {
  steps: PlanStep[];
  /** True once the answer has finished streaming. */
  complete: boolean;
}

type Shown = "waiting" | "running" | "done" | "failed" | "not_run" | "interrupted";

const SHOWN: Record<Shown, { label: string; text: string; border: string; icon: React.ReactNode }> = {
  waiting: {
    label: "Waiting",
    text: "text-slate-600 dark:text-slate-300",
    border: "border-slate-200 dark:border-slate-600",
    icon: <Circle className="h-3 w-3" aria-hidden="true" />,
  },
  running: {
    label: "Running",
    text: "text-orange-700 dark:text-orange-300",
    border: "border-orange-400 dark:border-orange-400/70",
    icon: <Loader2 className="h-3 w-3 animate-spin motion-reduce:animate-none" aria-hidden="true" />,
  },
  done: {
    label: "Done",
    text: "text-emerald-700 dark:text-emerald-300",
    border: "border-emerald-300 dark:border-emerald-500/50",
    icon: <CheckCircle2 className="h-3 w-3" aria-hidden="true" />,
  },
  failed: {
    label: "Failed",
    text: "text-red-700 dark:text-red-300",
    border: "border-red-300 dark:border-red-500/60",
    icon: <AlertTriangle className="h-3 w-3" aria-hidden="true" />,
  },
  not_run: {
    label: "Not run",
    text: "text-slate-600 dark:text-slate-300",
    border: "border-dashed border-slate-300 dark:border-slate-600",
    icon: <MinusCircle className="h-3 w-3" aria-hidden="true" />,
  },
  interrupted: {
    label: "Interrupted",
    text: "text-amber-700 dark:text-amber-300",
    border: "border-amber-300 dark:border-amber-500/60",
    icon: <MinusCircle className="h-3 w-3" aria-hidden="true" />,
  },
};

/** Once the answer is over, a step that never started or never finished says so. */
function shownState(step: PlanStep, complete: boolean): Shown {
  if (!complete) return step.state;
  if (step.state === "waiting") return "not_run";
  if (step.state === "running") return "interrupted";
  return step.state;
}

const CARD_W = 188;
const CARD_H = 68;
const COL_GAP = 44;
const ROW_GAP = 12;

function StepCard({ step, complete, style }: { step: PlanStep; complete: boolean; style?: React.CSSProperties }) {
  const shown = SHOWN[shownState(step, complete)];
  return (
    <div
      style={style}
      className={`flex flex-col justify-between rounded-lg border bg-white px-2.5 py-1.5 dark:bg-slate-900 ${shown.border}`}
    >
      <p className="truncate text-xs font-semibold text-slate-800 dark:text-slate-100" title={step.agentName}>
        {step.agentName}
      </p>
      <p className="truncate text-[11px] text-slate-600 dark:text-slate-300" title={step.description}>
        {step.description || "No task description"}
      </p>
      <p className={`flex items-center gap-1 text-[11px] font-medium ${shown.text}`}>
        {shown.icon}
        {shown.label}
      </p>
    </div>
  );
}

const joinNumbers = (numbers: number[]) =>
  numbers.length <= 1 ? numbers.join("") : `${numbers.slice(0, -1).join(", ")} and ${numbers[numbers.length - 1]}`;

/**
 * The execution plan of an answer produced by several agents: steps in columns
 * by dependency depth, with an arrow from each step to the steps that wait for it.
 * Renders nothing for a plan with fewer than two steps.
 */
export function PlanVisualization({ steps, complete }: PlanVisualizationProps) {
  const markerId = useId();
  const panelId = useId();
  const [userOpen, setUserOpen] = useState<boolean | null>(null);
  const layout = useMemo(() => layoutPlan(steps), [steps]);

  if (steps.length < 2) return null;

  const open = userOpen ?? !complete;
  const byNumber = new Map(steps.map((s) => [s.number, s]));

  // Card positions: one column per layer, shorter columns centred vertically.
  const rows = Math.max(1, ...layout.layers.map((layer) => layer.length));
  const height = rows * CARD_H + (rows - 1) * ROW_GAP;
  const width = layout.layers.length * CARD_W + Math.max(0, layout.layers.length - 1) * COL_GAP;
  const position = new Map<number, { x: number; y: number }>();
  layout.layers.forEach((layer, column) => {
    const columnHeight = layer.length * CARD_H + (layer.length - 1) * ROW_GAP;
    layer.forEach((number, row) => {
      position.set(number, {
        x: column * (CARD_W + COL_GAP),
        y: (height - columnHeight) / 2 + row * (CARD_H + ROW_GAP),
      });
    });
  });

  return (
    <section
      aria-label="Execution plan"
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
        <span aria-live="polite">{planSummary(steps)}</span>
        <span className="ml-auto text-[11px] font-normal text-slate-500 dark:text-slate-400">
          {open ? "Hide" : "Show"}
        </span>
      </button>

      {open && (
        <div id={panelId} className="border-t border-slate-200 p-3 dark:border-slate-700">
          {layout.kind === "layered" ? (
            <>
              <div className="overflow-x-auto pb-1" aria-hidden="true">
                <div className="relative" style={{ width, height }}>
                  <svg className="absolute inset-0" width={width} height={height} focusable="false">
                    <defs>
                      <marker id={markerId} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
                        <path d="M0,0 L8,4 L0,8 z" className="fill-slate-400 dark:fill-slate-400" />
                      </marker>
                    </defs>
                    {layout.edges.map((edge) => {
                      const from = position.get(edge.from);
                      const to = position.get(edge.to);
                      if (!from || !to) return null;
                      const x1 = from.x + CARD_W;
                      const y1 = from.y + CARD_H / 2;
                      const x2 = to.x - 2;
                      const y2 = to.y + CARD_H / 2;
                      const bend = COL_GAP / 2;
                      return (
                        <path
                          key={`${edge.from}-${edge.to}`}
                          d={`M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`}
                          fill="none"
                          strokeWidth={1.5}
                          markerEnd={`url(#${markerId})`}
                          className="stroke-slate-400 dark:stroke-slate-400"
                        />
                      );
                    })}
                  </svg>
                  {layout.order.map((number) => {
                    const step = byNumber.get(number);
                    const at = position.get(number);
                    if (!step || !at) return null;
                    return (
                      <StepCard
                        key={number}
                        step={step}
                        complete={complete}
                        style={{ position: "absolute", left: at.x, top: at.y, width: CARD_W, height: CARD_H }}
                      />
                    );
                  })}
                </div>
              </div>
              {/* The same plan as text, for screen readers. */}
              <ol className="sr-only">
                {layout.order.map((number) => {
                  const step = byNumber.get(number);
                  if (!step) return null;
                  return (
                    <li key={number}>
                      Step {step.number}: {step.agentName}. {step.description} State:{" "}
                      {SHOWN[shownState(step, complete)].label}.{" "}
                      {step.dependsOn.length > 0
                        ? `Runs after ${step.dependsOn.length === 1 ? "step" : "steps"} ${joinNumbers(Array.from(new Set(step.dependsOn)))}.`
                        : "Does not wait for another step."}
                    </li>
                  );
                })}
              </ol>
            </>
          ) : (
            /* The dependencies cannot be drawn as a graph (a loop, or a step that is not in the plan). */
            <ol className="space-y-2">
              {steps.map((step, index) => (
                <li key={`${step.number}-${index}`} className="flex items-start gap-2">
                  <span className="mt-1.5 w-5 flex-shrink-0 text-right text-[11px] text-slate-500 dark:text-slate-400">
                    {step.number}.
                  </span>
                  <div className="min-w-0 flex-1">
                    <StepCard step={step} complete={complete} style={{ minHeight: CARD_H }} />
                    {step.dependsOn.length > 0 && (
                      <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                        Listed as running after {step.dependsOn.length === 1 ? "step" : "steps"}{" "}
                        {joinNumbers(Array.from(new Set(step.dependsOn)))}
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </section>
  );
}
