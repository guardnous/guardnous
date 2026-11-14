"use client";

import React from "react";
import {
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Circle,
  Bot,
} from "lucide-react";
import { GlassmorphicCard } from "./GlassmorphicCard";

interface PlanStep {
  number: number;
  description: string;
  agent: string;
  status: "pending" | "running" | "complete" | "error";
  dependsOn: number[];
}

interface PlanDisplayProps {
  steps: PlanStep[];
  strategy: "single" | "sequential" | "dag";
}

const stepStatusIcon: Record<PlanStep["status"], React.ReactNode> = {
  pending: <Circle className="h-4 w-4 text-zinc-500" />,
  running: <Loader2 className="h-4 w-4 text-orange-400 animate-spin" />,
  complete: <CheckCircle2 className="h-4 w-4 text-emerald-400" />,
  error: <AlertTriangle className="h-4 w-4 text-red-400" />,
};

const stepStatusBorder: Record<PlanStep["status"], string> = {
  pending: "border-zinc-700",
  running: "border-orange-500/50",
  complete: "border-emerald-500/30",
  error: "border-red-500/30",
};

const strategyLabel: Record<PlanDisplayProps["strategy"], string> = {
  single: "Single Agent",
  sequential: "Sequential",
  dag: "Parallel (DAG)",
};

export function PlanDisplay({ steps, strategy }: PlanDisplayProps) {
  if (steps.length === 0) return null;

  const completedCount = steps.filter((s) => s.status === "complete").length;

  // Build dependency groups for DAG display
  const dagLevels: PlanStep[][] = [];
  if (strategy === "dag") {
    const placed = new Set<number>();
    while (placed.size < steps.length) {
      const level = steps.filter(
        (s) =>
          !placed.has(s.number) &&
          s.dependsOn.every((d) => placed.has(d))
      );
      if (level.length === 0) break; // prevent infinite loop on circular deps
      dagLevels.push(level);
      level.forEach((s) => placed.add(s.number));
    }
  }

  return (
    <GlassmorphicCard intensity="low" className="p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-white/60">
            Execution Plan
          </span>
          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-white/[0.06] text-white/40 border border-white/[0.06]">
            {strategyLabel[strategy]}
          </span>
        </div>
        <span className="text-[11px] text-white/30">
          {completedCount}/{steps.length} complete
        </span>
      </div>

      {strategy === "dag" ? (
        /* DAG layout: rows of parallel steps */
        <div className="space-y-3">
          {dagLevels.map((level, levelIdx) => (
            <div key={levelIdx}>
              {levelIdx > 0 && (
                <div className="flex justify-center my-1.5">
                  <div className="h-4 w-px bg-white/[0.08]" />
                </div>
              )}
              <div className="flex gap-2 flex-wrap">
                {level.map((step) => (
                  <StepItem key={step.number} step={step} />
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* Sequential / single layout: vertical stepper */
        <div className="relative">
          {steps.map((step, idx) => (
            <div key={step.number} className="flex gap-3">
              {/* Vertical connector */}
              <div className="flex flex-col items-center">
                <div
                  className={`flex-shrink-0 h-7 w-7 rounded-full border-2 flex items-center justify-center ${stepStatusBorder[step.status]} bg-[#0a0a0f]`}
                >
                  {stepStatusIcon[step.status]}
                </div>
                {idx < steps.length - 1 && (
                  <div
                    className={`w-px flex-1 min-h-[20px] ${
                      step.status === "complete"
                        ? "bg-emerald-500/30"
                        : "bg-white/[0.06]"
                    }`}
                  />
                )}
              </div>

              {/* Step content */}
              <div className={`pb-4 ${idx === steps.length - 1 ? "pb-0" : ""}`}>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-sm font-medium ${
                      step.status === "running"
                        ? "text-orange-400"
                        : step.status === "complete"
                          ? "text-white/70"
                          : "text-white/40"
                    }`}
                  >
                    {step.description}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <Bot className="h-3 w-3 text-white/25" />
                  <span className="text-[11px] text-white/30">
                    {step.agent}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </GlassmorphicCard>
  );
}

function StepItem({ step }: { step: PlanStep }) {
  return (
    <div
      className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border ${stepStatusBorder[step.status]} bg-white/[0.02] flex-1 min-w-[140px]`}
    >
      {stepStatusIcon[step.status]}
      <div className="min-w-0">
        <p
          className={`text-xs font-medium truncate ${
            step.status === "running"
              ? "text-orange-400"
              : step.status === "complete"
                ? "text-white/70"
                : "text-white/40"
          }`}
        >
          {step.description}
        </p>
        <p className="text-[10px] text-white/25 truncate">{step.agent}</p>
      </div>
    </div>
  );
}
