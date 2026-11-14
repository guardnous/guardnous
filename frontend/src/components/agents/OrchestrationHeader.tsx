"use client";

import React from "react";
import { Shield, Zap, Eye, Activity } from "lucide-react";

interface OrchestrationHeaderProps {
  mode: "single" | "supervised" | "idle";
  activeAgents: number;
  totalSteps: number;
  completedSteps: number;
  strategy?: string;
}

const modeConfig = {
  single: {
    label: "Single Agent",
    icon: Shield,
    color: "text-blue-700 dark:text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
  },
  supervised: {
    label: "Supervised",
    icon: Eye,
    color: "text-orange-700 dark:text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
  },
  idle: {
    label: "Idle",
    icon: Activity,
    color: "text-zinc-600 dark:text-zinc-500",
    bg: "bg-zinc-500/10",
    border: "border-zinc-500/20",
  },
};

export function OrchestrationHeader({
  mode,
  activeAgents,
  totalSteps,
  completedSteps,
  strategy,
}: OrchestrationHeaderProps) {
  const cfg = modeConfig[mode];
  const Icon = cfg.icon;
  const progress = totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0;

  if (mode === "idle" && activeAgents === 0) {
    return null;
  }

  return (
    <div className="backdrop-blur-xl bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.06] rounded-lg px-3 py-2 flex items-center gap-3 transition-all duration-300">
      {/* Mode badge */}
      <div
        className={`flex items-center gap-1.5 px-2 py-0.5 rounded-md border ${cfg.bg} ${cfg.border}`}
      >
        <Icon className={`h-3 w-3 ${cfg.color}`} />
        <span className={`text-[11px] font-medium ${cfg.color}`}>
          {cfg.label}
        </span>
      </div>

      {/* Agent count */}
      {activeAgents > 0 && (
        <div className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-white/50">
          <Zap className="h-3 w-3 text-orange-600 dark:text-orange-400" />
          <span>
            {activeAgents} agent{activeAgents !== 1 ? "s" : ""} active
          </span>
        </div>
      )}

      {/* Progress bar */}
      {totalSteps > 0 && (
        <div className="flex items-center gap-2 flex-1 max-w-[200px]">
          <div className="flex-1 h-1 rounded-full bg-slate-200 dark:bg-white/[0.06] overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-orange-500 to-orange-400 transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
          <span className="text-[11px] text-slate-600 dark:text-white/30 flex-shrink-0">
            {completedSteps}/{totalSteps}
          </span>
        </div>
      )}

      {/* Strategy label */}
      {strategy && (
        <span className="ml-auto text-[10px] text-slate-600 dark:text-white/25 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.04]">
          {strategy}
        </span>
      )}
    </div>
  );
}
