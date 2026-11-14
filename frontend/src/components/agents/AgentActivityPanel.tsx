"use client";

import React from "react";
import { Activity, ChevronRight, ChevronLeft } from "lucide-react";
import { AgentCard } from "./AgentCard";
import { GlassmorphicCard } from "./GlassmorphicCard";

interface AgentInfo {
  id: string;
  name: string;
  status: "thinking" | "tool_calling" | "complete" | "waiting" | "error";
  tool?: string;
  findings?: number;
  duration?: number;
  icon?: string;
}

interface AgentActivityPanelProps {
  agents: AgentInfo[];
  isOpen: boolean;
  onToggle: () => void;
}

export function AgentActivityPanel({
  agents,
  isOpen,
  onToggle,
}: AgentActivityPanelProps) {
  const completedCount = agents.filter((a) => a.status === "complete").length;
  const progress = agents.length > 0 ? (completedCount / agents.length) * 100 : 0;

  return (
    <>
      {/* Toggle button (always visible) */}
      <button
        onClick={onToggle}
        className="fixed right-0 top-1/2 -translate-y-1/2 z-50 flex items-center gap-1.5 px-2 py-3 rounded-l-lg bg-white dark:bg-white/[0.06] border border-r-0 border-slate-200 dark:border-white/[0.08] backdrop-blur-xl text-slate-600 dark:text-white/60 hover:text-slate-900 dark:hover:text-white/90 hover:bg-slate-100 dark:hover:bg-white/[0.1] transition-all"
        aria-label={isOpen ? "Close agent panel" : "Open agent panel"}
      >
        {isOpen ? (
          <ChevronRight className="h-4 w-4" />
        ) : (
          <>
            <Activity className="h-4 w-4 text-orange-600 dark:text-orange-400" />
            {agents.length > 0 && (
              <span className="text-xs font-medium text-orange-700 dark:text-orange-400">
                {agents.length}
              </span>
            )}
            <ChevronLeft className="h-4 w-4" />
          </>
        )}
      </button>

      {/* Panel */}
      <div
        className={`fixed right-0 top-0 h-full z-40 transition-transform duration-300 ease-in-out ${
          isOpen ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <GlassmorphicCard
          intensity="high"
          className="h-full w-80 rounded-none rounded-l-2xl border-r-0 flex flex-col"
        >
          {/* Header */}
          <div className="p-4 border-b border-slate-200 dark:border-white/[0.06]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-orange-600 dark:text-orange-400" />
                <h2 className="text-sm font-semibold text-slate-900 dark:text-white/90">
                  Agent Activity
                </h2>
                <span className="px-1.5 py-0.5 rounded-full bg-orange-500/15 text-orange-700 dark:text-orange-400 text-[10px] font-medium">
                  {agents.length}
                </span>
              </div>
            </div>

            {/* Progress bar */}
            {agents.length > 0 && (
              <div className="mt-3">
                <div className="flex items-center justify-between text-[11px] text-slate-600 dark:text-white/40 mb-1">
                  <span>Progress</span>
                  <span>
                    {completedCount}/{agents.length}
                  </span>
                </div>
                <div className="h-1 rounded-full bg-slate-200 dark:bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-orange-500 to-orange-400 transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Agent list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {agents.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-600 dark:text-white/30 text-sm">
                <Activity className="h-8 w-8 mb-2 opacity-40" />
                <span>No active agents</span>
              </div>
            ) : (
              agents.map((agent) => (
                <AgentCard
                  key={agent.id}
                  agentId={agent.id}
                  agentName={agent.name}
                  status={agent.status}
                  currentTool={agent.tool}
                  findings={agent.findings}
                  duration={agent.duration}
                  icon={agent.icon}
                />
              ))
            )}
          </div>
        </GlassmorphicCard>
      </div>
    </>
  );
}
