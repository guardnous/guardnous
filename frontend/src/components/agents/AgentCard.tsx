"use client";

import React, { useEffect, useState } from "react";
import {
  Bot,
  Cog,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Wrench,
} from "lucide-react";
import { GlassmorphicCard } from "./GlassmorphicCard";

interface AgentCardProps {
  agentId: string;
  agentName: string;
  status: "thinking" | "tool_calling" | "complete" | "waiting" | "error";
  currentTool?: string;
  findings?: number;
  duration?: number;
  icon?: string;
}

const statusConfig = {
  thinking: {
    label: "Thinking",
    color: "text-orange-700 dark:text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
  },
  tool_calling: {
    label: "Calling Tool",
    color: "text-blue-700 dark:text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
  },
  complete: {
    label: "Complete",
    color: "text-emerald-700 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
  },
  waiting: {
    label: "Waiting",
    color: "text-zinc-600 dark:text-zinc-400",
    bg: "bg-zinc-500/10",
    border: "border-zinc-500/30",
  },
  error: {
    label: "Error",
    color: "text-red-700 dark:text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
  },
};

function StatusIndicator({ status }: { status: AgentCardProps["status"] }) {
  if (status === "thinking") {
    return (
      <span className="relative flex h-2.5 w-2.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-orange-400 opacity-75" />
        <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-orange-500" />
      </span>
    );
  }
  if (status === "tool_calling") {
    return <Cog className="h-3.5 w-3.5 text-blue-700 dark:text-blue-400 animate-spin" />;
  }
  if (status === "complete") {
    return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-400" />;
  }
  if (status === "error") {
    return <AlertTriangle className="h-3.5 w-3.5 text-red-700 dark:text-red-400" />;
  }
  return (
    <span className="inline-flex h-2.5 w-2.5 rounded-full bg-zinc-500" />
  );
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

export function AgentCard({
  agentName,
  status,
  currentTool,
  findings,
  duration,
  icon,
}: AgentCardProps) {
  const [visible, setVisible] = useState(false);
  const cfg = statusConfig[status];

  useEffect(() => {
    const id = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(id);
  }, []);

  return (
    <GlassmorphicCard
      intensity="low"
      glow={status === "thinking" || status === "tool_calling"}
      className={`p-3 transition-all duration-500 ${visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"}`}
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div className="flex-shrink-0 h-8 w-8 rounded-lg bg-slate-100 dark:bg-white/[0.06] flex items-center justify-center text-lg">
          {icon ?? <Bot className="h-4 w-4 text-orange-600 dark:text-orange-400" />}
        </div>

        <div className="flex-1 min-w-0">
          {/* Name + status badge */}
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-900 dark:text-white/90 truncate">
              {agentName}
            </span>
            <span
              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium ${cfg.bg} ${cfg.color} ${cfg.border} border`}
            >
              <StatusIndicator status={status} />
              {cfg.label}
            </span>
          </div>

          {/* Current tool */}
          {currentTool && status === "tool_calling" && (
            <div className="mt-1.5 flex items-center gap-1.5 text-xs text-slate-600 dark:text-white/50">
              <Wrench className="h-3 w-3" />
              <span className="truncate">{currentTool}</span>
            </div>
          )}

          {/* Footer stats */}
          <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-600 dark:text-white/40">
            {findings !== undefined && (
              <span>{findings} finding{findings !== 1 ? "s" : ""}</span>
            )}
            {duration !== undefined && (
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {formatDuration(duration)}
              </span>
            )}
          </div>
        </div>
      </div>
    </GlassmorphicCard>
  );
}
