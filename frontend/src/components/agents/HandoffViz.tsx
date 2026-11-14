"use client";

import React from "react";
import { ArrowRight, Bot, Zap } from "lucide-react";
import { GlassmorphicCard } from "./GlassmorphicCard";

interface Handoff {
  from: string;
  to: string;
  task: string;
  timestamp: number;
}

interface HandoffVizProps {
  handoffs: Handoff[];
}

function AgentNode({
  name,
  isActive,
}: {
  name: string;
  isActive: boolean;
}) {
  return (
    <div
      className={`flex flex-col items-center gap-1.5 ${
        isActive ? "scale-105" : ""
      } transition-transform duration-300`}
    >
      <div
        className={`h-10 w-10 rounded-xl flex items-center justify-center border transition-all duration-300 ${
          isActive
            ? "bg-orange-500/15 border-orange-500/40 shadow-[0_0_20px_rgba(249,115,22,0.15)]"
            : "bg-white/[0.04] border-white/[0.08]"
        }`}
      >
        <Bot
          className={`h-4 w-4 ${isActive ? "text-orange-400" : "text-white/40"}`}
        />
      </div>
      <span
        className={`text-[10px] font-medium max-w-[80px] truncate ${
          isActive ? "text-orange-400" : "text-white/50"
        }`}
      >
        {name}
      </span>
    </div>
  );
}

function ConnectorArrow({
  task,
  isActive,
}: {
  task: string;
  isActive: boolean;
}) {
  return (
    <div className="flex flex-col items-center gap-1 px-2">
      {/* Task label */}
      <span className="text-[9px] text-white/30 max-w-[100px] truncate text-center leading-tight">
        {task}
      </span>
      {/* Arrow line */}
      <div className="flex items-center gap-0.5">
        <div
          className={`h-px w-8 transition-colors duration-300 ${
            isActive
              ? "bg-gradient-to-r from-orange-500/60 to-orange-400/60"
              : "bg-white/10"
          }`}
        />
        {isActive ? (
          <Zap className="h-3 w-3 text-orange-400 animate-pulse" />
        ) : (
          <ArrowRight className="h-3 w-3 text-white/20" />
        )}
        <div
          className={`h-px w-8 transition-colors duration-300 ${
            isActive
              ? "bg-gradient-to-r from-orange-400/60 to-orange-500/60"
              : "bg-white/10"
          }`}
        />
      </div>
    </div>
  );
}

export function HandoffViz({ handoffs }: HandoffVizProps) {
  if (handoffs.length === 0) return null;

  const lastIdx = handoffs.length - 1;

  // Collect unique agents in order
  const agentSequence: string[] = [];
  handoffs.forEach((h) => {
    if (!agentSequence.includes(h.from)) agentSequence.push(h.from);
    if (!agentSequence.includes(h.to)) agentSequence.push(h.to);
  });

  return (
    <GlassmorphicCard intensity="low" className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <Zap className="h-3.5 w-3.5 text-orange-400" />
        <span className="text-xs font-medium text-white/60">
          Agent Handoffs
        </span>
        <span className="text-[10px] text-white/30">
          {handoffs.length} handoff{handoffs.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Horizontal flow */}
      <div className="flex items-center overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-white/10">
        {handoffs.map((handoff, idx) => {
          const isActive = idx === lastIdx;
          return (
            <React.Fragment key={`${handoff.from}-${handoff.to}-${handoff.timestamp}`}>
              {idx === 0 && (
                <AgentNode name={handoff.from} isActive={false} />
              )}
              <ConnectorArrow task={handoff.task} isActive={isActive} />
              <AgentNode name={handoff.to} isActive={isActive} />
            </React.Fragment>
          );
        })}
      </div>
    </GlassmorphicCard>
  );
}
