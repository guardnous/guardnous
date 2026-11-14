"use client";

import React, { useEffect, useRef } from "react";
import { Brain } from "lucide-react";
import { GlassmorphicCard } from "./GlassmorphicCard";

interface Thought {
  agentId: string;
  agentName: string;
  content: string;
  timestamp: number;
}

interface ThinkingStreamProps {
  thoughts: Thought[];
  isStreaming: boolean;
}

function TypingIndicator() {
  return (
    <span className="inline-flex gap-0.5 ml-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1 w-1 rounded-full bg-orange-600 dark:bg-orange-400 animate-bounce"
          style={{ animationDelay: `${i * 150}ms` }}
        />
      ))}
    </span>
  );
}

export function ThinkingStream({ thoughts, isStreaming }: ThinkingStreamProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [thoughts]);

  if (thoughts.length === 0 && !isStreaming) return null;

  return (
    <GlassmorphicCard intensity="low" className="overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2 border-b border-slate-200 dark:border-white/[0.06] flex items-center gap-2">
        <Brain className="h-3.5 w-3.5 text-orange-600 dark:text-orange-400" />
        <span className="text-xs font-medium text-slate-700 dark:text-white/60">
          Agent Reasoning
        </span>
        {isStreaming && (
          <span className="ml-auto flex items-center gap-1 text-[10px] text-orange-700 dark:text-orange-400">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-orange-400 opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-orange-500" />
            </span>
            Live
          </span>
        )}
      </div>

      {/* Stream */}
      <div
        ref={scrollRef}
        className="max-h-60 overflow-y-auto p-2 space-y-1.5 scrollbar-thin scrollbar-thumb-slate-300 dark:scrollbar-thumb-white/10"
      >
        {thoughts.map((thought, idx) => {
          const isLatest = idx === thoughts.length - 1;
          return (
            <div
              key={`${thought.agentId}-${thought.timestamp}-${idx}`}
              className="flex gap-2 group"
            >
              {/* Orange left border */}
              <div className="w-0.5 flex-shrink-0 rounded-full bg-orange-300 dark:bg-orange-500/30" />

              <div className="flex-1 min-w-0 py-0.5">
                <span className="text-[10px] font-medium text-orange-700 dark:text-orange-400/70">
                  {thought.agentName}
                </span>
                <p className="text-xs text-slate-700 dark:text-white/50 leading-relaxed mt-0.5">
                  {thought.content}
                  {isLatest && isStreaming && <TypingIndicator />}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </GlassmorphicCard>
  );
}
