"use client";

import React from "react";

interface GlassmorphicCardProps {
  children: React.ReactNode;
  className?: string;
  intensity?: "low" | "medium" | "high";
  glow?: boolean;
  glowColor?: string;
}

const intensityStyles = {
  low: "bg-white dark:bg-white/[0.02] border-slate-200 dark:border-white/[0.04]",
  medium: "bg-white dark:bg-white/[0.05] border-slate-200 dark:border-white/[0.08]",
  high: "bg-white dark:bg-white/[0.08] border-slate-200 dark:border-white/[0.12]",
} as const;

export function GlassmorphicCard({
  children,
  className = "",
  intensity = "medium",
  glow = false,
  glowColor = "rgba(249,115,22,0.1)",
}: GlassmorphicCardProps) {
  return (
    <div
      className={`backdrop-blur-xl rounded-xl border transition-all duration-300 hover:border-slate-300 dark:hover:border-white/[0.15] ${intensityStyles[intensity]} ${className}`}
      style={glow ? { boxShadow: `0 0 30px ${glowColor}` } : undefined}
    >
      {children}
    </div>
  );
}
