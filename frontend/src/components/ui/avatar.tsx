"use client";

import React from "react";

const GRADIENTS = [
  "from-orange-400 to-pink-500",
  "from-blue-400 to-indigo-500",
  "from-green-400 to-emerald-500",
  "from-purple-400 to-violet-500",
  "from-rose-400 to-red-500",
  "from-cyan-400 to-blue-500",
  "from-amber-400 to-orange-500",
  "from-teal-400 to-green-500",
];

function hashName(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return Math.abs(hash);
}

const SIZES = {
  sm: "w-7 h-7 text-xs",
  md: "w-9 h-9 text-sm",
  lg: "w-12 h-12 text-base",
};

interface AvatarProps {
  name: string;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export default function Avatar({ name, size = "md", className = "" }: AvatarProps) {
  const gradient = GRADIENTS[hashName(name) % GRADIENTS.length];
  const initials = name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div
      className={`bg-gradient-to-br ${gradient} rounded-full flex items-center justify-center text-white font-semibold ${SIZES[size]} ${className}`}
    >
      {initials}
    </div>
  );
}
