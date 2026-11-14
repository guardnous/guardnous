"use client";

import React, { useRef, useEffect } from "react";

interface DropdownMenuProps {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  className?: string;
}

export function DropdownMenu({ open, onClose, children, className = "" }: DropdownMenuProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={ref}
      className={`absolute right-0 top-full mt-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl py-1 z-50 min-w-[200px] animate-scale-in ${className}`}
    >
      {children}
    </div>
  );
}

export function DropdownItem({
  onClick,
  children,
  danger,
}: {
  onClick?: () => void;
  children: React.ReactNode;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-2 text-sm flex items-center gap-2 transition-colors ${
        danger
          ? "text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
          : "text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50"
      }`}
    >
      {children}
    </button>
  );
}

export function DropdownSeparator() {
  return <div className="my-1 border-t border-gray-100 dark:border-gray-700" />;
}

export function DropdownLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-gray-100 dark:border-gray-700">
      {children}
    </div>
  );
}
