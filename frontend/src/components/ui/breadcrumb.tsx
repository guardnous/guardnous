"use client";

import React from "react";
import Link from "next/link";
import { ChevronRight, Home } from "lucide-react";

export interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
}

export default function Breadcrumb({ items }: BreadcrumbProps) {
  return (
    <nav className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 mb-2">
      <Link
        href="/dashboard"
        className="hover:text-orange-500 transition-colors"
      >
        <Home size={14} />
      </Link>
      {items.map((item, idx) => (
        <React.Fragment key={idx}>
          <ChevronRight size={12} className="text-gray-300 dark:text-gray-600" />
          {item.href ? (
            <Link
              href={item.href}
              className="hover:text-orange-500 transition-colors"
            >
              {item.label}
            </Link>
          ) : (
            <span className="text-gray-700 dark:text-gray-200 font-medium">
              {item.label}
            </span>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
}
