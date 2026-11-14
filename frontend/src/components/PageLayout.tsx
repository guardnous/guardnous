"use client";

import React from "react";
import { type LucideIcon } from "lucide-react";
import Breadcrumb, { type BreadcrumbItem } from "@/components/ui/breadcrumb";

interface PageLayoutProps {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  fullWidth?: boolean;
  noPadding?: boolean;
  actions?: React.ReactNode;
  icon?: LucideIcon;
  breadcrumbs?: BreadcrumbItem[];
}

export default function PageLayout({
  title,
  subtitle,
  children,
  fullWidth,
  noPadding,
  actions,
  icon: Icon,
  breadcrumbs,
}: PageLayoutProps) {
  return (
    <div
      className={
        noPadding
          ? "w-full"
          : `p-6 sm:p-8 lg:p-10 ${fullWidth ? "w-full" : "max-w-[1400px] mx-auto"}`
      }
    >
      {breadcrumbs && breadcrumbs.length > 0 && (
        <div className={noPadding ? "px-6 sm:px-8 pt-6" : "mb-2"}>
          <Breadcrumb items={breadcrumbs} />
        </div>
      )}

      <div
        className={`flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8 gap-4 ${
          noPadding ? "px-6 sm:px-8 pt-4" : ""
        }`}
      >
        <div className="flex items-center gap-4">
          {Icon && (
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-orange-50 to-amber-50 dark:from-orange-500/10 dark:to-amber-500/10 flex items-center justify-center shrink-0 border border-orange-100 dark:border-orange-500/20">
              <Icon size={20} className="text-orange-500" />
            </div>
          )}
          <div>
            <h1 className="text-2xl font-semibold text-slate-900 dark:text-white tracking-tight">
              {title}
            </h1>
            {subtitle && (
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                {subtitle}
              </p>
            )}
          </div>
        </div>
        {actions && (
          <div className="flex items-center gap-3">{actions}</div>
        )}
      </div>

      {children}
    </div>
  );
}
