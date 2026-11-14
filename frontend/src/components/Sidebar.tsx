"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  GitBranch,
  Play,
  FileText,
  AlertTriangle,
  Shield,
  ShieldAlert,
  Scale,
  Settings,
  Bot,
  Puzzle,
  Users,
  KeyRound,
  Building2,
  ClipboardList,
  UsersRound,
  X,
  Sparkles,
  ScrollText,
  BookOpen,
  ChevronsUpDown,
  Check,
  Cloud,
  CalendarClock,
  ListChecks,
  Radar,
} from "lucide-react";
import { useAuth, ADMIN_ROLES } from "@/lib/auth";
import { switchOrganization } from "@/lib/api";

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

const navSections = [
  {
    label: "Platform",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/integrations", label: "Integrations", icon: GitBranch },
      { href: "/scans", label: "Assessments", icon: Sparkles },
      { href: "/jobs", label: "Task Monitor", icon: Play },
      { href: "/schedules", label: "Schedules", icon: CalendarClock },
    ],
  },
  {
    label: "Investigation",
    items: [
      { href: "/findings", label: "Findings", icon: AlertTriangle },
      { href: "/cves", label: "CVE Intel", icon: Shield },
      { href: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Governance",
    items: [
      { href: "/iam", label: "IAM Intel", icon: ShieldAlert },
      { href: "/governance", label: "Enterprise Governance", icon: Scale },
      { href: "/policies", label: "Security Policies", icon: ScrollText },
      { href: "/cloud-accounts", label: "Cloud Connectors", icon: Cloud },
      { href: "/cloud-posture", label: "Cloud Posture", icon: Radar },
      { href: "/knowledge-base", label: "Knowledge Base", icon: BookOpen },
    ],
  },
  {
    label: "AI & Extensions",
    items: [
      { href: "/agents", label: "AI Copilot", icon: Bot },
      { href: "/agent-runs", label: "Agent Runs", icon: ListChecks },
      { href: "/plugins", label: "Plugins", icon: Puzzle },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

const adminNav = [
  { href: "/admin/tenants", label: "Tenants", icon: Building2 },
  { href: "/admin/users", label: "Users", icon: Users },
  { href: "/admin/groups", label: "Groups", icon: UsersRound },
  { href: "/admin/roles", label: "Roles", icon: KeyRound },
  { href: "/admin/service-accounts", label: "Service Accounts", icon: Bot },
  { href: "/admin/audit", label: "Audit Logs", icon: ClipboardList },
  { href: "/logs", label: "System Logs", icon: ScrollText },
];

function OrgSwitcher() {
  const { user, refreshUser } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [switching, setSwitching] = useState(false);

  const orgs = user?.organizations ?? [];
  const activeOrg = orgs.find((o) => o.organization_id === user?.organization_id);

  if (orgs.length <= 1) return null;

  const handleSwitch = async (orgId: number) => {
    if (orgId === user?.organization_id) { setIsOpen(false); return; }
    setSwitching(true);
    try {
      const res = await switchOrganization(orgId);
      if (res.access_token) {
        localStorage.setItem("token", res.access_token);
      }
      await refreshUser();
      window.location.reload();
    } catch {
      // silent — toast would be better
    } finally {
      setSwitching(false);
      setIsOpen(false);
    }
  };

  return (
    <div className="px-4 pt-2 border-t border-slate-100 dark:border-slate-800 relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl text-[13px] font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <Building2 size={16} className="text-orange-500 shrink-0" />
          <span className="truncate">{activeOrg?.organization_name ?? "Organization"}</span>
        </div>
        <ChevronsUpDown size={14} className="text-slate-400 shrink-0" />
      </button>

      {isOpen && (
        <div className="absolute bottom-full left-4 right-4 mb-1 bg-white dark:bg-slate-900 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 py-1 z-50 max-h-48 overflow-y-auto">
          <div className="px-3 py-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
            Switch Organization
          </div>
          {orgs.map((org) => (
            <button
              key={org.organization_id}
              onClick={() => handleSwitch(org.organization_id)}
              disabled={switching}
              className="w-full flex items-center gap-2 px-3 py-2 text-[13px] text-slate-700 dark:text-slate-300 hover:bg-orange-50 dark:hover:bg-orange-500/10 transition-colors"
            >
              <Building2 size={14} className="text-slate-400 shrink-0" />
              <span className="truncate">{org.organization_name}</span>
              {org.organization_id === user?.organization_id && (
                <Check size={14} className="ml-auto text-orange-500 shrink-0" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Sidebar({ open, onClose }: SidebarProps) {
  const pathname = usePathname();
  const { user } = useAuth();
  const isAdmin = ADMIN_ROLES.includes(user?.role || "");

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-0 left-0 h-full w-64 bg-white dark:bg-slate-900 border-r border-slate-200/80 dark:border-slate-700/50 z-50 transform transition-transform duration-300 ease-out ${
          open ? "translate-x-0" : "-translate-x-full"
        } lg:translate-x-0 lg:static lg:z-auto flex flex-col`}
      >
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <img src="/logo.svg" alt="GuardNous" className="w-8 h-8 drop-shadow-[0_2px_8px_rgba(249,115,22,0.3)]" />
            <div>
              <span className="text-base font-semibold text-slate-900 dark:text-white tracking-tight">GuardNous</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="lg:hidden p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"
          >
            <X size={16} />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
          {navSections.map((section) => (
            <div key={section.label}>
              <div className="mb-2 px-3 text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
                {section.label}
              </div>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const active = pathname === item.href || pathname?.startsWith(item.href + "/");
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={onClose}
                      className={`group flex items-center gap-3 px-3 py-2 rounded-xl text-[13px] font-medium transition-all duration-200 ${
                        active
                          ? "bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 shadow-sm"
                          : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200"
                      }`}
                    >
                      <item.icon size={18} strokeWidth={active ? 2 : 1.5} className={active ? "" : "group-hover:scale-105 transition-transform"} />
                      {item.label}
                      {active && (
                        <div className="ml-auto w-1.5 h-1.5 rounded-full bg-orange-500" />
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}

          {isAdmin && (
            <div>
              <div className="mb-2 px-3 text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
                Administration
              </div>
              <div className="space-y-0.5">
                {adminNav.map((item) => {
                  const active = pathname === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={onClose}
                      className={`group flex items-center gap-3 px-3 py-2 rounded-xl text-[13px] font-medium transition-all duration-200 ${
                        active
                          ? "bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 shadow-sm"
                          : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200"
                      }`}
                    >
                      <item.icon size={18} strokeWidth={active ? 2 : 1.5} className={active ? "" : "group-hover:scale-105 transition-transform"} />
                      {item.label}
                      {active && (
                        <div className="ml-auto w-1.5 h-1.5 rounded-full bg-orange-500" />
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          )}
        </nav>

        {/* Org Switcher */}
        <OrgSwitcher />

        {/* Footer */}
        <div className="px-4 pb-4 pt-2">
          <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-gradient-to-r from-orange-50 to-amber-50 dark:from-orange-500/5 dark:to-amber-500/5 border border-orange-100 dark:border-orange-500/10">
            <Sparkles size={14} className="text-orange-500" />
            <div>
              <p className="text-[11px] font-semibold text-orange-700 dark:text-orange-400">Enterprise</p>
              <p className="text-[10px] text-orange-500/70 dark:text-orange-400/50">v1.0.0</p>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
