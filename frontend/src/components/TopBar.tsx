"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  Bell,
  Moon,
  Sun,
  Menu,
  Search,
  Command,
  Settings,
  User,
  LogOut,
  Shield,
  Users,
  KeyRound,
  X,
  Check,
  CheckCheck,
  Trash2,
  Info,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { useAuth, ADMIN_ROLES } from "@/lib/auth";
import Avatar from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownItem,
  DropdownSeparator,
  DropdownLabel,
} from "@/components/ui/dropdown-menu";
import {
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
  clearAllNotifications,
} from "@/lib/api";

// ADMIN_ROLES imported from @/lib/auth

const COMMAND_ITEMS = [
  { label: "Dashboard", href: "/dashboard", icon: Shield },
  { label: "Findings", href: "/findings", icon: Search },
  { label: "Reports", href: "/reports", icon: Shield },
  { label: "Task Monitor", href: "/jobs", icon: Shield },
  { label: "Settings", href: "/settings", icon: Settings },
  { label: "Users (Admin)", href: "/admin/users", icon: Users, admin: true },
  { label: "Roles (Admin)", href: "/admin/roles", icon: KeyRound, admin: true },
];

interface TopBarProps {
  onToggleSidebar?: () => void;
}

export default function TopBar({ onToggleSidebar }: TopBarProps) {
  const { user, logout } = useAuth();
  const router = useRouter();
  const [dark, setDark] = useState(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("theme") === "dark" || document.documentElement.classList.contains("dark");
    }
    return false;
  });
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifLoading, setNotifLoading] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const isAdmin = ADMIN_ROLES.includes(user?.role || "");

  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved === "dark") {
      document.documentElement.classList.add("dark");
      setDark(true);
    }
  }, []);

  const toggleDark = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("theme", next ? "dark" : "light");
  };

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setShowCommandPalette((prev) => !prev);
        setSearchQuery("");
      }
      if (e.key === "Escape") {
        setShowCommandPalette(false);
      }
    },
    []
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  const filteredCommands = COMMAND_ITEMS.filter((item) => {
    if (item.admin && !isAdmin) return false;
    if (!searchQuery) return true;
    return item.label.toLowerCase().includes(searchQuery.toLowerCase());
  });

  const navigateTo = (href: string) => {
    setShowCommandPalette(false);
    router.push(href);
  };

  // ─── Notification helpers ─────────────────────────────────
  const fetchNotifications = useCallback(async () => {
    try {
      const data = await getNotifications();
      setNotifications(data.items || []);
      setUnreadCount(data.unread_count || 0);
    } catch {
      // silent — user may not be logged in yet
    }
  }, []);

  // Poll notifications every 30s
  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  // Close dropdown on outside click
  useEffect(() => {
    function handleOutside(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    }
    if (showNotifications) document.addEventListener("mousedown", handleOutside);
    return () => document.removeEventListener("mousedown", handleOutside);
  }, [showNotifications]);

  const handleToggleNotifications = () => {
    setShowNotifications((prev) => !prev);
    if (!showNotifications) fetchNotifications();
  };

  const handleMarkRead = async (id: number) => {
    await markNotificationRead(id);
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, is_read: true } : n)));
    setUnreadCount((c) => Math.max(0, c - 1));
  };

  const handleMarkAllRead = async () => {
    setNotifLoading(true);
    await markAllNotificationsRead();
    setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
    setUnreadCount(0);
    setNotifLoading(false);
  };

  const handleClearAll = async () => {
    setNotifLoading(true);
    await clearAllNotifications();
    setNotifications([]);
    setUnreadCount(0);
    setNotifLoading(false);
  };

  const notifCategoryIcon = (cat: string) => {
    switch (cat) {
      case "success": return <CheckCircle2 size={14} className="text-emerald-500" />;
      case "warning": return <AlertTriangle size={14} className="text-amber-500" />;
      case "error": return <XCircle size={14} className="text-red-500" />;
      default: return <Info size={14} className="text-blue-500" />;
    }
  };

  const timeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  };

  return (
    <>
      <header className="h-16 border-b border-slate-200/60 dark:border-slate-700/40 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl flex items-center px-5 sticky top-0 z-30">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden mr-4 p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500"
        >
          <Menu size={20} />
        </button>

        {/* Search / Command Palette Trigger */}
        <button
          onClick={() => { setShowCommandPalette(true); setSearchQuery(""); }}
          className="hidden sm:flex items-center gap-2.5 px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600 hover:shadow-sm transition-all text-sm w-72 bg-slate-50/50 dark:bg-slate-800/50"
        >
          <Search size={15} />
          <span className="flex-1 text-left">Search anything…</span>
          <kbd className="hidden md:inline-flex items-center gap-0.5 px-2 py-1 rounded-md bg-white dark:bg-slate-700 text-[10px] font-mono text-slate-500 shadow-sm border border-slate-200 dark:border-slate-600">
            <Command size={10} />K
          </kbd>
        </button>

        <div className="flex-1" />

        {/* Right-aligned controls */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={toggleDark}
            className="p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition-all"
            title="Toggle dark mode"
          >
            {dark ? <Sun size={18} /> : <Moon size={18} />}
          </button>

          {/* ── Notification Bell ────────────────────────── */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={handleToggleNotifications}
              className="p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 relative transition-all"
              title="Notifications"
            >
              <Bell size={18} />
              {unreadCount > 0 && (
                <span className="absolute top-1.5 right-1.5 min-w-[16px] h-4 px-1 flex items-center justify-center text-[10px] font-bold text-white bg-red-500 rounded-full ring-2 ring-white dark:ring-slate-900">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              )}
            </button>

            {showNotifications && (
              <div className="absolute right-0 top-full mt-2 w-96 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                    Notifications {unreadCount > 0 && <span className="ml-1.5 text-xs font-medium text-blue-600 dark:text-blue-400">({unreadCount} unread)</span>}
                  </h3>
                  <div className="flex gap-1">
                    {unreadCount > 0 && (
                      <button
                        onClick={handleMarkAllRead}
                        disabled={notifLoading}
                        className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-blue-600 transition-colors"
                        title="Mark all read"
                      >
                        <CheckCheck size={15} />
                      </button>
                    )}
                    {notifications.length > 0 && (
                      <button
                        onClick={handleClearAll}
                        disabled={notifLoading}
                        className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-red-500 transition-colors"
                        title="Clear all"
                      >
                        <Trash2 size={15} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Notification list */}
                <div className="max-h-80 overflow-y-auto">
                  {notifications.length === 0 ? (
                    <div className="py-10 text-center text-sm text-slate-400 dark:text-slate-500">
                      <Bell size={28} className="mx-auto mb-2 opacity-40" />
                      No notifications yet
                    </div>
                  ) : (
                    notifications.map((n: any) => (
                      <button
                        key={n.id}
                        onClick={() => {
                          if (!n.is_read) handleMarkRead(n.id);
                          if (n.link) { router.push(n.link); setShowNotifications(false); }
                        }}
                        className={`w-full text-left flex items-start gap-3 px-4 py-3 border-b border-slate-50 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors ${
                          !n.is_read ? "bg-blue-50/50 dark:bg-blue-950/20" : ""
                        }`}
                      >
                        <div className="mt-0.5 shrink-0">{notifCategoryIcon(n.category)}</div>
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm leading-tight ${!n.is_read ? "font-semibold text-slate-800 dark:text-slate-100" : "text-slate-600 dark:text-slate-300"}`}>
                            {n.title}
                          </p>
                          {n.message && (
                            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 truncate">{n.message}</p>
                          )}
                          <p className="text-[10px] text-slate-400 mt-1">{timeAgo(n.created_at)}</p>
                        </div>
                        {!n.is_read && (
                          <span className="mt-1.5 w-2 h-2 bg-blue-500 rounded-full shrink-0" />
                        )}
                      </button>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="w-px h-6 bg-slate-200 dark:bg-slate-700 mx-1.5" />

          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
            >
              <Avatar name={user?.full_name || "User"} size="sm" />
              <div className="hidden sm:block text-left">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200 block max-w-[120px] truncate leading-tight">
                  {user?.full_name || "User"}
                </span>
                <span className="text-[10px] text-slate-400 capitalize">{user?.role?.replace("_", " ")}</span>
              </div>
            </button>

            <DropdownMenu open={showUserMenu} onClose={() => setShowUserMenu(false)}>
              <DropdownLabel>
                <p className="text-sm font-semibold text-slate-800 dark:text-white">
                  {user?.full_name}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">{user?.email}</p>
                <span className="inline-block mt-1.5 px-2.5 py-0.5 text-[10px] font-semibold rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400 uppercase tracking-wide">
                  {user?.role?.replace("_", " ")}
                </span>
              </DropdownLabel>
              <DropdownItem onClick={() => router.push("/settings")}>
                <User size={14} /> Profile & Settings
              </DropdownItem>
              {isAdmin && (
                <DropdownItem onClick={() => router.push("/admin/users")}>
                  <Users size={14} /> User Management
                </DropdownItem>
              )}
              <DropdownSeparator />
              <DropdownItem onClick={logout} danger>
                <LogOut size={14} /> Sign out
              </DropdownItem>
            </DropdownMenu>
          </div>
        </div>
      </header>

      {/* Command Palette Modal */}
      {showCommandPalette && (
        <div
          className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-start justify-center pt-[18vh]"
          onClick={() => setShowCommandPalette(false)}
        >
          <div
            className="bg-white dark:bg-slate-800 rounded-2xl shadow-elevated w-full max-w-xl mx-4 overflow-hidden animate-scale-in border border-slate-200 dark:border-slate-700"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 dark:border-slate-700">
              <Search size={18} className="text-slate-400" />
              <input
                type="text"
                autoFocus
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Type a command or search…"
                className="flex-1 bg-transparent text-slate-900 dark:text-white placeholder-slate-400 outline-none text-[15px]"
              />
              <button
                onClick={() => setShowCommandPalette(false)}
                className="text-slate-400 hover:text-slate-600 p-1"
              >
                <X size={16} />
              </button>
            </div>
            <div className="max-h-72 overflow-y-auto py-2">
              {filteredCommands.length === 0 ? (
                <div className="px-5 py-10 text-center text-sm text-slate-400">
                  No results found
                </div>
              ) : (
                filteredCommands.map((item) => (
                  <button
                    key={item.href}
                    onClick={() => navigateTo(item.href)}
                    className="w-full flex items-center gap-3 px-5 py-3 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                  >
                    <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center">
                      <item.icon size={15} className="text-slate-500 dark:text-slate-400" />
                    </div>
                    <span className="font-medium">{item.label}</span>
                  </button>
                ))
              )}
            </div>
            <div className="px-5 py-3 border-t border-slate-100 dark:border-slate-700 flex items-center gap-5 text-[11px] text-slate-400 font-medium">
              <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 font-mono">↑↓</kbd> Navigate</span>
              <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 font-mono">↵</kbd> Open</span>
              <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 font-mono">Esc</kbd> Close</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
