"use client";

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import api from "@/lib/api";
import { useAuth } from "@/lib/auth";
import PageLayout from "@/components/PageLayout";
import {
  Users, UserPlus, Upload, Search, Shield, Clock, Mail, X,
  MoreHorizontal, Copy, Check, Download, ChevronUp, ChevronDown,
  UserX, RefreshCw, Eye, AlertCircle, AlertTriangle, FileText, Send,
} from "lucide-react";

/* ───────── Types ───────── */

interface UserRecord {
  id: string;
  email: string;
  full_name: string;
  role: string;
  status: string;
  is_active: boolean;
  tenant_id: string;
  organization_id: string;
  last_login_at: string | null;
  created_at: string;
}

interface Role {
  id: string;
  name: string;
  slug: string;
  description: string;
  is_system: boolean;
}

interface InviteResponse {
  token: string;
  email: string;
  invite_url?: string;
  email_sent?: boolean;
  email_error?: string;
}

interface BulkResult {
  invited: number;
  skipped: number;
  errors: number;
  details?: string[];
}

interface Toast {
  id: number;
  message: string;
  type: "success" | "error";
}

type SortField = "full_name" | "role" | "status" | "last_login_at";
type SortDir = "asc" | "desc";
type Tab = "users" | "invitations";

/* ───────── Helpers ───────── */

const STATUS_STYLES: Record<string, string> = {
  active: "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 ring-1 ring-emerald-600/20",
  invited: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 ring-1 ring-amber-600/20",
  deactivated: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400 ring-1 ring-red-600/20",
  suspended: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 ring-1 ring-orange-600/20",
};

const ROLE_COLORS: Record<string, string> = {
  admin: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 ring-1 ring-orange-600/20",
  owner: "bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400 ring-1 ring-purple-600/20",
  manager: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 ring-1 ring-sky-600/20",
  analyst: "bg-teal-50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-400 ring-1 ring-teal-600/20",
  viewer: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 ring-1 ring-slate-400/20",
};

function roleStyle(role: string): string {
  const key = role.toLowerCase();
  return ROLE_COLORS[key] ?? "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 ring-1 ring-slate-400/20";
}

function relativeTime(date: string | null): string {
  if (!date) return "Never";
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(date).toLocaleDateString();
}

function formatDate(date: string | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/* ───────── Modal Shell ───────── */

function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700/60 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X size={18} className="text-slate-400 dark:text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}

/* ───────── Toast Container ───────── */

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-6 right-6 z-[60] flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg text-sm font-medium ${
            t.type === "success"
              ? "bg-emerald-600 text-white"
              : "bg-red-600 text-white"
          }`}
        >
          {t.type === "success" ? <Check size={16} /> : <AlertCircle size={16} />}
          <span className="flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="p-0.5 hover:opacity-70">
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

/* ───────── Main Page ───────── */

export default function AdminUsersPage() {
  const { user: authUser } = useAuth();

  const [users, setUsers] = useState<UserRecord[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("full_name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [activeTab, setActiveTab] = useState<Tab>("users");
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Modal states
  const [inviteOpen, setInviteOpen] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    userId: string;
    action: string;
    name: string;
  } | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<{
    userId: string;
    email: string;
    name: string;
  } | null>(null);
  const [deleteEmailInput, setDeleteEmailInput] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Invite form
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteFullName, setInviteFullName] = useState("");
  const [inviteRoleId, setInviteRoleId] = useState("");
  const [inviteOrgId, setInviteOrgId] = useState("");
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteLink, setInviteLink] = useState("");
  const [linkCopied, setLinkCopied] = useState(false);
  const [inviteEmailSent, setInviteEmailSent] = useState(false);
  const [inviteEmailError, setInviteEmailError] = useState("");

  // Bulk form
  const [bulkFile, setBulkFile] = useState<File | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const [dragOver, setDragOver] = useState(false);

  // User detail slide-out
  const [selectedUser, setSelectedUser] = useState<UserRecord | null>(null);

  // Action loading
  const [actionLoading, setActionLoading] = useState(false);

  // Toasts
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const addToast = useCallback((message: string, type: "success" | "error") => {
    const id = ++toastId.current;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  /* ── Data fetching ── */

  const fetchUsers = useCallback(async () => {
    try {
      const res = await api.get("/users/");
      setUsers(res.data);
    } catch {
      addToast("Failed to load users", "error");
    }
  }, [addToast]);

  const fetchRoles = useCallback(async () => {
    try {
      const res = await api.get("/roles/");
      setRoles(res.data);
    } catch {
      addToast("Failed to load roles", "error");
    }
  }, [addToast]);

  useEffect(() => {
    Promise.all([fetchUsers(), fetchRoles()]).finally(() => setLoading(false));
  }, [fetchUsers, fetchRoles]);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  /* ── Stats ── */

  const stats = useMemo(() => ({
    total: users.length,
    active: users.filter((u) => u.status === "active").length,
    invited: users.filter((u) => u.status === "invited").length,
    deactivated: users.filter((u) => u.status === "deactivated" || u.status === "suspended").length,
  }), [users]);

  /* ── Sort / Filter ── */

  const handleSort = useCallback((field: SortField) => {
    setSortDir((prev) => (sortField === field ? (prev === "asc" ? "desc" : "asc") : "asc"));
    setSortField(field);
  }, [sortField]);

  const filteredUsers = useMemo(() => {
    const term = search.toLowerCase();
    let list = users.filter((u) => {
      if (activeTab === "invitations") return u.status === "invited";
      return u.status !== "invited";
    });
    if (term) {
      list = list.filter(
        (u) =>
          u.full_name.toLowerCase().includes(term) ||
          u.email.toLowerCase().includes(term)
      );
    }
    list.sort((a, b) => {
      const valA = a[sortField] ?? "";
      const valB = b[sortField] ?? "";
      const cmp = String(valA).localeCompare(String(valB));
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [users, search, sortField, sortDir, activeTab]);

  /* ── Invite User ── */

  const handleInvite = useCallback(async () => {
    if (!inviteEmail || !inviteRoleId) return;
    setInviteLoading(true);
    try {
      const body: Record<string, string> = {
        email: inviteEmail,
        role_id: inviteRoleId,
      };
      if (inviteFullName.trim()) body.full_name = inviteFullName.trim();
      if (inviteOrgId) body.organization_id = inviteOrgId;
      const res = await api.post("/users/invite", body);
      const data: InviteResponse = res.data;
      const link = data.invite_url || `${window.location.origin}/invite/${data.token}`;
      setInviteLink(link);
      setInviteEmailSent(data.email_sent ?? false);
      setInviteEmailError(data.email_error ?? "");
      if (data.email_sent) {
        addToast(`Invitation email sent to ${inviteEmail}`, "success");
      } else {
        addToast(`Invitation link generated for ${inviteEmail}`, "success");
      }
      fetchUsers();
    } catch (err: unknown) {
      const axErr = err as { response?: { status?: number; data?: { detail?: string } } };
      if (axErr.response?.status === 400) {
        const detail = axErr.response.data?.detail ?? "Bad request";
        if (detail.toLowerCase().includes("limit")) {
          addToast("User limit reached for your plan", "error");
        } else if (detail.toLowerCase().includes("already")) {
          addToast(detail, "error");
        } else {
          addToast(detail, "error");
        }
      } else {
        addToast("Failed to send invitation", "error");
      }
    } finally {
      setInviteLoading(false);
    }
  }, [inviteEmail, inviteFullName, inviteRoleId, inviteOrgId, addToast, fetchUsers]);

  const resetInviteForm = useCallback(() => {
    setInviteEmail("");
    setInviteFullName("");
    setInviteRoleId("");
    setInviteOrgId("");
    setInviteLink("");
    setLinkCopied(false);
    setInviteEmailSent(false);
    setInviteEmailError("");
    setInviteOpen(false);
  }, []);

  const copyLink = useCallback(async () => {
    await navigator.clipboard.writeText(inviteLink);
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), 2000);
  }, [inviteLink]);

  /* ── Bulk CSV ── */

  const handleDownloadTemplate = useCallback(async () => {
    try {
      const res = await api.get("/users/invite/template", { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = "invite-template.csv";
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      addToast("Failed to download template", "error");
    }
  }, [addToast]);

  const handleBulkUpload = useCallback(async () => {
    if (!bulkFile) return;
    setBulkLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", bulkFile);
      const res = await api.post("/users/invite/csv", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setBulkResult(res.data);
      addToast(
        `Bulk import: ${res.data.invited} invited, ${res.data.skipped} skipped, ${res.data.errors} errors`,
        res.data.errors > 0 ? "error" : "success"
      );
      fetchUsers();
    } catch {
      addToast("Bulk import failed", "error");
    } finally {
      setBulkLoading(false);
    }
  }, [bulkFile, addToast, fetchUsers]);

  const resetBulkForm = useCallback(() => {
    setBulkFile(null);
    setBulkResult(null);
    setBulkOpen(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith(".csv")) {
      setBulkFile(file);
    }
  }, []);

  /* ── User Actions ── */

  const handleDeactivate = useCallback(
    async (userId: string) => {
      setActionLoading(true);
      try {
        await api.patch(`/users/${userId}/status`, { status: "deactivated" });
        addToast("User deactivated", "success");
        fetchUsers();
      } catch {
        addToast("Failed to deactivate user", "error");
      } finally {
        setActionLoading(false);
        setConfirmAction(null);
      }
    },
    [addToast, fetchUsers]
  );

  const handleResendInvite = useCallback(
    async (invitationId: string, email: string) => {
      try {
        await api.post(`/users/invite/resend/${invitationId}`);
        addToast(`Invite resent to ${email}`, "success");
      } catch {
        addToast("Failed to resend invite", "error");
      }
    },
    [addToast]
  );

  const handleRevokeInvite = useCallback(
    async (invitationId: string) => {
      setActionLoading(true);
      try {
        await api.delete(`/org/invitations/${invitationId}`);
        addToast("Invitation revoked", "success");
        fetchUsers();
      } catch {
        addToast("Failed to revoke invitation", "error");
      } finally {
        setActionLoading(false);
      }
    },
    [addToast, fetchUsers]
  );

  const handleDeleteUser = useCallback(
    async (userId: string, confirmEmail: string) => {
      setDeleteLoading(true);
      try {
        await api.delete(`/users/${userId}`, {
          params: { confirm_email: confirmEmail.trim() },
        });
        addToast("User permanently deleted", "success");
        fetchUsers();
      } catch (err: unknown) {
        const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "Failed to delete user";
        addToast(msg, "error");
      } finally {
        setDeleteLoading(false);
        setDeleteConfirm(null);
        setDeleteEmailInput("");
      }
    },
    [addToast, fetchUsers]
  );

  /* ── Sort header helper ── */

  function SortHeader({ field, label }: { field: SortField; label: string }) {
    const active = sortField === field;
    return (
      <button
        onClick={() => handleSort(field)}
        className="inline-flex items-center gap-1 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
      >
        {label}
        {active ? (
          sortDir === "asc" ? (
            <ChevronUp size={14} className="text-orange-600" />
          ) : (
            <ChevronDown size={14} className="text-orange-600" />
          )
        ) : (
          <ChevronDown size={14} className="text-slate-300" />
        )}
      </button>
    );
  }

  /* ── Stat cards config ── */

  const statCards = [
    {
      label: "Total Users",
      value: stats.total,
      icon: Users,
      color: "text-slate-900 dark:text-slate-100",
      bg: "bg-slate-50 dark:bg-slate-800",
    },
    {
      label: "Active",
      value: stats.active,
      icon: Check,
      color: "text-emerald-600 dark:text-emerald-400",
      bg: "bg-emerald-50 dark:bg-emerald-950/40",
    },
    {
      label: "Invited",
      value: stats.invited,
      icon: Send,
      color: "text-amber-600 dark:text-amber-400",
      bg: "bg-amber-50 dark:bg-amber-950/40",
    },
    {
      label: "Deactivated",
      value: stats.deactivated,
      icon: UserX,
      color: "text-red-600 dark:text-red-400",
      bg: "bg-red-50 dark:bg-red-950/40",
    },
  ];

  /* ───────── Render ───────── */

  return (
    <PageLayout
      title="User Management"
      subtitle="Manage platform users, invitations, and access"
      icon={Users}
    >
      {/* ── Stats ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {statCards.map((s) => {
          const Icon = s.icon;
          return (
            <div
              key={s.label}
              className="bg-white dark:bg-slate-900 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700/60 dark:border-slate-700/60 p-5 flex items-center gap-4"
            >
              <div className={`${s.bg} rounded-xl p-2.5`}>
                <Icon size={20} className={s.color} />
              </div>
              <div>
                <p className={`text-2xl font-bold tracking-tight ${s.color}`}>
                  {loading ? "—" : s.value}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{s.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Toolbar ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        {/* Tabs */}
        <div className="flex bg-slate-100 dark:bg-slate-800 rounded-xl p-1">
          {(["users", "invitations"] as Tab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab
                  ? "bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100 shadow-sm"
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
              }`}
            >
              {tab === "users" ? "Users" : "Pending Invitations"}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:flex-initial sm:w-64">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name or email…"
              className="w-full pl-9 pr-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-300 transition-shadow"
            />
          </div>
          <button
            onClick={() => setInviteOpen(true)}
            className="bg-orange-600 hover:bg-orange-700 text-white font-medium rounded-xl px-4 py-2.5 text-sm flex items-center gap-2 transition-colors shadow-sm"
          >
            <UserPlus size={16} />
            <span className="hidden sm:inline">Invite User</span>
          </button>
          <button
            onClick={() => setBulkOpen(true)}
            className="border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-xl px-4 py-2.5 text-sm flex items-center gap-2 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors shadow-sm"
          >
            <Upload size={16} />
            <span className="hidden sm:inline">Bulk Import CSV</span>
          </button>
        </div>
      </div>

      {/* ── Table ── */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700/60 overflow-hidden max-h-[calc(100vh-300px)] overflow-y-auto">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
              <tr className="bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-700/60 dark:border-slate-700">
                <th className="text-left px-6 py-3.5">
                  <SortHeader field="full_name" label="Name / Email" />
                </th>
                <th className="text-left px-6 py-3.5">
                  <SortHeader field="role" label="Role" />
                </th>
                <th className="text-left px-6 py-3.5">
                  <SortHeader field="status" label="Status" />
                </th>
                <th className="text-left px-6 py-3.5">
                  <SortHeader field="last_login_at" label="Last Login" />
                </th>
                <th className="text-left px-6 py-3.5">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Actions
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-16 text-center">
                    <div className="flex flex-col items-center gap-3">
                      <RefreshCw size={24} className="text-slate-300 animate-spin" />
                      <span className="text-sm text-slate-400">Loading users…</span>
                    </div>
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-16 text-center">
                    <div className="flex flex-col items-center gap-3">
                      <div className="bg-slate-100 dark:bg-slate-800 rounded-2xl p-4">
                        <Users size={32} className="text-slate-300 dark:text-slate-600 dark:text-slate-300" />
                      </div>
                      <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
                        {activeTab === "invitations"
                          ? "No pending invitations"
                          : "No users yet. Invite your team to get started."}
                      </p>
                      {activeTab === "users" && (
                        <button
                          onClick={() => setInviteOpen(true)}
                          className="mt-1 text-sm text-orange-600 hover:text-orange-700 font-medium"
                        >
                          Send your first invite →
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => (
                  <tr
                    key={u.id}
                    className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:bg-slate-800/70 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    {/* Name / Email */}
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-full bg-gradient-to-br from-orange-500 to-purple-500 flex items-center justify-center text-white font-semibold text-sm shrink-0">
                          {(u.full_name || u.email || "?").charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="font-medium text-slate-900 dark:text-slate-100 truncate">
                            {u.full_name || "—"}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{u.email}</p>
                        </div>
                      </div>
                    </td>

                    {/* Role pill */}
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium ${roleStyle(
                          u.role
                        )}`}
                      >
                        <Shield size={12} />
                        {u.role}
                      </span>
                    </td>

                    {/* Status badge */}
                    <td className="px-6 py-4">
                      <span
                        className={`inline-block px-2.5 py-1 rounded-lg text-xs font-medium ${
                          STATUS_STYLES[u.status] ?? STATUS_STYLES.deactivated
                        }`}
                      >
                        {(u.status || "unknown").charAt(0).toUpperCase() + (u.status || "unknown").slice(1)}
                      </span>
                    </td>

                    {/* Last login */}
                    <td className="px-6 py-4">
                      <span className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 text-sm">
                        <Clock size={13} />
                        {relativeTime(u.last_login_at)}
                      </span>
                    </td>

                    {/* Actions dropdown */}
                    <td className="px-6 py-4">
                      <div className="relative" ref={openMenu === u.id ? menuRef : undefined}>
                        <button
                          onClick={() =>
                            setOpenMenu(openMenu === u.id ? null : u.id)
                          }
                          className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                        >
                          <MoreHorizontal size={16} className="text-slate-400" />
                        </button>
                        {openMenu === u.id && (
                          <div className="absolute right-0 top-10 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 shadow-xl z-20 py-1 min-w-[160px]">
                            <button
                              onClick={() => { setOpenMenu(null); setSelectedUser(u); }}
                              className="w-full text-left px-4 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center gap-2"
                            >
                              <Eye size={14} /> View Details
                            </button>
                            {activeTab === "invitations" ? (
                              <>
                                <button
                                  onClick={() => {
                                    setOpenMenu(null);
                                    handleResendInvite(u.id, u.email);
                                  }}
                                  className="w-full text-left px-4 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center gap-2"
                                >
                                  <RefreshCw size={14} /> Resend Invite
                                </button>
                                <button
                                  onClick={() => {
                                    setOpenMenu(null);
                                    handleRevokeInvite(u.id);
                                  }}
                                  className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors flex items-center gap-2"
                                >
                                  <X size={14} /> Revoke
                                </button>
                              </>
                            ) : (
                              <>
                                {u.status === "active" && (
                                  <button
                                    onClick={() => {
                                      setOpenMenu(null);
                                      setConfirmAction({
                                        userId: u.id,
                                        action: "deactivate",
                                        name: u.full_name || u.email,
                                      });
                                    }}
                                    className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors flex items-center gap-2"
                                  >
                                    <UserX size={14} /> Deactivate
                                  </button>
                                )}
                                {u.status === "invited" && (
                                  <button
                                    onClick={() => {
                                      setOpenMenu(null);
                                      handleResendInvite(u.id, u.email);
                                    }}
                                    className="w-full text-left px-4 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center gap-2"
                                  >
                                    <RefreshCw size={14} /> Resend Invite
                                  </button>
                                )}
                                {(u.status === "deactivated" || u.status === "suspended") && (
                                  <button
                                    onClick={() => {
                                      setOpenMenu(null);
                                      setDeleteConfirm({
                                        userId: u.id,
                                        email: u.email,
                                        name: u.full_name || u.email,
                                      });
                                    }}
                                    className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors flex items-center gap-2"
                                  >
                                    <AlertTriangle size={14} /> Delete Permanently
                                  </button>
                                )}
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Table footer */}
        {!loading && filteredUsers.length > 0 && (
          <div className="px-6 py-3 bg-slate-50 dark:bg-slate-800/50 dark:bg-slate-800/50 border-t border-slate-100 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
            Showing {filteredUsers.length} of {users.length} users
          </div>
        )}
      </div>

      {/* ─── Invite User Modal ─── */}
      <Modal open={inviteOpen} onClose={resetInviteForm} title="Invite User">
        {inviteLink ? (
          <div className="space-y-4">
            {inviteEmailSent ? (
              <div className="bg-emerald-50 dark:bg-emerald-950/30 rounded-xl p-4 flex items-start gap-3">
                <Check size={20} className="text-emerald-600 dark:text-emerald-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-emerald-800 dark:text-emerald-300">
                    Invitation email sent to {inviteEmail} ✉️
                  </p>
                  <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-1">
                    The user will receive a branded email with a link to accept the invitation. You can also share the link below directly.
                  </p>
                </div>
              </div>
            ) : (
              <div className="bg-amber-50 dark:bg-amber-950/30 rounded-xl p-4 flex items-start gap-3">
                <AlertTriangle size={20} className="text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                    Invitation link generated for {inviteEmail}
                  </p>
                  <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                    {inviteEmailError
                      ? `${inviteEmailError}. Share the link below manually.`
                      : "Email not configured. Share the link below directly with the user. Configure SMTP in Settings → Email to enable automatic emails."}
                  </p>
                </div>
              </div>
            )}
            <div className="flex items-center gap-2">
              <input
                readOnly
                value={inviteLink}
                className="flex-1 px-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm font-mono truncate"
              />
              <button
                onClick={copyLink}
                className={`px-4 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2 transition-colors ${
                  linkCopied
                    ? "bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-400"
                    : "bg-orange-600 hover:bg-orange-700 text-white"
                }`}
              >
                {linkCopied ? <Check size={14} /> : <Copy size={14} />}
                {linkCopied ? "Copied!" : "Copy Link"}
              </button>
            </div>
            <button
              onClick={resetInviteForm}
              className="w-full border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl px-4 py-2.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Done
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Email Address <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <Mail
                  size={16}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  type="email"
                  name="invite-email"
                  autoComplete="off"
                  placeholder="user@company.com"
                  className="w-full pl-9 pr-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-300 transition-shadow"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Full Name
              </label>
              <input
                value={inviteFullName}
                onChange={(e) => setInviteFullName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-300 transition-shadow"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Role <span className="text-red-500">*</span>
              </label>
              <select
                value={inviteRoleId}
                onChange={(e) => setInviteRoleId(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-300 transition-shadow"
              >
                <option value="">Select a role…</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </div>
            {authUser?.organization_id && (
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Team
                </label>
                <select
                  value={inviteOrgId}
                  onChange={(e) => setInviteOrgId(e.target.value)}
                  className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-300 transition-shadow"
                >
                  <option value="">Current team</option>
                </select>
              </div>
            )}
            <button
              disabled={!inviteEmail || !inviteRoleId || inviteLoading}
              onClick={handleInvite}
              className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl px-4 py-2.5 text-sm transition-colors flex items-center justify-center gap-2"
            >
              {inviteLoading ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  Sending Invitation…
                </>
              ) : (
                <>
                  <Send size={14} />
                  Send Invitation
                </>
              )}
            </button>
          </div>
        )}
      </Modal>

      {/* ─── Bulk Import Modal ─── */}
      <Modal open={bulkOpen} onClose={resetBulkForm} title="Bulk Import CSV">
        {bulkResult ? (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-emerald-50 dark:bg-emerald-950/40 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-emerald-700 dark:text-emerald-400">{bulkResult.invited}</p>
                <p className="text-xs text-emerald-600 dark:text-emerald-500 mt-1">Invited</p>
              </div>
              <div className="bg-amber-50 dark:bg-amber-950/40 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-amber-700 dark:text-amber-400">{bulkResult.skipped}</p>
                <p className="text-xs text-amber-600 dark:text-amber-500 mt-1">Skipped</p>
              </div>
              <div className="bg-red-50 dark:bg-red-950/40 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-red-700 dark:text-red-400">{bulkResult.errors}</p>
                <p className="text-xs text-red-600 dark:text-red-500 mt-1">Errors</p>
              </div>
            </div>
            {bulkResult.details && bulkResult.details.length > 0 && (
              <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-4 max-h-40 overflow-y-auto">
                <p className="text-xs font-medium text-slate-600 dark:text-slate-400 mb-2">Details:</p>
                {bulkResult.details.map((d, i) => (
                  <p key={i} className="text-xs text-slate-500 dark:text-slate-400 py-0.5">
                    {d}
                  </p>
                ))}
              </div>
            )}
            <button
              onClick={resetBulkForm}
              className="w-full border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl px-4 py-2.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Done
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Download template */}
            <button
              onClick={handleDownloadTemplate}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-sm text-slate-700 dark:text-slate-300 transition-colors"
            >
              <Download size={16} className="text-orange-600" />
              <div className="text-left">
                <p className="font-medium">Download CSV Template</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Pre-formatted template with required columns
                </p>
              </div>
            </button>

            {/* Drop zone */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
                dragOver
                  ? "border-orange-400 bg-orange-50 dark:bg-orange-950/30"
                  : bulkFile
                  ? "border-emerald-300 bg-emerald-50 dark:bg-emerald-950/30"
                  : "border-slate-300 dark:border-slate-600 hover:border-orange-300"
              }`}
            >
              {bulkFile ? (
                <div className="flex items-center justify-center gap-3">
                  <FileText size={20} className="text-emerald-600" />
                  <div className="text-left">
                    <p className="text-sm font-medium text-slate-900 dark:text-slate-100">{bulkFile.name}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {(bulkFile.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                  <button
                    onClick={() => setBulkFile(null)}
                    className="p-1 rounded-lg hover:bg-emerald-100 transition-colors"
                  >
                    <X size={14} className="text-slate-400" />
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <Upload size={24} className="mx-auto text-slate-400" />
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Drag & drop a CSV file, or{" "}
                    <label className="text-orange-600 hover:text-orange-700 font-medium cursor-pointer">
                      browse
                      <input
                        type="file"
                        accept=".csv"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) setBulkFile(file);
                        }}
                      />
                    </label>
                  </p>
                  <p className="text-xs text-slate-400">CSV files only</p>
                </div>
              )}
            </div>

            <button
              disabled={!bulkFile || bulkLoading}
              onClick={handleBulkUpload}
              className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl px-4 py-2.5 text-sm transition-colors flex items-center justify-center gap-2"
            >
              {bulkLoading ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  Importing…
                </>
              ) : (
                <>
                  <Upload size={14} />
                  Upload &amp; Import
                </>
              )}
            </button>
          </div>
        )}
      </Modal>

      {/* ─── Confirm Deactivate Modal ─── */}
      <Modal
        open={!!confirmAction}
        onClose={() => setConfirmAction(null)}
        title="Confirm Deactivation"
      >
        {confirmAction && (
          <div className="space-y-4">
            <div className="bg-red-50 dark:bg-red-950/30 rounded-xl p-4 flex items-start gap-3">
              <AlertCircle size={20} className="text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium text-red-800 dark:text-red-300">
                  Are you sure you want to deactivate{" "}
                  <strong>{confirmAction.name}</strong>?
                </p>
                <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                  This user will lose access to the platform immediately.
                </p>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirmAction(null)}
                className="border border-slate-200 dark:border-slate-700/60 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl px-4 py-2.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeactivate(confirmAction.userId)}
                disabled={actionLoading}
                className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white font-medium rounded-xl px-4 py-2.5 text-sm transition-colors flex items-center gap-2"
              >
                {actionLoading ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Deactivating…
                  </>
                ) : (
                  "Deactivate User"
                )}
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* ─── Confirm Delete Modal ─── */}
      <Modal
        open={!!deleteConfirm}
        onClose={() => { setDeleteConfirm(null); setDeleteEmailInput(""); }}
        title="Permanently Delete User"
      >
        {deleteConfirm && (
          <div className="space-y-4">
            <div className="bg-red-50 dark:bg-red-950/30 rounded-xl p-4 flex items-start gap-3">
              <AlertTriangle size={20} className="text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium text-red-800 dark:text-red-300">
                  This action is <strong>irreversible</strong>. The user{" "}
                  <strong>{deleteConfirm.name}</strong> will be permanently removed from the system.
                </p>
                <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                  All associated data will be deleted. This cannot be undone.
                </p>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Type <strong className="text-red-600 dark:text-red-400">{deleteConfirm.email}</strong> to confirm
              </label>
              <input
                type="text"
                value={deleteEmailInput}
                onChange={(e) => setDeleteEmailInput(e.target.value)}
                placeholder={deleteConfirm.email}
                className="w-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 dark:focus:ring-red-400"
                autoFocus
              />
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => { setDeleteConfirm(null); setDeleteEmailInput(""); }}
                className="border border-slate-200 dark:border-slate-700/60 text-slate-700 dark:text-slate-300 rounded-xl px-4 py-2.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteUser(deleteConfirm.userId, deleteEmailInput)}
                disabled={deleteLoading || deleteEmailInput.trim().toLowerCase() !== deleteConfirm.email.trim().toLowerCase()}
                className="bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl px-4 py-2.5 text-sm transition-colors flex items-center gap-2"
              >
                {deleteLoading ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Deleting…
                  </>
                ) : (
                  "Delete Permanently"
                )}
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* ── User Detail Slide-out ── */}
      {selectedUser && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/40" onClick={() => setSelectedUser(null)} />
          <div className="relative w-full max-w-md bg-white dark:bg-slate-900 shadow-2xl border-l border-slate-200 dark:border-slate-700 overflow-y-auto animate-in slide-in-from-right">
            {/* Header */}
            <div className="sticky top-0 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 px-6 py-4 flex items-center justify-between z-10">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">User Details</h3>
              <button onClick={() => setSelectedUser(null)} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400">
                <X size={18} />
              </button>
            </div>
            {/* Avatar + Name */}
            <div className="px-6 py-6 flex flex-col items-center gap-3 border-b border-slate-100 dark:border-slate-800">
              <div className="w-16 h-16 rounded-full bg-gradient-to-br from-orange-500 to-purple-600 flex items-center justify-center text-white text-2xl font-bold shadow-lg">
                {(selectedUser.full_name || selectedUser.email)[0]?.toUpperCase()}
              </div>
              <div className="text-center">
                <p className="text-lg font-semibold text-slate-900 dark:text-white">{selectedUser.full_name || "—"}</p>
                <p className="text-sm text-slate-500 dark:text-slate-400">{selectedUser.email}</p>
              </div>
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                selectedUser.status === "active"
                  ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                  : "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
              }`}>
                {selectedUser.status || "active"}
              </span>
            </div>
            {/* Detail rows */}
            <div className="px-6 py-4 space-y-4">
              {[
                { label: "User ID", value: String(selectedUser.id) },
                { label: "Role", value: selectedUser.role },
                { label: "Organization ID", value: selectedUser.tenant_id ? String(selectedUser.tenant_id) : "—" },
                { label: "Team ID", value: selectedUser.organization_id ? String(selectedUser.organization_id) : "—" },
                { label: "Last Login", value: selectedUser.last_login_at ? new Date(selectedUser.last_login_at).toLocaleString() : "Never" },
                { label: "Created", value: selectedUser.created_at ? new Date(selectedUser.created_at).toLocaleString() : "—" },
              ].map((row) => (
                <div key={row.label} className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-800 last:border-0">
                  <span className="text-sm text-slate-500 dark:text-slate-400">{row.label}</span>
                  <span className="text-sm font-medium text-slate-900 dark:text-white">{row.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Toasts ── */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </PageLayout>
  );
}
