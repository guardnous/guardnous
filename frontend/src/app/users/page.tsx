"use client";

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import { useAuth } from "@/lib/auth";
import PageLayout from "@/components/PageLayout";
import {
  Users,
  UserPlus,
  Search,
  Shield,
  Clock,
  Mail,
  X,
  MoreHorizontal,
  Check,
  ChevronUp,
  ChevronDown,
  UserX,
  AlertCircle,
  Send,
  Loader2,
  Crown,
  Activity,
  UserCheck,
  ShieldCheck,
  Trash2,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";

/* ───────── Types ───────── */

interface OrgUser {
  id: number;
  email: string;
  full_name: string;
  role: string;
  status: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface Toast {
  id: number;
  message: string;
  type: "success" | "error";
}

type SortField = "full_name" | "role" | "status" | "last_login_at";
type SortDir = "asc" | "desc";

/* ───────── Style Maps ───────── */

const STATUS_STYLES: Record<string, string> = {
  active: "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 ring-1 ring-emerald-600/20",
  invited: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 ring-1 ring-amber-600/20",
  disabled: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400 ring-1 ring-red-600/20",
  pending: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 ring-1 ring-amber-600/20",
};

const ROLE_COLORS: Record<string, string> = {
  admin: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 ring-1 ring-orange-600/20",
  owner: "bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400 ring-1 ring-purple-600/20",
  manager: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 ring-1 ring-sky-600/20",
  analyst: "bg-teal-50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-400 ring-1 ring-teal-600/20",
  member: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 ring-1 ring-slate-400/20",
  viewer: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 ring-1 ring-slate-400/20",
};

// Must be role names the backend accepts (core/rbac.py ROLE_RANK)
const AVAILABLE_ROLES = ["org_admin", "security_engineer", "devops_engineer", "member", "auditor", "viewer"];

/* ───────── Helpers ───────── */

function roleStyle(role: string): string {
  return ROLE_COLORS[role.toLowerCase()] ?? ROLE_COLORS.member;
}

function statusStyle(status: string): string {
  return STATUS_STYLES[status.toLowerCase()] ?? STATUS_STYLES.active;
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

function initials(name: string): string {
  return name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

/* ───────── Modal ───────── */

function Modal({ open, onClose, title, children }: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
            <X size={18} className="text-slate-400" />
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
        <div key={t.id} className={`flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg text-sm font-medium ${
          t.type === "success" ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
        }`}>
          {t.type === "success" ? <Check size={16} /> : <AlertCircle size={16} />}
          <span className="flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="p-0.5 hover:opacity-70"><X size={14} /></button>
        </div>
      ))}
    </div>
  );
}

/* ───────── Main Page ───────── */

export default function UsersPage() {
  const { user: authUser, isAdmin } = useAuth();
  const queryClient = useQueryClient();

  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("full_name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [openMenu, setOpenMenu] = useState<number | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Modals
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("member");
  const [inviteLoading, setInviteLoading] = useState(false);

  const [roleChangeUser, setRoleChangeUser] = useState<OrgUser | null>(null);
  const [newRole, setNewRole] = useState("");

  const addToast = useCallback((message: string, type: "success" | "error") => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000);
  }, []);

  // Fetch users
  const { data: usersData, isLoading } = useQuery({
    queryKey: ["org-users"],
    queryFn: async () => {
      const { data } = await api.get("/users/");
      return data;
    },
  });

  // Fetch invitations
  const { data: invitationsData } = useQuery({
    queryKey: ["org-invitations"],
    queryFn: async () => {
      const { data } = await api.get("/org/invitations");
      return data;
    },
  });

  // GET /users/ returns a plain array that also contains pending invitations
  const users: OrgUser[] = (Array.isArray(usersData) ? usersData : usersData?.users ?? usersData?.items ?? [])
    .filter((u: OrgUser) => u.status !== "invited");
  const pendingInvites = Array.isArray(invitationsData)
    ? invitationsData.filter((inv: { status: string }) => inv.status === "pending")
    : [];
  const planLimit = 50; // configurable from org settings

  // Stats
  const totalUsers = users.length;
  const activeUsers = users.filter((u) => u.is_active).length;
  const pendingCount = pendingInvites.length;

  // Sorting & filtering
  const filtered = useMemo(() => {
    let list = [...users];
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (u) =>
          u.full_name.toLowerCase().includes(q) ||
          u.email.toLowerCase().includes(q) ||
          u.role.toLowerCase().includes(q),
      );
    }
    list.sort((a, b) => {
      const aVal = a[sortField] ?? "";
      const bVal = b[sortField] ?? "";
      const cmp = String(aVal).localeCompare(String(bVal));
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [users, search, sortField, sortDir]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  };

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpenMenu(null);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Actions
  const handleInvite = async () => {
    if (!inviteEmail.trim()) return;
    setInviteLoading(true);
    try {
      await api.post("/org/invite", { emails: [inviteEmail], role: inviteRole });
      addToast(`Invitation sent to ${inviteEmail}`, "success");
      setInviteEmail("");
      setInviteRole("member");
      setInviteOpen(false);
      queryClient.invalidateQueries({ queryKey: ["org-invitations"] });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "Failed to send invitation";
      addToast(msg, "error");
    } finally {
      setInviteLoading(false);
    }
  };

  const handleToggleActive = async (user: OrgUser) => {
    try {
      await api.patch(`/users/${user.id}/status`, { status: user.is_active ? "deactivated" : "active" });
      addToast(`${user.full_name} ${user.is_active ? "disabled" : "enabled"}`, "success");
      queryClient.invalidateQueries({ queryKey: ["org-users"] });
    } catch {
      addToast("Failed to update user status", "error");
    }
    setOpenMenu(null);
  };

  const handleChangeRole = async () => {
    if (!roleChangeUser || !newRole) return;
    try {
      await api.put(`/users/${roleChangeUser.id}/role`, { role: newRole });
      addToast(`${roleChangeUser.full_name}'s role updated to ${newRole}`, "success");
      queryClient.invalidateQueries({ queryKey: ["org-users"] });
      setRoleChangeUser(null);
    } catch (err: any) {
      addToast(err?.response?.data?.detail || "Failed to change role", "error");
    }
  };

  const handleRemoveUser = async (user: OrgUser) => {
    try {
      await api.delete(`/org/remove-user`, {
        data: { user_id: user.id, organization_id: authUser?.organization_id },
      });
      addToast(`${user.full_name} removed from organization`, "success");
      queryClient.invalidateQueries({ queryKey: ["org-users"] });
    } catch {
      addToast("Failed to remove user", "error");
    }
    setOpenMenu(null);
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ChevronUp size={14} className="opacity-0 group-hover:opacity-30" />;
    return sortDir === "asc" ? <ChevronUp size={14} /> : <ChevronDown size={14} />;
  };

  const inputCls = "w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-orange-500 focus:border-orange-500 transition-colors";

  return (
    <PageLayout
      title="User Management"
      subtitle="Manage your organization's team members and access"
      icon={Users}
      actions={
        isAdmin ? (
          <button
            onClick={() => setInviteOpen(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium transition-colors shadow-sm"
          >
            <UserPlus size={16} />
            Invite User
          </button>
        ) : undefined
      }
    >
      {/* ── Stats Bar ── */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-8">
        {[
          { label: "Total Users", value: totalUsers, icon: Users, color: "text-blue-500", bg: "bg-blue-50 dark:bg-blue-950/40" },
          { label: "Active", value: activeUsers, icon: UserCheck, color: "text-emerald-500", bg: "bg-emerald-50 dark:bg-emerald-950/40" },
          { label: "Pending Invitations", value: pendingCount, icon: Mail, color: "text-amber-500", bg: "bg-amber-50 dark:bg-amber-950/40" },
          { label: "Plan Usage", value: `${totalUsers}/${planLimit}`, icon: Activity, color: "text-orange-500", bg: "bg-orange-50 dark:bg-orange-950/40" },
        ].map((stat) => (
          <div key={stat.label} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-xl ${stat.bg} flex items-center justify-center`}>
                <stat.icon size={18} className={stat.color} />
              </div>
              <div>
                <p className="text-2xl font-bold text-slate-900 dark:text-white">{stat.value}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">{stat.label}</p>
              </div>
            </div>
            {stat.label === "Plan Usage" && (
              <div className="mt-3">
                <div className="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-orange-500 transition-all"
                    style={{ width: `${Math.min((totalUsers / planLimit) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-[11px] text-slate-400 mt-1">{Math.round((totalUsers / planLimit) * 100)}% of plan limit</p>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Search Bar ── */}
      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex-1 max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name, email, or role…"
            className={`${inputCls} pl-9`}
          />
        </div>
      </div>

      {/* ── Users Table ── */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="animate-spin text-slate-400" size={28} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 text-slate-400">
            <UserX size={40} className="mx-auto mb-3 opacity-40" />
            <p className="text-sm">No users found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                <tr className="text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  <th className="px-6 py-3 cursor-pointer group" onClick={() => toggleSort("full_name")}>
                    <span className="flex items-center gap-1">User <SortIcon field="full_name" /></span>
                  </th>
                  <th className="px-6 py-3 cursor-pointer group" onClick={() => toggleSort("role")}>
                    <span className="flex items-center gap-1">Role <SortIcon field="role" /></span>
                  </th>
                  <th className="px-6 py-3 cursor-pointer group" onClick={() => toggleSort("status")}>
                    <span className="flex items-center gap-1">Status <SortIcon field="status" /></span>
                  </th>
                  <th className="px-6 py-3 cursor-pointer group" onClick={() => toggleSort("last_login_at")}>
                    <span className="flex items-center gap-1">Last Login <SortIcon field="last_login_at" /></span>
                  </th>
                  {isAdmin && <th className="px-6 py-3 text-right">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {filtered.map((u) => {
                  const isSelf = u.id === authUser?.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-orange-100 to-amber-50 dark:from-orange-500/20 dark:to-amber-500/10 flex items-center justify-center text-xs font-bold text-orange-600 dark:text-orange-400">
                            {initials(u.full_name)}
                          </div>
                          <div>
                            <p className="font-medium text-slate-900 dark:text-white flex items-center gap-1.5">
                              {u.full_name}
                              {isSelf && <span className="text-[10px] text-orange-500 font-semibold">(you)</span>}
                            </p>
                            <p className="text-xs text-slate-500 dark:text-slate-400">{u.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium capitalize ${roleStyle(u.role)}`}>
                          {u.role === "admin" && <Crown size={11} />}
                          {u.role === "manager" && <ShieldCheck size={11} />}
                          {u.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium capitalize ${statusStyle(u.is_active ? "active" : "disabled")}`}>
                          {u.is_active ? "Active" : "Disabled"}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                          <Clock size={12} />
                          {relativeTime(u.last_login_at)}
                        </div>
                      </td>
                      {isAdmin && (
                        <td className="px-6 py-4 text-right">
                          {!isSelf && (
                            <div className="relative inline-block" ref={openMenu === u.id ? menuRef : undefined}>
                              <button
                                onClick={() => setOpenMenu(openMenu === u.id ? null : u.id)}
                                className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                              >
                                <MoreHorizontal size={16} className="text-slate-400" />
                              </button>
                              {openMenu === u.id && (
                                <div className="absolute right-0 mt-1 w-48 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-700 shadow-xl z-20 py-1">
                                  <button
                                    onClick={() => { setRoleChangeUser(u); setNewRole(u.role); setOpenMenu(null); }}
                                    className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                                  >
                                    <Shield size={14} /> Change Role
                                  </button>
                                  <button
                                    onClick={() => handleToggleActive(u)}
                                    className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                                  >
                                    {u.is_active ? <ToggleLeft size={14} /> : <ToggleRight size={14} />}
                                    {u.is_active ? "Disable" : "Enable"}
                                  </button>
                                  <div className="border-t border-slate-100 dark:border-slate-800 my-1" />
                                  <button
                                    onClick={() => handleRemoveUser(u)}
                                    className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30"
                                  >
                                    <Trash2 size={14} /> Remove from Org
                                  </button>
                                </div>
                              )}
                            </div>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Invite User Modal ── */}
      <Modal open={inviteOpen} onClose={() => setInviteOpen(false)} title="Invite Team Member">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Email Address</label>
            <div className="relative">
              <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="colleague@company.com"
                className={`${inputCls} pl-9`}
                autoFocus
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Role</label>
            <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} className={inputCls}>
              {AVAILABLE_ROLES.map((r) => (
                <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
              ))}
            </select>
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {inviteRole === "org_admin" && "Team administration and user management"}
              {inviteRole === "security_engineer" && "Manage scans, findings, and reports"}
              {inviteRole === "devops_engineer" && "Run scans and manage integrations"}
              {inviteRole === "member" && "Standard access to dashboards and findings"}
              {inviteRole === "auditor" && "Read-only access with export"}
              {inviteRole === "viewer" && "Read-only access to dashboards"}
            </p>
          </div>
          <div className="flex items-center justify-end gap-3 pt-2">
            <button onClick={() => setInviteOpen(false)} className="px-4 py-2.5 rounded-xl text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
              Cancel
            </button>
            <button
              onClick={handleInvite}
              disabled={!inviteEmail.trim() || inviteLoading}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-sm font-medium transition-colors"
            >
              {inviteLoading ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
              Send Invitation
            </button>
          </div>
        </div>
      </Modal>

      {/* ── Change Role Modal ── */}
      <Modal open={!!roleChangeUser} onClose={() => setRoleChangeUser(null)} title="Change User Role">
        {roleChangeUser && (
          <div className="space-y-4">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              Change role for <span className="font-medium text-slate-900 dark:text-white">{roleChangeUser.full_name}</span>
            </p>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">New Role</label>
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)} className={inputCls}>
                {AVAILABLE_ROLES.map((r) => (
                  <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button onClick={() => setRoleChangeUser(null)} className="px-4 py-2.5 rounded-xl text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                Cancel
              </button>
              <button
                onClick={handleChangeRole}
                disabled={newRole === roleChangeUser.role}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-sm font-medium transition-colors"
              >
                <Check size={16} /> Update Role
              </button>
            </div>
          </div>
        )}
      </Modal>

      <ToastContainer toasts={toasts} onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))} />
    </PageLayout>
  );
}
