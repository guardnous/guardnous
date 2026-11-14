"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  ShieldCheck, Lock, Plus, ChevronDown, ChevronUp,
  X, Trash2, Pencil, Check, Search,
} from "lucide-react";

interface Permission {
  resource: string;
  action: string;
}

interface Role {
  id: string;
  name: string;
  slug: string;
  description: string;
  is_system: boolean;
  created_at: string;
  permissions?: Permission[];
}

const INPUT_CLS =
  "w-full h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500";

const RESOURCES = [
  "tenants", "organizations", "users", "groups", "roles", "scans",
  "findings", "reports", "integrations", "agents", "settings", "audit_logs",
];

const ACTIONS = ["create", "read", "update", "delete", "manage", "export"];

const systemRoleDescriptions: Record<string, string> = {
  platform_admin: "Full platform access across all organizations and features",
  tenant_admin: "Full access within assigned organization scope",
  org_admin: "Team-level administration and user management",
  security_engineer: "Manage scans, findings, and security configurations",
  devops_engineer: "Manage agents, integrations, and deployment configs",
  auditor: "Read-only access to all resources and audit logs",
  viewer: "Read-only access to dashboards and reports",
};

function Modal({ open, onClose, children }: { open: boolean; onClose: () => void; children: React.ReactNode }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl w-full max-w-2xl p-6 max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

export default function AdminRolesPage() {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editRole, setEditRole] = useState<Role | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [perms, setPerms] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");

  const { data: roles = [] } = useQuery<Role[]>({
    queryKey: ["admin-roles"],
    queryFn: () => api.get("/roles/").then((r) => r.data),
  });

  const createMut = useMutation({
    mutationFn: (body: { name: string; description: string; permissions: Permission[] }) =>
      api.post("/roles", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-roles"] });
      closeModal();
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, ...body }: { id: string; name: string; description: string; permissions: Permission[] }) =>
      api.put(`/roles/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-roles"] });
      closeModal();
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/roles/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-roles"] }),
  });

  const filtered = useMemo(() => {
    if (!search) return roles;
    const q = search.toLowerCase();
    return roles.filter(
      (r) => r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q)
    );
  }, [roles, search]);

  const systemRoles = filtered.filter((r) => r.is_system);
  const customRoles = filtered.filter((r) => !r.is_system);

  const systemCount = roles.filter((r) => r.is_system).length;

  function permKey(resource: string, action: string) {
    return `${resource}:${action}`;
  }

  function togglePerm(resource: string, action: string) {
    const key = permKey(resource, action);
    setPerms((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function openCreate() {
    setEditRole(null);
    setName("");
    setDescription("");
    setPerms(new Set());
    setModalOpen(true);
  }

  function openEdit(role: Role) {
    setEditRole(role);
    setName(role.name);
    setDescription(role.description);
    setPerms(new Set((role.permissions ?? []).map((p) => permKey(p.resource, p.action))));
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditRole(null);
    setName("");
    setDescription("");
    setPerms(new Set());
  }

  function handleSave() {
    const permissions = Array.from(perms).map((k) => {
      const [resource, action] = k.split(":");
      return { resource, action };
    });
    if (editRole) {
      updateMut.mutate({ id: editRole.id, name, description, permissions });
    } else {
      createMut.mutate({ name, description, permissions });
    }
  }

  return (
    <PageLayout
      title="Role Management"
      subtitle="Configure system and custom RBAC roles"
      icon={ShieldCheck}
      breadcrumbs={[{ label: "Admin" }, { label: "Roles" }]}
    >
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-orange-50 dark:bg-orange-500/10 flex items-center justify-center">
              <ShieldCheck size={18} className="text-orange-600 dark:text-orange-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Total Roles</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{roles.length}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-500/10 flex items-center justify-center">
              <Lock size={18} className="text-amber-600 dark:text-amber-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">System Roles</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{systemCount}</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 mb-6">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search roles…"
            className={`${INPUT_CLS} pl-10`}
          />
        </div>
        <button
          onClick={openCreate}
          className="bg-orange-600 hover:bg-orange-700 text-white rounded-xl h-12 px-6 font-semibold text-sm flex items-center justify-center gap-2 transition-colors"
        >
          <Plus size={16} /> Create Role
        </button>
      </div>

      {/* System Roles */}
      {systemRoles.length > 0 && (
        <div className="mb-8">
          <h2 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Lock size={14} /> System Roles
          </h2>
          <div className="grid gap-3">
            {systemRoles.map((role) => (
              <div key={role.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                <button
                  onClick={() => setExpanded(expanded === role.id ? null : role.id)}
                  className="w-full flex items-center justify-between p-6 text-left"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center">
                      <Lock size={16} className="text-slate-500 dark:text-slate-400" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">{role.name}</p>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        {systemRoleDescriptions[role.name] || role.description}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300">
                      System
                    </span>
                    {expanded === role.id ? (
                      <ChevronUp size={16} className="text-slate-400" />
                    ) : (
                      <ChevronDown size={16} className="text-slate-400" />
                    )}
                  </div>
                </button>
                {expanded === role.id && role.permissions && (
                  <div className="px-6 pb-6 border-t border-slate-100 dark:border-slate-800 pt-4">
                    <div className="flex flex-wrap gap-2">
                      {role.permissions.map((p) => (
                        <span
                          key={`${p.resource}:${p.action}`}
                          className="px-2.5 py-1 rounded-full bg-slate-50 dark:bg-slate-800 text-xs font-medium text-slate-600 dark:text-slate-400"
                        >
                          {p.resource}:{p.action}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Custom Roles */}
      <div>
        <h2 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-4">Custom Roles</h2>
        {customRoles.length === 0 ? (
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
              <ShieldCheck size={28} className="text-slate-400 dark:text-slate-500 dark:text-slate-400" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              {search ? "No roles found" : "No custom roles yet"}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
              {search
                ? "Try adjusting your search terms."
                : "Create a custom role to define fine-grained permissions for your team."}
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            {customRoles.map((role) => (
              <div key={role.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between p-6">
                  <button
                    onClick={() => setExpanded(expanded === role.id ? null : role.id)}
                    className="flex items-center gap-3 text-left flex-1"
                  >
                    <div className="w-9 h-9 rounded-xl bg-orange-50 dark:bg-orange-500/10 flex items-center justify-center">
                      <ShieldCheck size={16} className="text-orange-600 dark:text-orange-400" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">{role.name}</p>
                      <p className="text-sm text-slate-500 dark:text-slate-400">{role.description}</p>
                    </div>
                  </button>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded-full bg-orange-50 dark:bg-orange-500/10 text-xs font-medium text-orange-600 dark:text-orange-400">
                      Custom
                    </span>
                    <button
                      onClick={() => openEdit(role)}
                      className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                    >
                      <Pencil size={14} className="text-slate-500 dark:text-slate-400" />
                    </button>
                    <button
                      onClick={() => {
                        if (confirm("Delete this role?")) deleteMut.mutate(role.id);
                      }}
                      className="p-2 rounded-lg hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                    >
                      <Trash2 size={14} className="text-red-500" />
                    </button>
                  </div>
                </div>
                {expanded === role.id && role.permissions && (
                  <div className="px-6 pb-6 border-t border-slate-100 dark:border-slate-800 pt-4">
                    <div className="flex flex-wrap gap-2">
                      {role.permissions.map((p) => (
                        <span
                          key={`${p.resource}:${p.action}`}
                          className="px-2.5 py-1 rounded-full bg-orange-50 dark:bg-orange-500/10 text-xs font-medium text-orange-600 dark:text-orange-400"
                        >
                          {p.resource}:{p.action}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create/Edit Modal with Permission Matrix */}
      <Modal open={modalOpen} onClose={closeModal}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {editRole ? "Edit Role" : "Create Role"}
          </h2>
          <button onClick={closeModal} className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700">
            <X size={18} className="text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Role Name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. security_analyst"
              className={INPUT_CLS}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="Describe this role…"
              className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500 resize-none"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">Permission Matrix</label>
            <div className="overflow-x-auto border border-slate-200 dark:border-slate-700 rounded-xl">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700">
                    <th className="text-left px-3 py-2.5 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      Resource
                    </th>
                    {ACTIONS.map((a) => (
                      <th key={a} className="px-3 py-2.5 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider text-center">
                        {a}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {RESOURCES.map((resource) => (
                    <tr key={resource} className="border-b border-slate-100 dark:border-slate-700/50">
                      <td className="px-3 py-2 font-medium text-slate-700 dark:text-slate-300">
                        {resource.replace(/_/g, " ")}
                      </td>
                      {ACTIONS.map((action) => {
                        const checked = perms.has(permKey(resource, action));
                        return (
                          <td key={action} className="px-3 py-2 text-center">
                            <button
                              onClick={() => togglePerm(resource, action)}
                              className={`w-5 h-5 rounded flex items-center justify-center transition-colors ${
                                checked
                                  ? "bg-orange-600 text-white"
                                  : "border border-slate-300 dark:border-slate-600 hover:border-orange-400"
                              }`}
                            >
                              {checked && <Check size={12} />}
                            </button>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              {perms.size} permission{perms.size !== 1 ? "s" : ""} selected
            </p>
          </div>
          <button
            disabled={!name || createMut.isPending || updateMut.isPending}
            onClick={handleSave}
            className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white font-semibold rounded-xl h-12 px-6 text-sm transition-colors"
          >
            {createMut.isPending || updateMut.isPending
              ? "Saving…"
              : editRole
                ? "Update Role"
                : "Create Role"}
          </button>
        </div>
      </Modal>
    </PageLayout>
  );
}
