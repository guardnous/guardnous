"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  FolderKey, Plus, ChevronDown, ChevronUp, Users,
  ShieldCheck, X, UserPlus, Trash2, Search,
} from "lucide-react";

interface GroupMember {
  id: string;
  full_name: string;
  email: string;
}

interface GroupRole {
  id: string;
  name: string;
}

interface Group {
  id: string;
  name: string;
  description: string;
  member_count: number;
  role_count: number;
  members?: GroupMember[];
  roles?: GroupRole[];
}

interface User {
  id: string;
  full_name: string;
  email: string;
}

interface Role {
  id: string;
  name: string;
}

const INPUT_CLS =
  "w-full h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500";

function Modal({ open, onClose, children }: { open: boolean; onClose: () => void; children: React.ReactNode }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

export default function AdminGroupsPage() {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [addMemberId, setAddMemberId] = useState<string | null>(null);
  const [assignRoleId, setAssignRoleId] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", description: "" });
  const [selectedUser, setSelectedUser] = useState("");
  const [selectedRole, setSelectedRole] = useState("");
  const [userSearch, setUserSearch] = useState("");
  const [search, setSearch] = useState("");

  const { data: groups = [] } = useQuery<Group[]>({
    queryKey: ["admin-groups"],
    queryFn: () => api.get("/groups/").then((r) => r.data),
  });

  const { data: groupDetail } = useQuery<Group>({
    queryKey: ["admin-group", expanded],
    queryFn: () => api.get(`/groups/${expanded}`).then((r) => r.data),
    enabled: !!expanded,
  });

  const { data: allUsers = [] } = useQuery<User[]>({
    queryKey: ["admin-users"],
    queryFn: () => api.get("/users/").then((r) => r.data),
  });

  const { data: allRoles = [] } = useQuery<Role[]>({
    queryKey: ["admin-roles"],
    queryFn: () => api.get("/roles/").then((r) => r.data),
  });

  const createMut = useMutation({
    mutationFn: (body: { name: string; description: string }) => api.post("/groups", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-groups"] });
      setCreateOpen(false);
      setForm({ name: "", description: "" });
    },
  });

  const addMemberMut = useMutation({
    mutationFn: ({ groupId, user_id }: { groupId: string; user_id: string }) =>
      api.post(`/groups/${groupId}/members`, { user_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-group", addMemberId] });
      qc.invalidateQueries({ queryKey: ["admin-groups"] });
      setAddMemberId(null);
      setSelectedUser("");
    },
  });

  const assignRoleMut = useMutation({
    mutationFn: ({ groupId, role_id }: { groupId: string; role_id: string }) =>
      api.post(`/groups/${groupId}/roles`, { role_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-group", assignRoleId] });
      qc.invalidateQueries({ queryKey: ["admin-groups"] });
      setAssignRoleId(null);
      setSelectedRole("");
    },
  });

  const removeMemberMut = useMutation({
    mutationFn: ({ groupId, userId }: { groupId: string; userId: string }) =>
      api.delete(`/groups/${groupId}/members/${userId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-group", expanded] });
      qc.invalidateQueries({ queryKey: ["admin-groups"] });
    },
  });

  const removeRoleMut = useMutation({
    mutationFn: ({ groupId, roleId }: { groupId: string; roleId: string }) =>
      api.delete(`/groups/${groupId}/roles/${roleId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-group", expanded] });
      qc.invalidateQueries({ queryKey: ["admin-groups"] });
    },
  });

  const filteredUsers = useMemo(
    () =>
      allUsers.filter(
        (u) =>
          !userSearch ||
          u.full_name.toLowerCase().includes(userSearch.toLowerCase()) ||
          u.email.toLowerCase().includes(userSearch.toLowerCase())
      ),
    [allUsers, userSearch]
  );

  const filtered = useMemo(() => {
    if (!search) return groups;
    const q = search.toLowerCase();
    return groups.filter(
      (g) => g.name.toLowerCase().includes(q) || g.description.toLowerCase().includes(q)
    );
  }, [groups, search]);

  const totalMembers = groups.reduce((sum, g) => sum + g.member_count, 0);

  return (
    <PageLayout
      title="Group Management"
      subtitle="Organize users into groups with shared role assignments"
      icon={FolderKey}
      breadcrumbs={[{ label: "Admin" }, { label: "Groups" }]}
    >
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-orange-50 dark:bg-orange-500/10 flex items-center justify-center">
              <FolderKey size={18} className="text-orange-600 dark:text-orange-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Total Groups</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{groups.length}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 flex items-center justify-center">
              <Users size={18} className="text-emerald-600 dark:text-emerald-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Total Members</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{totalMembers}</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 mb-6">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search groups…"
            className={`${INPUT_CLS} pl-10`}
          />
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          className="bg-orange-600 hover:bg-orange-700 text-white rounded-xl h-12 px-6 font-semibold text-sm flex items-center justify-center gap-2 transition-colors"
        >
          <Plus size={16} /> Create Group
        </button>
      </div>

      {/* Group List */}
      <div className="grid gap-4">
        {filtered.map((group) => (
          <div key={group.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
            <div className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-orange-50 to-blue-50 dark:from-orange-500/10 dark:to-blue-500/10 flex items-center justify-center border border-orange-100 dark:border-orange-500/20">
                    <FolderKey size={20} className="text-orange-600 dark:text-orange-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900 dark:text-white">{group.name}</h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400">{group.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300">
                    <Users size={12} /> {group.member_count} members
                  </span>
                  <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-orange-50 dark:bg-orange-500/10 text-xs font-medium text-orange-600 dark:text-orange-400">
                    <ShieldCheck size={12} /> {group.role_count} roles
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-3 mt-4 pt-4 border-t border-slate-100 dark:border-slate-800">
                <button
                  onClick={() => setExpanded(expanded === group.id ? null : group.id)}
                  className="text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 flex items-center gap-1 transition-colors"
                >
                  {expanded === group.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  {expanded === group.id ? "Collapse" : "Expand"}
                </button>
                <button
                  onClick={() => { setAddMemberId(group.id); setUserSearch(""); }}
                  className="text-sm text-orange-600 dark:text-orange-400 hover:text-orange-700 flex items-center gap-1 transition-colors"
                >
                  <UserPlus size={14} /> Add Member
                </button>
                <button
                  onClick={() => setAssignRoleId(group.id)}
                  className="text-sm text-orange-600 dark:text-orange-400 hover:text-orange-700 flex items-center gap-1 transition-colors"
                >
                  <ShieldCheck size={14} /> Assign Role
                </button>
              </div>
            </div>

            {expanded === group.id && groupDetail && (
              <div className="px-6 pb-6 border-t border-slate-100 dark:border-slate-800 pt-4 space-y-4">
                <div>
                  <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Members</h4>
                  {groupDetail.members && groupDetail.members.length > 0 ? (
                    <div className="space-y-2">
                      {groupDetail.members.map((m) => (
                        <div key={m.id} className="flex items-center justify-between px-4 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-800">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-orange-400 to-blue-500 flex items-center justify-center text-white text-xs font-semibold">
                              {m.full_name?.charAt(0)?.toUpperCase() || "?"}
                            </div>
                            <div>
                              <p className="text-sm font-medium text-slate-900 dark:text-white">{m.full_name}</p>
                              <p className="text-xs text-slate-500 dark:text-slate-400">{m.email}</p>
                            </div>
                          </div>
                          <button
                            onClick={() => { if (!confirm("Remove this member from the group?")) return; removeMemberMut.mutate({ groupId: group.id, userId: m.id }); }}
                            className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                          >
                            <Trash2 size={14} className="text-red-500" />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-400 text-center py-3">No members</p>
                  )}
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Assigned Roles</h4>
                  {groupDetail.roles && groupDetail.roles.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {groupDetail.roles.map((r) => (
                        <span key={r.id} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-orange-50 dark:bg-orange-500/10 text-sm text-orange-700 dark:text-orange-400">
                          <ShieldCheck size={12} /> {r.name}
                          <button onClick={() => { if (!confirm("Remove this role from the group?")) return; removeRoleMut.mutate({ groupId: group.id, roleId: r.id }); }} className="hover:text-red-500 transition-colors">
                            <X size={12} />
                          </button>
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-400 text-center py-3">No roles assigned</p>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}

        {filtered.length === 0 && (
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
              <FolderKey size={28} className="text-slate-400 dark:text-slate-500 dark:text-slate-400" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              {search ? "No groups found" : "No groups yet"}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
              {search
                ? "Try adjusting your search terms."
                : "Create your first group to organize users with shared role assignments."}
            </p>
          </div>
        )}
      </div>

      {/* Create Group Modal */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Create Group</h2>
          <button onClick={() => setCreateOpen(false)} className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700">
            <X size={18} className="text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Group Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. Security Team"
              className={INPUT_CLS}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Description</label>
            <textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              rows={3}
              placeholder="Describe this group…"
              className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500 resize-none"
            />
          </div>
          <button
            disabled={!form.name || createMut.isPending}
            onClick={() => createMut.mutate(form)}
            className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white font-semibold rounded-xl h-12 px-6 text-sm transition-colors"
          >
            {createMut.isPending ? "Creating…" : "Create Group"}
          </button>
        </div>
      </Modal>

      {/* Add Member Modal */}
      <Modal open={!!addMemberId} onClose={() => setAddMemberId(null)}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Add Member</h2>
          <button onClick={() => setAddMemberId(null)} className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700">
            <X size={18} className="text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="space-y-4">
          <div className="relative">
            <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              placeholder="Search users…"
              className={`${INPUT_CLS} pl-10`}
            />
          </div>
          <div className="max-h-48 overflow-y-auto space-y-1 border border-slate-200 dark:border-slate-700 rounded-xl p-2">
            {filteredUsers.map((u) => (
              <button
                key={u.id}
                onClick={() => setSelectedUser(u.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  selectedUser === u.id
                    ? "bg-orange-50 dark:bg-orange-500/10 text-orange-700 dark:text-orange-400"
                    : "text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                }`}
              >
                <p className="font-medium">{u.full_name}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">{u.email}</p>
              </button>
            ))}
          </div>
          <button
            disabled={!selectedUser || addMemberMut.isPending}
            onClick={() => addMemberId && addMemberMut.mutate({ groupId: addMemberId, user_id: selectedUser })}
            className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white font-semibold rounded-xl h-12 px-6 text-sm transition-colors"
          >
            {addMemberMut.isPending ? "Adding…" : "Add Member"}
          </button>
        </div>
      </Modal>

      {/* Assign Role Modal */}
      <Modal open={!!assignRoleId} onClose={() => setAssignRoleId(null)}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Assign Role</h2>
          <button onClick={() => setAssignRoleId(null)} className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700">
            <X size={18} className="text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="space-y-4">
          <select
            value={selectedRole}
            onChange={(e) => setSelectedRole(e.target.value)}
            className={INPUT_CLS}
          >
            <option value="">Select role…</option>
            {allRoles.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
          <button
            disabled={!selectedRole || assignRoleMut.isPending}
            onClick={() => assignRoleId && assignRoleMut.mutate({ groupId: assignRoleId, role_id: selectedRole })}
            className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white font-semibold rounded-xl h-12 px-6 text-sm transition-colors"
          >
            {assignRoleMut.isPending ? "Assigning…" : "Assign Role"}
          </button>
        </div>
      </Modal>
    </PageLayout>
  );
}
