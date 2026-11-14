"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  Building2, Plus, ChevronDown, ChevronUp, Globe,
  Users, Calendar, X, Search, Sparkles, CheckCircle2,
} from "lucide-react";

interface Tenant {
  id: string;
  name: string;
  slug: string;
  domain: string | null;
  plan: string;
  status: string;
  max_users: number;
  max_organizations: number;
  max_scans_per_month: number;
  is_active: boolean;
  created_at: string;
}

const INPUT_CLS =
  "w-full h-12 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500";

const planStyles: Record<string, string> = {
  free: "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300",
  professional: "bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400",
  enterprise: "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400",
};

const statusStyles: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400",
  suspended: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400",
  inactive: "bg-slate-100 text-slate-600 dark:bg-slate-50 dark:bg-slate-8000/10 dark:text-slate-400",
};

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

function capitalize(s: string | null | undefined) {
  if (!s) return "Unknown";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export default function AdminTenantsPage() {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [form, setForm] = useState({ name: "", domain: "", plan: "free", max_users: "50", max_organizations: "5" });

  const { data: tenants = [] } = useQuery<Tenant[]>({
    queryKey: ["admin-tenants"],
    queryFn: () => api.get("/tenants/").then((r) => r.data),
  });

  const createMut = useMutation({
    mutationFn: (body: { name: string; domain?: string; plan: string }) =>
      api.post("/tenants", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-tenants"] });
      setCreateOpen(false);
      setForm({ name: "", domain: "", plan: "free", max_users: "50", max_organizations: "5" });
    },
  });

  const filtered = useMemo(() => {
    if (!search) return tenants;
    const q = search.toLowerCase();
    return tenants.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.slug.toLowerCase().includes(q) ||
        (t.domain && t.domain.toLowerCase().includes(q))
    );
  }, [tenants, search]);

  const activeCount = tenants.filter((t) => t.is_active || t.status === "active").length;
  const enterpriseCount = tenants.filter((t) => t.plan === "enterprise").length;

  return (
    <PageLayout
      title="Tenant Management"
      subtitle="Manage tenants and subscription plans"
      icon={Building2}
      breadcrumbs={[{ label: "Admin" }, { label: "Tenants" }]}
    >
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-orange-50 dark:bg-orange-500/10 flex items-center justify-center">
              <Building2 size={18} className="text-orange-600 dark:text-orange-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Total Tenants</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{tenants.length}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 flex items-center justify-center">
              <CheckCircle2 size={18} className="text-emerald-600 dark:text-emerald-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Active</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{activeCount}</p>
        </div>
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-500/10 flex items-center justify-center">
              <Sparkles size={18} className="text-amber-600 dark:text-amber-400" />
            </div>
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Enterprise</p>
          </div>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{enterpriseCount}</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 mb-6">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search tenants by name, slug, or domain…"
            className={`${INPUT_CLS} pl-10`}
          />
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          className="bg-orange-600 hover:bg-orange-700 text-white rounded-xl h-12 px-6 font-semibold text-sm flex items-center justify-center gap-2 transition-colors"
        >
          <Plus size={16} /> Create Tenant
        </button>
      </div>

      {/* Tenant List */}
      <div className="grid gap-4">
        {filtered.map((tenant) => (
          <div key={tenant.id} className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800">
            <div className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-orange-50 to-blue-50 dark:from-orange-500/10 dark:to-blue-500/10 flex items-center justify-center border border-orange-100 dark:border-orange-500/20">
                    <Building2 size={20} className="text-orange-600 dark:text-orange-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900 dark:text-white text-lg">{tenant.name}</h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400">{tenant.slug}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${planStyles[tenant.plan] || planStyles.free}`}>
                    {capitalize(tenant.plan)}
                  </span>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${statusStyles[tenant.status] || statusStyles.inactive}`}>
                    {capitalize(tenant.status)}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5">
                {tenant.domain && (
                  <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                    <Globe size={14} className="text-slate-400" /> {tenant.domain}
                  </div>
                )}
                <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                  <Users size={14} className="text-slate-400" /> {tenant.max_users} max users
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                  <Building2 size={14} className="text-slate-400" /> {tenant.max_organizations} max teams
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                  <Calendar size={14} className="text-slate-400" /> {new Date(tenant.created_at).toLocaleDateString()}
                </div>
              </div>

              <div className="flex items-center gap-3 mt-4 pt-4 border-t border-slate-100 dark:border-slate-800">
                <button
                  onClick={() => setExpanded(expanded === tenant.id ? null : tenant.id)}
                  className="text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 flex items-center gap-1 transition-colors"
                >
                  {expanded === tenant.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  {expanded === tenant.id ? "Hide" : "Show"} Details
                </button>
              </div>
            </div>

            {expanded === tenant.id && (
              <div className="px-6 pb-6 border-t border-slate-100 dark:border-slate-800 pt-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-3 text-center">
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Max Users</p>
                    <p className="text-lg font-bold text-slate-900 dark:text-white mt-1">{tenant.max_users}</p>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-3 text-center">
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Max Teams</p>
                    <p className="text-lg font-bold text-slate-900 dark:text-white mt-1">{tenant.max_organizations}</p>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-800 rounded-xl p-3 text-center">
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Scans / Month</p>
                    <p className="text-lg font-bold text-slate-900 dark:text-white mt-1">{tenant.max_scans_per_month}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}

        {filtered.length === 0 && (
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
              <Building2 size={28} className="text-slate-400 dark:text-slate-500 dark:text-slate-400" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
              {search ? "No tenants found" : "No tenants yet"}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
              {search
                ? "Try adjusting your search terms."
                : "Create your first tenant to get started."}
            </p>
          </div>
        )}
      </div>

      {/* Create Tenant Modal */}
      <Modal open={createOpen} onClose={() => setCreateOpen(false)}>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Create Tenant</h2>
          <button onClick={() => setCreateOpen(false)} className="p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700">
            <X size={18} className="text-slate-500 dark:text-slate-400" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Tenant Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Acme Corporation"
              className={INPUT_CLS}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Domain (optional)</label>
            <input
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              placeholder="acme.com"
              className={INPUT_CLS}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Plan</label>
            <div className="grid grid-cols-3 gap-2">
              {["free", "professional", "enterprise"].map((p) => (
                <button
                  key={p}
                  onClick={() => setForm({ ...form, plan: p })}
                  className={`h-10 rounded-xl text-sm font-medium transition-colors border ${
                    form.plan === p
                      ? "bg-orange-600 border-orange-600 text-white"
                      : "border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                  }`}
                >
                  {capitalize(p)}
                </button>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Max Users</label>
              <input
                type="number"
                value={form.max_users}
                onChange={(e) => setForm({ ...form, max_users: e.target.value })}
                className={INPUT_CLS}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Max Teams</label>
              <input
                type="number"
                value={form.max_organizations}
                onChange={(e) => setForm({ ...form, max_organizations: e.target.value })}
                className={INPUT_CLS}
              />
            </div>
          </div>
          <button
            disabled={!form.name || createMut.isPending}
            onClick={() => createMut.mutate({ name: form.name, domain: form.domain || undefined, plan: form.plan })}
            className="w-full bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white font-semibold rounded-xl h-12 px-6 text-sm transition-colors"
          >
            {createMut.isPending ? "Creating…" : "Create Tenant"}
          </button>
        </div>
      </Modal>
    </PageLayout>
  );
}
