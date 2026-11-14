"use client";

import { useState } from "react";
import {
  Building2,
  Users,
  Mail,
  Send,
  Plus,
  X,
  Shield,
  Globe,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  MailPlus,
  ClipboardList,
  LayoutDashboard,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchOrgDashboard,
  fetchOrganizations,
  createOrganization,
  bulkInviteUsers,
  fetchInvitations,
  revokeInvitation,
} from "@/lib/api";
import PageLayout from "@/components/PageLayout";

type Tab = "overview" | "organizations" | "invite" | "invitations";

const TAB_CONFIG: { key: Tab; label: string; icon: typeof Building2 }[] = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "organizations", label: "Teams", icon: Building2 },
  { key: "invite", label: "Invite Users", icon: MailPlus },
  { key: "invitations", label: "Invitations", icon: ClipboardList },
];

const PLAN_COLORS: Record<string, string> = {
  enterprise: "bg-violet-100 text-violet-700",
  professional: "bg-blue-100 text-blue-700",
  starter: "bg-emerald-100 text-emerald-700",
  free: "bg-slate-100 text-slate-600 dark:text-slate-300",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-emerald-100 text-emerald-700",
  inactive: "bg-slate-100 text-slate-500 dark:text-slate-400",
  suspended: "bg-red-100 text-red-700",
  pending: "bg-amber-100 text-amber-700",
  accepted: "bg-emerald-100 text-emerald-700",
  revoked: "bg-red-100 text-red-700",
};

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number | string;
  icon: typeof Building2;
  accent: string;
}) {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 p-6 flex items-start gap-4">
      <div className={`p-3 rounded-xl ${accent}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</p>
        <p className="text-2xl font-bold text-slate-900 dark:text-white mt-1">{value}</p>
      </div>
    </div>
  );
}

function Badge({ text, colorClass }: { text: string; colorClass: string }) {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${colorClass}`}
    >
      {text}
    </span>
  );
}

function OverviewTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["org-dashboard"],
    queryFn: fetchOrgDashboard,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  const dashboard = data ?? {
    total_tenants: 0,
    total_organizations: 0,
    total_users: 0,
    total_invitations: 0,
    pending_invitations: 0,
    tenants: [],
  };

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Organizations"
          value={dashboard.total_tenants}
          icon={Shield}
          accent="bg-orange-100 text-orange-600"
        />
        <StatCard
          label="Teams"
          value={dashboard.total_organizations}
          icon={Building2}
          accent="bg-violet-100 text-violet-600"
        />
        <StatCard
          label="Total Users"
          value={dashboard.total_users}
          icon={Users}
          accent="bg-emerald-100 text-emerald-600"
        />
        <StatCard
          label="Pending Invitations"
          value={dashboard.pending_invitations}
          icon={Mail}
          accent="bg-amber-100 text-amber-600"
        />
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700">
        <div className="px-6 py-4 border-b border-slate-100">
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">Organizations</h3>
        </div>
        {dashboard.tenants.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Shield className="h-10 w-10 text-slate-300 mx-auto mb-3" />
            <p className="text-sm text-slate-500 dark:text-slate-400">No organizations found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Name
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Slug
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Plan
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Status
                  </th>
                  <th className="text-right px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Teams
                  </th>
                  <th className="text-right px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Users
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {dashboard.tenants.map(
                  (t: {
                    id: string;
                    name: string;
                    slug: string;
                    plan: string;
                    status: string;
                    org_count: number;
                    user_count: number;
                    created_at: string;
                  }) => (
                    <tr key={t.id} className="hover:bg-slate-50 dark:bg-slate-800/50">
                      <td className="px-6 py-3 font-medium text-slate-900 dark:text-white">
                        {t.name}
                      </td>
                      <td className="px-6 py-3 text-slate-500 dark:text-slate-400 font-mono text-xs">
                        {t.slug}
                      </td>
                      <td className="px-6 py-3">
                        <Badge
                          text={t.plan}
                          colorClass={
                            PLAN_COLORS[t.plan] ?? "bg-slate-100 text-slate-600 dark:text-slate-300"
                          }
                        />
                      </td>
                      <td className="px-6 py-3">
                        <Badge
                          text={t.status}
                          colorClass={
                            STATUS_COLORS[t.status] ??
                            "bg-slate-100 text-slate-500 dark:text-slate-400"
                          }
                        />
                      </td>
                      <td className="px-6 py-3 text-right text-slate-700 dark:text-slate-200">
                        {t.org_count}
                      </td>
                      <td className="px-6 py-3 text-right text-slate-700 dark:text-slate-200">
                        {t.user_count}
                      </td>
                      <td className="px-6 py-3 text-slate-500 dark:text-slate-400">
                        {new Date(t.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function CreateOrgModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    slug: "",
    subdomain: "",
    admin_email: "",
  });

  const mutation = useMutation({
    mutationFn: () =>
      createOrganization({
        name: form.name,
        slug: form.slug,
        subdomain: form.subdomain || undefined,
        admin_email: form.admin_email || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
      queryClient.invalidateQueries({ queryKey: ["org-dashboard"] });
      onClose();
    },
  });

  const handleSlugify = (name: string) => {
    setForm((prev) => ({
      ...prev,
      name,
      slug: name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, ""),
    }));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            Create Team
          </h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-400 hover:text-slate-600 dark:text-slate-300 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
          className="p-6 space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
              Team Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              required
              value={form.name}
              onChange={(e) => handleSlugify(e.target.value)}
              placeholder="Acme Corporation"
              className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
              Slug <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              required
              value={form.slug}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, slug: e.target.value }))
              }
              placeholder="acme-corporation"
              className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
              Subdomain
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={form.subdomain}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, subdomain: e.target.value }))
                }
                placeholder="acme"
                className="flex-1 h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
              />
              <span className="text-sm text-slate-400">.guardnous.io</span>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
              Admin Email
            </label>
            <input
              type="email"
              value={form.admin_email}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, admin_email: e.target.value }))
              }
              placeholder="admin@acme.com"
              className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
            />
          </div>
          {mutation.isError && (
            <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 text-red-700 text-sm">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>Failed to create team. Please try again.</span>
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="h-12 px-5 rounded-xl text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending || !form.name || !form.slug}
              className="h-12 px-6 rounded-xl text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
            >
              {mutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin" />
              )}
              Create Team
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function OrganizationsTab() {
  const [showModal, setShowModal] = useState(false);
  const { data: orgs, isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: fetchOrganizations,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  const organizations = orgs ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {organizations.length} team
          {organizations.length !== 1 ? "s" : ""}
        </p>
        <button
          onClick={() => setShowModal(true)}
          className="h-12 px-5 rounded-xl text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 transition-colors flex items-center gap-2"
        >
          <Plus className="h-4 w-4" />
          Create Team
        </button>
      </div>

      {organizations.length === 0 ? (
        <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 px-6 py-16 text-center">
          <Building2 className="h-12 w-12 text-slate-300 mx-auto mb-4" />
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">
            No teams yet
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
            Create your first team to get started.
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="h-12 px-5 rounded-xl text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 transition-colors inline-flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            Create Team
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {organizations.map(
            (org: {
              id: string;
              name: string;
              slug: string;
              subdomain: string | null;
              admin_email: string | null;
              plan: string;
              status: string;
              is_active: boolean;
              created_at: string;
            }) => (
              <div
                key={org.id}
                className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 p-5 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-xl bg-orange-50">
                      <Building2 className="h-5 w-5 text-orange-600" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-slate-900 dark:text-white">
                        {org.name}
                      </h4>
                      <p className="text-xs font-mono text-slate-400">
                        {org.slug}
                      </p>
                    </div>
                  </div>
                  <Badge
                    text={org.status}
                    colorClass={
                      STATUS_COLORS[org.status] ??
                      "bg-slate-100 text-slate-500 dark:text-slate-400"
                    }
                  />
                </div>
                <div className="space-y-2 text-sm">
                  {org.subdomain && (
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                      <Globe className="h-3.5 w-3.5 flex-shrink-0" />
                      <span className="truncate">
                        {org.subdomain}.guardnous.io
                      </span>
                    </div>
                  )}
                  {org.admin_email && (
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                      <Mail className="h-3.5 w-3.5 flex-shrink-0" />
                      <span className="truncate">{org.admin_email}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-2 text-slate-400">
                    <Clock className="h-3.5 w-3.5 flex-shrink-0" />
                    <span>
                      Created {new Date(org.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-100 flex items-center gap-2">
                  <Badge
                    text={org.plan}
                    colorClass={
                      PLAN_COLORS[org.plan] ?? "bg-slate-100 text-slate-600 dark:text-slate-300"
                    }
                  />
                  {org.is_active ? (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
                      <CheckCircle2 className="h-3 w-3" /> Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-slate-400">
                      <XCircle className="h-3 w-3" /> Inactive
                    </span>
                  )}
                </div>
              </div>
            )
          )}
        </div>
      )}

      {showModal && <CreateOrgModal onClose={() => setShowModal(false)} />}
    </div>
  );
}

function InviteUsersTab() {
  const queryClient = useQueryClient();
  const [emailText, setEmailText] = useState("");
  const [role, setRole] = useState("viewer");
  const [message, setMessage] = useState("");
  const [sentCount, setSentCount] = useState<number | null>(null);

  const mutation = useMutation({
    mutationFn: () => {
      const emails = emailText
        .split("\n")
        .map((e) => e.trim())
        .filter((e) => e.length > 0);
      return bulkInviteUsers({
        emails,
        role,
        message: message || undefined,
      });
    },
    onSuccess: (data) => {
      const count = Array.isArray(data) ? data.length : 0;
      setSentCount(count);
      setEmailText("");
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["invitations"] });
      queryClient.invalidateQueries({ queryKey: ["org-dashboard"] });
    },
  });

  const emailCount = emailText
    .split("\n")
    .map((e) => e.trim())
    .filter((e) => e.length > 0).length;

  return (
    <div className="max-w-2xl space-y-6">
      <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 p-6 space-y-5">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">
            Invite Team Members
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Send invitations to join your organization. Enter one email address
            per line.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
            Email Addresses <span className="text-red-500">*</span>
          </label>
          <textarea
            rows={6}
            value={emailText}
            onChange={(e) => {
              setEmailText(e.target.value);
              setSentCount(null);
            }}
            placeholder={"alice@example.com\nbob@example.com\ncharlie@example.com"}
            className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition resize-none font-mono"
          />
          {emailCount > 0 && (
            <p className="mt-1 text-xs text-slate-400">
              {emailCount} email{emailCount !== 1 ? "s" : ""} detected
            </p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
            Role
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full h-12 px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition appearance-none"
          >
            <option value="viewer">Viewer — Read-only access</option>
            <option value="editor">Editor — Can modify resources</option>
            <option value="admin">Admin — Full administrative access</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1.5">
            Personal Message{" "}
            <span className="text-slate-400 font-normal">(optional)</span>
          </label>
          <textarea
            rows={3}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Welcome to the team! We're excited to have you on board."
            className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition resize-none"
          />
        </div>

        {mutation.isError && (
          <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 text-red-700 text-sm">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            <span>Failed to send invitations. Please try again.</span>
          </div>
        )}

        {sentCount !== null && (
          <div className="flex items-center gap-2 p-3 rounded-xl bg-emerald-50 text-emerald-700 text-sm">
            <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
            <span>
              Successfully sent {sentCount} invitation
              {sentCount !== 1 ? "s" : ""}.
            </span>
          </div>
        )}

        <div className="flex justify-end pt-1">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || emailCount === 0}
            className="h-12 px-6 rounded-xl text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {mutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
            Send Invitations
          </button>
        </div>
      </div>
    </div>
  );
}

function InvitationsTab() {
  const queryClient = useQueryClient();
  const [revokeTarget, setRevokeTarget] = useState<number | null>(null);

  const { data: invitations, isLoading } = useQuery({
    queryKey: ["invitations"],
    queryFn: () => fetchInvitations("pending"),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: number) => revokeInvitation(id),
    onSuccess: () => {
      setRevokeTarget(null);
      queryClient.invalidateQueries({ queryKey: ["invitations"] });
      queryClient.invalidateQueries({ queryKey: ["org-dashboard"] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  const items = invitations ?? [];

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500 dark:text-slate-400">
        {items.length} pending invitation{items.length !== 1 ? "s" : ""}
      </p>

      {items.length === 0 ? (
        <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 px-6 py-16 text-center">
          <Mail className="h-12 w-12 text-slate-300 mx-auto mb-4" />
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mb-1">
            No pending invitations
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            All invitations have been accepted or revoked.
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Email
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Role
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Status
                  </th>
                  <th className="text-left px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Sent
                  </th>
                  <th className="text-right px-6 py-3 font-medium text-slate-500 dark:text-slate-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {items.map(
                  (inv: {
                    id: number;
                    email: string;
                    role: string;
                    role_slug: string;
                    status: string;
                    created_at: string;
                  }) => (
                    <tr key={inv.id} className="hover:bg-slate-50 dark:bg-slate-800/50">
                      <td className="px-6 py-3 font-medium text-slate-900 dark:text-white">
                        {inv.email}
                      </td>
                      <td className="px-6 py-3">
                        <span className="capitalize text-slate-600 dark:text-slate-300">
                          {inv.role}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <Badge
                          text={inv.status}
                          colorClass={
                            STATUS_COLORS[inv.status] ??
                            "bg-slate-100 text-slate-500 dark:text-slate-400"
                          }
                        />
                      </td>
                      <td className="px-6 py-3 text-slate-500 dark:text-slate-400">
                        {new Date(inv.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-3 text-right">
                        {inv.status === "pending" && (
                          <>
                            {revokeTarget === inv.id ? (
                              <div className="inline-flex items-center gap-2">
                                <span className="text-xs text-slate-500 dark:text-slate-400">
                                  Revoke?
                                </span>
                                <button
                                  onClick={() => revokeMutation.mutate(inv.id)}
                                  disabled={revokeMutation.isPending}
                                  className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 transition-colors"
                                >
                                  {revokeMutation.isPending
                                    ? "Revoking…"
                                    : "Confirm"}
                                </button>
                                <button
                                  onClick={() => setRevokeTarget(null)}
                                  className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 transition-colors"
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : (
                              <button
                                onClick={() => setRevokeTarget(inv.id)}
                                className="px-3 py-1.5 rounded-lg text-xs font-medium text-red-600 hover:bg-red-50 transition-colors"
                              >
                                Revoke
                              </button>
                            )}
                          </>
                        )}
                      </td>
                    </tr>
                  )
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function OrganizationsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");

  return (
    <PageLayout
      title="Team Management"
      icon={Building2}
      breadcrumbs={[
        { label: "Admin", href: "/admin/users" },
        { label: "Teams" },
      ]}
    >
      <div className="space-y-6">
        {/* Tab Navigation */}
        <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-xl w-fit">
          {TAB_CONFIG.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === key
                  ? "bg-white text-slate-900 dark:text-white shadow-sm"
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:text-slate-200"
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && <OverviewTab />}
        {activeTab === "organizations" && <OrganizationsTab />}
        {activeTab === "invite" && <InviteUsersTab />}
        {activeTab === "invitations" && <InvitationsTab />}
      </div>
    </PageLayout>
  );
}
