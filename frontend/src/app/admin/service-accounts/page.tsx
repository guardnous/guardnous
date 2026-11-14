"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import PageLayout from "@/components/PageLayout";
import {
  getServiceAccounts,
  createServiceAccount,
  updateServiceAccount,
  rotateServiceAccountToken,
  deleteServiceAccount,
} from "@/lib/api";
import {
  Bot,
  Plus,
  Trash2,
  Loader2,
  X,
  KeyRound,
  Copy,
  Check,
  Power,
  ShieldCheck,
} from "lucide-react";

interface SvcAccount {
  id: number;
  name: string;
  description: string | null;
  bot_username: string;
  bot_email: string;
  token_prefix: string | null;
  has_token: boolean;
  is_active: boolean;
  last_used_at: string | null;
  created_by: string | null;
  created_at: string | null;
}

export default function ServiceAccountsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [tokenModal, setTokenModal] = useState<{ token: string; name: string } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["service-accounts"],
    queryFn: getServiceAccounts,
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, is_active }: { id: number; is_active: boolean }) =>
      updateServiceAccount(id, { is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["service-accounts"] }),
  });

  const rotateMut = useMutation({
    mutationFn: (id: number) => rotateServiceAccountToken(id),
    onSuccess: (res: any, id) => {
      const acct = (data ?? []).find((a: SvcAccount) => a.id === id);
      setTokenModal({ token: res.token, name: acct?.name ?? "Service account" });
      qc.invalidateQueries({ queryKey: ["service-accounts"] });
    },
  });

  const delMut = useMutation({
    mutationFn: (id: number) => deleteServiceAccount(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["service-accounts"] }),
  });

  const accounts: SvcAccount[] = data ?? [];

  return (
    <PageLayout
      title="Service Accounts"
      subtitle="Bot identities that author automated remediation pull requests"
      breadcrumbs={[{ label: "Home", href: "/dashboard" }, { label: "Service Accounts" }]}
      actions={
        <button
          onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-orange-500 px-3 py-2 text-[13px] font-medium text-white hover:bg-orange-600"
        >
          <Plus className="h-4 w-4" /> New service account
        </button>
      }
    >
      <div className="mb-4 flex items-start gap-3 rounded-xl border border-blue-100 bg-blue-50/60 p-4">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-blue-500" />
        <p className="text-[13px] leading-relaxed text-blue-800">
          Auto-fix pull requests are committed with the <strong>git author name &amp; email</strong> of the
          active service account, giving a consistent, auditable bot identity (instead of a human user&apos;s
          personal token). The access token is shown <strong>once</strong> at creation — store it securely.
        </p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-gray-400">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : accounts.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-200 bg-white py-16 text-center">
          <Bot className="mx-auto h-10 w-10 text-gray-300" />
          <p className="mt-3 text-[14px] font-medium text-gray-700">No service accounts yet</p>
          <p className="mt-1 text-[13px] text-gray-500">
            Create a bot identity to author automated remediation PRs.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50/60 text-left text-[12px] text-gray-500">
                <th className="px-4 py-2.5 font-medium">Name</th>
                <th className="px-4 py-2.5 font-medium">Git identity</th>
                <th className="px-4 py-2.5 font-medium">Token</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id} className="border-b border-gray-50 last:border-0">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-50">
                        <Bot className="h-4 w-4 text-orange-500" />
                      </div>
                      <div>
                        <div className="font-medium text-gray-900">{a.name}</div>
                        {a.description && <div className="text-[12px] text-gray-400">{a.description}</div>}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-gray-700">{a.bot_username}</div>
                    <div className="text-[12px] text-gray-400">{a.bot_email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <code className="rounded bg-gray-100 px-1.5 py-0.5 text-[12px] text-gray-600">
                      {a.token_prefix ?? "—"}…
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ${
                        a.is_active
                          ? "bg-emerald-50 text-emerald-700"
                          : "bg-gray-100 text-gray-500"
                      }`}
                    >
                      {a.is_active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => toggleMut.mutate({ id: a.id, is_active: !a.is_active })}
                        className="rounded-md p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700"
                        title={a.is_active ? "Disable" : "Enable"}
                      >
                        <Power className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => rotateMut.mutate(a.id)}
                        className="rounded-md p-1.5 text-gray-400 hover:bg-blue-50 hover:text-blue-600"
                        title="Rotate token"
                      >
                        <KeyRound className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(`Delete service account "${a.name}"?`)) delMut.mutate(a.id);
                        }}
                        className="rounded-md p-1.5 text-gray-400 hover:bg-red-50 hover:text-red-600"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={(token, name) => {
            setShowCreate(false);
            setTokenModal({ token, name });
            qc.invalidateQueries({ queryKey: ["service-accounts"] });
          }}
        />
      )}

      {tokenModal && <TokenModal data={tokenModal} onClose={() => setTokenModal(null)} />}
    </PageLayout>
  );
}

function CreateModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (token: string, name: string) => void;
}) {
  const [name, setName] = useState("GuardNous Auto-Fix Bot");
  const [description, setDescription] = useState("Authors automated remediation pull requests");
  const [botUsername, setBotUsername] = useState("guardnous-bot");
  const [botEmail, setBotEmail] = useState("bot@guardnous.local");
  const [err, setErr] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createServiceAccount({ name, description, bot_username: botUsername, bot_email: botEmail }),
    onSuccess: (res: any) => onCreated(res.token, res.name),
    onError: (e: any) => setErr(e?.response?.data?.detail ?? "Failed to create service account"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-100 px-5 py-4">
          <h3 className="text-[15px] font-semibold text-gray-900">New service account</h3>
          <button onClick={onClose} className="rounded-md p-1 text-gray-400 hover:bg-gray-100">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="space-y-3 p-5">
          {err && <div className="rounded-lg bg-red-50 px-3 py-2 text-[13px] text-red-700">{err}</div>}
          <Field label="Name">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg border border-gray-200 px-3 py-2 text-[13px] outline-none focus:border-orange-400"
            />
          </Field>
          <Field label="Description">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border border-gray-200 px-3 py-2 text-[13px] outline-none focus:border-orange-400"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Git author name">
              <input
                value={botUsername}
                onChange={(e) => setBotUsername(e.target.value)}
                className="w-full rounded-lg border border-gray-200 px-3 py-2 text-[13px] outline-none focus:border-orange-400"
              />
            </Field>
            <Field label="Git author email">
              <input
                value={botEmail}
                onChange={(e) => setBotEmail(e.target.value)}
                className="w-full rounded-lg border border-gray-200 px-3 py-2 text-[13px] outline-none focus:border-orange-400"
              />
            </Field>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-100 px-5 py-4">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-[13px] font-medium text-gray-600 hover:bg-gray-100">
            Cancel
          </button>
          <button
            onClick={() => {
              setErr("");
              if (!name.trim()) {
                setErr("Name is required.");
                return;
              }
              mut.mutate();
            }}
            disabled={mut.isPending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-orange-500 px-4 py-2 text-[13px] font-medium text-white hover:bg-orange-600 disabled:opacity-60"
          >
            {mut.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-[12px] font-medium text-gray-600">{label}</label>
      {children}
    </div>
  );
}

function TokenModal({ data, onClose }: { data: { token: string; name: string }; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-100 px-5 py-4">
          <h3 className="flex items-center gap-2 text-[15px] font-semibold text-gray-900">
            <KeyRound className="h-4 w-4 text-orange-500" /> Access token for {data.name}
          </h3>
          <button onClick={onClose} className="rounded-md p-1 text-gray-400 hover:bg-gray-100">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="space-y-3 p-5">
          <div className="rounded-lg bg-amber-50 px-3 py-2 text-[13px] text-amber-800">
            Copy this token now — it will <strong>not</strong> be shown again.
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-gray-200 bg-gray-50 p-3">
            <code className="flex-1 break-all font-mono text-[12px] text-gray-800">{data.token}</code>
            <button
              onClick={() => {
                navigator.clipboard.writeText(data.token);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }}
              className="shrink-0 rounded-md border border-gray-200 bg-white p-1.5 text-gray-500 hover:bg-gray-100"
            >
              {copied ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="flex justify-end border-t border-gray-100 px-5 py-4">
          <button
            onClick={onClose}
            className="rounded-lg bg-orange-500 px-4 py-2 text-[13px] font-medium text-white hover:bg-orange-600"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
