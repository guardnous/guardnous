"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Loader2, Pencil, Play, Plus, Trash2, X } from "lucide-react";
import PageLayout from "@/components/PageLayout";
import {
  createReportSchedule,
  createScanSchedule,
  deleteReportSchedule,
  deleteScanSchedule,
  getAllIntegrations,
  getReportSchedules,
  getScanSchedules,
  runReportSchedule,
  runScanSchedule,
  updateReportSchedule,
  updateScanSchedule,
} from "@/lib/api";

/* ── Types ── */

interface ScanSchedule {
  id: number;
  name: string;
  integration_id: number | null;
  repository: string | null;
  cron_expression: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
}

interface ReportSchedule {
  id: number;
  name: string;
  report_type: string;
  cron_expression: string;
  recipients: string[];
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_report_id: number | null;
}

interface Integration {
  id: number;
  vcs_type: string;
  account_name: string | null;
  is_active: boolean;
  repositories: { full_name: string; enabled?: boolean }[] | null;
}

type Tab = "scans" | "reports";
type ApiError = { response?: { data?: { detail?: unknown } } };

/* ── Helpers ── */

const PRESETS: { label: string; cron: string }[] = [
  { label: "Every day at 02:00 UTC", cron: "0 2 * * *" },
  { label: "Every 6 hours", cron: "0 */6 * * *" },
  { label: "Weekdays at 06:00 UTC", cron: "0 6 * * 1-5" },
  { label: "Every Monday at 08:00 UTC", cron: "0 8 * * 1" },
  { label: "First day of the month at 08:00 UTC", cron: "0 8 1 * *" },
];

function describeCron(cron: string): string {
  return PRESETS.find((p) => p.cron === cron)?.label ?? `Custom (${cron})`;
}

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function errorText(err: unknown, fallback: string): string {
  const detail = (err as ApiError)?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
}

const STATUS_STYLE: Record<string, string> = {
  queued: "text-emerald-700 border-emerald-300 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/40 dark:bg-emerald-900/20",
  sent: "text-emerald-700 border-emerald-300 bg-emerald-50 dark:text-emerald-300 dark:border-emerald-800/40 dark:bg-emerald-900/20",
  generated: "text-amber-700 border-amber-300 bg-amber-50 dark:text-amber-300 dark:border-amber-800/40 dark:bg-amber-900/20",
  failed: "text-red-700 border-red-300 bg-red-50 dark:text-red-300 dark:border-red-800/40 dark:bg-red-900/20",
};

const STATUS_TEXT: Record<string, string> = {
  queued: "Scan queued",
  sent: "Report emailed",
  generated: "Report saved, not emailed",
  failed: "Failed",
};

function LastRun({ status, error, at }: { status: string | null; error: string | null; at: string | null }) {
  if (!status) return <span className="text-gray-500">Never run</span>;
  return (
    <div>
      <span className={`inline-block rounded border px-2 py-0.5 text-[11px] ${STATUS_STYLE[status] ?? "text-gray-700 border-gray-300 dark:text-gray-300 dark:border-gray-700"}`}>
        {STATUS_TEXT[status] ?? status}
      </span>
      <span className="ml-2 text-gray-500">{formatTime(at)}</span>
      {error && <p className="mt-1 max-w-md text-[11px] text-amber-700 dark:text-amber-300/90">{error}</p>}
    </div>
  );
}

const inputCls =
  "w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 placeholder-gray-400 focus:border-blue-500 focus:outline-none dark:border-white/[0.08] dark:bg-[#161c2b] dark:text-gray-100 dark:placeholder-gray-500";
const labelCls = "mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400";

function CronField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const isPreset = PRESETS.some((p) => p.cron === value);
  const [custom, setCustom] = useState(!isPreset);
  return (
    <div>
      <label className={labelCls}>How often</label>
      <select
        className={inputCls}
        value={custom ? "custom" : value}
        onChange={(e) => {
          if (e.target.value === "custom") setCustom(true);
          else {
            setCustom(false);
            onChange(e.target.value);
          }
        }}
      >
        {PRESETS.map((p) => (
          <option key={p.cron} value={p.cron}>{p.label}</option>
        ))}
        <option value="custom">Custom cron expression…</option>
      </select>
      {custom && (
        <>
          <input
            className={`${inputCls} mt-2 font-mono`}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="minute hour day month weekday"
          />
          <p className="mt-1 text-[11px] text-gray-500">
            Five fields, in UTC. Schedules are checked every 5 minutes and cannot run more often than every 15.
          </p>
        </>
      )}
    </div>
  );
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-gray-200 bg-white p-6 shadow-xl dark:border-white/[0.08] dark:bg-[#0f1420]">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">{title}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 dark:hover:text-gray-300" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function FormButtons({ onClose, saving, disabled }: { onClose: () => void; saving: boolean; disabled: boolean }) {
  return (
    <div className="mt-5 flex justify-end gap-2">
      <button type="button" onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200">
        Cancel
      </button>
      <button
        type="submit"
        disabled={saving || disabled}
        className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
      >
        {saving && <Loader2 className="h-4 w-4 animate-spin" />}
        Save schedule
      </button>
    </div>
  );
}

/* ── Scan schedule form ── */

function ScanScheduleForm({ existing, onClose }: { existing: ScanSchedule | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const { data: integrations = [], isLoading } = useQuery<Integration[]>({
    queryKey: ["integrations-all"],
    queryFn: getAllIntegrations,
  });
  const repoOptions = useMemo(
    () =>
      integrations
        .filter((i) => i.is_active)
        .flatMap((i) =>
          (i.repositories ?? [])
            .filter((r) => r.enabled)
            .map((r) => ({ key: `${i.id}|${r.full_name}`, label: `${r.full_name} (${i.vcs_type})` }))
        ),
    [integrations]
  );

  const [name, setName] = useState(existing?.name ?? "");
  const [target, setTarget] = useState(
    existing?.integration_id && existing.repository ? `${existing.integration_id}|${existing.repository}` : ""
  );
  const [cron, setCron] = useState(existing?.cron_expression ?? "0 2 * * *");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [error, setError] = useState("");

  const save = useMutation({
    mutationFn: () => {
      const [integrationId, ...rest] = target.split("|");
      const body = {
        name,
        integration_id: Number(integrationId),
        repository: rest.join("|"),
        cron_expression: cron,
        enabled,
      };
      return existing ? updateScanSchedule(existing.id, body) : createScanSchedule(body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
      onClose();
    },
    onError: (err) => setError(errorText(err, "Could not save the schedule.")),
  });

  return (
    <Modal title={existing ? "Edit scan schedule" : "New scan schedule"} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError("");
          save.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label className={labelCls}>Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly infra scan" required />
        </div>
        <div>
          <label className={labelCls}>Repository</label>
          {isLoading ? (
            <p className="text-sm text-gray-500">Loading repositories…</p>
          ) : repoOptions.length === 0 ? (
            <p className="text-sm text-amber-700 dark:text-amber-300">
              No repositories are enabled for scanning.{" "}
              <Link href="/integrations" className="underline">Connect and enable one under Integrations</Link>.
            </p>
          ) : (
            <select className={inputCls} value={target} onChange={(e) => setTarget(e.target.value)} required>
              <option value="">Select a repository…</option>
              {repoOptions.map((o) => (
                <option key={o.key} value={o.key}>{o.label}</option>
              ))}
            </select>
          )}
        </div>
        <CronField value={cron} onChange={setCron} />
        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <FormButtons onClose={onClose} saving={save.isPending} disabled={!name.trim() || !target} />
      </form>
    </Modal>
  );
}

/* ── Report schedule form ── */

function ReportScheduleForm({ existing, onClose }: { existing: ReportSchedule | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [reportType, setReportType] = useState(existing?.report_type ?? "security");
  const [recipients, setRecipients] = useState((existing?.recipients ?? []).join(", "));
  const [cron, setCron] = useState(existing?.cron_expression ?? "0 8 * * 1");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [error, setError] = useState("");

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name,
        report_type: reportType,
        cron_expression: cron,
        recipients: recipients.split(/[\s,;]+/).filter(Boolean),
        enabled,
      };
      return existing ? updateReportSchedule(existing.id, body) : createReportSchedule(body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["report-schedules"] });
      onClose();
    },
    onError: (err) => setError(errorText(err, "Could not save the schedule.")),
  });

  return (
    <Modal title={existing ? "Edit report schedule" : "New report schedule"} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError("");
          save.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label className={labelCls}>Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekly security report" required />
        </div>
        <div>
          <label className={labelCls}>Report type</label>
          <select className={inputCls} value={reportType} onChange={(e) => setReportType(e.target.value)}>
            <option value="security">Security</option>
            <option value="compliance">Compliance</option>
            <option value="executive">Executive summary</option>
          </select>
        </div>
        <div>
          <label className={labelCls}>Recipients</label>
          <input
            className={inputCls}
            value={recipients}
            onChange={(e) => setRecipients(e.target.value)}
            placeholder="ciso@example.com, secops@example.com"
            required
          />
          <p className="mt-1 text-[11px] text-gray-500">
            Each run builds a new report from current findings and emails it as a PDF. Email needs SMTP set up under
            Settings; without it the report is still saved under Reports.
          </p>
        </div>
        <CronField value={cron} onChange={setCron} />
        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
        <FormButtons onClose={onClose} saving={save.isPending} disabled={!name.trim() || !recipients.trim()} />
      </form>
    </Modal>
  );
}

/* ── Table ── */

interface RowBase {
  id: number;
  name: string;
  cron_expression: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
}

function ScheduleTable<T extends RowBase>({
  rows,
  targetHeader,
  renderTarget,
  queryKey,
  onEdit,
  runFn,
  deleteFn,
  toggleFn,
  runLabel,
}: {
  rows: T[];
  targetHeader: string;
  renderTarget: (row: T) => React.ReactNode;
  queryKey: string;
  onEdit: (row: T) => void;
  runFn: (id: number) => Promise<unknown>;
  deleteFn: (id: number) => Promise<unknown>;
  toggleFn: (id: number, enabled: boolean) => Promise<unknown>;
  runLabel: string;
}) {
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: [queryKey] });

  const run = useMutation({
    mutationFn: runFn,
    onSuccess: () => setMessage({ ok: true, text: runLabel }),
    onError: (err) => setMessage({ ok: false, text: errorText(err, "The run failed.") }),
    onSettled: refresh,
  });
  const remove = useMutation({ mutationFn: deleteFn, onSettled: refresh });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => toggleFn(id, enabled),
    onError: (err) => setMessage({ ok: false, text: errorText(err, "Could not update the schedule.") }),
    onSettled: refresh,
  });

  return (
    <div>
      {message && (
        <p className={`mb-3 text-sm ${message.ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-600 dark:text-red-400"}`}>{message.text}</p>
      )}
      <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm dark:border-white/[0.06] dark:bg-white/[0.02] dark:shadow-none">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-gray-200 text-gray-500 dark:border-white/[0.06]">
            <tr>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">{targetHeader}</th>
              <th className="px-4 py-3 font-medium">Runs</th>
              <th className="px-4 py-3 font-medium">Next run</th>
              <th className="px-4 py-3 font-medium">Last run</th>
              <th className="px-4 py-3 font-medium">Enabled</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-gray-100 align-top last:border-0 dark:border-white/[0.04]">
                <td className="px-4 py-3 font-medium text-gray-900 dark:text-gray-100">{row.name}</td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300">{renderTarget(row)}</td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300">{describeCron(row.cron_expression)}</td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300">{row.enabled ? formatTime(row.next_run_at) : "Paused"}</td>
                <td className="px-4 py-3">
                  <LastRun status={row.last_status} error={row.last_error} at={row.last_run_at} />
                </td>
                <td className="px-4 py-3">
                  <input
                    type="checkbox"
                    checked={row.enabled}
                    disabled={toggle.isPending}
                    onChange={(e) => toggle.mutate({ id: row.id, enabled: e.target.checked })}
                    aria-label={`Enable ${row.name}`}
                  />
                </td>
                <td className="px-4 py-3">
                  <div className="flex justify-end gap-1">
                    <button
                      onClick={() => {
                        setMessage(null);
                        run.mutate(row.id);
                      }}
                      disabled={run.isPending}
                      className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-2 py-1 text-gray-700 hover:bg-gray-100 disabled:opacity-50 dark:border-white/[0.08] dark:text-gray-200 dark:hover:bg-white/[0.05]"
                    >
                      {run.isPending && run.variables === row.id ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Play className="h-3 w-3" />
                      )}
                      Run now
                    </button>
                    <button onClick={() => onEdit(row)} className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-white/[0.05] dark:hover:text-gray-200" aria-label="Edit">
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      onClick={() => {
                        if (window.confirm(`Delete the schedule "${row.name}"?`)) remove.mutate(row.id);
                      }}
                      className="rounded-lg p-1.5 text-gray-500 hover:bg-red-50 hover:text-red-600 dark:text-gray-400 dark:hover:bg-red-900/20 dark:hover:text-red-300"
                      aria-label="Delete"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Empty({ text, action, onAction }: { text: string; action: string; onAction: () => void }) {
  return (
    <div className="rounded-xl border border-dashed border-gray-300 px-6 py-12 text-center dark:border-white/[0.08]">
      <CalendarClock className="mx-auto mb-3 h-8 w-8 text-gray-400 dark:text-gray-600" />
      <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">{text}</p>
      <button onClick={onAction} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500">
        <Plus className="h-4 w-4" />
        {action}
      </button>
    </div>
  );
}

/* ── Page ── */

export default function SchedulesPage() {
  const [tab, setTab] = useState<Tab>("scans");
  const [scanForm, setScanForm] = useState<{ open: boolean; row: ScanSchedule | null }>({ open: false, row: null });
  const [reportForm, setReportForm] = useState<{ open: boolean; row: ReportSchedule | null }>({ open: false, row: null });

  const scans = useQuery<ScanSchedule[]>({ queryKey: ["scan-schedules"], queryFn: getScanSchedules, refetchInterval: 30_000 });
  const reports = useQuery<ReportSchedule[]>({ queryKey: ["report-schedules"], queryFn: getReportSchedules, refetchInterval: 30_000 });

  const active = tab === "scans" ? scans : reports;
  const openNew = () =>
    tab === "scans" ? setScanForm({ open: true, row: null }) : setReportForm({ open: true, row: null });

  return (
    <PageLayout
      title="Schedules"
      subtitle="Recurring repository scans and emailed reports"
      icon={CalendarClock}
      actions={
        <button onClick={openNew} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500">
          <Plus className="h-4 w-4" />
          {tab === "scans" ? "New scan schedule" : "New report schedule"}
        </button>
      }
    >
      <div className="mb-5 flex gap-1 border-b border-gray-200 dark:border-white/[0.06]">
        {(
          [
            ["scans", `Scan schedules (${scans.data?.length ?? 0})`],
            ["reports", `Report schedules (${reports.data?.length ?? 0})`],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`-mb-px border-b-2 px-4 py-2 text-sm ${
              tab === key
                ? "border-blue-500 text-gray-900 dark:text-gray-100"
                : "border-transparent text-gray-500 hover:text-gray-800 dark:hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {active.isLoading ? (
        <div className="flex items-center gap-2 py-12 text-sm text-gray-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading schedules…
        </div>
      ) : active.isError ? (
        <p className="py-12 text-sm text-red-600 dark:text-red-400">{errorText(active.error, "Could not load schedules.")}</p>
      ) : tab === "scans" ? (
        (scans.data ?? []).length === 0 ? (
          <Empty text="No scan schedules yet. Schedule a repository to be scanned automatically." action="New scan schedule" onAction={openNew} />
        ) : (
          <ScheduleTable<ScanSchedule>
            rows={scans.data ?? []}
            targetHeader="Repository"
            renderTarget={(row) => row.repository ?? <span className="text-red-600 dark:text-red-300">No repository</span>}
            queryKey="scan-schedules"
            onEdit={(row) => setScanForm({ open: true, row })}
            runFn={runScanSchedule}
            deleteFn={deleteScanSchedule}
            toggleFn={(id, enabled) => updateScanSchedule(id, { enabled })}
            runLabel="Scan queued. Follow it under Assessments."
          />
        )
      ) : (reports.data ?? []).length === 0 ? (
        <Empty text="No report schedules yet. Send a fresh security report to your team on a schedule." action="New report schedule" onAction={openNew} />
      ) : (
        <ScheduleTable<ReportSchedule>
          rows={reports.data ?? []}
          targetHeader="Report · recipients"
          renderTarget={(row) => (
            <>
              <span className="capitalize">{row.report_type}</span>
              <span className="text-gray-500"> · {row.recipients.join(", ")}</span>
            </>
          )}
          queryKey="report-schedules"
          onEdit={(row) => setReportForm({ open: true, row })}
          runFn={runReportSchedule}
          deleteFn={deleteReportSchedule}
          toggleFn={(id, enabled) => updateReportSchedule(id, { enabled })}
          runLabel="Report generated. See the Last run column for delivery, and Reports for the report."
        />
      )}

      {scanForm.open && <ScanScheduleForm existing={scanForm.row} onClose={() => setScanForm({ open: false, row: null })} />}
      {reportForm.open && <ReportScheduleForm existing={reportForm.row} onClose={() => setReportForm({ open: false, row: null })} />}
    </PageLayout>
  );
}
