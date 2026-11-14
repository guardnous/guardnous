"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api, { API_URL } from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  FileBarChart,
  Plus,
  X,
  ClipboardCheck,
  ShieldAlert,
  Presentation,
  FileSearch,
  Download,
  Trash2,
  Loader2,
  FileText,
  Eye,
  FileSpreadsheet,
  FileCode2,
  CheckCircle2,
  Clock,
  AlertCircle,
  Globe,
  ChevronDown,
} from "lucide-react";

interface Report {
  id: number;
  name: string;
  title?: string;
  report_type: string;
  format: string;
  status: "pending" | "generating" | "completed" | "failed";
  file_url: string | null;
  file_size: number | null;
  scan_id: number | null;
  created_at: string;
  completed_at: string | null;
  created_by: string | null;
  config: Record<string, unknown> | null;
  has_pdf?: boolean;
  file_name?: string;
  content?: string;
}

const REPORT_TYPE_CONFIG: Record<
  string,
  { label: string; icon: React.ElementType; bg: string; text: string; badge: string }
> = {
  compliance: {
    label: "Compliance Reports",
    icon: ClipboardCheck,
    bg: "bg-orange-50 dark:bg-orange-500/10",
    text: "text-orange-600 dark:text-orange-400",
    badge: "bg-orange-50 text-orange-700 dark:bg-orange-500/20 dark:text-orange-300",
  },
  vulnerability: {
    label: "Vulnerability Assessments",
    icon: ShieldAlert,
    bg: "bg-red-50 dark:bg-red-500/10",
    text: "text-red-600 dark:text-red-400",
    badge: "bg-red-50 text-red-700 dark:bg-red-500/20 dark:text-red-300",
  },
  executive: {
    label: "Executive Summaries",
    icon: Presentation,
    bg: "bg-purple-50 dark:bg-purple-500/10",
    text: "text-purple-600 dark:text-purple-400",
    badge: "bg-purple-50 text-purple-700 dark:bg-purple-500/20 dark:text-purple-300",
  },
  detailed: {
    label: "Detailed Findings",
    icon: FileSearch,
    bg: "bg-emerald-50 dark:bg-emerald-500/10",
    text: "text-emerald-600 dark:text-emerald-400",
    badge: "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300",
  },
};

const FORMAT_CONFIG: Record<
  string,
  { icon: React.ElementType; badge: string }
> = {
  pdf: {
    icon: FileText,
    badge: "bg-red-50 text-red-700 dark:bg-red-500/20 dark:text-red-300",
  },
  csv: {
    icon: FileSpreadsheet,
    badge: "bg-green-50 text-green-700 dark:bg-green-500/20 dark:text-green-300",
  },
  json: {
    icon: FileCode2,
    badge: "bg-blue-50 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300",
  },
};

const STATUS_CONFIG: Record<
  string,
  { label: string; icon: React.ElementType; cls: string; pulse?: boolean }
> = {
  pending: {
    label: "Pending",
    icon: Clock,
    cls: "bg-yellow-50 text-yellow-700 dark:bg-yellow-500/20 dark:text-yellow-300",
  },
  generating: {
    label: "Generating",
    icon: Loader2,
    cls: "bg-blue-50 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300",
    pulse: true,
  },
  completed: {
    label: "Completed",
    icon: CheckCircle2,
    cls: "bg-green-50 text-green-700 dark:bg-green-500/20 dark:text-green-300",
  },
  failed: {
    label: "Failed",
    icon: AlertCircle,
    cls: "bg-red-50 text-red-700 dark:bg-red-500/20 dark:text-red-300",
  },
};

function formatFileSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || bytes === 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function relativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export default function ReportsPage() {
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [viewReport, setViewReport] = useState<Report | null>(null);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("compliance");
  const [formFormat, setFormFormat] = useState("pdf");
  const [exportDropdownId, setExportDropdownId] = useState<number | null>(null);

  const handleExport = async (reportId: number, fmt: string, title: string) => {
    setExportDropdownId(null);
    try {
      const token = typeof window !== "undefined" ? (localStorage.getItem("token") || sessionStorage.getItem("token") || "") : "";
      const res = await fetch(
        `${API_URL}/api/v1/reports/${reportId}/download?format=${fmt}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${title || "report"}.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  };

  const { data: reports = [], isLoading } = useQuery<Report[]>({
    queryKey: ["reports"],
    queryFn: async () => {
      const res = await api.get("/reports");
      return res.data;
    },
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post("/reports", {
        title: formName || `${formType.charAt(0).toUpperCase() + formType.slice(1)} Report`,
        report_type: formType,
        format: formFormat,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      setShowModal(false);
      setFormName("");
      setFormType("compliance");
      setFormFormat("pdf");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await api.delete(`/reports/${id}`);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {
      compliance: 0,
      vulnerability: 0,
      executive: 0,
      detailed: 0,
    };
    reports.forEach((r) => {
      if (r.report_type in counts) counts[r.report_type]++;
    });
    return counts;
  }, [reports]);

  const openModal = () => setShowModal(true);
  const closeModal = () => {
    setShowModal(false);
    setFormName("");
    setFormType("compliance");
    setFormFormat("pdf");
  };

  return (
    <PageLayout
      title="Reports"
      subtitle="Generate and download security reports"
      icon={FileBarChart}
      actions={
        <button
          onClick={openModal}
          className="flex items-center gap-2 px-5 h-12 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold transition-colors"
        >
          <Plus className="w-4 h-4" />
          Generate Report
        </button>
      }
    >
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-orange-500" />
        </div>
      ) : reports.length === 0 ? (
        /* ── Empty State ── */
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-16 text-center">
          <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto mb-4">
            <FileBarChart className="w-8 h-8 text-slate-400" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
            No reports yet
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
            Generate your first security report to get started
          </p>
          <button
            onClick={openModal}
            className="inline-flex items-center gap-2 px-5 h-12 bg-orange-600 hover:bg-orange-700 text-white rounded-xl font-semibold transition-colors"
          >
            <Plus className="w-4 h-4" />
            Generate Report
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {/* ── Report Type Overview Cards ── */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {(Object.keys(REPORT_TYPE_CONFIG) as string[]).map((key) => {
              const cfg = REPORT_TYPE_CONFIG[key];
              const Icon = cfg.icon;
              return (
                <div
                  key={key}
                  className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6"
                >
                  <div className="flex items-center gap-3 mb-3">
                    <div
                      className={`w-10 h-10 rounded-xl ${cfg.bg} flex items-center justify-center`}
                    >
                      <Icon className={`w-5 h-5 ${cfg.text}`} />
                    </div>
                    <span className="text-2xl font-bold text-slate-900 dark:text-white">
                      {typeCounts[key]}
                    </span>
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{cfg.label}</p>
                </div>
              );
            })}
          </div>

          {/* ── Reports Table ── */}
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden max-h-[calc(100vh-340px)] overflow-y-auto">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-800/90 backdrop-blur">
                  <tr className="border-b border-slate-200 dark:border-slate-800">
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Name
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Type
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Format
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Status
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Size
                    </th>
                    <th className="text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Created
                    </th>
                    <th className="text-right text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider px-6 py-4">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {reports.map((report) => {
                    const typeCfg =
                      REPORT_TYPE_CONFIG[report.report_type] ??
                      REPORT_TYPE_CONFIG.compliance;
                    const fmtCfg =
                      FORMAT_CONFIG[report.format] ?? FORMAT_CONFIG.pdf;
                    const statusCfg =
                      STATUS_CONFIG[report.status] ?? STATUS_CONFIG.pending;
                    const StatusIcon = statusCfg.icon;
                    const FormatIcon = fmtCfg.icon;

                    return (
                      <tr
                        key={report.id}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                      >
                        {/* Name */}
                        <td className="px-6 py-4">
                          <span className="text-sm font-medium text-slate-900 dark:text-white">
                            {report.title || report.name || "Untitled Report"}
                          </span>
                        </td>

                        {/* Type Badge */}
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${typeCfg.badge}`}
                          >
                            {report.report_type}
                          </span>
                        </td>

                        {/* Format Badge */}
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${fmtCfg.badge}`}
                          >
                            <FormatIcon className="w-3 h-3" />
                            {report.format.toUpperCase()}
                          </span>
                        </td>

                        {/* Status */}
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${statusCfg.cls} ${statusCfg.pulse ? "animate-pulse" : ""}`}
                          >
                            <StatusIcon className="w-3 h-3" />
                            {statusCfg.label}
                          </span>
                        </td>

                        {/* Size */}
                        <td className="px-6 py-4">
                          <span className="text-sm text-slate-500 dark:text-slate-400">
                            {formatFileSize(report.file_size)}
                          </span>
                        </td>

                        {/* Created */}
                        <td className="px-6 py-4">
                          <span className="text-sm text-slate-500 dark:text-slate-400">
                            {relativeTime(report.created_at)}
                          </span>
                        </td>

                        {/* Actions */}
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-2">
                            {report.status === "completed" && report.content && (
                              <button
                                onClick={() => setViewReport(report)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-orange-50 text-orange-700 hover:bg-orange-100 dark:bg-orange-500/20 dark:text-orange-300 dark:hover:bg-orange-500/30 transition-colors"
                              >
                                <Eye className="w-3.5 h-3.5" />
                                View
                              </button>
                            )}
                            {report.status === "completed" && (
                              <div className="relative">
                                <button
                                  onClick={() => setExportDropdownId(exportDropdownId === report.id ? null : report.id)}
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-50 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-500/20 dark:text-emerald-300 dark:hover:bg-emerald-500/30 transition-colors"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  Export
                                  <ChevronDown className="w-3 h-3" />
                                </button>
                                {exportDropdownId === report.id && (
                                  <div className="absolute right-0 top-full mt-1 w-48 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-xl z-30 py-1">
                                    {[
                                      { fmt: "pdf", label: "PDF Report", icon: FileText, desc: "Enterprise PDF" },
                                      { fmt: "html", label: "HTML Report", icon: Globe, desc: "Interactive HTML" },
                                      { fmt: "csv", label: "CSV Spreadsheet", icon: FileSpreadsheet, desc: "Tabular data" },
                                      { fmt: "json", label: "JSON Data", icon: FileCode2, desc: "Raw JSON" },
                                    ].map((opt) => (
                                      <button
                                        key={opt.fmt}
                                        onClick={() => handleExport(report.id, opt.fmt, report.title || report.name || "report")}
                                        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                                      >
                                        <opt.icon className="w-4 h-4 text-slate-400" />
                                        <div>
                                          <div className="text-xs font-medium text-slate-900 dark:text-white">{opt.label}</div>
                                          <div className="text-[10px] text-slate-400">{opt.desc}</div>
                                        </div>
                                      </button>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                            <button
                              onClick={() => {
                                if (!confirm("Are you sure you want to delete this report?")) return;
                                deleteMutation.mutate(report.id);
                              }}
                              disabled={deleteMutation.isPending}
                              className="inline-flex items-center p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:text-red-400 dark:hover:bg-red-500/10 transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Generate Report Modal ── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                Generate Report
              </h2>
              <button
                onClick={closeModal}
                className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5 text-slate-400" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Report Name */}
              <div>
                <label className="block text-sm font-medium text-slate-900 dark:text-white mb-1.5">
                  Report Name
                </label>
                <input
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="Enter report name"
                  className="w-full px-4 h-12 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-orange-500"
                />
              </div>

              {/* Report Type */}
              <div>
                <label className="block text-sm font-medium text-slate-900 dark:text-white mb-1.5">
                  Report Type
                </label>
                <select
                  value={formType}
                  onChange={(e) => setFormType(e.target.value)}
                  className="w-full px-4 h-12 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                >
                  <option value="compliance">Compliance</option>
                  <option value="vulnerability">Vulnerability Assessment</option>
                  <option value="executive">Executive Summary</option>
                  <option value="detailed">Detailed Findings</option>
                </select>
              </div>

              {/* Format */}
              <div>
                <label className="block text-sm font-medium text-slate-900 dark:text-white mb-1.5">
                  Format
                </label>
                <select
                  value={formFormat}
                  onChange={(e) => setFormFormat(e.target.value)}
                  className="w-full px-4 h-12 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                >
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </select>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={closeModal}
                className="flex-1 h-12 rounded-xl border border-slate-200 dark:border-slate-800 text-sm font-semibold text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => generateMutation.mutate()}
                disabled={generateMutation.isPending}
                className="flex-1 h-12 rounded-xl bg-orange-600 hover:bg-orange-700 text-white text-sm font-semibold disabled:opacity-60 transition-colors"
              >
                {generateMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin mx-auto" />
                ) : (
                  "Generate"
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── View Report Modal ── */}
      {viewReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-5xl max-h-[90vh] bg-white dark:bg-slate-900 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white truncate">
                {viewReport.title || viewReport.name}
              </h2>
              <button
                onClick={() => setViewReport(null)}
                className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5 text-slate-500 dark:text-slate-400" />
              </button>
            </div>
            {/* Body */}
            <div className="flex-1 overflow-auto">
              {viewReport.format === "pdf" && viewReport.content ? (
                <iframe
                  src={`data:application/pdf;base64,${viewReport.content}`}
                  className="w-full h-full min-h-[70vh] border-0"
                  title={viewReport.title || viewReport.name}
                />
              ) : viewReport.format === "json" && viewReport.content ? (
                <pre className="p-6 text-sm text-slate-300 bg-slate-950 overflow-auto min-h-[70vh] whitespace-pre-wrap font-mono">
                  {viewReport.content}
                </pre>
              ) : viewReport.format === "csv" && viewReport.content ? (
                <pre className="p-6 text-sm text-slate-300 bg-slate-950 overflow-auto min-h-[70vh] whitespace-pre-wrap font-mono">
                  {viewReport.content}
                </pre>
              ) : (
                <iframe
                  srcDoc={viewReport.content}
                  className="w-full h-full min-h-[70vh] border-0"
                  title={viewReport.title || viewReport.name}
                  sandbox="allow-same-origin"
                />
              )}
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
