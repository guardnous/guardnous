"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import api from "@/lib/api";
import PageLayout from "@/components/PageLayout";
import {
  ArrowLeft,
  Download,
  FileText,
  AlertTriangle,
  Shield,
  Loader2,
  ChevronDown,
  Globe,
  FileSpreadsheet,
  FileCode2,
} from "lucide-react";

interface ReportView {
  id: number;
  title: string;
  report_type: string;
  created_at: string;
  summary?: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    risk_score: number;
  };
  scan_info?: {
    repository_name: string;
    account_name: string;
    scan_type: string;
    completed_at: string;
  };
  findings?: {
    id: number;
    title: string;
    severity: string;
    category: string;
    file_path?: string;
    line_number?: number;
    description: string;
    recommendation?: string;
  }[];
  compliance?: {
    framework: string;
    passed: number;
    failed: number;
    total: number;
  }[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
  medium: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
  low: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
};

export default function ReportViewPage() {
  const params = useParams();
  const router = useRouter();
  const reportId = params.id as string;

  const { data: report, isLoading } = useQuery<ReportView>({
    queryKey: ["report", reportId],
    queryFn: () => api.get(`/reports/${reportId}/view`).then((r) => r.data),
  });

  const [exportOpen, setExportOpen] = React.useState(false);

  const handleExport = async (fmt: string) => {
    setExportOpen(false);
    try {
      const token = typeof window !== "undefined" ? (localStorage.getItem("token") || sessionStorage.getItem("token") || "") : "";
      const res = await fetch(
        `${api.defaults.baseURL}/reports/${reportId}/download?format=${fmt}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report?.title || "report"}.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 size={32} className="animate-spin text-orange-500" />
      </div>
    );
  }

  if (!report) {
    return (
      <PageLayout title="Report Not Found">
        <p className="text-gray-500">This report could not be loaded.</p>
      </PageLayout>
    );
  }

  return (
    <PageLayout
      title={report.title}
      subtitle={`Generated ${new Date(report.created_at).toLocaleString()}`}
      actions={
        <div className="flex gap-2">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1.5 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <ArrowLeft size={14} />
            Back
          </button>
          <div className="relative">
            <button
              onClick={() => setExportOpen(!exportOpen)}
              className="flex items-center gap-1.5 px-3 py-2 text-sm bg-orange-500 text-white rounded-lg hover:bg-orange-600"
            >
              <Download size={14} />
              Export Report
              <ChevronDown size={12} />
            </button>
            {exportOpen && (
              <div className="absolute right-0 top-full mt-1 w-52 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl z-30 py-1">
                {[
                  { fmt: "pdf", label: "PDF Report", icon: FileText, desc: "Enterprise PDF" },
                  { fmt: "html", label: "HTML Report", icon: Globe, desc: "Interactive HTML" },
                  { fmt: "csv", label: "CSV Spreadsheet", icon: FileSpreadsheet, desc: "Tabular data" },
                  { fmt: "json", label: "JSON Data", icon: FileCode2, desc: "Raw JSON" },
                ].map((opt) => (
                  <button
                    key={opt.fmt}
                    onClick={() => handleExport(opt.fmt)}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                  >
                    <opt.icon className="w-4 h-4 text-gray-400" />
                    <div>
                      <div className="text-xs font-medium text-gray-900 dark:text-white">{opt.label}</div>
                      <div className="text-[10px] text-gray-400">{opt.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      }
    >
      {/* Scan Info */}
      {report.scan_info && (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 mb-6">
          <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-3">
            Scan Information
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Account</span>
              <p className="font-medium text-gray-900 dark:text-white">{report.scan_info.account_name}</p>
            </div>
            <div>
              <span className="text-gray-500">Repository</span>
              <p className="font-medium text-gray-900 dark:text-white">{report.scan_info.repository_name}</p>
            </div>
            <div>
              <span className="text-gray-500">Scan Type</span>
              <p className="font-medium text-gray-900 dark:text-white">{report.scan_info.scan_type}</p>
            </div>
            <div>
              <span className="text-gray-500">Completed</span>
              <p className="font-medium text-gray-900 dark:text-white">
                {new Date(report.scan_info.completed_at).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {report.summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 mb-6">
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <Shield size={20} className="mx-auto text-orange-500 mb-1" />
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{report.summary.risk_score}</div>
            <div className="text-xs text-gray-500">Risk Score</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{report.summary.total_findings}</div>
            <div className="text-xs text-gray-500">Total Findings</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <div className="text-2xl font-bold text-red-600">{report.summary.critical}</div>
            <div className="text-xs text-gray-500">Critical</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <div className="text-2xl font-bold text-orange-600">{report.summary.high}</div>
            <div className="text-xs text-gray-500">High</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <div className="text-2xl font-bold text-yellow-600">{report.summary.medium}</div>
            <div className="text-xs text-gray-500">Medium</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <div className="text-2xl font-bold text-blue-600">{report.summary.low}</div>
            <div className="text-xs text-gray-500">Low</div>
          </div>
        </div>
      )}

      {/* Compliance */}
      {report.compliance && report.compliance.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4 mb-6">
          <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-3">
            Compliance Frameworks
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {report.compliance.map((c) => (
              <div key={c.framework} className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                <div className="font-medium text-gray-900 dark:text-white mb-1">{c.framework}</div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                    <div
                      className="bg-green-500 h-2 rounded-full"
                      style={{ width: `${c.total > 0 ? (c.passed / c.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500">
                    {c.passed}/{c.total}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings List */}
      {report.findings && report.findings.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider">
              Findings ({report.findings.length})
            </h3>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {report.findings.map((f) => (
              <div key={f.id} className="p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle
                    size={16}
                    className={
                      f.severity === "critical"
                        ? "text-red-500"
                        : f.severity === "high"
                        ? "text-orange-500"
                        : f.severity === "medium"
                        ? "text-yellow-500"
                        : "text-blue-500"
                    }
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-gray-900 dark:text-white">{f.title}</span>
                      <span className={`px-1.5 py-0.5 text-[10px] font-medium rounded-full ${SEVERITY_COLORS[f.severity] || ""}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs text-gray-400">{f.category}</span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">{f.description}</p>
                    {f.file_path && (
                      <p className="text-xs text-gray-400 font-mono">
                        {f.file_path}
                        {f.line_number ? `:${f.line_number}` : ""}
                      </p>
                    )}
                    {f.recommendation && (
                      <p className="text-xs text-green-600 mt-1">💡 {f.recommendation}</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </PageLayout>
  );
}
