"use client";

import React, { useEffect, useState } from "react";
import { Download, Loader2, Package, RefreshCw } from "lucide-react";
import api from "@/lib/api";

type ReviewItem = {
  package: string;
  version: string | null;
  ecosystem: string;
  license: string;
  category: string;
  scope: string;
  manifest_path: string | null;
};

type LicenseSummary = {
  status: "not_checked" | "checked" | "partial";
  lookup_enabled: boolean;
  setting: string;
  message?: string;
  by_category?: Record<string, number>;
  not_looked_up?: number;
  review_needed_count?: number;
  review_needed?: ReviewItem[];
};

type SbomSummary = {
  component_count: number;
  manifests: number;
  by_ecosystem: Record<string, number>;
  by_scope: { production: number; development: number };
  without_version: number;
  vulnerable_components: number;
  vulnerabilities: number;
  licenses: LicenseSummary;
};

const CATEGORY_LABELS: Record<string, string> = {
  permissive: "Permissive",
  weak_copyleft: "Weak copyleft",
  strong_copyleft: "Strong copyleft",
  restrictive: "Restrictive",
  unknown: "Unknown",
};

const REVIEW_ROWS_SHOWN = 8;

async function errorDetail(err: any, fallback: string): Promise<string> {
  const data = err?.response?.data;
  if (data instanceof Blob) {
    try {
      return JSON.parse(await data.text()).detail || fallback;
    } catch {
      return fallback;
    }
  }
  return data?.detail || fallback;
}

/* The dependency inventory of a repository assessment: counts, licence check and the SBOM download. */
export default function SbomCard({ scanId }: { scanId: number }) {
  const [summary, setSummary] = useState<SbomSummary | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setSummary(null);
    api
      .get(`/sbom/scans/${scanId}/summary`)
      .then((res) => active && setSummary(res.data))
      .catch(() => active && setSummary(null)); // no stored inventory: nothing to show
    return () => {
      active = false;
    };
  }, [scanId]);

  if (!summary) return null;

  const download = async () => {
    setDownloading(true);
    setError(null);
    try {
      const res = await api.get(`/sbom/scans/${scanId}`, { responseType: "blob" });
      const named = /filename="([^"]+)"/.exec(res.headers["content-disposition"] || "");
      const url = URL.createObjectURL(new Blob([res.data], { type: "application/vnd.cyclonedx+json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = named ? named[1] : `sbom-${scanId}.cdx.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(await errorDetail(err, "The SBOM could not be downloaded."));
    } finally {
      setDownloading(false);
    }
  };

  const refreshLicenses = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const res = await api.post(`/sbom/scans/${scanId}/licenses/refresh`);
      setSummary(res.data);
    } catch (err) {
      setError(await errorDetail(err, "The licences could not be checked again."));
    } finally {
      setRefreshing(false);
    }
  };

  const lic = summary.licenses;
  const review = lic.review_needed ?? [];
  const ecosystems = Object.entries(summary.by_ecosystem);

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 mb-8">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold text-slate-900 dark:text-white">
            <Package size={16} className="text-slate-400" />
            Software bill of materials
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Direct dependencies declared in {summary.manifests} package {summary.manifests === 1 ? "manifest" : "manifests"},
            with the versions the manifests declare.
          </p>
        </div>
        <button
          onClick={download}
          disabled={downloading}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60 transition-colors"
        >
          {downloading ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
          Download SBOM (CycloneDX 1.5)
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Components" value={summary.component_count} />
        <Stat label="Production" value={summary.by_scope.production} />
        <Stat label="Development only" value={summary.by_scope.development} />
        <Stat
          label="With known vulnerabilities"
          value={summary.vulnerable_components}
          tone={summary.vulnerable_components > 0 ? "warn" : undefined}
        />
      </div>

      {ecosystems.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-4">
          {ecosystems.map(([name, count]) => (
            <span
              key={name}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
            >
              {name} {count}
            </span>
          ))}
        </div>
      )}

      <div className="mt-5 pt-4 border-t border-slate-100 dark:border-slate-800">
        <div className="flex items-center justify-between gap-3 mb-2">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Licences</h3>
          {lic.lookup_enabled && (
            <button
              onClick={refreshLicenses}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 disabled:opacity-60"
            >
              <RefreshCw size={12} className={refreshing ? "animate-spin" : ""} />
              Check again
            </button>
          )}
        </div>

        {lic.status === "not_checked" ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Licences not checked.{" "}
            {lic.lookup_enabled ? (
              "They have not been looked up yet for this assessment."
            ) : (
              <>
                Set <code className="px-1 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-xs">{lic.setting}=true</code> to
                look them up at deps.dev. Package names and versions are then sent to that service.
              </>
            )}
          </p>
        ) : (
          <>
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm text-slate-600 dark:text-slate-300">
              {Object.entries(lic.by_category ?? {})
                .filter(([, count]) => count > 0)
                .map(([category, count]) => (
                  <span key={category}>
                    {CATEGORY_LABELS[category] ?? category}: <span className="font-semibold">{count}</span>
                  </span>
                ))}
            </div>
            {lic.status === "partial" && (lic.not_looked_up ?? 0) > 0 && (
              <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                {lic.not_looked_up} {lic.not_looked_up === 1 ? "package was" : "packages were"} not looked up and
                {" "}count as unknown.
              </p>
            )}

            {review.length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-3">
                No production dependency has a licence that needs review.
              </p>
            ) : (
              <div className="mt-3">
                <p className="text-sm text-amber-700 dark:text-amber-400 mb-2">
                  {review.length} production {review.length === 1 ? "dependency has" : "dependencies have"} a licence
                  that needs review.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-slate-400 uppercase tracking-wider">
                        <th className="py-1.5 pr-4 font-medium">Package</th>
                        <th className="py-1.5 pr-4 font-medium">Version</th>
                        <th className="py-1.5 pr-4 font-medium">Licence</th>
                        <th className="py-1.5 font-medium">Declared in</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {review.slice(0, REVIEW_ROWS_SHOWN).map((item) => (
                        <tr key={`${item.ecosystem}:${item.package}:${item.version}`}>
                          <td className="py-1.5 pr-4 font-mono text-xs text-slate-700 dark:text-slate-300">{item.package}</td>
                          <td className="py-1.5 pr-4 text-slate-600 dark:text-slate-400">{item.version ?? "—"}</td>
                          <td className="py-1.5 pr-4 text-slate-700 dark:text-slate-300">{item.license}</td>
                          <td className="py-1.5 font-mono text-xs text-slate-500 dark:text-slate-400">{item.manifest_path ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {review.length > REVIEW_ROWS_SHOWN && (
                  <p className="text-xs text-slate-400 mt-2">
                    {review.length - REVIEW_ROWS_SHOWN} more are not shown. The SBOM lists the licence of every component.
                  </p>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {error && <p className="text-sm text-red-600 dark:text-red-400 mt-3">{error}</p>}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "warn" }) {
  return (
    <div>
      <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-2xl font-bold ${tone === "warn" ? "text-amber-600 dark:text-amber-400" : "text-slate-900 dark:text-white"}`}>
        {value}
      </div>
    </div>
  );
}
