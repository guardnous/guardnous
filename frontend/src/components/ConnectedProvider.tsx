"use client";

import React, { useState, useMemo } from "react";
import {
  RefreshCw,
  Search,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  GitBranch,
  Star,
  Clock,
  Shield,
  Unlink,
} from "lucide-react";

interface Repo {
  full_name: string;
  enabled: boolean;
  private?: boolean;
  language?: string;
  stargazers_count?: number;
  updated_at?: string;
  description?: string;
}

interface ConnectedProviderProps {
  integration: {
    id: number;
    vcs_type: string;
    account_name: string;
    status: string;
    repositories: Repo[];
    settings?: {
      scan_on_push?: boolean;
      scan_on_pr?: boolean;
      scan_frequency?: string;
    };
  };
  onSync: () => void;
  onToggle: (fullName: string, enabled: boolean) => void;
  onDisconnect: () => void;
  onEnableScan: (repos: string[]) => void;
  syncing?: boolean;
}

export default function ConnectedProvider({
  integration,
  onSync,
  onToggle,
  onDisconnect,
  onEnableScan,
  syncing,
}: ConnectedProviderProps) {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<"name" | "language" | "stars" | "updated">("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());
  const [showSettings, setShowSettings] = useState(false);

  const repos = integration.repositories || [];

  const filtered = useMemo(() => {
    let list = repos.filter((r) =>
      r.full_name.toLowerCase().includes(search.toLowerCase())
    );
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name":
          cmp = a.full_name.localeCompare(b.full_name);
          break;
        case "language":
          cmp = (a.language || "").localeCompare(b.language || "");
          break;
        case "stars":
          cmp = (a.stargazers_count || 0) - (b.stargazers_count || 0);
          break;
        case "updated":
          cmp = (a.updated_at || "").localeCompare(b.updated_at || "");
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [repos, search, sortKey, sortDir]);

  const enabledCount = repos.filter((r) => r.enabled).length;

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const SortIcon = ({ col }: { col: typeof sortKey }) =>
    sortKey === col ? (
      sortDir === "asc" ? <ChevronUp size={14} /> : <ChevronDown size={14} />
    ) : (
      <ChevronDown size={14} className="opacity-30" />
    );

  const allFilteredSelected =
    filtered.length > 0 && filtered.every((r) => selectedRepos.has(r.full_name));

  const handleSelectAll = () => {
    if (allFilteredSelected) {
      const next = new Set(selectedRepos);
      filtered.forEach((r) => next.delete(r.full_name));
      setSelectedRepos(next);
    } else {
      const next = new Set(selectedRepos);
      filtered.forEach((r) => next.add(r.full_name));
      setSelectedRepos(next);
    }
  };

  const handleSelect = (fullName: string) => {
    const next = new Set(selectedRepos);
    if (next.has(fullName)) next.delete(fullName);
    else next.add(fullName);
    setSelectedRepos(next);
  };

  const handleEnableScan = () => {
    if (selectedRepos.size === 0) return;
    onEnableScan(Array.from(selectedRepos));
    setSelectedRepos(new Set());
  };

  return (
    <div className="w-full bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
      {/* Header */}
      <div className="p-4 sm:p-5 border-b border-gray-200 dark:border-gray-700">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              integration.vcs_type === "github" ? "bg-gray-900" :
              integration.vcs_type === "gitlab" ? "bg-orange-600" :
              integration.vcs_type === "bitbucket" ? "bg-blue-600" :
              integration.vcs_type === "azure_devops" ? "bg-blue-500" :
              "bg-gray-900"
            }`}>
              <GitBranch size={20} className="text-white" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                {integration.account_name}
              </h3>
              <p className="text-sm text-gray-500">
                {integration.vcs_type.toUpperCase()} · {repos.length} repositories · {enabledCount} enabled
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onSync}
              disabled={syncing}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
            >
              <RefreshCw size={14} className={syncing ? "animate-spin" : ""} />
              Sync
            </button>
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="px-3 py-1.5 text-sm font-medium border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Settings
            </button>
            <button
              onClick={onDisconnect}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-red-600 border border-red-300 rounded-lg hover:bg-red-50"
            >
              <Unlink size={14} />
              Disconnect
            </button>
          </div>
        </div>

        {/* Stats cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">{repos.length}</div>
            <div className="text-xs text-gray-500">Total Repos</div>
          </div>
          <div className="p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
            <div className="text-2xl font-bold text-green-600">{enabledCount}</div>
            <div className="text-xs text-gray-500">Scan Enabled</div>
          </div>
          <div className="p-3 rounded-lg bg-orange-50 dark:bg-orange-900/20">
            <div className="text-2xl font-bold text-orange-600">
              {repos.filter((r) => r.private).length}
            </div>
            <div className="text-xs text-gray-500">Private</div>
          </div>
          <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20">
            <div className="text-2xl font-bold text-blue-600">
              {repos.filter((r) => !r.private).length}
            </div>
            <div className="text-xs text-gray-500">Public</div>
          </div>
        </div>

        {showSettings && (
          <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
            <h4 className="text-sm font-medium mb-2">Scan Settings</h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={integration.settings?.scan_on_push ?? false}
                  readOnly
                  className="rounded"
                />
                Scan on push
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={integration.settings?.scan_on_pr ?? false}
                  readOnly
                  className="rounded"
                />
                Scan on PR
              </label>
              <div className="text-gray-500">
                Frequency: {integration.settings?.scan_frequency || "manual"}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Toolbar */}
      <div className="p-3 sm:p-4 border-b border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search repositories..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-orange-500 focus:border-transparent outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          {selectedRepos.size > 0 && (
            <span className="text-sm text-gray-500">{selectedRepos.size} selected</span>
          )}
          <button
            onClick={handleEnableScan}
            disabled={selectedRepos.size === 0}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-orange-500 rounded-lg hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
          >
            <Shield size={14} />
            Enable Scan
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[60vh]">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-700/50 sticky top-0">
            <tr>
              <th className="w-10 px-3 py-3 text-left">
                <input
                  type="checkbox"
                  checked={allFilteredSelected}
                  onChange={handleSelectAll}
                  className="rounded"
                />
              </th>
              <th
                className="px-3 py-3 text-left font-medium text-gray-500 cursor-pointer select-none"
                onClick={() => toggleSort("name")}
              >
                <span className="flex items-center gap-1">
                  Repository <SortIcon col="name" />
                </span>
              </th>
              <th
                className="px-3 py-3 text-left font-medium text-gray-500 cursor-pointer select-none hidden md:table-cell"
                onClick={() => toggleSort("language")}
              >
                <span className="flex items-center gap-1">
                  Language <SortIcon col="language" />
                </span>
              </th>
              <th
                className="px-3 py-3 text-left font-medium text-gray-500 cursor-pointer select-none hidden lg:table-cell"
                onClick={() => toggleSort("stars")}
              >
                <span className="flex items-center gap-1">
                  Stars <SortIcon col="stars" />
                </span>
              </th>
              <th
                className="px-3 py-3 text-left font-medium text-gray-500 cursor-pointer select-none hidden lg:table-cell"
                onClick={() => toggleSort("updated")}
              >
                <span className="flex items-center gap-1">
                  Updated <SortIcon col="updated" />
                </span>
              </th>
              <th className="px-3 py-3 text-center font-medium text-gray-500">
                Scan
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
            {filtered.map((repo) => (
              <tr
                key={repo.full_name}
                className="hover:bg-gray-50 dark:hover:bg-gray-700/30"
              >
                <td className="px-3 py-2.5">
                  <input
                    type="checkbox"
                    checked={selectedRepos.has(repo.full_name)}
                    onChange={() => handleSelect(repo.full_name)}
                    className="rounded"
                  />
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-900 dark:text-white">
                      {repo.full_name.split("/")[1]}
                    </span>
                    {repo.private && (
                      <span className="px-1.5 py-0.5 text-[10px] font-medium bg-gray-200 dark:bg-gray-600 rounded text-gray-600 dark:text-gray-300">
                        Private
                      </span>
                    )}
                    <a
                      href={`https://github.com/${repo.full_name}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <ExternalLink size={12} />
                    </a>
                  </div>
                  {repo.description && (
                    <p className="text-xs text-gray-400 mt-0.5 truncate max-w-md">
                      {repo.description}
                    </p>
                  )}
                </td>
                <td className="px-3 py-2.5 hidden md:table-cell">
                  <span className="text-gray-500">{repo.language || "—"}</span>
                </td>
                <td className="px-3 py-2.5 hidden lg:table-cell">
                  <span className="flex items-center gap-1 text-gray-500">
                    <Star size={12} /> {repo.stargazers_count || 0}
                  </span>
                </td>
                <td className="px-3 py-2.5 hidden lg:table-cell">
                  <span className="flex items-center gap-1 text-gray-500">
                    <Clock size={12} />{" "}
                    {repo.updated_at
                      ? new Date(repo.updated_at).toLocaleDateString()
                      : "—"}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-center">
                  <button
                    onClick={() => onToggle(repo.full_name, !repo.enabled)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                      repo.enabled ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"
                    }`}
                  >
                    <span
                      className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                        repo.enabled ? "translate-x-4" : "translate-x-0.5"
                      }`}
                    />
                  </button>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-8 text-center text-gray-400">
                  {search ? "No repositories match your search" : "No repositories found"}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
