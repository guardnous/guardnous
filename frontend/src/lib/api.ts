import axios from "axios";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:7002";

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("token") || sessionStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && typeof window !== "undefined") {
      const path = window.location.pathname;
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      sessionStorage.removeItem("token");
      sessionStorage.removeItem("user");
      // Don't redirect if already on login/first-run (avoids loop)
      if (path !== "/login" && path !== "/first-run") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);

/* ── Auth ── */
export async function login(email: string, password: string) {
  const form = new URLSearchParams();
  form.append("username", email);
  form.append("password", password);
  const { data } = await api.post("/auth/login", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return data;
}

export async function verifyLoginOTP(mfa_token: string, code: string) {
  const { data } = await api.post("/auth/verify-2fa", { mfa_token, code });
  return data;
}

export async function setup2FA() {
  const { data } = await api.post("/auth/2fa/setup");
  return data as { totp_uri: string; qr_code: string; backup_codes: string[] };
}

export async function confirm2FASetup(code: string) {
  const { data } = await api.post("/auth/2fa/confirm", { code });
  return data;
}

export async function disable2FA() {
  const { data } = await api.post("/auth/2fa/disable");
  return data;
}

export async function regenerateBackupCodes() {
  const { data } = await api.get("/auth/2fa/backup-codes");
  return data as { backup_codes: string[] };
}

export async function register(body: {
  email: string;
  password: string;
  full_name: string;
  organization_name: string;
  tenant_name: string;
}) {
  const { data } = await api.post("/auth/register", body);
  return data;
}

export async function getMe() {
  const { data } = await api.get("/auth/me");
  return data;
}

/* ── Dashboard ── */
export async function getDashboard() {
  const { data } = await api.get("/dashboard");
  return data;
}

/* ── Jobs ── */
export async function getJobs(params?: {
  page?: number;
  page_size?: number;
  status?: string;
}) {
  const { data } = await api.get("/jobs", { params });
  return data;
}

export async function getJob(id: number) {
  const { data } = await api.get(`/jobs/${id}`);
  return data;
}

export async function getJobProgress(id: number) {
  const { data } = await api.get(`/jobs/${id}/progress`);
  return data;
}

export async function cancelJob(id: number) {
  const { data } = await api.post(`/jobs/${id}/cancel`);
  return data;
}

export async function triggerRepoScan(body: {
  repository_full_name: string;
  scan_types?: string[];
}) {
  const { data } = await api.post("/jobs/scan-repo", body);
  return data;
}

/* ── Integrations ── */
export async function connectPAT(body: {
  vcs_type: string;
  token: string;
  base_url?: string;
  username?: string;
}) {
  const { data } = await api.post("/integrations/connect", body);
  return data;
}

export async function getGitHubAppInstall() {
  const { data } = await api.get("/integrations/github/app/install");
  return data;
}

export async function githubAppCallback(body: {
  installation_id: number;
  setup_action?: string;
}) {
  const { data } = await api.post("/integrations/github/app/callback", body);
  return data;
}

export async function getIntegrationStatus() {
  const { data } = await api.get("/integrations/status");
  return data;
}

export async function getRepos() {
  const { data } = await api.get("/integrations/repos");
  return data;
}

export async function toggleRepo(body: { full_name: string; enabled: boolean }) {
  const { data } = await api.post("/integrations/repos/toggle", body);
  return data;
}

export async function syncRepos() {
  const { data } = await api.post("/integrations/repos/sync");
  return data;
}

export async function updateIntegrationSettings(body: {
  scan_on_push?: boolean;
  scan_on_pr?: boolean;
  auto_fix_prs?: boolean;
  scan_frequency?: string;
}) {
  const { data } = await api.put("/integrations/settings", body);
  return data;
}

export async function disconnectIntegration() {
  const { data } = await api.delete("/integrations/disconnect");
  return data;
}

export async function getCapabilities() {
  const { data } = await api.get("/integrations/capabilities");
  return data;
}

export async function getAllIntegrations() {
  const { data } = await api.get("/integrations/all");
  return data;
}

export async function scanRepository(body: { full_name: string; integration_id?: number }) {
  const { data } = await api.post("/integrations/scan/repo", body);
  return data;
}

export async function removeRepository(fullName: string, cascade = true) {
  const { data } = await api.delete(`/integrations/repos/${fullName}`, { params: { cascade } });
  return data;
}

/* ── Scans ── */
export async function getScans(params?: {
  page?: number;
  page_size?: number;
  status?: string;
  scan_type?: string;
}) {
  const { data } = await api.get("/scans", { params });
  return data;
}

export async function getScan(id: number) {
  const { data } = await api.get(`/scans/${id}`);
  return data;
}

/* ── Agent Conversations ── */
export async function getConversations() {
  const { data } = await api.get("/agents/conversations");
  return data;
}

export async function getConversation(id: number) {
  const { data } = await api.get(`/agents/conversations/${id}`);
  return data;
}

export async function deleteConversation(id: number) {
  const { data } = await api.delete(`/agents/conversations/${id}`);
  return data;
}

export async function renameConversation(id: number, title: string) {
  const { data } = await api.patch(`/agents/conversations/${id}`, { title });
  return data;
}

/* ── Agent Config ── */
export async function getAgentConfig() {
  const { data } = await api.get("/agents/config");
  return data;
}

export async function updateAgentConfig(body: {
  provider?: string;
  model?: string;
  api_key?: string;
  base_url?: string;
  api_version?: string;
}) {
  const { data } = await api.put("/agents/config", body);
  return data;
}

export async function testAgentConfig(body?: {
  provider?: string;
  model?: string;
  api_key?: string;
  base_url?: string;
  api_version?: string;
}) {
  const { data } = await api.post("/agents/config/test", body ?? {});
  return data;
}

/* ── CVE Stats ── */
export async function getCVEStats() {
  const { data } = await api.get("/cves/stats");
  return data;
}

export async function syncCVEDatabase() {
  const { data } = await api.post("/cves/sync");
  return data;
}

/* ── Reports ── */
export async function createReport(body: {
  title?: string;
  report_type?: string;
  format?: string;
  scan_ids?: number[];
}) {
  const { data } = await api.post("/reports", body);
  return data;
}

export async function getReports() {
  const { data } = await api.get("/reports");
  return data;
}

export async function getReport(id: number) {
  const { data } = await api.get(`/reports/${id}`);
  return data;
}

export async function viewReport(id: number) {
  const { data } = await api.get(`/reports/${id}/view`);
  return data;
}

export async function downloadReport(id: number, format: string = "pdf") {
  const { data } = await api.get(`/reports/${id}/download`, {
    params: { format },
    responseType: "blob",
  });
  return data;
}

/* ── Findings ── */
export async function getFindings(params?: {
  page?: number;
  page_size?: number;
  severity?: string;
  cloud_provider?: string;
  category?: string;
  is_fixed?: boolean;
  is_ignored?: boolean;
  search?: string;
  scan_id?: number;
}) {
  const { data } = await api.get("/findings", { params });
  return data;
}

export async function getFinding(id: number) {
  const { data } = await api.get(`/findings/${id}`);
  return data;
}

export async function updateFinding(
  id: number,
  body: { is_fixed?: boolean; is_ignored?: boolean }
) {
  const { data } = await api.patch(`/findings/${id}`, body);
  return data;
}

/* ── CVEs ── */
export async function getCVEs(params?: {
  page?: number;
  page_size?: number;
  severity?: string;
  search?: string;
}) {
  const { data } = await api.get("/cves", { params });
  return data;
}

/* ── Settings ── */
export async function getSettings() {
  const { data } = await api.get("/settings/general");
  return data;
}

export async function updateSettings(body: Record<string, unknown>) {
  const { data } = await api.put("/settings/general", body);
  return data;
}

/* ── AWS without access keys ── */
export async function getAwsFederation() {
  const { data } = await api.get("/cloud-accounts/aws/federation");
  return data;
}

export async function connectAwsKeyless(body: { account_id: string; name?: string; allow_fixes?: boolean }) {
  const { data } = await api.post("/cloud-accounts/aws/federated", body);
  return data;
}

export async function getAwsKeylessSetup(id: number) {
  const { data } = await api.get(`/cloud-accounts/${id}/aws-setup`);
  return data;
}

export async function downloadAwsKeylessTemplate(id: number, filename: string) {
  const { data } = await api.get(`/cloud-accounts/${id}/aws-template`, { responseType: "blob" });
  const url = URL.createObjectURL(data as Blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/* ── Cloud posture ── */
export async function getCloudPosture(accountId?: number) {
  const { data } = await api.get("/cloud-posture", { params: accountId ? { account_id: accountId } : undefined });
  return data;
}

export async function evaluateCloudPosture() {
  const { data } = await api.post("/cloud-posture/evaluate");
  return data;
}

export async function rollbackCloudChange(id: number) {
  const { data } = await api.post(`/cloud-posture/changes/${id}/rollback`);
  return data;
}

/* ── Agent runs ── */
export async function getAgentList() {
  const { data } = await api.get("/agents/");
  return data;
}

export async function getAgentRuns(params?: { status?: string }) {
  const { data } = await api.get("/agents/runs", { params });
  return data;
}

export async function getAgentRun(id: number) {
  const { data } = await api.get(`/agents/runs/${id}`);
  return data;
}

export async function startAgentRun(body: { goal: string; agent_id?: string }) {
  const { data } = await api.post("/agents/runs", body);
  return data;
}

export async function cancelAgentRun(id: number) {
  const { data } = await api.post(`/agents/runs/${id}/cancel`);
  return data;
}

export async function getAgentApprovals(status = "pending") {
  const { data } = await api.get("/agents/approvals", { params: { status } });
  return data;
}

export async function decideAgentApproval(id: number, body: { approve: boolean; note?: string }) {
  const { data } = await api.post(`/agents/approvals/${id}/decision`, body);
  return data;
}

export async function getAgentUsage() {
  const { data } = await api.get("/agents/usage");
  return data;
}

/* ── Agents ── */
export async function getAgentStatus() {
  const { data } = await api.get("/agents/status");
  return data;
}

export async function chatWithAgent(body: {
  message: string;
  conversation_id?: number;
}) {
  const { data } = await api.post("/agents/chat", body);
  return data;
}

/**
 * Stream chat responses via SSE with full agent event support.
 * Events: routing, tool_start, tool_result, token, done, error.
 * Returns an AbortController so the caller can cancel.
 */
export interface StreamRouting {
  agent_id: string;
  agent_name: string;
  confidence: number;
  reasoning?: string;
}

export interface StreamToolEvent {
  tool: string;
  args?: Record<string, unknown>;
  preview?: string;
  step: number;
}

/**
 * ChatGPT-like direct SSE streaming.
 *
 * POST the message → read SSE tokens directly from the same response.
 * One connection, instant first token, no Celery/Redis in the hot path.
 * If you close the tab, the server-side asyncio task continues saving to DB.
 */
export interface ChatFile {
  id: number;
  kind: "upload" | "generated";
  filename: string;
  content_type?: string | null;
  size_bytes: number;
  truncated?: boolean;
  redactions?: number;
}

/** File types the chat accepts as attachments (mirrors the server's list). */
export const CHAT_ATTACHMENT_ACCEPT =
  ".pdf,.docx,.xlsx,.xlsm,.png,.jpg,.jpeg,.gif,.webp,.bmp,.tif,.tiff,.csv,.tsv,.json,.jsonl,.yaml,.yml,.xml,.html,.txt,.md,.log,.tf,.tfvars,.hcl,.bicep,.toml,.ini,.conf,.sql,.sh,.ps1,.py,.js,.ts,.go,.java,.sarif,.rego";

export async function uploadChatFile(file: File): Promise<ChatFile> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post("/agents/chat/files", form, { headers: { "Content-Type": "multipart/form-data" } });
  return data;
}

/** Fetch a protected file with the session token and hand it to the browser as a download. */
async function saveProtectedFile(path: string, fallbackName: string) {
  const res = await api.get(path, { responseType: "blob" });
  const named = /filename="?([^";]+)"?/.exec(res.headers["content-disposition"] || "");
  const url = URL.createObjectURL(res.data as Blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = named?.[1] || fallbackName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const downloadChatFile = (file: ChatFile) =>
  saveProtectedFile(`/agents/chat/files/${file.id}/download`, file.filename);

export const downloadMessageAsPdf = (messageId: number) =>
  saveProtectedFile(`/agents/messages/${messageId}/pdf`, "guardnous-answer.pdf");

export function streamChat(
  body: { message: string; conversation_id?: number; agent_id?: string; attachment_ids?: number[] },
  callbacks: {
    onToken: (token: string) => void;
    onDone: (meta: { conversation_id: number; provider: string; model?: string; tool_trace?: string[] }) => void;
    onError: (err: Error) => void;
    onRouting?: (routing: StreamRouting) => void;
    onToolStart?: (event: StreamToolEvent) => void;
    onToolResult?: (event: StreamToolEvent) => void;
    onPlan?: (event: Record<string, unknown>) => void;
    onAgentSpawn?: (event: Record<string, unknown>) => void;
    onAgentThinking?: (event: Record<string, unknown>) => void;
    onAgentTool?: (event: Record<string, unknown>) => void;
    onAgentComplete?: (event: Record<string, unknown>) => void;
    onAgentHandoff?: (event: Record<string, unknown>) => void;
    onProgress?: (event: Record<string, unknown>) => void;
    onMessageId?: (messageId: number, conversationId: number, userMessageId?: number) => void;
  },
): AbortController {
  const controller = new AbortController();
  const authToken = typeof window !== "undefined"
    ? (localStorage.getItem("token") || sessionStorage.getItem("token"))
    : null;

  fetch(`${API_URL}/api/v1/agents/chat/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(body),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body?.getReader();
      if (!reader) throw new Error("No readable stream");
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const event = JSON.parse(line.slice(6));
            _dispatchSSEEvent(event, callbacks);
          } catch {
            // ignore malformed events
          }
        }
      }
    })
    .catch((err: Error) => {
      if (err.name !== "AbortError") {
        callbacks.onError(err);
      }
    });

  return controller;
}

/**
 * Reconnect to an in-progress or completed message via GET SSE.
 * Used on page reload — polls DB content, no Redis needed.
 */
export function subscribeToProgress(
  messageId: number,
  callbacks: {
    onToken: (token: string) => void;
    onDone: (meta: { conversation_id: number; provider: string; model?: string; tool_trace?: string[] }) => void;
    onError: (err: Error) => void;
    onCatchup?: (content: string) => void;
  },
): AbortController {
  const controller = new AbortController();
  const authToken = typeof window !== "undefined"
    ? (localStorage.getItem("token") || sessionStorage.getItem("token"))
    : null;

  fetch(`${API_URL}/api/v1/agents/chat/progress/${messageId}`, {
    headers: {
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body?.getReader();
      if (!reader) throw new Error("No readable stream");
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const event = JSON.parse(line.slice(6));
            if (event.type === "catchup" && callbacks.onCatchup) {
              callbacks.onCatchup(event.content || "");
            } else {
              _dispatchSSEEvent(event, callbacks);
            }
          } catch {
            // ignore malformed events
          }
        }
      }
    })
    .catch((err: Error) => {
      if (err.name !== "AbortError") {
        callbacks.onError(err);
      }
    });

  return controller;
}

/** Shared SSE event dispatcher — handles all event types from both endpoints. */
function _dispatchSSEEvent(
  event: Record<string, unknown>,
  cbs: {
    onToken: (token: string) => void;
    onDone: (meta: { conversation_id: number; provider: string; model?: string; tool_trace?: string[] }) => void;
    onError: (err: Error) => void;
    onRouting?: (routing: StreamRouting) => void;
    onToolStart?: (event: StreamToolEvent) => void;
    onToolResult?: (event: StreamToolEvent) => void;
    onPlan?: (event: Record<string, unknown>) => void;
    onAgentSpawn?: (event: Record<string, unknown>) => void;
    onAgentThinking?: (event: Record<string, unknown>) => void;
    onAgentTool?: (event: Record<string, unknown>) => void;
    onAgentComplete?: (event: Record<string, unknown>) => void;
    onAgentHandoff?: (event: Record<string, unknown>) => void;
    onProgress?: (event: Record<string, unknown>) => void;
    onMessageId?: (messageId: number, conversationId: number, userMessageId?: number) => void;
  },
) {
  if (event.type === "heartbeat") return;

  // Meta event (first event from POST /chat/stream with message + conversation IDs)
  if (event.type === "meta") {
    cbs.onMessageId?.(event.message_id as number, event.conversation_id as number, event.user_message_id as number | undefined);
    return;
  }

  // Done / completion
  if (event.done) {
    cbs.onDone({
      conversation_id: event.conversation_id as number,
      provider: event.provider as string,
      model: event.model as string | undefined,
      tool_trace: event.tool_trace as string[] | undefined,
    });
    return;
  }

  // Error
  if (event.type === "error") {
    cbs.onError(new Error((event.message as string) || "Agent error"));
    return;
  }

  // Routing, tools, agents
  if (event.type === "routing" && cbs.onRouting) {
    cbs.onRouting({ agent_id: event.agent_id as string, agent_name: event.agent_name as string, confidence: event.confidence as number, reasoning: event.reasoning as string });
  } else if (event.type === "tool_start" && cbs.onToolStart) {
    cbs.onToolStart({ tool: event.tool as string, args: event.args as Record<string, unknown>, step: event.step as number });
  } else if (event.type === "tool_result" && cbs.onToolResult) {
    cbs.onToolResult({ tool: event.tool as string, preview: event.preview as string, step: event.step as number });
  } else if (event.type === "plan" && cbs.onPlan) {
    cbs.onPlan(event);
  } else if (event.type === "agent_spawn" && cbs.onAgentSpawn) {
    cbs.onAgentSpawn(event);
  } else if (event.type === "agent_thinking" && cbs.onAgentThinking) {
    cbs.onAgentThinking(event);
  } else if (event.type === "agent_tool" && cbs.onAgentTool) {
    cbs.onAgentTool(event);
  } else if (event.type === "agent_complete" && cbs.onAgentComplete) {
    cbs.onAgentComplete(event);
  } else if (event.type === "agent_handoff" && cbs.onAgentHandoff) {
    cbs.onAgentHandoff(event);
  } else if (event.type === "progress" && cbs.onProgress) {
    cbs.onProgress(event);
  } else if (event.token !== undefined) {
    cbs.onToken(event.token as string);
  }
}

/* ── Plugins ── */
export async function getPlugins() {
  const { data } = await api.get("/plugins");
  return data;
}

export async function togglePlugin(pluginName: string, enabled: boolean) {
  const { data } = await api.post(`/plugins/${pluginName}/toggle`, { enabled });
  return data;
}

export async function getPluginVersions(pluginName: string) {
  const { data } = await api.get(`/plugins/${pluginName}/versions`);
  return data;
}

export async function installPluginVersion(pluginName: string, version: string) {
  const { data } = await api.post(`/plugins/${pluginName}/versions/install`, { version });
  return data;
}

export async function activatePluginVersion(pluginName: string, version: string) {
  const { data } = await api.post(`/plugins/${pluginName}/versions/activate`, { version });
  return data;
}

export async function rollbackPluginVersion(pluginName: string) {
  const { data } = await api.post(`/plugins/${pluginName}/versions/rollback`);
  return data;
}

export async function getVersionPolicy(pluginName: string) {
  const { data } = await api.get(`/plugins/${pluginName}/versions/policy`);
  return data;
}

export async function updateVersionPolicy(pluginName: string, policy: Record<string, unknown>) {
  const { data } = await api.put(`/plugins/${pluginName}/versions/policy`, policy);
  return data;
}

export async function getSupplyChainHealth() {
  const { data } = await api.get("/plugins/supply-chain/health");
  return data;
}

export async function getPluginCacheStats() {
  const { data } = await api.get("/plugins/supply-chain/cache");
  return data;
}

export async function getPluginIntegrity() {
  const { data } = await api.get("/plugins/integrity");
  return data;
}

export async function approvePluginBinary(pluginName: string) {
  const { data } = await api.post(`/plugins/${pluginName}/integrity/approve`);
  return data;
}

/* ── Schedules ── */
export interface ScanScheduleInput {
  name: string;
  integration_id: number;
  repository: string;
  cron_expression: string;
  enabled: boolean;
}

export interface ReportScheduleInput {
  name: string;
  report_type: string;
  cron_expression: string;
  recipients: string[];
  enabled: boolean;
}

export async function getScanSchedules() {
  const { data } = await api.get("/scan-schedules");
  return data;
}

export async function createScanSchedule(body: ScanScheduleInput) {
  const { data } = await api.post("/scan-schedules", body);
  return data;
}

export async function updateScanSchedule(id: number, body: Partial<ScanScheduleInput>) {
  const { data } = await api.put(`/scan-schedules/${id}`, body);
  return data;
}

export async function deleteScanSchedule(id: number) {
  await api.delete(`/scan-schedules/${id}`);
}

export async function runScanSchedule(id: number) {
  const { data } = await api.post(`/scan-schedules/${id}/run`);
  return data;
}

export async function getReportSchedules() {
  const { data } = await api.get("/report-schedules");
  return data;
}

export async function createReportSchedule(body: ReportScheduleInput) {
  const { data } = await api.post("/report-schedules", body);
  return data;
}

export async function updateReportSchedule(id: number, body: Partial<ReportScheduleInput>) {
  const { data } = await api.put(`/report-schedules/${id}`, body);
  return data;
}

export async function deleteReportSchedule(id: number) {
  await api.delete(`/report-schedules/${id}`);
}

export async function runReportSchedule(id: number) {
  const { data } = await api.post(`/report-schedules/${id}/run`);
  return data;
}

/* ── Admin ── */
export async function getAdminUsers(params?: { page?: number; page_size?: number }) {
  const { data } = await api.get("/users/", { params });
  return data;
}

export async function getAdminRoles() {
  const { data } = await api.get("/roles/");
  return data;
}

export async function getAdminTenants(params?: { page?: number; page_size?: number }) {
  const { data } = await api.get("/tenants/", { params });
  return data;
}

export async function getAdminAudit(params?: { page?: number; page_size?: number }) {
  const { data } = await api.get("/audit/logs", { params });
  return data;
}

export async function getAdminGroups() {
  const { data } = await api.get("/groups/");
  return data;
}

/* ── IAM Threat Intelligence ── */
export async function getIAMDashboard() {
  const { data } = await api.get("/iam/dashboard");
  return data;
}
export async function getIAMIdentities(params?: Record<string, any>) {
  const { data } = await api.get("/iam/identities", { params });
  return data;
}
export async function getIAMIdentity(id: number) {
  const { data } = await api.get(`/iam/identities/${id}`);
  return data;
}
export async function getIAMThreats(params?: Record<string, any>) {
  const { data } = await api.get("/iam/threats", { params });
  return data;
}
export async function updateThreatStatus(id: number, status: string, notes?: string) {
  const { data } = await api.patch(`/iam/threats/${id}/status`, null, { params: { status, notes } });
  return data;
}
export async function getIAMAttackPaths(params?: Record<string, any>) {
  const { data } = await api.get("/iam/attack-paths", { params });
  return data;
}
export async function startIAMScan(body: { cloud_provider: string; scan_type?: string }) {
  const { data } = await api.post("/iam/scan", body);
  return data;
}
export async function getIAMScans() {
  const { data } = await api.get("/iam/scans");
  return data;
}

/* ── Enterprise Governance ── */
export async function getGovernanceDashboard() {
  const { data } = await api.get("/governance/dashboard");
  return data;
}
export async function getComplianceFrameworks() {
  const { data } = await api.get("/governance/frameworks");
  return data;
}
export async function seedFrameworks() {
  const { data } = await api.post("/governance/frameworks/seed");
  return data;
}
export async function evaluateCompliance() {
  const { data } = await api.post("/governance/evaluate");
  return data;
}
export async function getFramework(id: number) {
  const { data } = await api.get(`/governance/frameworks/${id}`);
  return data;
}
export async function getFrameworkControls(id: number, params?: Record<string, any>) {
  const { data } = await api.get(`/governance/frameworks/${id}/controls`, { params });
  return data;
}
export async function getControlAffectedResources(controlId: number, params?: Record<string, any>) {
  const { data } = await api.get(`/governance/controls/${controlId}/affected-resources`, { params });
  return data;
}
export async function getSecurityPolicies() {
  const { data } = await api.get("/governance/policies");
  return data;
}
export async function createSecurityPolicy(body: Record<string, any>) {
  const { data } = await api.post("/governance/policies", body);
  return data;
}
export async function updateSecurityPolicy(id: number, body: Record<string, any>) {
  const { data } = await api.put(`/governance/policies/${id}`, body);
  return data;
}
export async function deleteSecurityPolicy(id: number) {
  const { data } = await api.delete(`/governance/policies/${id}`);
  return data;
}
export async function toggleSecurityPolicy(id: number) {
  const { data } = await api.post(`/governance/policies/${id}/toggle`);
  return data;
}
export async function seedPolicies() {
  const { data } = await api.post("/governance/policies/seed");
  return data;
}
export async function evaluatePolicies() {
  const { data } = await api.post("/governance/policies/evaluate");
  return data;
}
export async function getGovernanceViolations(params?: Record<string, any>) {
  const { data } = await api.get("/governance/violations", { params });
  return data;
}
export async function getViolationDetail(id: number) {
  const { data } = await api.get(`/governance/violations/${id}`);
  return data;
}
export async function acceptViolation(id: number, reason?: string) {
  const { data } = await api.post(`/governance/violations/${id}/accept`, { reason });
  return data;
}
export async function reopenViolation(id: number) {
  const { data } = await api.post(`/governance/violations/${id}/reject`);
  return data;
}
export async function toggleFramework(id: number) {
  const { data } = await api.post(`/governance/frameworks/${id}/toggle`);
  return data;
}
export async function runAssessment(body?: Record<string, any>) {
  const { data } = await api.post("/governance/assessments/run", body || {});
  return data;
}
export async function getAssessments(params?: Record<string, any>) {
  const { data } = await api.get("/governance/assessments", { params });
  return data;
}
export async function getAssessmentDetail(id: number) {
  const { data } = await api.get(`/governance/assessments/${id}`);
  return data;
}
export async function seedGovernanceData() {
  const { data } = await api.post("/governance/seed");
  return data;
}
export async function getCloudResources(params?: Record<string, any>) {
  const { data } = await api.get("/governance/resources", { params });
  return data;
}
export async function getCloudResourcesSummary() {
  const { data } = await api.get("/governance/resources/summary");
  return data;
}
export async function getRiskExceptions(params?: Record<string, any>) {
  const { data } = await api.get("/governance/exceptions", { params });
  return data;
}
export async function createRiskException(body: Record<string, any>) {
  const { data } = await api.post("/governance/exceptions", body);
  return data;
}
export async function updateRiskException(id: number, body: Record<string, any>) {
  const { data } = await api.put(`/governance/exceptions/${id}`, body);
  return data;
}
export async function approveException(id: number) {
  const { data } = await api.patch(`/governance/exceptions/${id}/approve`);
  return data;
}
export async function rejectException(id: number) {
  const { data } = await api.patch(`/governance/exceptions/${id}/reject`);
  return data;
}

// ─── Multi-Tenancy / Org Management ─────────────────────
export async function fetchOrgDashboard() {
  const { data } = await api.get("/org/dashboard");
  return data;
}
export async function fetchOrganizations() {
  const { data } = await api.get("/org/organizations");
  return data;
}
export async function createOrganization(body: { name: string; slug: string; subdomain?: string; admin_email?: string }) {
  const { data } = await api.post("/org/organizations", body);
  return data;
}
export async function bulkInviteUsers(body: { emails: string[]; role: string; message?: string }) {
  const { data } = await api.post("/org/invite", body);
  return data;
}
export async function fetchInvitations(status?: string) {
  const { data } = await api.get("/org/invitations", { params: status ? { status } : {} });
  return data;
}
export async function revokeInvitation(id: number) {
  const { data } = await api.delete(`/org/invitations/${id}`);
  return data;
}
export async function switchTenant(tenantId: number) {
  const { data } = await api.get(`/org/tenants/${tenantId}/switch`);
  return data;
}

// ─── Notifications ──────────────────────────────────────────
export async function getNotifications(unreadOnly = false) {
  const { data } = await api.get(`/notifications`, { params: { unread_only: unreadOnly, limit: 50 } });
  return data;
}
export async function markNotificationRead(id: number) {
  const { data } = await api.patch(`/notifications/${id}/read`);
  return data;
}
export async function markAllNotificationsRead() {
  const { data } = await api.post(`/notifications/mark-all-read`);
  return data;
}
export async function clearAllNotifications() {
  const { data } = await api.delete(`/notifications/clear`);
  return data;
}

// ─── Organization Settings ──────────────────────────────────
export async function getGeneralSettings() {
  const { data } = await api.get(`/settings/general`);
  return data;
}
export async function updateGeneralSettings(body: Record<string, unknown>) {
  const { data } = await api.put(`/settings/general`, body);
  return data;
}
export async function getNotificationPrefs() {
  const { data } = await api.get(`/settings/notifications`);
  return data;
}
export async function updateNotificationPrefs(body: Record<string, unknown>) {
  const { data } = await api.put(`/settings/notifications`, body);
  return data;
}


// ─── SMTP Settings ──────────────────────────────────────────
export async function getSmtpSettings() {
  const { data } = await api.get(`/settings/smtp`);
  return data;
}
export async function updateSmtpSettings(body: Record<string, unknown>) {
  const { data } = await api.put(`/settings/smtp`, body);
  return data;
}
export async function testSmtpConnection(recipientEmail: string) {
  const { data } = await api.post(`/settings/smtp/test`, { recipient_email: recipientEmail });
  return data;
}

// ─── Setup Wizard (post-login settings config) ──────────────
export async function getSetupStatus() {
  const { data } = await api.get("/settings/setup-status");
  return data;
}

export async function completeSetup(payload: Record<string, unknown>) {
  const { data } = await api.post("/settings/complete-setup", payload);
  return data;
}

// ─── First-Run Setup (pre-login admin bootstrap) ────────────
export async function checkFirstRunSetup(): Promise<{
  is_setup_complete: boolean;
  has_admin: boolean;
  has_tenant: boolean;
  db_connected: boolean;
}> {
  const { data } = await api.get("/setup/check");
  return data;
}

export async function initializeSetup(payload: {
  admin_email: string;
  admin_password: string;
  admin_full_name: string;
  tenant_name: string;
  organization_name: string;
}): Promise<{
  success: boolean;
  message: string;
  tenant_id: number;
  admin_user_id: number;
  access_token: string;
}> {
  const { data } = await api.post("/setup/initialize", payload);
  return data;
}

// ─── Email Verification ─────────────────────────────────────
export async function verifyEmail(token: string) {
  const { data } = await api.get(`/auth/verify-email?token=${encodeURIComponent(token)}`);
  return data;
}

export async function resendVerificationEmail() {
  const { data } = await api.post("/auth/resend-verification");
  return data;
}

// ─── Organization Management ────────────────────────────────
export async function switchOrganization(orgId: number) {
  const { data } = await api.post(`/org/switch/${orgId}`);
  return data;
}

export async function searchUsersInTenant(q: string) {
  const { data } = await api.get(`/org/users/search?q=${encodeURIComponent(q)}`);
  return data;
}

export async function assignUserToOrg(userId: number, organizationId: number, roleInOrg = "member") {
  const { data } = await api.post("/org/assign-user", { user_id: userId, organization_id: organizationId, role_in_org: roleInOrg });
  return data;
}

export async function removeUserFromOrg(userId: number, organizationId: number) {
  const { data } = await api.delete("/org/remove-user", { data: { user_id: userId, organization_id: organizationId } });
  return data;
}

export async function getUserMemberships(userId: number) {
  const { data } = await api.get(`/org/user-memberships/${userId}`);
  return data;
}

// ─── Knowledge Base ─────────────────────────────────────
export async function getKnowledgeEntries(params?: Record<string, any>) {
  const { data } = await api.get("/knowledge", { params });
  return data;
}
export async function getKnowledgeStats() {
  const { data } = await api.get("/knowledge/stats/summary");
  return data;
}
export async function getKnowledgeEntry(id: number) {
  const { data } = await api.get(`/knowledge/${id}`);
  return data;
}
export async function createKnowledgeEntry(body: Record<string, any>) {
  const { data } = await api.post("/knowledge", body);
  return data;
}
export async function updateKnowledgeEntry(id: number, body: Record<string, any>) {
  const { data } = await api.put(`/knowledge/${id}`, body);
  return data;
}
export async function deleteKnowledgeEntry(id: number) {
  const { data } = await api.delete(`/knowledge/${id}`);
  return data;
}
export async function seedKnowledgeBase() {
  const { data } = await api.post("/knowledge/seed");
  return data;
}

// ─── Service Accounts (bot users for auto-fix PRs) ──────
export async function getServiceAccounts() {
  const { data } = await api.get("/service-accounts");
  return data;
}
export async function createServiceAccount(body: Record<string, any>) {
  const { data } = await api.post("/service-accounts", body);
  return data;
}
export async function updateServiceAccount(id: number, body: Record<string, any>) {
  const { data } = await api.patch(`/service-accounts/${id}`, body);
  return data;
}
export async function rotateServiceAccountToken(id: number) {
  const { data } = await api.post(`/service-accounts/${id}/rotate`);
  return data;
}
export async function deleteServiceAccount(id: number) {
  const { data } = await api.delete(`/service-accounts/${id}`);
  return data;
}

// ─── Cloud Accounts (real cloud connector integration) ───────────────────────
export async function listCloudAccounts(params?: { provider?: string; status?: string }) {
  const { data } = await api.get("/cloud-accounts", { params });
  return data;
}
export async function getCloudAccount(id: number) {
  const { data } = await api.get(`/cloud-accounts/${id}`);
  return data;
}
export async function createCloudAccount(body: {
  provider: string;
  name: string;
  account_identifier: string;
  credentials: Record<string, string>;
  regions?: string[];
  sync_interval_hours?: number;
}) {
  const { data } = await api.post("/cloud-accounts", body);
  return data;
}
export async function updateCloudAccount(id: number, body: Record<string, unknown>) {
  const { data } = await api.patch(`/cloud-accounts/${id}`, body);
  return data;
}
export async function deleteCloudAccount(id: number) {
  await api.delete(`/cloud-accounts/${id}`);
}
export async function testCloudAccount(id: number) {
  const { data } = await api.post(`/cloud-accounts/${id}/test`);
  return data;
}
/** Validate credentials against the provider without saving an account. */
export async function testCloudCredentials(provider: string, credentials: Record<string, string>) {
  const { data } = await api.post("/cloud-accounts/test-credentials", { provider, credentials });
  return data as { status: string; error?: string; details?: Record<string, unknown> };
}
export async function syncCloudAccount(id: number) {
  const { data } = await api.post(`/cloud-accounts/${id}/sync`);
  return data;
}
export async function getCloudAccountResources(id: number, params?: { resource_type?: string; limit?: number; offset?: number }) {
  const { data } = await api.get(`/cloud-accounts/${id}/resources`, { params });
  return data;
}
export async function getCredentialSchema(provider: string) {
  const { data } = await api.get(`/cloud-accounts/credential-schema/${provider}`);
  return data;
}

export default api;
