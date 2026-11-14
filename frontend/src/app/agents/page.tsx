"use client";

import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  getConversations,
  getConversation,
  deleteConversation,
  renameConversation,
  getAgentConfig,
  updateAgentConfig,
  testAgentConfig,
  streamChat,
  subscribeToProgress,
  uploadChatFile,
  downloadChatFile,
  downloadMessageAsPdf,
  CHAT_ATTACHMENT_ACCEPT,
  type ChatFile,
  type StreamRouting,
  type StreamToolEvent,
} from "@/lib/api";
import { AgentActivityPanel, OrchestrationHeader, ThinkingStream } from '@/components/agents';
import { PlanVisualization } from "@/components/agents/PlanVisualization";
import { HandoffVisualization, parseHandoff, type AgentHandoff } from "@/components/agents/HandoffVisualization";
import { applyStepState, parsePlanSteps, type PlanStep } from "@/components/agents/planLayout";
import {
  Plus,
  Search,
  Send,
  Trash2,
  Settings,
  PanelLeftClose,
  PanelLeftOpen,
  MessageSquare,
  Shield,
  Copy,
  Check,
  X,
  Loader2,
  ChevronDown,
  Eye,
  EyeOff,
  Sparkles,
  ScanSearch,
  FileBarChart,
  ClipboardCheck,
  Bot,
  AlertTriangle,
  Wrench,
  Route,
  ChevronRight,
  SquarePen,
  StopCircle,
  Pencil,
  Paperclip,
  FileText,
  Download,
} from "lucide-react";

/* ─── Types ─── */
interface Message {
  id: number;
  role: "user" | "assistant";
  content: string;
  status?: string;
  task_id?: string;
  created_at: string;
  files?: ChatFile[];
}

const fileSize = (bytes: number) =>
  bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;

interface Conversation {
  id: number;
  title: string;
  message_count: number;
  created_at: string;
  updated_at: string;
}

interface AgentConfig {
  provider: string;
  model: string;
  base_url: string;
  api_version: string;
  has_api_key: boolean;
  providers: { id: string; label: string; description: string }[];
}

/* ─── Copy Button Component ─── */
function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      className="flex items-center gap-1 text-slate-400 hover:text-white transition-colors"
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      <span>{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

/* ─── Markdown Renderer (react-markdown + remark-gfm) ─── */
function MarkdownContent({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        /* ── Headings ── */
        h1: ({ children }) => <h1 className="text-xl font-bold mt-4 mb-2 text-slate-800 dark:text-slate-100">{children}</h1>,
        h2: ({ children }) => <h2 className="text-lg font-semibold mt-4 mb-1.5 text-slate-800 dark:text-slate-100">{children}</h2>,
        h3: ({ children }) => <h3 className="text-base font-semibold mt-3 mb-1 text-slate-800 dark:text-slate-100">{children}</h3>,
        h4: ({ children }) => <h4 className="text-sm font-semibold mt-2 mb-1 text-slate-800 dark:text-slate-100">{children}</h4>,

        /* ── Paragraphs — tight spacing ── */
        p: ({ children }) => <p className="mb-2 last:mb-0 leading-relaxed">{children}</p>,

        /* ── Bold / Italic / Underline ── */
        strong: ({ children }) => <strong className="font-semibold text-slate-900 dark:text-white">{children}</strong>,
        em: ({ children }) => <em className="italic">{children}</em>,

        /* ── Lists ── */
        ul: ({ children }) => <ul className="list-disc ml-5 mb-2 space-y-0.5">{children}</ul>,
        ol: ({ children }) => <ol className="list-decimal ml-5 mb-2 space-y-0.5">{children}</ol>,
        li: ({ children }) => <li className="text-slate-700 dark:text-slate-200 leading-relaxed">{children}</li>,

        /* ── Blockquote ── */
        blockquote: ({ children }) => (
          <blockquote className="border-l-3 border-orange-400 pl-3 my-2 text-slate-600 dark:text-slate-300 italic bg-orange-50/50 dark:bg-orange-900/10 py-1.5 rounded-r-lg">
            {children}
          </blockquote>
        ),

        /* ── Horizontal rule ── */
        hr: () => <hr className="my-3 border-slate-200 dark:border-slate-700" />,

        /* ── Inline code ── */
        code: ({ className, children, ...props }) => {
          const isBlock = className?.includes("language-");
          if (isBlock) {
            const lang = className?.replace("language-", "") || "code";
            const codeStr = String(children).replace(/\n$/, "");
            return (
              <div className="my-3 rounded-xl overflow-hidden">
                <div className="bg-slate-800 px-4 py-2 text-xs text-slate-400 flex items-center justify-between">
                  <span>{lang}</span>
                  <CopyBtn text={codeStr} />
                </div>
                <pre className="bg-slate-900 px-4 py-3 overflow-x-auto text-sm">
                  <code className="text-slate-100 font-mono">{codeStr}</code>
                </pre>
              </div>
            );
          }
          return (
            <code className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-sm font-mono text-orange-700 dark:text-orange-300">
              {children}
            </code>
          );
        },

        /* ── Code blocks (pre) ── */
        pre: ({ children }) => <>{children}</>,

        /* ── Tables — proper styled HTML tables ── */
        table: ({ children }) => (
          <div className="my-3 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
            <table className="min-w-full text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => (
          <thead className="bg-slate-100 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">{children}</thead>
        ),
        tbody: ({ children }) => <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>,
        tr: ({ children }) => <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">{children}</tr>,
        th: ({ children }) => (
          <th className="px-3 py-2 text-left text-xs font-semibold text-slate-600 dark:text-slate-300 uppercase tracking-wider whitespace-nowrap">
            {children}
          </th>
        ),
        td: ({ children }) => <td className="px-3 py-2 text-slate-700 dark:text-slate-200 whitespace-normal">{children}</td>,

        /* ── Links ── */
        a: ({ href, children }) => (
          <a href={href} target="_blank" rel="noopener noreferrer" className="text-orange-600 dark:text-orange-400 hover:underline font-medium">
            {children}
          </a>
        ),
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

/* ─── Time helpers ─── */
function relativeTime(dateStr: string) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return mins + "m ago";
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + "h ago";
  const days = Math.floor(hrs / 24);
  if (days === 1) return "Yesterday";
  if (days < 7) return days + "d ago";
  return new Date(dateStr).toLocaleDateString();
}

function groupConversations(convos: Conversation[]) {
  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const yesterdayStart = todayStart - 86400000;
  const weekStart = todayStart - 7 * 86400000;
  const groups: { label: string; items: Conversation[] }[] = [
    { label: "Today", items: [] },
    { label: "Yesterday", items: [] },
    { label: "Previous 7 Days", items: [] },
    { label: "Older", items: [] },
  ];
  for (const c of convos) {
    const t = new Date(c.updated_at).getTime();
    if (t >= todayStart) groups[0].items.push(c);
    else if (t >= yesterdayStart) groups[1].items.push(c);
    else if (t >= weekStart) groups[2].items.push(c);
    else groups[3].items.push(c);
  }
  return groups.filter((g) => g.items.length > 0);
}

/* ─── Suggestion Cards ─── */
const SUGGESTIONS = [
  { icon: ScanSearch, title: "Triage critical findings", prompt: "Triage my critical and high severity findings and prioritize them by risk." },
  { icon: Shield, title: "Analyze security posture", prompt: "Analyze my overall security posture and identify the biggest risk areas." },
  { icon: FileBarChart, title: "Review recent scans", prompt: "Review my most recent scan results and summarize key issues found." },
  { icon: ClipboardCheck, title: "Check compliance status", prompt: "Check my compliance status across all frameworks and highlight gaps." },
];

interface ProviderField {
  key: string;
  label: string;
  type: "text" | "password" | "url";
  placeholder: string;
  required: boolean;
  helpText?: string;
}

interface ProviderDef {
  id: string;
  label: string;
  fields: ProviderField[];
}

const PROVIDERS: ProviderDef[] = [
  {
    id: "mock", label: "Built-in (Demo)",
    fields: [],
  },
  {
    id: "openai", label: "OpenAI",
    fields: [
      { key: "api_key", label: "API Key", type: "password", placeholder: "sk-...", required: true },
      { key: "model", label: "Model", type: "text", placeholder: "gpt-4o, gpt-4o-mini", required: true },
      { key: "base_url", label: "Custom Base URL", type: "url", placeholder: "https://api.openai.com/v1", required: false, helpText: "Leave blank for default OpenAI endpoint" },
    ],
  },
  {
    id: "azure_foundry", label: "Azure AI Foundry",
    fields: [
      { key: "api_key", label: "API Key", type: "password", placeholder: "your-azure-api-key", required: true },
      { key: "model", label: "Deployment Name", type: "text", placeholder: "gpt-4.1 or claude-opus-4-5", required: true, helpText: "Deployment name from Azure AI Foundry" },
      { key: "base_url", label: "Endpoint URL", type: "url", placeholder: "https://<resource>.services.ai.azure.com/anthropic", required: true, helpText: "GPT: https://<resource>.cognitiveservices.azure.com — Claude: https://<resource>.services.ai.azure.com/anthropic" },
      { key: "api_version", label: "API Version", type: "text", placeholder: "2024-12-01-preview", required: false, helpText: "Azure API version (GPT only, ignored for Claude)" },
    ],
  },
  {
    id: "anthropic", label: "Anthropic (Claude)",
    fields: [
      { key: "api_key", label: "API Key", type: "password", placeholder: "sk-ant-...", required: true },
      { key: "model", label: "Model", type: "text", placeholder: "claude-3-5-sonnet-latest", required: true },
    ],
  },
  {
    id: "ollama", label: "Ollama (Self-hosted)",
    fields: [
      { key: "base_url", label: "Ollama Server URL", type: "url", placeholder: "http://localhost:11434/v1", required: true, helpText: "URL of your local Ollama instance" },
      { key: "model", label: "Model", type: "text", placeholder: "llama3.1, mistral, codellama", required: true },
    ],
  },
];

/* ════════════════════════════════════════════════ */
/*                   MAIN PAGE                      */
/* ════════════════════════════════════════════════ */
export default function AgentChatPage() {
  const qc = useQueryClient();

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeConvoId, setActiveConvoId] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [inputValue, setInputValue] = useState("");
  const [attachments, setAttachments] = useState<ChatFile[]>([]);
  const [uploading, setUploading] = useState(0);
  const [attachError, setAttachError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback(async (picked: FileList | File[] | null) => {
    const files = Array.from(picked || []);
    if (!files.length) return;
    setAttachError("");
    for (const file of files) {
      setUploading((n) => n + 1);
      try {
        const saved = await uploadChatFile(file);
        setAttachments((prev) => (prev.length >= 5 ? prev : [...prev, saved]));
      } catch (err) {
        const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
        setAttachError(`${file.name}: ${typeof detail === "string" ? detail : "could not be uploaded."}`);
      } finally {
        setUploading((n) => n - 1);
      }
    }
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);
  const [showConfig, setShowConfig] = useState(false);
  const [pendingMessages, setPendingMessages] = useState<Message[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [activeRouting, setActiveRouting] = useState<StreamRouting | null>(null);
  const [activeTools, setActiveTools] = useState<{ tool: string; status: "running" | "done"; preview?: string; step: number }[]>([]);
  const [agentActivity, setAgentActivity] = useState<Array<{id: string; name: string; status: string; tool?: string; findings?: number}>>([]);
  const [executionPlan, setExecutionPlan] = useState<PlanStep[]>([]);
  // The assistant message the plan and handoffs belong to; they are drawn above that message only.
  const [orchestrationMsgId, setOrchestrationMsgId] = useState<number | null>(null);
  const [thinkingStream, setThinkingStream] = useState<Array<{agentId: string; agentName: string; content: string; timestamp: number}>>([]);
  const [handoffs, setHandoffs] = useState<AgentHandoff[]>([]);
  const [orchestrationMode, setOrchestrationMode] = useState<"idle" | "single" | "supervised">("idle");
  const [showAgentPanel, setShowAgentPanel] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<{ id: number; title: string } | null>(null);
  const [renamingConvoId, setRenamingConvoId] = useState<number | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  /* ── Config check ── */
  const { data: agentConfig } = useQuery<{ provider: string; model: string; has_api_key: boolean; providers?: { id: string; label: string }[] }>({
    queryKey: ["agent-config"],
    queryFn: getAgentConfig,
  });

  const isConfigured = agentConfig
    ? agentConfig.provider === "mock" || agentConfig.provider === "ollama" || agentConfig.has_api_key
    : false;
  const [showModelPicker, setShowModelPicker] = useState(false);

  /* ── Queries ── */
  const { data: conversations = [] } = useQuery<Conversation[]>({
    queryKey: ["conversations"],
    queryFn: getConversations,
    refetchInterval: 30000,
  });

  const { data: activeConvo, isLoading: convoLoading } = useQuery<{
    id: number;
    title: string;
    messages: Message[];
  }>({
    queryKey: ["conversation", activeConvoId],
    queryFn: () => getConversation(activeConvoId!),
    enabled: !!activeConvoId,
  });

  /* ── Streaming state ── */
  const streamAbortRef = useRef<AbortController | null>(null);
  const streamingMsgIdRef = useRef<number>(0);
  const sendLockRef = useRef(false); // synchronous guard against double-sends
  const deferredConvoIdRef = useRef<number | null>(null); // defer setActiveConvoId until streaming ends

  const startStreamingChat = useCallback(
    (msg: string, convoId: number | null, attachmentIds: number[] = []) => {
      const tempId = Date.now() + 1;
      let assistantMsgId = tempId;
      streamingMsgIdRef.current = assistantMsgId;
      hasFirstTokenRef.current = false;
      setActiveRouting(null);
      setActiveTools([]);
      setPendingMessages((prev) => [
        ...prev,
        { id: tempId, role: "assistant", content: "", created_at: new Date().toISOString() },
      ]);

      const controller = streamChat(
        { message: msg, conversation_id: convoId ?? undefined, attachment_ids: attachmentIds },
        {
          onToken: (token) => {
            if (!hasFirstTokenRef.current) {
              hasFirstTokenRef.current = true;
              forceIndicatorUpdate((v) => v + 1); // trigger re-render to hide loading dots
            }
            setPendingMessages((prev) =>
              prev.map((m) =>
                m.id === assistantMsgId ? { ...m, content: m.content + token } : m,
              ),
            );
          },
          onDone: (meta) => {
            setIsStreaming(false);
            sendLockRef.current = false;
            setActiveRouting(null);
            setActiveTools([]);
            streamAbortRef.current = null;
            // Clear pending FIRST — before setting convoId which triggers DB refetch
            setPendingMessages([]);
            // NOW apply the deferred conversation ID — DB refetch will load final content
            const finalConvoId = deferredConvoIdRef.current || convoId || meta.conversation_id;
            deferredConvoIdRef.current = null;
            if (finalConvoId) {
              setActiveConvoId(finalConvoId);
            }
            qc.invalidateQueries({ queryKey: ["conversations"] });
            qc.invalidateQueries({ queryKey: ["conversation", finalConvoId] });
          },
          onError: () => {
            setIsStreaming(false);
            sendLockRef.current = false;
            setActiveRouting(null);
            setActiveTools([]);
            streamAbortRef.current = null;
            // Apply deferred convo ID on error too
            const errorConvoId = deferredConvoIdRef.current;
            deferredConvoIdRef.current = null;
            if (errorConvoId) setActiveConvoId(errorConvoId);
            setPendingMessages((prev) =>
              prev.map((m) =>
                m.id === assistantMsgId
                  ? { ...m, content: m.content || "Sorry, I encountered an error processing your request. Please try again." }
                  : m,
              ),
            );
          },
          onRouting: (routing) => {
            setActiveRouting(routing);
          },
          onToolStart: (event) => {
            setActiveTools((prev) => [...prev, { tool: event.tool, status: "running", step: event.step }]);
          },
          onToolResult: (event) => {
            setActiveTools((prev) =>
              prev.map((t) =>
                t.tool === event.tool && t.step === event.step
                  ? { ...t, status: "done" as const, preview: event.preview }
                  : t,
              ),
            );
          },
          onPlan: (parsed) => {
            setExecutionPlan(parsePlanSteps(parsed.steps));
            setOrchestrationMode("supervised");
          },
          onAgentSpawn: (parsed) => {
            setExecutionPlan(prev => applyStepState(prev, {step: parsed.step, agentId: parsed.agent_id ?? parsed.agent}, "running"));
            setAgentActivity(prev => [...prev, {id: parsed.agent_id as string || parsed.agent as string, name: parsed.agent_name as string || parsed.agent as string, status: "thinking"}]);
            setShowAgentPanel(true);
          },
          onAgentThinking: (parsed) => {
            setThinkingStream(prev => [...prev, {agentId: parsed.agent_id as string || parsed.agent as string, agentName: parsed.agent_name as string || parsed.agent as string, content: (parsed.content as string) || (parsed.reasoning as string) || "", timestamp: Date.now()}]);
          },
          onAgentTool: (parsed) => {
            setAgentActivity(prev => prev.map(a => a.id === (parsed.agent_id as string || parsed.agent as string) ? {...a, status: "tool_calling", tool: parsed.tool as string} : a));
          },
          onAgentComplete: (parsed) => {
            setAgentActivity(prev => prev.map(a => a.id === (parsed.agent_id as string || parsed.agent as string) ? {...a, status: "complete"} : a));
            setExecutionPlan(prev => applyStepState(prev, {step: parsed.step, agentId: parsed.agent_id ?? parsed.agent}, parsed.success === false ? "failed" : "done"));
          },
          onAgentHandoff: (parsed) => {
            const handoff = parseHandoff(parsed);
            if (handoff) setHandoffs(prev => [...prev, handoff]);
          },
          onProgress: () => {
            // Update progress display
          },
          onMessageId: (realMsgId: number, conversationId: number, userMessageId?: number) => {
            const oldId = assistantMsgId;
            assistantMsgId = realMsgId;
            streamingMsgIdRef.current = realMsgId;
            setOrchestrationMsgId(realMsgId);
            setPendingMessages((prev) =>
              prev.map((m) => {
                if (m.id === oldId) return { ...m, id: realMsgId };
                if (userMessageId && m.role === "user") return { ...m, id: userMessageId };
                return m;
              }),
            );
            // DEFER setActiveConvoId — don't trigger conversation query during streaming
            // (prevents race: DB refetch returns before pending ID remap renders → duplicate)
            if (!convoId && conversationId) {
              deferredConvoIdRef.current = conversationId;
              // Update sidebar only — lightweight, no message data
              qc.invalidateQueries({ queryKey: ["conversations"] });
            }
          },
        },
      );
      streamAbortRef.current = controller;
    },
    [qc],
  );

  const deleteMutation = useMutation({
    mutationFn: deleteConversation,
    onSuccess: (_: unknown, deletedId: number) => {
      qc.invalidateQueries({ queryKey: ["conversations"] });
      if (activeConvoId === deletedId) {
        setActiveConvoId(null);
        setPendingMessages([]);
      }
      setDeleteTarget(null);
    },
  });

  const renameMutation = useMutation({
    mutationFn: ({ id, title }: { id: number; title: string }) => renameConversation(id, title),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conversations"] });
      setRenamingConvoId(null);
    },
  });

  /* ── Track whether first token has arrived (for loading indicator) ── */
  const hasFirstTokenRef = useRef(false);
  const [, forceIndicatorUpdate] = useState(0);

  /* ── All messages: loaded + pending (pending OVERRIDES loaded during streaming) ── */
  const allMessages = useMemo(() => {
    const loaded: Message[] = activeConvo?.messages ?? [];
    if (pendingMessages.length === 0) return loaded;

    // Build a set of pending IDs — during streaming, pending has live-updating content
    const pendingIds = new Set(pendingMessages.map((m) => m.id));

    // Loaded messages that are NOT shadowed by pending (pending takes priority)
    const unshadowedLoaded = loaded.filter((m: Message) => !pendingIds.has(m.id));

    // Combine: unshadowed loaded first, then ALL pending messages
    return [...unshadowedLoaded, ...pendingMessages];
  }, [activeConvo, pendingMessages]);

  /* ── Clear pending once DB has the completed assistant response (NEVER during active streaming) ── */
  useEffect(() => {
    if (isStreaming) return; // Don't clear pending while streaming — pending has live tokens
    if (!activeConvo?.messages || pendingMessages.length === 0) return;
    const loadedIds = new Set(activeConvo.messages.map((m: Message) => m.id));
    const pendingAssistant = pendingMessages.find((m) => m.role === "assistant");
    if (pendingAssistant && loadedIds.has(pendingAssistant.id)) {
      const loadedVersion = activeConvo.messages.find((m: Message) => m.id === pendingAssistant.id);
      if (loadedVersion?.content && loadedVersion.status !== "processing") {
        setPendingMessages([]);
      }
    }
  }, [activeConvo?.messages, pendingMessages, isStreaming]);

  /* ── Reconnect to processing messages after page load / convo switch ── */
  useEffect(() => {
    if (!activeConvo?.messages || isStreaming) return;
    const lastMsg = activeConvo.messages[activeConvo.messages.length - 1];
    if (lastMsg?.role === "assistant" && lastMsg.status === "processing" && lastMsg.id) {
      // Server is still processing — reconnect to the progress stream
      const assistantMsgId = lastMsg.id;
      streamingMsgIdRef.current = assistantMsgId;
      setIsStreaming(true);
      setPendingMessages([
        { id: assistantMsgId, role: "assistant", content: lastMsg.content || "", created_at: lastMsg.created_at, status: "processing" },
      ]);

      const controller = subscribeToProgress(assistantMsgId, {
        onCatchup: (content: string) => {
          // Replace pending content with server's accumulated content (no doubling)
          setPendingMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content } : m,
            ),
          );
        },
        onToken: (token: string) => {
          setPendingMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content: (m.content || "") + token } : m,
            ),
          );
        },
        onDone: (meta: { conversation_id: number }) => {
          setIsStreaming(false);
          streamAbortRef.current = null;
          qc.invalidateQueries({ queryKey: ["conversations"] });
          qc.invalidateQueries({ queryKey: ["conversation", meta.conversation_id || activeConvoId] });
        },
        onError: () => {
          setIsStreaming(false);
          streamAbortRef.current = null;
          qc.invalidateQueries({ queryKey: ["conversation", activeConvoId] });
        },
      });
      streamAbortRef.current = controller;
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeConvo?.id]);

  /* ── Auto-scroll ── */
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [allMessages]);

  /* ── Auto-resize textarea ── */
  const resizeTextarea = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 160) + "px";
  }, []);

  useEffect(() => { resizeTextarea(); }, [inputValue, resizeTextarea]);

  /* ── Send message ── */
  const sendMessage = useCallback(
    (text?: string) => {
      const msg = (text ?? inputValue).trim();
      const files = text === undefined ? attachments : [];
      if ((!msg && !files.length) || isStreaming || uploading > 0) return;
      if (!isConfigured) return;
      // Synchronous ref guard — prevents double-sends from rapid clicks/Enter
      // (React state batching means isStreaming won't update until next render)
      if (sendLockRef.current) return;
      sendLockRef.current = true;
      setPendingMessages((prev) => [
        ...prev,
        { id: Date.now(), role: "user", content: msg, created_at: new Date().toISOString(), files },
      ]);
      setInputValue("");
      setAttachments([]);
      setAttachError("");
      setIsStreaming(true);
      setAgentActivity([]);
      setExecutionPlan([]);
      setThinkingStream([]);
      setHandoffs([]);
      setOrchestrationMsgId(null);
      setOrchestrationMode("idle");
      startStreamingChat(msg, activeConvoId, files.map((f) => f.id));
    },
    [inputValue, isStreaming, activeConvoId, startStreamingChat, agentConfig, attachments, uploading],
  );

  const handleNewChat = useCallback(() => {
    streamAbortRef.current?.abort();
    streamAbortRef.current = null;
    setIsStreaming(false);
    sendLockRef.current = false;
    setActiveConvoId(null);
    setPendingMessages([]);
    setInputValue("");
    textareaRef.current?.focus();
  }, []);

  const handleSelectConvo = useCallback(
    (id: number) => {
      if (id === activeConvoId) return;
      setActiveConvoId(id);
      setPendingMessages([]);
    },
    [activeConvoId]
  );

  const filtered = useMemo(() => {
    if (!searchTerm) return conversations;
    const q = searchTerm.toLowerCase();
    return conversations.filter((c: Conversation) => c.title.toLowerCase().includes(q));
  }, [conversations, searchTerm]);

  const grouped = useMemo(() => groupConversations(filtered), [filtered]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex h-screen bg-slate-50 dark:bg-slate-950" style={{ fontFamily: "Inter, system-ui, sans-serif" }}>
      {/* ════════ Sidebar ════════ */}
      <aside
        className={`${sidebarOpen ? "w-80" : "w-0"} flex-shrink-0 transition-all duration-300 overflow-hidden bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-700 flex flex-col`}
      >
        <div className="flex flex-col h-full w-80">
          {/* Sidebar header with new-chat icon */}
          <div className="h-14 flex items-center justify-between px-4 border-b border-slate-200 dark:border-slate-700 flex-shrink-0">
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Conversations</span>
            <button
              onClick={handleNewChat}
              title="New chat"
              className="h-8 w-8 rounded-lg hover:bg-orange-50 dark:hover:bg-orange-900/20 text-slate-500 hover:text-orange-600 dark:text-slate-400 dark:hover:text-orange-400 flex items-center justify-center transition-colors"
            >
              <SquarePen className="h-4.5 w-4.5" />
            </button>
          </div>

          {/* Search */}
          <div className="px-4 pb-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search conversations…"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full h-10 pl-10 pr-4 rounded-xl border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent placeholder:text-slate-400"
              />
            </div>
          </div>

          {/* Conversation list */}
          <div className="flex-1 overflow-y-auto px-2 space-y-4">
            {grouped.map((group) => (
              <div key={group.label}>
                <p className="px-3 py-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  {group.label}
                </p>
                <div className="space-y-0.5">
                  {group.items.map((c) => (
                    <ConversationItem
                      key={c.id}
                      conversation={c}
                      isActive={c.id === activeConvoId}
                      onSelect={() => handleSelectConvo(c.id)}
                      onDelete={() => setDeleteTarget({ id: c.id, title: c.title || "Untitled" })}
                      isRenaming={renamingConvoId === c.id}
                      onRename={(title) => renameMutation.mutate({ id: c.id, title })}
                      onStartRename={() => setRenamingConvoId(c.id)}
                      onCancelRename={() => setRenamingConvoId(null)}
                    />
                  ))}
                </div>
              </div>
            ))}
            {conversations.length === 0 && (
              <div className="text-center py-12 text-slate-400">
                <MessageSquare className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No conversations yet</p>
              </div>
            )}
          </div>

          {/* Bottom settings */}
          <div className="p-3 border-t border-slate-100 dark:border-slate-700">
            <button
              onClick={() => setShowConfig(true)}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
            >
              <Settings className="h-4 w-4" />
              <span>AI Configuration</span>
            </button>
          </div>
        </div>
      </aside>

      {/* ════════ Main Area ════════ */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-14 flex items-center gap-3 px-4 border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 flex-shrink-0">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 transition-colors"
          >
            {sidebarOpen ? <PanelLeftClose className="h-5 w-5" /> : <PanelLeftOpen className="h-5 w-5" />}
          </button>
          <div className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-orange-600 dark:text-orange-400" />
            <span className="font-semibold text-slate-800 dark:text-slate-100">{activeConvo?.title ?? "AI Security Copilot"}</span>
          </div>
          {isStreaming && (
            <div className="ml-auto flex items-center gap-2 text-sm text-orange-600 dark:text-orange-400">
              <Loader2 className="h-4 w-4 animate-spin" />
              {activeRouting ? `${activeRouting.agent_name} analyzing…` : "Analyzing…"}
            </div>
          )}
        </header>

        {/* Orchestration header — shown when agentic mode is active */}
        {orchestrationMode !== "idle" && (
          <OrchestrationHeader
            mode={orchestrationMode}
            activeAgents={agentActivity.filter(a => a.status === "running").length}
            totalSteps={agentActivity.length}
            completedSteps={agentActivity.filter(a => a.status === "complete").length}
          />
        )}

        {/* Content area with optional agent sidebar */}
        <div className="flex-1 flex min-h-0">
        {/* Message area */}
        <div className="flex-1 overflow-y-auto">
          {!activeConvoId && allMessages.length === 0 ? (
            /* ── Welcome screen ── */
            <div className="flex flex-col items-center justify-center h-full px-6 max-w-3xl mx-auto">
              <div className="relative mb-6">
                <div className="h-20 w-20 rounded-2xl bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center shadow-lg shadow-orange-200 dark:shadow-orange-900/40">
                  <Shield className="h-10 w-10 text-white" />
                </div>
                <div className="absolute -bottom-1 -right-1 h-7 w-7 rounded-full bg-emerald-500 border-[3px] border-white dark:border-slate-950 flex items-center justify-center">
                  <Sparkles className="h-3.5 w-3.5 text-white" />
                </div>
              </div>
              <h1 className="text-2xl font-bold text-slate-800 dark:text-white mb-2">How can I help secure your infrastructure?</h1>
              <p className="text-slate-500 dark:text-slate-400 mb-10 text-center max-w-md">
                I can analyze findings, triage vulnerabilities, review compliance status, and provide security recommendations.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 w-full max-w-xl">
                {SUGGESTIONS.map((s) => (
                  <button
                    key={s.title}
                    onClick={() => sendMessage(s.prompt)}
                    className="flex items-start gap-3 p-4 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 hover:border-orange-300 dark:hover:border-orange-500 hover:shadow-md hover:shadow-orange-50 dark:hover:shadow-orange-900/20 transition-all text-left group"
                  >
                    <div className="h-9 w-9 rounded-xl bg-orange-50 dark:bg-orange-900/30 flex items-center justify-center flex-shrink-0 group-hover:bg-orange-100 dark:group-hover:bg-orange-900/50 transition-colors">
                      <s.icon className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                    </div>
                    <span className="text-sm text-slate-700 dark:text-slate-200 font-medium leading-snug">{s.title}</span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* ── Messages ── */
            <div className="max-w-3xl mx-auto py-6 px-4 space-y-6">
              {convoLoading && (
                <div className="flex justify-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-orange-400" />
                </div>
              )}
              {allMessages.map((msg, idx) => {
                const isLiveAssistant = isStreaming && msg.id === streamingMsgIdRef.current;
                // Plan and handoffs of a multi-agent answer, above the answer they produced.
                // A plan with one step is a single-agent answer: nothing is drawn.
                const orchestration = msg.role === "assistant" && msg.id === orchestrationMsgId && executionPlan.length > 1 ? (
                  <div key={msg.id + "-orchestration"} className="space-y-2">
                    <PlanVisualization steps={executionPlan} complete={!isStreaming} />
                    <HandoffVisualization handoffs={handoffs} complete={!isStreaming} />
                  </div>
                ) : null;
                // Hide empty assistant placeholder — the shimmer indicator covers this state
                if (isLiveAssistant && msg.role === "assistant" && !msg.content) return orchestration;
                const chatMessage = (
                  <ChatMessage
                    key={msg.id + "-" + idx}
                    message={msg}
                    isLive={isLiveAssistant}
                  />
                );
                return orchestration ? [orchestration, chatMessage] : chatMessage;
              })}

              {/* Processing messages: reconnect to progress SSE if assistant message is still processing */}

              {/* ── Streaming Activity Indicator — clean ChatGPT-style ── */}
              {isStreaming && !hasFirstTokenRef.current && (
                <div className="flex gap-3 items-start chat-message-enter">
                  <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center flex-shrink-0">
                    <Sparkles className="h-4 w-4 text-white" />
                  </div>
                  <div className="pt-2">
                    <div className="flex items-center gap-1.5">
                      <span className="typing-dot" />
                      <span className="typing-dot" />
                      <span className="typing-dot" />
                    </div>
                    {activeRouting && (
                      <p className="text-xs text-slate-400 mt-2 animate-pulse">{activeRouting.agent_name}</p>
                    )}
                  </div>
                </div>
              )}
              {/* Agent thinking stream — shown when agents are actively thinking */}
              {thinkingStream.length > 0 && isStreaming && (
                <ThinkingStream thoughts={thinkingStream} isStreaming={isStreaming} />
              )}

              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Agent activity sidebar — shown when agents are active */}
        {showAgentPanel && (
          <AgentActivityPanel
            agents={agentActivity as any}
            isOpen={showAgentPanel}
            onToggle={() => setShowAgentPanel(!showAgentPanel)}
          />
        )}
        </div>{/* end content area flex wrapper */}

        {/* Input area */}
        <div className="flex-shrink-0 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3">
          <div className="max-w-3xl mx-auto">
            {!isConfigured && (
              <div className="flex items-center gap-3 mb-3 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 rounded-xl">
                <Bot className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-200">AI Assistant Not Configured</p>
                  <p className="text-xs text-amber-600 dark:text-amber-400 mt-0.5">Configure an LLM provider to start chatting.</p>
                </div>
                <button
                  onClick={() => setShowConfig(true)}
                  className="px-3 py-1.5 bg-amber-600 text-white text-xs font-medium rounded-lg hover:bg-amber-700 transition-colors"
                >
                  Configure
                </button>
              </div>
            )}
            {(attachments.length > 0 || uploading > 0 || attachError) && (
              <div className="mb-2 flex flex-wrap items-center gap-2">
                {attachments.map((f) => (
                  <span key={f.id} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2.5 py-1 text-xs text-slate-700 dark:text-slate-200">
                    <FileText className="h-3.5 w-3.5 text-orange-500" />
                    <span className="max-w-[220px] truncate">{f.filename}</span>
                    <span className="text-slate-500 dark:text-slate-400">{fileSize(f.size_bytes)}{f.truncated ? " · first part only" : ""}{f.redactions ? ` · ${f.redactions} secret${f.redactions === 1 ? "" : "s"} hidden` : ""}</span>
                    <button
                      onClick={() => setAttachments((prev) => prev.filter((x) => x.id !== f.id))}
                      className="text-slate-400 hover:text-red-500" aria-label={`Remove ${f.filename}`}
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </span>
                ))}
                {uploading > 0 && (
                  <span className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Reading file…
                  </span>
                )}
                {attachError && <span className="text-xs text-red-600 dark:text-red-400">{attachError}</span>}
              </div>
            )}
            <div
              className="relative flex items-end gap-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded-2xl px-4 py-2 focus-within:ring-2 focus-within:ring-orange-500 focus-within:border-transparent transition-shadow"
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); addFiles(e.dataTransfer.files); }}
            >
              <input
                ref={fileInputRef} type="file" multiple hidden accept={CHAT_ATTACHMENT_ACCEPT}
                onChange={(e) => addFiles(e.target.files)}
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={!isConfigured || attachments.length >= 5}
                title="Attach files: PDF, Word, Excel, images, CSV, JSON, text (up to 5, 15 MB each)"
                aria-label="Attach files"
                className="mb-0.5 h-9 w-9 flex-shrink-0 rounded-xl text-slate-500 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-40 flex items-center justify-center transition-colors"
              >
                <Paperclip className="h-4 w-4" />
              </button>
              <textarea
                ref={textareaRef}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your security posture…"
                rows={1}
                className="flex-1 bg-transparent resize-none text-sm text-slate-800 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none py-1.5 max-h-40 leading-relaxed"
              />
              <div className="flex items-center gap-2 pb-0.5">
                {inputValue.length > 0 && (
                  <span className="text-xs text-slate-400 tabular-nums">{inputValue.length}</span>
                )}
                {isStreaming ? (
                  <button
                    onClick={() => {
                      streamAbortRef.current?.abort();
                      streamAbortRef.current = null;
                      setIsStreaming(false);
                      setActiveRouting(null);
                      setActiveTools([]);
                    }}
                    className="h-9 w-9 rounded-xl bg-red-500 hover:bg-red-600 text-white flex items-center justify-center transition-colors flex-shrink-0"
                    title="Stop generating"
                  >
                    <StopCircle className="h-4 w-4" />
                  </button>
                ) : (
                  <button
                    onClick={() => sendMessage()}
                    disabled={(!inputValue.trim() && attachments.length === 0) || uploading > 0 || !isConfigured}
                    className="h-9 w-9 rounded-xl bg-orange-500 hover:bg-orange-600 disabled:bg-slate-300 dark:disabled:bg-slate-600 disabled:cursor-not-allowed text-white flex items-center justify-center transition-colors flex-shrink-0"
                  >
                    <Send className="h-4 w-4" />
                  </button>
                )}
              </div>
            </div>
            {/* Model switcher + hints row */}
            <div className="flex items-center justify-between mt-2 px-1">
              {/* Model pill / switcher */}
              <div className="relative">
                <button
                  onClick={() => setShowModelPicker((p) => !p)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                >
                  <Sparkles className="h-3 w-3 text-orange-500" />
                  {agentConfig?.provider
                    ? (PROVIDERS.find((p) => p.id === agentConfig.provider)?.label ?? agentConfig.provider)
                    : "Not configured"}
                  {agentConfig?.model && (
                    <span className="text-slate-400 dark:text-slate-500 font-normal">/ {agentConfig.model}</span>
                  )}
                  <ChevronDown className="h-3 w-3 text-slate-400" />
                </button>

                {/* Dropdown */}
                {showModelPicker && (
                  <>
                    <div className="fixed inset-0 z-30" onClick={() => setShowModelPicker(false)} />
                    <div className="absolute bottom-full left-0 mb-2 w-64 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-xl z-40 overflow-hidden">
                      <div className="px-3 py-2.5 border-b border-slate-100 dark:border-slate-700">
                        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">AI Provider</p>
                      </div>
                      <div className="py-1 max-h-60 overflow-y-auto">
                        {(agentConfig?.providers ?? PROVIDERS.map((p) => ({ id: p.id, label: p.label }))).filter((p) => p.id !== "mock").map((provider) => (
                          <button
                            key={provider.id}
                            onClick={() => {
                              setShowModelPicker(false);
                              setShowConfig(true);
                            }}
                            className={`w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors ${
                              agentConfig?.provider === provider.id ? "bg-orange-50 dark:bg-orange-900/20" : ""
                            }`}
                          >
                            <div className={`h-2 w-2 rounded-full flex-shrink-0 ${
                              agentConfig?.provider === provider.id ? "bg-emerald-500" : "bg-slate-300 dark:bg-slate-600"
                            }`} />
                            <div className="flex-1 min-w-0">
                              <p className={`text-sm font-medium truncate ${
                                agentConfig?.provider === provider.id
                                  ? "text-orange-700 dark:text-orange-300"
                                  : "text-slate-700 dark:text-slate-200"
                              }`}>{provider.label}</p>
                              {agentConfig?.provider === provider.id && agentConfig.model && (
                                <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">{agentConfig.model}</p>
                              )}
                            </div>
                            {agentConfig?.provider === provider.id && (
                              <Check className="h-4 w-4 text-emerald-500 flex-shrink-0" />
                            )}
                          </button>
                        ))}
                      </div>
                      <div className="px-3 py-2 border-t border-slate-100 dark:border-slate-700">
                        <button
                          onClick={() => { setShowModelPicker(false); setShowConfig(true); }}
                          className="w-full flex items-center gap-2 px-2 py-1.5 text-xs font-medium text-orange-600 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-900/20 rounded-lg transition-colors"
                        >
                          <Settings className="h-3.5 w-3.5" />
                          Configure Providers
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>

              {/* Keyboard hints */}
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                <kbd className="px-1 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-[10px] font-mono border border-slate-200 dark:border-slate-600 dark:text-slate-300">Enter</kbd> send · <kbd className="px-1 py-0.5 bg-slate-100 dark:bg-slate-800 rounded text-[10px] font-mono border border-slate-200 dark:border-slate-600 dark:text-slate-300">Shift+Enter</kbd> newline
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* ════════ Config Panel ════════ */}
      {showConfig && <ConfigPanel onClose={() => setShowConfig(false)} />}

      {/* ════════ Delete Confirmation Modal ════════ */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center modal-backdrop" onClick={() => setDeleteTarget(null)}>
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
          <div className="relative modal-content bg-white dark:bg-slate-800 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 p-6 max-w-sm w-full mx-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="h-10 w-10 rounded-xl bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                <Trash2 className="h-5 w-5 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-800 dark:text-white">Delete conversation</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">This action cannot be undone.</p>
              </div>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300 mb-6 bg-slate-50 dark:bg-slate-900 rounded-lg px-3 py-2 truncate">
              &ldquo;{deleteTarget.title}&rdquo;
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setDeleteTarget(null)} className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-xl hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors">
                Cancel
              </button>
              <button onClick={() => deleteMutation.mutate(deleteTarget.id)} className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-xl hover:bg-red-700 transition-colors">
                {deleteMutation.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Conversation sidebar item ─── */
function ConversationItem({
  conversation,
  isActive,
  onSelect,
  onDelete,
  isRenaming,
  onRename,
  onStartRename,
  onCancelRename,
}: {
  conversation: Conversation;
  isActive: boolean;
  onSelect: () => void;
  onDelete: () => void;
  isRenaming?: boolean;
  onRename?: (title: string) => void;
  onStartRename?: () => void;
  onCancelRename?: () => void;
}) {
  const [hovering, setHovering] = useState(false);
  const [renameValue, setRenameValue] = useState(conversation.title || "");
  const renameInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isRenaming) {
      setRenameValue(conversation.title || "");
      setTimeout(() => renameInputRef.current?.focus(), 50);
    }
  }, [isRenaming, conversation.title]);

  const handleRenameSubmit = () => {
    const trimmed = renameValue.trim();
    if (trimmed && trimmed !== conversation.title) {
      onRename?.(trimmed);
    } else {
      onCancelRename?.();
    }
  };

  return (
    <div
      onClick={isRenaming ? undefined : onSelect}
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
      className={`group flex items-center gap-2 px-3 py-2.5 rounded-xl cursor-pointer transition-colors ${
        isActive ? "bg-orange-50 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300" : "text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
      }`}
    >
      <MessageSquare className={`h-4 w-4 flex-shrink-0 ${isActive ? "text-orange-500" : "text-slate-400"}`} />
      <div className="flex-1 min-w-0">
        {isRenaming ? (
          <div className="flex items-center gap-1 w-full">
            <input
              ref={renameInputRef}
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => {
                e.stopPropagation();
                if (e.key === "Enter") { e.preventDefault(); handleRenameSubmit(); }
                if (e.key === "Escape") { e.preventDefault(); onCancelRename?.(); }
              }}
              className="flex-1 min-w-0 text-sm font-medium bg-white dark:bg-slate-700 border border-orange-400 rounded-lg px-2 py-0.5 focus:outline-none focus:ring-1 focus:ring-orange-500 text-slate-800 dark:text-slate-100"
              onClick={(e) => e.stopPropagation()}
            />
            <button
              onClick={(e) => { e.stopPropagation(); handleRenameSubmit(); }}
              className="p-1 rounded-md text-green-500 hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors flex-shrink-0"
              title="Save"
            >
              <Check className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); onCancelRename?.(); }}
              className="p-1 rounded-md text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors flex-shrink-0"
              title="Cancel"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <p className="text-sm font-medium truncate">{conversation.title || "Untitled"}</p>
        )}
        <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
          <span>{relativeTime(conversation.updated_at)}</span>
          <span className="inline-flex items-center gap-0.5">
            <MessageSquare className="h-3 w-3" />
            {conversation.message_count}
          </span>
        </p>
      </div>
      {hovering && !isRenaming && (
        <div className="flex items-center gap-0.5 flex-shrink-0">
          <button
            onClick={(e) => { e.stopPropagation(); onStartRename?.(); }}
            className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700 hover:text-orange-500 transition-colors"
            title="Rename conversation"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onDelete(); }}
            className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700 hover:text-red-500 transition-colors"
            title="Delete conversation"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

/* ─── Single chat message ─── */
/* ─── Typewriter hook: reveals content character-by-character while streaming ─── */
function useTypewriter(fullText: string, isLive: boolean, speed = 12) {
  const posRef = useRef(0);
  const wasLiveRef = useRef(false);
  const [displayed, setDisplayed] = useState("");

  useEffect(() => {
    if (!isLive) {
      // Not streaming — show everything instantly (loaded/completed messages)
      posRef.current = fullText.length;
      setDisplayed(fullText);
      wasLiveRef.current = false;
      return;
    }

    // Transition to live: reset position to 0 if just became live
    if (!wasLiveRef.current) {
      posRef.current = 0;
      setDisplayed("");
      wasLiveRef.current = true;
    }

    // Already caught up — show what we have and wait for more tokens
    if (posRef.current >= fullText.length) {
      setDisplayed(fullText);
      return;
    }

    // Reveal chars progressively for smooth typing feel
    const charsPerTick = 3;
    const timer = setInterval(() => {
      posRef.current = Math.min(posRef.current + charsPerTick, fullText.length);
      setDisplayed(fullText.slice(0, posRef.current));
      if (posRef.current >= fullText.length) clearInterval(timer);
    }, speed);

    return () => clearInterval(timer);
  }, [fullText, isLive, speed]);

  return displayed;
}

function ChatMessage({ message, isLive }: { message: Message; isLive?: boolean }) {
  const isUser = message.role === "user";
  const [showTime, setShowTime] = useState(false);
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const displayedContent = useTypewriter(message.content || "", !!isLive);
  const uploads = (message.files || []).filter((f) => f.kind === "upload");
  const downloads = (message.files || []).filter((f) => f.kind === "generated");

  const save = async (job: () => Promise<void>) => {
    setSaving(true);
    try { await job(); } finally { setSaving(false); }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`flex gap-3 ${isUser ? "justify-end" : "justify-start"}`}
      onMouseEnter={() => setShowTime(true)}
      onMouseLeave={() => setShowTime(false)}
    >
      {!isUser && (
        <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center flex-shrink-0 mt-0.5">
          <Bot className="h-4 w-4 text-white" />
        </div>
      )}
      <div className={`max-w-[80%] relative ${isUser ? "order-first" : ""}`}>
        <div
          className={`px-5 py-3.5 text-sm leading-relaxed ${
            isUser
              ? "bg-orange-500 text-white rounded-2xl rounded-br-sm"
              : "bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-100 rounded-2xl rounded-bl-sm"
          }`}
        >
          {isUser ? (
            <>
              {uploads.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {uploads.map((f) => (
                    <span key={f.id} className="inline-flex items-center gap-1.5 rounded-lg bg-white/20 px-2 py-1 text-xs">
                      <FileText className="h-3.5 w-3.5" />
                      <span className="max-w-[220px] truncate">{f.filename}</span>
                    </span>
                  ))}
                </div>
              )}
              {message.content && <p className="whitespace-pre-wrap">{message.content}</p>}
            </>
          ) : (
            <>
              {displayedContent ? <MarkdownContent content={displayedContent} /> : null}
              {isLive && <span className="typewriter-cursor" />}
              {downloads.map((f) => (
                <button
                  key={f.id}
                  onClick={() => save(() => downloadChatFile(f))}
                  className="mt-3 flex w-full max-w-sm items-center gap-3 rounded-xl border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2.5 text-left hover:border-orange-400 transition-colors"
                >
                  <span className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-red-50 dark:bg-red-900/30">
                    <FileText className="h-4 w-4 text-red-600 dark:text-red-400" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-slate-900 dark:text-slate-100">{f.filename}</span>
                    <span className="block text-xs text-slate-600 dark:text-slate-300">PDF · {fileSize(f.size_bytes)}</span>
                  </span>
                  <Download className="h-4 w-4 text-slate-500 dark:text-slate-300" />
                </button>
              ))}
            </>
          )}
        </div>
        <div
          className={`flex items-center gap-2 mt-1 ${isUser ? "justify-end" : "justify-start"} ${
            showTime ? "opacity-100" : "opacity-0"
          } transition-opacity`}
        >
          <span className="text-xs text-slate-400">
            {new Date(message.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </span>
          {!isUser && (
            <button onClick={handleCopy} className="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1 transition-colors">
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          )}
          {!isUser && !isLive && message.id < 1e12 && (
            <button
              onClick={() => save(() => downloadMessageAsPdf(message.id))}
              disabled={saving}
              className="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1 transition-colors"
            >
              {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
              PDF
            </button>
          )}
        </div>
      </div>
      {isUser && (
        <div className="h-8 w-8 rounded-xl bg-slate-700 flex items-center justify-center flex-shrink-0 mt-0.5">
          <span className="text-xs font-semibold text-white">U</span>
        </div>
      )}
    </div>
  );
}

/* ─── Config Panel (slide-out from right) ─── */
function ConfigPanel({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: config } = useQuery<AgentConfig>({
    queryKey: ["agent-config"],
    queryFn: getAgentConfig,
  });

  const [formProvider, setFormProvider] = useState("openai");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});

  const selectedProvider = PROVIDERS.find((p) => p.id === formProvider) ?? PROVIDERS[0];

  useEffect(() => {
    if (config) {
      setFormProvider(config.provider || "openai");
      setFieldValues({
        model: config.model || "",
        base_url: config.base_url || "",
        api_version: config.api_version || "",
      });
    }
  }, [config]);

  const handleProviderChange = (newProvider: string) => {
    setFormProvider(newProvider);
    setFieldValues({});
  };

  const saveMutation = useMutation({
    mutationFn: (body: Record<string, string>) => updateAgentConfig(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-config"] });
      setTestResult({ success: true, message: "Configuration saved successfully." });
    },
  });

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const body: Record<string, string> = { provider: formProvider };
      for (const field of selectedProvider.fields) {
        const val = fieldValues[field.key];
        if (val) body[field.key] = val;
      }
      const result = await testAgentConfig(body);
      setTestResult({
        success: result.ok ?? result.success ?? false,
        message: result.ok
          ? `Connected successfully${result.latency_ms ? ` (${result.latency_ms}ms)` : ""}`
          : result.error || "Connection test failed.",
      });
    } catch {
      setTestResult({ success: false, message: "Connection test failed." });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = () => {
    const body: Record<string, string> = { provider: formProvider };
    for (const field of selectedProvider.fields) {
      const val = fieldValues[field.key];
      if (val) body[field.key] = val;
    }
    saveMutation.mutate(body);
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-40" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 w-full max-w-md bg-white dark:bg-slate-900 shadow-2xl z-50 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-slate-200 dark:border-slate-700">
          <div>
            <h2 className="text-lg font-semibold text-slate-800 dark:text-white">AI Configuration</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">Configure your AI provider and model</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-5">
          {/* Provider */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">Provider</label>
            <div className="relative">
              <select
                value={formProvider}
                onChange={(e) => handleProviderChange(e.target.value)}
                className="w-full h-12 rounded-xl border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-100 px-4 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent appearance-none"
              >
                {PROVIDERS.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
            </div>
          </div>

          {/* Dynamic provider fields */}
          {selectedProvider.fields.map((field) => (
            <div key={field.key}>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {field.label}
                {field.required && <span className="text-red-400 ml-0.5">*</span>}
                {field.key === "api_key" && config?.has_api_key && (
                  <span className="ml-2 text-xs text-emerald-600 dark:text-emerald-400 font-normal">● Key is set</span>
                )}
              </label>
              {field.helpText && (
                <p className="text-xs text-slate-400 mb-1.5">{field.helpText}</p>
              )}
              <div className="relative">
                <input
                  type={field.type === "password" ? (showKey ? "text" : "password") : field.type}
                  value={fieldValues[field.key] || ""}
                  onChange={(e) => setFieldValues((v) => ({ ...v, [field.key]: e.target.value }))}
                  placeholder={field.key === "api_key" && config?.has_api_key ? "••••••••••••••••" : field.placeholder}
                  className={`w-full h-12 rounded-xl border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-100 px-4 ${field.type === "password" ? "pr-12 font-mono" : ""} text-sm focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent placeholder:text-slate-400`}
                />
                {field.type === "password" && (
                  <button type="button" onClick={() => setShowKey(!showKey)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors">
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Test result */}
          {testResult && (
            <div className={`flex items-start gap-3 p-4 rounded-xl ${testResult.success ? "bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-700" : "bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700"}`}>
              {testResult.success ? <Check className="h-5 w-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0 mt-0.5" /> : <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />}
              <p className={`text-sm ${testResult.success ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>{testResult.message}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex items-center gap-3">
          <button
            onClick={handleTest}
            disabled={isTesting}
            className="flex-1 h-12 rounded-xl border border-slate-200 dark:border-slate-600 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
          >
            {isTesting ? <><Loader2 className="h-4 w-4 animate-spin" />Testing…</> : "Test Connection"}
          </button>
          <button
            onClick={handleSave}
            disabled={saveMutation.isPending}
            className="flex-1 h-12 rounded-xl bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
          >
            {saveMutation.isPending ? <><Loader2 className="h-4 w-4 animate-spin" />Saving…</> : "Save Configuration"}
          </button>
        </div>
      </div>
    </>
  );
}
