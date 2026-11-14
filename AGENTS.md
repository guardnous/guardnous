# GuardNous — Agent Architecture

> **Version:** 2.0 · **Status:** Production · **License:** Apache 2.0

## Overview

GuardNous uses an **agentic AI architecture** where a central orchestrator routes user queries through specialized security skills to deliver data-driven, actionable insights.

```
┌─────────────────────────────────────────────────────────────┐
│                     FRONTEND (Next.js)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Copilot Chat  │  │ Triage Panel │  │  Dashboard / API  │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────────────┘  │
│         │                 │                                   │
│         └────────┬────────┘                                   │
└──────────────────┼───────────────────────────────────────────┘
                   │ SSE / REST
┌──────────────────┼───────────────────────────────────────────┐
│                  ▼          BACKEND (FastAPI)                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                    ORCHESTRATOR                         │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │  │
│  │  │  Intent   │  │  Context  │  │   Prompt Builder     │ │  │
│  │  │  Detect   │  │  Builder  │  │   (PROMPTS.md)       │ │  │
│  │  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘ │  │
│  │       │              │                    │             │  │
│  │       ▼              ▼                    ▼             │  │
│  │  ┌──────────────────────────────────────────────┐      │  │
│  │  │              LLM PROVIDER                     │      │  │
│  │  │  OpenAI │ Azure OpenAI │ Ollama │ Mock Demo   │      │  │
│  │  └────────────────────┬─────────────────────────┘      │  │
│  │                       │                                 │  │
│  │                       ▼ tool_calls                      │  │
│  │  ┌──────────────────────────────────────────────┐      │  │
│  │  │           SKILL EXECUTION ENGINE              │      │  │
│  │  │                                               │      │  │
│  │  │  ┌─────────────┐  ┌───────────────────────┐  │      │  │
│  │  │  │ Core Tools   │  │ Advanced Skills       │  │      │  │
│  │  │  │ list_findings │  │ check_compliance      │  │      │  │
│  │  │  │ get_finding   │  │ analyze_attack_surface│  │      │  │
│  │  │  │ risk_score    │  │ posture_trend         │  │      │  │
│  │  │  │ search_cves   │  │ remediation_guide     │  │      │  │
│  │  │  │ recent_scans  │  │                       │  │      │  │
│  │  │  │ severity_brkdn│  │                       │  │      │  │
│  │  │  └─────────────┘  └───────────────────────┘  │      │  │
│  │  └──────────────────────────────────────────────┘      │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
│  │ PostgreSQL│  │  Redis   │  │  Celery  │  │ Risk Scorer  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

## Agent Execution Model

### Dual-Mode Architecture

GuardNous operates in two modes, both providing **genuine agentic behavior**:

| Mode | LLM Provider | Skill Execution | Use Case |
|------|-------------|-----------------|----------|
| **Live** | OpenAI, Azure OpenAI, Ollama | LLM-driven tool-calling loop | Production with API keys |
| **Mock/Demo** | Built-in heuristic engine | Direct skill dispatch (real functions) | Demo, development, air-gapped |

**Critical design principle:** Mock mode is NOT a degraded experience. It invokes the **same skill functions** that live mode uses, producing real data-driven responses. The only difference is intent routing: live mode lets the LLM decide which tools to call; mock mode uses deterministic keyword-based routing.

### Execution Flow

```
User Message
    │
    ├─── Intent Detection (detect_mode)
    │         │
    │         ├── "triage" → list_findings, severity_breakdown
    │         ├── "remediate" → list_findings, get_finding (detail)
    │         ├── "compliance" → check_compliance, severity_breakdown
    │         ├── "attack_surface" → analyze_attack_surface
    │         ├── "compare" → list_recent_scans, posture_trend
    │         └── None (general) → risk_score, severity_breakdown
    │
    ├─── Context Building
    │         │
    │         ├── Live Security Posture (pre-formatted narrative)
    │         ├── System Prompt (role + capabilities + guardrails)
    │         └── Conversation History
    │
    ├─── Skill Dispatch
    │         │
    │         ├── [Live Mode] LLM issues tool_calls → execute_tool() → results fed back
    │         └── [Mock Mode] _mock_skill_dispatch() → execute_tool() → results enriched
    │
    └─── Response Synthesis
              │
              ├── [Live Mode] LLM synthesizes from tool results
              └── [Mock Mode] Template engine formats from real skill data
```

### Tool Trace (Observability)

Every response includes a `tool_trace` array showing which skills were invoked:

```json
{
  "content": "Three critical findings need attention first...",
  "tool_trace": [
    {"tool": "get_severity_breakdown", "arguments": {}},
    {"tool": "list_findings", "arguments": {"severity": "CRITICAL", "limit": 5}}
  ],
  "provider": {"provider": "mock", "model": "mock-heuristic", "supports_tools": false, "live": false}
}
```

The frontend renders tool_trace entries as skill badges, giving users transparency into what the AI agent did to produce its answer.

## Core Components

### 1. Orchestrator (`orchestrator.py`)

The central coordinator. Responsibilities:
- Build LIVE_CONTEXT from real-time org data (risk score, findings, severity)
- Route to greeting path (no tools) or analytical path (skill dispatch)
- Manage the tool-calling loop (live mode) or direct dispatch (mock mode)
- Return structured response with content + tool_trace + provider info

### 2. LLM Client (`llm.py`)

Provider-agnostic LLM interface supporting:
- **OpenAI** — Direct API with function-calling
- **Azure OpenAI** — Enterprise deployment with managed keys
- **Ollama** — Local/self-hosted models
- **Azure AI Foundry** — OpenAI-compatible deployments and Claude deployments
- **Anthropic** — Claude models with native tool calling and token usage reporting
- **Mock** — Zero-dependency demo mode; answers from the same tools with keyword routing

### 3. Skill Engine (`skills.py` + `tools.py`)

72 registered tools with OpenAI function-calling schemas (`GET /api/v1/agents/manifest` lists them all). 67 only read data. Five change something and run only inside an approved agent run: `triage_finding`, `triage_findings`, `open_fix_pull_request`, `send_slack_message`, `remediate_cloud_finding`. Every agent also gets the cloud inventory tools (`cloud_inventory_summary`, `list_cloud_resources`, `get_cloud_resource`, `cloud_posture_summary`, `internet_exposure`); in chat, `export_pdf_report` is added.

A tool with no data behind it returns `data_source: not_connected` and says what to connect. It never invents a result.

Some of the core tools:

| Tool | Category | Description |
|------|----------|-------------|
| `list_findings` | Core | Query findings with severity/category/cloud filters |
| `get_finding` | Core | Full finding detail with code snippets and remediation |
| `get_severity_breakdown` | Core | Counts grouped by CRITICAL/HIGH/MEDIUM/LOW |
| `get_risk_score` | Core | Overall risk score (0-100) with per-cloud breakdown |
| `search_cves` | Core | CVE database search by keyword and severity |
| `list_recent_scans` | Core | Recent scan history with status and risk scores |
| `check_compliance` | Advanced | Map findings to CIS, SOC 2, PCI-DSS, HIPAA, NIST |
| `analyze_attack_surface` | Advanced | External exposure analysis (secrets, IAM, encryption) |
| `get_posture_trend` | Advanced | Risk trajectory over time (improving/worsening) |
| `generate_remediation_guide` | Advanced | Step-by-step fix playbooks with verification |

### 4. Prompt System (`prompts.py` + `PROMPTS.md`)

Multi-layer prompt architecture:
- **Base persona** — the chat assistant "Aegis": identity and conversation rules
- **Answer rules** — `REACT_GROUNDING` (`planner.py`) is appended last: answer only, no reasoning labels, no emoji
- **Mode-specific instructions** — Tailored guidance per conversation mode
- **Capabilities block** — Loaded from SKILLS.md/AGENTS.md for self-awareness
- **LIVE_CONTEXT** — Pre-formatted security posture narrative

## Security Guardrails (`guardrails.py`)

The agent operates under a multi-layer guardrail system with **55 security patterns**:

### Input Guardrails
1. **PII Detection** (11 patterns) — SSN, credit card, phone, email, passport, driver's license, date of birth, bank account, IP address, medical record, biometric identifiers
2. **Prompt Injection Blocking** (25 patterns) — System prompt override, role manipulation, jailbreak phrases, instruction ignoring, encoding attacks, prompt leaking, social engineering

### Output Guardrails
3. **Output Sanitization** (19 patterns) — 9 secret patterns (credentials, API keys, tokens, connection strings) and 10 internal-path patterns

### Operational Guardrails
4. **Chat is read-only** — A tool that changes anything is refused in chat. It runs only inside an agent run, after approval (see "Agent Runs and Approvals")
5. **Org-scoped** — Every query is filtered by `organization_id`; no cross-tenant data access
6. **Rate-limited** — Chat tool-calling loop capped at `AGENT_MAX_STEPS` (default: 6); runs at `AGENT_RUN_MAX_STEPS` (default: 12) with a token budget
7. **Typed text vs. attached files** — Length limits, PII redaction and injection blocking apply to what the user types. Text from attached files is passed as quoted material in a separate turn. Credentials, card numbers and social security numbers in it are replaced on upload (`redact_sensitive`); IP addresses, e-mail addresses and account IDs are kept
8. **RBAC enforcement** — Roles can restrict which agents and tools a user can invoke (`allowed_agents`, `allowed_tools` on Role model); the user's own roles are used

## Agent Runs and Approvals (`runtime.py`)

A run is one agent task executed by a Celery worker. It is stored, survives restarts, and pauses when an action needs a person.

```
POST /agents/runs  →  queued → running ──────────────► completed / failed / cancelled
                                  │        ▲
                 write tool asked │        │ approved: the prepared change is executed
                                  ▼        │ rejected: the model is told, nothing is executed
                          awaiting_approval
```

| Risk class | Example tools | Who may approve |
|------------|---------------|-----------------|
| `read` | everything not listed in `TOOL_RISK` | no approval |
| `internal_write` | `triage_finding` | the requester, or anyone with `agents:manage` |
| `external_write` | `open_fix_pull_request`, `send_slack_message`, `remediate_cloud_finding` | a **different** person with `agents:manage` (`AGENT_ALLOW_SELF_APPROVAL=false`) |

- **Prepare before asking.** The exact change is computed first (for a fix PR: the file and diff; for a cloud fix: the plan from live state) and shown to the approver. If it cannot be prepared, nobody is asked.
- **Execute what was approved.** After approval the stored, prepared arguments are executed, not new model output.
- **Every step is stored** (`agent_steps`): model calls, tool calls, approvals, with duration and token usage.
- **Delegated child runs are read-only.**
- **Recovery.** A periodic sweep fails runs whose worker stopped reporting (`AGENT_RUN_STALE_MINUTES`).

API: `POST/GET /api/v1/agents/runs`, `GET /agents/runs/{id}`, `POST /agents/runs/{id}/cancel`, `GET /agents/approvals`, `POST /agents/approvals/{id}/decision`, `GET /agents/usage`.

## Chat Files and Answer Style

- **Attachments** (`attachments.py`): `POST /agents/chat/files` extracts text from PDF, `.docx`, `.xlsx`, CSV, JSON, text files and images (15 MB, 60,000 characters per file, 5 files per message) and stores only the text, with secrets replaced by a marker. Images and scanned PDFs are read with the local `tesseract` program (installed in the backend image); only the text in a picture is read. The text goes to the model in its own turn, marked as material and not instructions. The newest attachments keep their place in context; older ones drop out first.
- **PDF export** (`pdf_export.py`, `chat_files.py`): the chat-only tool `export_pdf_report` renders Markdown to a PDF attached to the reply. `GET /agents/messages/{id}/pdf` does the same for any answer.
- **Answer style** (`planner.py`): agents work silently and reply with the answer only. No "Thought / Observation" labels, no emoji, no narration of the process. `clean_answer()` removes reasoning labels a model writes before its answer.

## Multi-Agent Delegation Protocol

The orchestrator supports **depth-tracked sub-task delegation** between specialized agents:

```
User Message
    │
    ▼
┌─────────────────────┐
│   Main Orchestrator  │  depth=0
│                      │
│   Delegates to:      │
│   ├── Triage Agent   │  depth=1 (specialized finding analysis)
│   ├── Remediation    │  depth=1 (code fix generation)
│   └── Compliance     │  depth=1 (framework mapping)
└─────────────────────┘
```

- **Max delegation depth:** 3 (configurable) — prevents infinite delegation loops
- **Delegation tool:** `delegate_to_agent` — registered in `tools.py` with agent_id + task parameters
- **Audit:** Every delegation is logged to the agent audit trail

## Agent Audit Trail (`agent_audit.py`)

Every agent execution is persisted to the `agent_audit_entries` table:

| Field | Description |
|-------|-------------|
| `agent_id` | Which agent was invoked |
| `action` | What action was taken |
| `input_data` | User message / task input (JSON) |
| `output_data` | Agent response / result (JSON) |
| `tools_used` | List of tools called during execution |
| `duration_ms` | Execution time in milliseconds |
| `token_usage` | Input/output token counts |
| `success` | Whether execution completed successfully |

API endpoint: `GET /api/v1/agent-audit/recent` — returns recent audit entries for the organization.

## Prompt Registry (`prompt_registry.py`)

13 built-in prompts, used by the background agents and the router:

| Prompt keys | Used by |
|-------------|---------|
| `triage_system`, `triage_agent_system` | Triage of new findings |
| `remediation_explain`, `remediation_agent_system` | Fix explanation and generation |
| `investigation_system`, `investigation_agent_system` | Investigations |
| `compliance_system`, `compliance_advisor_system` | Compliance mapping |
| `security_analyst_system`, `devsecops_coach_system`, `threat_intel_system`, `general_system` | Chat personas |
| `router_classify` | Choosing the agent for a message |

A row in the `prompt_templates` table replaces a built-in prompt for one organization. There is no screen or API for editing them yet.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `mock` | Provider: `openai`, `azure`, `azure_foundry`, `ollama`, `anthropic`, `mock` |
| `AGENT_RUN_MAX_STEPS` | `12` | Model calls an agent run may make before it must conclude |
| `AGENT_ALLOW_SELF_APPROVAL` | `false` | Let a requester approve their own external actions (test installations only) |
| `LLM_MODEL` | `gpt-4o-mini` | Model identifier |
| `LLM_API_KEY` | — | API key (not needed for mock/ollama) |
| `LLM_BASE_URL` | — | Custom endpoint URL |
| `LLM_API_VERSION` | — | Azure API version |
| `LLM_TEMPERATURE` | `0.3` | Response creativity (0.0-1.0) |
| `LLM_MAX_TOKENS` | `2048` | Maximum response length |
| `AGENT_MAX_STEPS` | `6` | Max tool-calling iterations |

### Per-Organization LLM Settings

Organizations can configure their own LLM provider via the Settings page. Per-org settings override environment defaults and are stored in the `llm_configs` table. Changing them needs the `settings:update` permission.

## Extension Points

### Adding a New Skill

1. **Write the executor** in `skills.py`:
   ```python
   async def _my_new_skill(ctx: ToolContext, param1: str = "") -> dict:
       # Query data using ctx.db and ctx.organization_id
       return {"result": "..."}
   ```

2. **Register the schema** in `tools.py`:
   ```python
   TOOL_SCHEMAS.append({
       "type": "function",
       "function": {
           "name": "my_new_skill",
           "description": "What this skill does and when to use it.",
           "parameters": {...}
       }
   })
   ```

3. **Add to the resolver** in `tools.py`:
   ```python
   _SKILL_TOOL_MAP["my_new_skill"] = "_my_new_skill"
   ```

4. **Classify it** in `tools.py`. If the skill changes anything, add it to `TOOL_RISK` (`INTERNAL_WRITE` or `EXTERNAL_WRITE`) and implement its prepare step in `runtime.py`. A tool missing from `TOOL_RISK` is treated as read-only.

5. **Update mock routing** in `orchestrator.py`:
   ```python
   _MODE_TOOL_MAP["relevant_mode"].append(("my_new_skill", {}))
   ```

### Adding a New LLM Provider

Implement the request/response translation in `llm.py`:
1. Add provider name to `_OPENAI_COMPATIBLE` set (if OpenAI-compatible) or create new methods
2. Handle endpoint construction in `_openai_endpoint()`
3. Handle auth headers in `_openai_headers()`

---

*This architecture is designed for enterprise deployment. The dual-mode design ensures the product works in any environment — from air-gapped on-prem installations to cloud-native deployments with managed LLM services.*
