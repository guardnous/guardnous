# GuardNous — Prompts

How the system prompt for an AI agent is put together, and where each part lives.
The code is the source of truth; this file describes it.

## Prompt Architecture

A request to the model is built from these parts, in this order:

| # | Part | Source |
|---|------|--------|
| 1 | Persona and conversation rules | `COPILOT_PERSONA` in `backend/app/services/agents/prompts.py`, or the agent's own prompt from `registry.py` |
| 2 | Short capabilities reference | Selected sections of `AGENTS.md`, `SKILLS.md` and this file, read by `docs_loader.py` |
| 3 | Mode instructions (optional) | `MODE_PROMPTS` in `prompts.py`, chosen by `detect_mode()` from keywords in the message |
| 4 | Example exchanges | `FEW_SHOT_EXAMPLES` in `prompts.py` |
| 5 | Live security context | A summary of the organization's current findings and scans (`context.py`) |
| 6 | Answer rules | `REACT_GROUNDING` in `planner.py`. Added last, and it overrides anything above it |
| 7 | Conversation history and attached files | Earlier turns; attached file text travels as its own turn |

The tools the agent may call are sent separately as tool definitions, not as prompt text.

## Persona

The chat assistant is called **Aegis**. Its persona asks for a calm, direct, technically
exact colleague: short answers to short questions, no list of capabilities, no data
dump on a greeting, specifics (finding IDs, CVEs, resource names, file paths) instead
of general advice.

Each of the 20 agents in `registry.py` has its own system prompt describing its
speciality. The persona above is used by the general chat assistant.

## Modes

`detect_mode()` picks at most one mode from keywords in the user's message. A greeting
selects no mode.

| Mode | When | What it asks for |
|------|------|------------------|
| `triage` | "prioritize", "what should I fix first" | A ranked table, grouped by root cause |
| `explain` | "what is", "why does it matter" | What it is, why it matters, what to do |
| `remediate` | "how do I fix" | Root cause, fix as code, how to verify, how to prevent |
| `compliance` | Framework names | Findings mapped to controls, largest gaps first |
| `compare` | "compare", "since last scan" | New, resolved, change in risk, trend |
| `attack_surface` | "exposed", "attack surface" | Risk-ranked exposure table |
| `autofix` | "fix it", "open a PR" | Preview the fix, then request the change through an approval |
| `auto_triage` | "triage everything" | Set triage status on open findings and summarise |
| `investigation` | Domain keywords (IAM, network, Kubernetes, incident) | Scope, collect, analyse, recommend |

Domain keywords (container, CI/CD, API, DNS, TLS and others) route to the matching
investigation tools.

## Answer rules

`REACT_GROUNDING` is appended to every agent prompt. It tells the model to:

- work silently and write only the answer; no "Thought", "Action", "Observation" labels
  and no description of its own process;
- start with the answer, and match the length to the question;
- use plain words and specific names and numbers from the data;
- use no emoji, and write severity as a word (Critical, High, Medium, Low);
- avoid capitals for emphasis and exclamation marks;
- use a table only for items compared on the same attributes;
- say plainly when something is unknown or was not checked, and never invent data.

`clean_answer()` in `planner.py` then removes any reasoning labels the model wrote anyway.

## What an agent must not do

1. Refer to findings, resources or numbers that the tools did not return.
2. Put secrets in an answer. Output is also filtered by `guardrails.sanitize_output`.
3. Say a change was made before the tool reports that it was. Pull requests, cloud
   changes and Slack messages wait for a second person's approval.
4. Give legal advice or promise that a system is secure.

## Defences against prompt injection

- 25 patterns block typed messages that try to override instructions, change the
  agent's role or extract the system prompt (`guardrails.sanitize_input`).
- Attached files and tool results are data, not instructions. Attached text is sent as
  a separate turn marked as an attachment.
- The tools an agent may call are fixed by `registry.py` and the user's role. Text in
  a finding or a file cannot add tools.
- Actions outside GuardNous need approval from a person other than the one who started
  the run, so an injected instruction cannot complete a change on its own.

## Prompt registry

`backend/app/services/prompt_registry.py` holds 13 built-in prompts used by the
background agents and the router:

`triage_system`, `router_classify`, `remediation_explain`, `investigation_system`,
`compliance_system`, `security_analyst_system`, `compliance_advisor_system`,
`devsecops_coach_system`, `threat_intel_system`, `triage_agent_system`,
`remediation_agent_system`, `investigation_agent_system`, `general_system`

A row in the `prompt_templates` table with the same key replaces the built-in text for
that organization, and versions are kept. There is no screen or API for editing these
yet; rows are added in the database.

## Changing a prompt

1. Edit the text in `prompts.py`, `planner.py`, `registry.py` or `prompt_registry.py`.
2. Keep the answer rules consistent: no emoji, no reasoning labels, no claims of
   actions that need approval.
3. Run `backend/tests/test_chat_files.py` and `backend/tests/test_agent_runtime.py`;
   they check the answer style and the approval flow.
