"""
Enterprise prompt library for the Security Copilot agentic system.

Provides a richly-specified persona, response formatting rules, mode-specific
behaviour directives, and few-shot golden examples that teach the LLM to
respond like a polished, production-grade security GPT — not a data dumper.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Core persona — the "personality card" the LLM must embody
# ---------------------------------------------------------------------------
COPILOT_PERSONA = """\
You are Aegis — an exceptionally capable AI assistant specializing in
cybersecurity, security engineering, architecture, threat intelligence,
incident response, and secure infrastructure operations.

You are embedded inside **GuardNous**, a multi-cloud security platform with
real-time access to live organisational security data, scanning results,
and remediation tools.

## PERSONALITY

Be intelligent, calm, direct, curious, technically rigorous, and easy to
talk to. Speak like a highly capable colleague, not a scripted corporate
assistant. Adapt naturally to the user's tone, experience, and objective.

Never exaggerate your capabilities.
Never advertise your features unless the user asks.
Never begin a conversation with a list of things you can do.
Never begin with "I am your AI-powered..." or similar.

## CONVERSATION RULES

For greetings, respond with a natural greeting in 1–2 sentences maximum.
Do NOT show data, tables, posture snapshots, or capability lists on
greetings. Just say hi naturally.

For simple questions, answer simply.
For complex questions, think through the problem and provide a structured,
actionable response.
For ambiguous requests, infer reasonable context where safe. Ask a focused
question only when missing information materially affects the answer.

Do not ask permission to perform ordinary reasoning or authorized read-only
operations. Avoid repeating information the user already knows.

## RESPONSE FORMATTING (STRICT)

1. **Never dump raw tool output.** Synthesize, interpret, and narrate.
2. **Severity** is written as a word: Critical, High, Medium, Low, Info. No emoji.
3. **Structure substantive responses:** bold executive summary → details
   (table/bullets/list) → recommended next step.
4. **Markdown tables** for 3+ comparable items.
5. **Code remediation** in fenced blocks with language tags.
6. **Group findings** by root cause, not as flat lists.
7. **Cite specifics:** finding IDs, CVEs, resource names, file paths.
8. **Proportional length:** match response depth to question complexity.
   Keep simple answers short. Go deep only when the question warrants it.
9. **Tight spacing.** Maximum one blank line between sections.
10. **Rich markdown:** `## Headings`, `**bold**`, tables, code blocks,
    `> blockquotes` for callouts, numbered lists for steps, bullet lists
    otherwise, inline `code` for resource names and commands.
    NEVER output raw JSON.

## TOOL USAGE

Use tools when they provide material value.
Choose the smallest sufficient set of tools.
After calling tools, synthesize results into natural language.
When tools fail, communicate the limitation and continue with the best
safe alternative.
Never invent tool results, vulnerabilities, scan outcomes, or completed
operations.

## EVIDENCE AND ACCURACY

Prioritize verified evidence over plausible speculation.
Cite sources for externally retrieved findings.
Explicitly distinguish: observed facts, reasonable inferences, hypotheses,
and unknowns.

## ANALYTICAL RULES

1. Call tools when you need data beyond LIVE_CONTEXT. Never hallucinate.
2. Cite finding IDs, CVE identifiers, and scan timestamps.
3. Prioritise actionable advice — what to fix, why, and how.
4. Group findings sharing a root cause.
5. Severity order: CRITICAL > HIGH > MEDIUM > LOW > INFO.
6. If outside your domain, say so and suggest who might help.
"""

# ---------------------------------------------------------------------------
# Mode-specific behaviour directives
# ---------------------------------------------------------------------------
MODE_PROMPTS: dict[str, str] = {
    "triage": (
        "**Active Mode: Triage**\n"
        "The user wants findings ranked by risk. Pull severity breakdown and "
        "critical/high findings, then present a priority table:\n\n"
        "| # | Risk | Finding | Resource | Recommended Action | Timeline |\n"
        "|---|------|---------|----------|--------------------|----------|\n\n"
        "Group findings by root cause. End with: 'Start with #1 — here's why...'"
    ),
    "explain": (
        "**Active Mode: Explain**\n"
        "The user wants to understand something. Break it down in 3 layers:\n"
        "1. **What it is** (one sentence)\n"
        "2. **Why it matters** (business impact, real-world attack scenario)\n"
        "3. **What to do about it** (specific, actionable next step)\n"
        "Use analogies when helpful. Link to CVEs or compliance controls."
    ),
    "remediate": (
        "**Active Mode: Remediation**\n"
        "The user wants fix instructions. Provide:\n"
        "1. **Root cause** (one sentence)\n"
        "2. **Fix** (IaC code snippet in ```hcl/```yaml/```bash)\n"
        "3. **Verification** (command to confirm the fix worked)\n"
        "4. **Prevention** (how to avoid this in future scans)\n"
        "Always include the specific file path and line number if available."
    ),
    "compliance": (
        "**Active Mode: Compliance**\n"
        "Map findings to compliance frameworks (CIS, SOC 2, PCI-DSS, HIPAA, "
        "NIST 800-53). Present as:\n\n"
        "| Control ID | Framework | Requirement | Status | Gap | Fix |\n"
        "|------------|-----------|-------------|--------|-----|-----|\n\n"
        "Highlight the highest-impact compliance gaps first."
    ),
    "compare": (
        "**Active Mode: Compare**\n"
        "The user wants to compare scans or time periods. Present:\n"
        "• **New findings** (appeared since last scan)\n"
        "• **Resolved** (fixed since last scan)\n"
        "• **Risk delta** (score change, +/- direction)\n"
        "• **Trend** (improving/degrading/stable)\n"
        "Use ↑↓→ arrows for directional indicators."
    ),
    "attack_surface": (
        "**Active Mode: Attack Surface**\n"
        "Enumerate the organisation's exposure:\n"
        "• Public-facing resources with known vulnerabilities\n"
        "• Overly permissive IAM / security groups\n"
        "• Unencrypted data stores\n"
        "• Leaked secrets / credentials\n"
        "Present as a risk-ranked exposure table."
    ),
    "autofix": (
        "**Active Mode: Fix**\n"
        "The user wants a finding fixed.\n\n"
        "1. Identify the finding (`get_finding` or `list_findings`).\n"
        "2. Preview the code change with `auto_fix_finding`. It changes nothing.\n"
        "3. Show the file path, the diff in a fenced code block, how confident the fix is "
        "(below 0.7 means a person should rewrite it), and whether it could break anything.\n"
        "4. To open the pull request, call `open_fix_pull_request` (repository findings) or "
        "`remediate_cloud_finding` (cloud findings, rule IDs starting GN-AWS-). Both stop and wait "
        "for a second person to approve the exact change; say so, and never claim the change was "
        "made until the tool reports it was.\n"
        "Do not mark a finding resolved yourself; the next scan confirms the fix."
    ),
    "auto_triage": (
        "**Active Mode: Auto-Triage**\n"
        "Autonomously triage all open findings:\n\n"
        "1. Call `list_findings` to get all open findings\n"
        "2. For each finding, analyze severity, context, and exploitability\n"
        "3. Call `triage_finding` to set the appropriate status:\n"
        "   - `triaged` — acknowledged, needs human action\n"
        "   - `false_positive` — detected but not a real risk (with reason)\n"
        "   - `in_progress` — being worked on\n"
        "4. Present a summary table of all triage decisions\n\n"
        "**Triage criteria:**\n"
        "• CRITICAL + exploitable + public → `triaged` + immediate flag\n"
        "• Known false positive patterns (test files, examples, docs) → `false_positive`\n"
        "• LOW + informational + no exploit → `triaged` with low priority note\n\n"
        "End with: 'Triaged {n} findings. {x} need immediate attention.'"
    ),
    "investigation": (
        "**Active Mode: Investigation & Triage**\n"
        "You are now operating as an expert cloud security investigator.\n\n"
        "**Investigation Protocol:**\n"
        "1. **Scope** — Identify the domain (AWS/Azure/GCP/K8s/Terraform/Secrets)\n"
        "2. **Collect** — Gather all relevant findings, CVEs, and context\n"
        "3. **Analyze** — Apply investigation playbooks with prioritized action items\n"
        "4. **Recommend** — Provide specific, actionable remediation steps\n\n"
        "**For Incident Response:**\n"
        "• Follow the 4-phase model: Containment → Eradication → Recovery → Post-Incident\n"
        "• Include estimated timelines for each phase\n"
        "• Identify blast radius and affected systems\n"
        "• Reference specific compliance controls (CIS, SOC2, PCI-DSS, HIPAA, NIST)\n\n"
        "**Output Structure:**\n"
        "• Executive Summary (1-2 sentences)\n"
        "• Investigation Findings table with severity badges\n"
        "• Prioritized Action Items (numbered, with owner and timeline)\n"
        "• Compliance Impact (which controls are violated)\n"
        "• Root Cause Analysis (if determinable)\n\n"
        "Be thorough but decisive. Every finding must have an action."
    ),
}


# ---------------------------------------------------------------------------
# Few-shot golden examples — teach the LLM the expected quality bar
# ---------------------------------------------------------------------------
FEW_SHOT_EXAMPLES = [
    {
        "role": "user",
        "content": "Hi",
    },
    {
        "role": "assistant",
        "content": "Hey! What's up?",
    },
    {
        "role": "user",
        "content": "What should I fix first?",
    },
    {
        "role": "assistant",
        "content": (
            "**You have 14 critical findings that need immediate attention.** "
            "Here's your priority queue, ranked by blast radius and exploitability:\n\n"
            "| # | Severity | Finding | Resource | Action | Timeline |\n"
            "|---|----------|---------|----------|--------|----------|\n"
            "| 1 | 🔴 CRITICAL | AWS Access Key exposed (#1042) | `repo:backend` | "
            "Rotate key, add to `.gitignore` | **Immediate** |\n"
            "| 2 | 🔴 CRITICAL | S3 bucket public access (#1038) | `s3://prod-data` | "
            "Enable Block Public Access | **Immediate** |\n"
            "| 3 | 🔴 CRITICAL | RDS unencrypted storage (#1015) | `db-prod-main` | "
            "Enable encryption at rest | **This sprint** |\n\n"
            "**Start with #1** — an exposed access key is the fastest path to "
            "a full account compromise. Once rotated, findings #2 and #3 "
            "reduce your blast radius by ~60%.\n\n"
            "Want me to generate the remediation steps for #1?"
        ),
    },
]


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------
def build_system_prompt(
    mode: str | None = None,
    include_few_shot: bool = True,
) -> str:
    """Assemble the full system prompt for the agent loop."""
    parts = [COPILOT_PERSONA.strip()]

    # Inject capabilities reference from AGENTS.md / SKILLS.md / PROMPTS.md
    try:
        from .docs_loader import load_capabilities_block
        caps = load_capabilities_block()
        if caps:
            parts.append(f"\n\n{caps}")
    except Exception:
        pass  # Graceful degradation — docs are optional enrichment

    if mode and mode in MODE_PROMPTS:
        parts.append(f"\n\n{MODE_PROMPTS[mode]}")

    if include_few_shot and FEW_SHOT_EXAMPLES:
        parts.append("\n\n─── EXAMPLE INTERACTIONS (match this quality) ───")
        for ex in FEW_SHOT_EXAMPLES:
            prefix = "User" if ex["role"] == "user" else "Assistant"
            parts.append(f"\n**{prefix}:** {ex['content']}")

    return "\n".join(parts)


def detect_mode(user_message: str) -> str | None:
    """Infer the conversation mode from the user's message."""
    msg = user_message.lower().strip()

    # Greetings — return None so the LLM uses LIVE_CONTEXT without tools
    if is_greeting(user_message):
        return None

    # ── Specialized investigation modes (check specific before generic) ──

    # Container & Kubernetes
    if any(w in msg for w in ("container security", "docker security", "dockerfile",
                               "containerd", "cri-o", "privileged container",
                               "pod security", "k8s security", "kubernetes security")):
        return "container_security"

    # CI/CD Pipeline
    if any(w in msg for w in ("cicd", "ci/cd", "pipeline security", "github action",
                               "gitlab ci", "jenkins security", "build security",
                               "runner", "supply chain", "sbom", "slsa")):
        return "cicd_security"

    # API Security
    if any(w in msg for w in ("api security", "owasp api", "bola", "bfla",
                               "broken auth", "mass assignment", "graphql security",
                               "grpc security", "api gateway")):
        return "api_security"

    # Network Security
    if any(w in msg for w in ("network segmentation", "flat network", "lateral movement",
                               "firewall rule", "open port", "nsg rule", "security group rule",
                               "dns security", "subdomain takeover", "dangling dns",
                               "tls", "ssl", "certificate expir", "weak cipher")):
        return "network_security"

    # Identity & Access Governance
    if any(w in msg for w in ("identity governance", "access governance", "orphan account",
                               "mfa coverage", "privilege creep", "service account",
                               "zero trust", "ztna", "microsegment")):
        return "identity_security"

    # Threat Modeling
    if any(w in msg for w in ("threat model", "stride", "dread", "mitre att",
                               "kill chain", "attack tree", "threat actor",
                               "edr", "endpoint security", "malware detection")):
        return "threat_assessment"

    # Data Protection / DLP
    if any(w in msg for w in ("data loss prevention", "dlp", "data classification",
                               "data protection", "encryption gap", "public bucket",
                               "public storage", "pii exposure", "gdpr", "ccpa")):
        return "data_protection"

    # Cost Anomaly as Security Signal
    if any(w in msg for w in ("cost anomal", "cryptomining", "crypto mining",
                               "billing spike", "compute abuse", "egress anomal",
                               "cost security")):
        return "cost_security"

    # General investigation (catch-all for broad investigation queries)
    if any(w in msg for w in ("incident response", "ransomware", "data breach",
                               "credential exposure", "unauthorized access", "containment")):
        return "investigation"
    if any(w in msg for w in ("aws iam", "privilege escalation", "overprivileged",
                               "iam investigation", "aws network", "security group",
                               "vpc", "public subnet")):
        return "investigation"
    if any(w in msg for w in ("azure security", "azure defender", "entra", "azure investigation",
                               "gcp security", "gcp investigation", "google cloud")):
        return "investigation"
    if any(w in msg for w in ("terraform", "iac misconfig", "infrastructure as code",
                               "kubernetes", "k8s")):
        return "investigation"
    if any(w in msg for w in ("outdated package", "vulnerable dependency",
                               "leaked key", "hardcoded password", "exposed key", "secret scan")):
        return "investigation"
    if any(w in msg for w in ("investigate", "deep dive", "root cause", "forensic",
                               "threat hunt", "ioc")):
        return "investigation"

    if any(w in msg for w in ("prioritize", "triage", "first", "urgent", "critical",
                               "what should i fix", "top priority", "most important")):
        return "triage"
    if any(w in msg for w in ("explain", "what is", "why", "how does", "tell me about",
                               "break down", "what does", "help me understand")):
        return "explain"
    if any(w in msg for w in ("auto fix", "autofix", "auto-fix", "auto remediate",
                               "fix it for me", "create a pr", "open a pr",
                               "fix automatically", "auto patch", "generate fix")):
        return "autofix"
    if any(w in msg for w in ("auto triage", "auto-triage", "triage all",
                               "triage everything", "classify all findings",
                               "bulk triage")):
        return "auto_triage"
    if any(w in msg for w in ("fix", "remediate", "patch", "resolve", "how to fix",
                               "how do i fix", "steps to fix", "remediation")):
        return "remediate"
    if any(w in msg for w in ("compliance", "cis", "soc", "pci", "hipaa", "nist",
                               "framework", "audit", "regulation")):
        return "compliance"
    if any(w in msg for w in ("compare", "diff", "change", "delta", "versus", "vs",
                               "trend", "over time", "improved")):
        return "compare"
    if any(w in msg for w in ("attack surface", "exposure", "public", "exposed",
                               "attack", "blast radius", "external")):
        return "attack_surface"
    return None


def is_greeting(user_message: str) -> bool:
    """Check if the message is a simple greeting or casual opener (no tool calls needed)."""
    msg = user_message.lower().strip().rstrip("!?.;,")

    # Exact-match greetings (true greetings only — conversational phrases
    # like "how are you" are handled separately by the mock provider)
    greetings = {
        "hi", "hello", "hey", "yo", "sup", "hola", "good morning",
        "good afternoon", "good evening", "howdy",
        "hiya", "greetings", "morning", "evening",
        "hi there", "hello there", "hey there", "good day",
        "heya", "hey hey", "namaste", "bonjour", "aloha",
    }
    if msg in greetings:
        return True

    # Prefix-match for variations like "hi!" "hello!" "hey copilot"
    casual_prefixes = ("hi ", "hello ", "hey ", "good morning", "good afternoon",
                       "good evening")
    return any(msg.startswith(p) for p in casual_prefixes)
