"""Agentic auto-fix engine — generates real code patches for security findings.

This is the core brain of the remediation system. Given a finding and the
source file content, it produces a concrete code patch (unified diff format)
that fixes the security issue. The LLM generates the actual IaC code, not
just advice.

Supported fix types:
- IaC misconfigurations (Terraform, CloudFormation, Bicep, Kubernetes YAML)
- Secrets removal (replace with env var / vault references)
- Dependency version bumps (requirements.txt, package.json, etc.)
- Security group / IAM policy tightening

In mock mode, returns template-based fixes for common rule patterns.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from app.services.agents.llm import LLMClient, LLMSettings

logger = logging.getLogger(__name__)


@dataclass
class CodeFix:
    """A concrete code fix ready to be committed."""

    finding_id: int
    file_path: str
    original_content: str
    fixed_content: str
    diff: str
    explanation: str
    confidence: float  # 0.0 - 1.0
    fix_type: str  # "iac_config" | "secret_removal" | "dependency_bump" | "policy_fix"
    pr_title: str
    pr_body: str
    commit_message: str
    breaking_change: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "diff": self.diff,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "fix_type": self.fix_type,
            "pr_title": self.pr_title,
            "pr_body": self.pr_body,
            "commit_message": self.commit_message,
            "breaking_change": self.breaking_change,
        }


# ── LLM prompt for code fix generation ──────────────────────────────

_AUTOFIX_SYSTEM = """\
You are an expert cloud-security remediation engineer. You generate precise,
production-ready code fixes for infrastructure-as-code security findings.

RULES:
1. Return ONLY valid JSON. No markdown, no prose outside the JSON.
2. The "fixed_content" must be the COMPLETE file with the fix applied.
   Do NOT return a partial snippet — return the entire file.
3. The "diff" must be a valid unified diff (--- a/file, +++ b/file format).
4. Set confidence between 0.0 and 1.0:
   - 0.9+ : Simple, well-known fix (enable encryption, restrict CIDR)
   - 0.7-0.9 : Standard fix with some context needed
   - 0.5-0.7 : Fix requires assumptions about the environment
   - <0.5 : Complex fix, human review strongly recommended
5. Set breaking_change=true if the fix could cause downtime or break existing
   functionality (e.g., restricting a security group, rotating a key).
6. Generate a clear, conventional commit message:
   - Format: "fix(security): <short description>"
   - Example: "fix(security): enable S3 bucket encryption at rest"
7. Generate a PR title and body that explains:
   - What was found (the vulnerability)
   - What was changed (the fix)
   - Why it matters (the risk)
   - How to verify (validation steps)

RESPONSE FORMAT (strict JSON):
{
  "fixed_content": "<entire file with fix applied>",
  "diff": "<unified diff>",
  "explanation": "<what was changed and why>",
  "confidence": 0.85,
  "fix_type": "iac_config",
  "pr_title": "fix(security): enable encryption for S3 bucket prod-data",
  "pr_body": "## Security Fix\\n\\n...",
  "commit_message": "fix(security): enable S3 bucket encryption at rest",
  "breaking_change": false
}
"""


def _build_fix_prompt(finding: dict, file_content: str) -> str:
    return (
        f"FINDING:\n"
        f"  Rule ID: {finding.get('rule_id', 'unknown')}\n"
        f"  Title: {finding.get('title', 'unknown')}\n"
        f"  Severity: {finding.get('severity', 'unknown')}\n"
        f"  Cloud: {finding.get('cloud_provider', 'unknown')}\n"
        f"  Resource Type: {finding.get('resource_type', 'unknown')}\n"
        f"  Resource Name: {finding.get('resource_name', 'unknown')}\n"
        f"  File: {finding.get('file_path', 'unknown')}\n"
        f"  Line: {finding.get('line_number', 'unknown')}\n"
        f"  Description: {finding.get('description', 'n/a')}\n"
        f"  Existing Remediation Hint: {finding.get('remediation', 'n/a')}\n\n"
        f"FILE CONTENT ({finding.get('file_path', 'file')}):\n"
        f"```\n{file_content}\n```\n\n"
        "Generate the fix. Return strict JSON only."
    )


def _parse_fix_response(content: str) -> dict | None:
    """Extract JSON from LLM response, handling markdown fences."""
    # Try direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Try extracting from markdown code fence
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try finding JSON object
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


# ── Mock fix generation (template-based, no LLM needed) ─────────────

_TERRAFORM_FIXES: dict[str, dict[str, Any]] = {
    "encryption": {
        "patterns": [
            (r'encrypted\s*=\s*false', 'encrypted = true'),
            (r'server_side_encryption_configuration\s*\{[^}]*\}', None),  # needs full block
            (r'kms_master_key_id\s*=\s*""', 'kms_master_key_id = aws_kms_key.main.arn'),
        ],
        "add_block": (
            '\n  server_side_encryption_configuration {\n'
            '    rule {\n'
            '      apply_server_side_encryption_by_default {\n'
            '        sse_algorithm = "aws:kms"\n'
            '      }\n'
            '    }\n'
            '  }\n'
        ),
        "fix_type": "iac_config",
        "confidence": 0.92,
    },
    "public_access": {
        "patterns": [
            (r'acl\s*=\s*"public-read"', 'acl = "private"'),
            (r'acl\s*=\s*"public-read-write"', 'acl = "private"'),
            (r'block_public_acls\s*=\s*false', 'block_public_acls = true'),
            (r'block_public_policy\s*=\s*false', 'block_public_policy = true'),
            (r'ignore_public_acls\s*=\s*false', 'ignore_public_acls = true'),
            (r'restrict_public_buckets\s*=\s*false', 'restrict_public_buckets = true'),
        ],
        "fix_type": "iac_config",
        "confidence": 0.95,
    },
    "logging": {
        "patterns": [
            (r'enable_logging\s*=\s*false', 'enable_logging = true'),
            (r'access_logs\s*\{\s*enabled\s*=\s*false', 'access_logs {\n    enabled = true'),
        ],
        "add_block": (
            '\n  logging {\n'
            '    target_bucket = aws_s3_bucket.logs.id\n'
            '    target_prefix = "access-logs/"\n'
            '  }\n'
        ),
        "fix_type": "iac_config",
        "confidence": 0.88,
    },
    "network": {
        "patterns": [
            (r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', 'cidr_blocks = ["10.0.0.0/8"]'),
            (r'ingress\s*\{[^}]*from_port\s*=\s*0[^}]*to_port\s*=\s*65535',
             None),  # too dangerous for auto-fix
            (r'from_port\s*=\s*22\s*\n\s*to_port\s*=\s*22\s*\n\s*protocol\s*=\s*"tcp"\s*\n\s*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
             'from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = [var.allowed_ssh_cidr]'),
        ],
        "fix_type": "policy_fix",
        "confidence": 0.80,
        "breaking_change": True,
    },
}

_SECRET_PATTERNS = [
    (r'(AKIA[0-9A-Z]{16})', 'var.aws_access_key_id  # rotated — use env var or secrets manager'),
    (r'(["\'])(?:sk-[a-zA-Z0-9]{48})\1', 'var.openai_api_key  # rotated — use secrets manager'),
    (r'password\s*=\s*"[^"]{4,}"', 'password = var.db_password  # use secrets manager'),
    (r'secret_key\s*=\s*"[^"]{8,}"', 'secret_key = var.secret_key  # use secrets manager'),
]


def _classify_finding(finding: dict) -> str:
    """Classify a finding into a fix category."""
    title = (finding.get("title") or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    category = (finding.get("category") or "").lower()

    if category == "secrets" or "secret" in title or "credential" in title or "key exposed" in title:
        return "secret"
    if "encrypt" in title or "encryption" in rule_id:
        return "encryption"
    if "public" in title or "acl" in title or "block_public" in rule_id:
        return "public_access"
    if "log" in title and ("enabl" in title or "missing" in title):
        return "logging"
    if "cidr" in title or "0.0.0.0" in title or "security group" in title or "ingress" in title:
        return "network"
    return "generic"


def _generate_diff(file_path: str, original: str, fixed: str) -> str:
    """Generate a unified diff between original and fixed content."""
    from difflib import unified_diff
    orig_lines = original.splitlines(keepends=True)
    fix_lines = fixed.splitlines(keepends=True)
    diff = unified_diff(orig_lines, fix_lines, fromfile=f"a/{file_path}", tofile=f"b/{file_path}")
    return "".join(diff)


def _mock_fix(finding: dict, file_content: str) -> CodeFix | None:
    """Generate a template-based fix without LLM. Returns None if no pattern matches."""
    category = _classify_finding(finding)
    file_path = finding.get("file_path", "main.tf")
    fixed = file_content
    applied = False

    if category == "secret":
        for pattern, replacement in _SECRET_PATTERNS:
            new_content = re.sub(pattern, replacement, fixed)
            if new_content != fixed:
                fixed = new_content
                applied = True
    elif category in _TERRAFORM_FIXES:
        fix_data = _TERRAFORM_FIXES[category]
        for pattern, replacement in fix_data["patterns"]:
            if replacement is not None:
                new_content = re.sub(pattern, replacement, fixed, flags=re.IGNORECASE)
                if new_content != fixed:
                    fixed = new_content
                    applied = True

    if not applied:
        return None

    title = finding.get("title", "security issue")
    severity = finding.get("severity", "MEDIUM")
    rule_id = finding.get("rule_id", "unknown")

    return CodeFix(
        finding_id=finding.get("id", 0),
        file_path=file_path,
        original_content=file_content,
        fixed_content=fixed,
        diff=_generate_diff(file_path, file_content, fixed),
        explanation=f"Fixed {category} issue: {title}",
        confidence=_TERRAFORM_FIXES.get(category, {}).get("confidence", 0.75),
        fix_type=_TERRAFORM_FIXES.get(category, {}).get("fix_type", "iac_config"),
        pr_title=f"fix(security): {title[:80]}",
        pr_body=(
            f"## 🛡️ Security Fix — {severity}\n\n"
            f"**Finding:** {title}\n"
            f"**Rule:** `{rule_id}`\n"
            f"**Severity:** {severity}\n"
            f"**File:** `{file_path}`\n\n"
            f"### What Changed\n\n"
            f"Automated fix for {category} misconfiguration detected by GuardNous.\n\n"
            f"### Verification\n\n"
            f"- [ ] Re-run scan to confirm finding is resolved\n"
            f"- [ ] Review the change for environment-specific impact\n"
            f"- [ ] Verify no downstream services are affected\n"
        ),
        commit_message=f"fix(security): {title[:72]}",
        breaking_change=_TERRAFORM_FIXES.get(category, {}).get("breaking_change", False),
    )


# ── Main API ─────────────────────────────────────────────────────────

async def generate_fix(
    finding: dict,
    file_content: str,
    llm_settings: LLMSettings | None = None,
) -> CodeFix | None:
    """Generate a code fix for a security finding.

    Args:
        finding: Finding dict with rule_id, title, severity, file_path, etc.
        file_content: The full content of the file to fix.
        llm_settings: Optional LLM config. Falls back to mock if not live.

    Returns:
        CodeFix if a fix was generated, None if the finding can't be auto-fixed.
    """
    llm = LLMClient(llm_settings)

    # Mock mode: use template-based fixes
    if not llm.is_live:
        return _mock_fix(finding, file_content)

    # Live LLM: generate a real fix
    messages = [
        {"role": "system", "content": _AUTOFIX_SYSTEM},
        {"role": "user", "content": _build_fix_prompt(finding, file_content)},
    ]

    try:
        resp = await _chat_async(llm, messages)
        parsed = _parse_fix_response(resp.content)
        if not parsed:
            logger.warning("AutoFix: LLM returned unparseable response for finding %s", finding.get("id"))
            return _mock_fix(finding, file_content)

        fixed_content = parsed.get("fixed_content", "")
        if not fixed_content or fixed_content == file_content:
            logger.info("AutoFix: LLM returned no changes for finding %s", finding.get("id"))
            return None

        file_path = finding.get("file_path", "main.tf")
        return CodeFix(
            finding_id=finding.get("id", 0),
            file_path=file_path,
            original_content=file_content,
            fixed_content=fixed_content,
            diff=parsed.get("diff") or _generate_diff(file_path, file_content, fixed_content),
            explanation=parsed.get("explanation", "LLM-generated fix"),
            confidence=float(parsed.get("confidence", 0.7)),
            fix_type=parsed.get("fix_type", "iac_config"),
            pr_title=parsed.get("pr_title", f"fix(security): {finding.get('title', '')[:80]}"),
            pr_body=parsed.get("pr_body", "Automated security fix by GuardNous AI"),
            commit_message=parsed.get("commit_message", f"fix(security): {finding.get('title', '')[:72]}"),
            breaking_change=bool(parsed.get("breaking_change", False)),
        )
    except Exception:
        logger.exception("AutoFix: LLM call failed for finding %s", finding.get("id"))
        return _mock_fix(finding, file_content)


async def generate_batch_fixes(
    findings: list[dict],
    file_contents: dict[str, str],
    llm_settings: LLMSettings | None = None,
) -> list[CodeFix]:
    """Generate fixes for multiple findings. Groups by file to avoid conflicts.

    Args:
        findings: List of finding dicts.
        file_contents: Map of file_path → file content.
        llm_settings: Optional LLM config.

    Returns:
        List of CodeFix objects (only for findings that could be fixed).
    """
    import asyncio

    fixes: list[CodeFix] = []
    # Group findings by file to apply fixes sequentially per file
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file_path", "")
        if fp and fp in file_contents:
            by_file.setdefault(fp, []).append(f)

    async def fix_file_findings(file_path: str, file_findings: list[dict]) -> list[CodeFix]:
        result: list[CodeFix] = []
        current_content = file_contents[file_path]
        for finding in file_findings:
            fix = await generate_fix(finding, current_content, llm_settings)
            if fix:
                result.append(fix)
                current_content = fix.fixed_content  # chain fixes
        return result

    tasks = [fix_file_findings(fp, ffs) for fp, ffs in by_file.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            fixes.extend(r)
    return fixes


async def _chat_async(llm: LLMClient, messages: list[dict]):
    """Async wrapper around LLM chat."""
    import asyncio
    if hasattr(llm, "chat") and asyncio.iscoroutinefunction(llm.chat):
        return await llm.chat(messages)
    return await asyncio.to_thread(llm.chat_sync, messages)
