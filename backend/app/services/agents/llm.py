"""Provider-agnostic LLM client.

Supports OpenAI-compatible providers (OpenAI, Azure OpenAI, Ollama and any
OpenAI-compatible gateway) and Anthropic (direct or through Azure Foundry),
all with native tool calling and token usage, plus an offline "mock" provider
that needs no API key and answers from the injected context only.

Messages are kept in OpenAI chat format internally and converted for Anthropic.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_OPENAI_COMPATIBLE = {"openai", "azure", "azure_foundry", "ollama"}


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ""


class LLMError(RuntimeError):
    """The provider could not be reached or rejected the request."""


def to_anthropic_tools(tools: Optional[list[dict]]) -> list[dict]:
    """OpenAI function schemas -> Anthropic tool definitions."""
    out = []
    for tool in tools or []:
        fn = tool.get("function", tool)
        out.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return out


def to_anthropic_messages(messages: list[dict]) -> tuple[str, list[dict]]:
    """OpenAI-format messages -> (system text, Anthropic messages).

    Assistant tool calls become ``tool_use`` blocks and tool outputs become
    ``tool_result`` blocks in a user turn. Anthropic requires alternating
    roles, so consecutive same-role messages are merged.
    """
    system = "\n\n".join(m.get("content") or "" for m in messages if m.get("role") == "system")
    convo: list[dict] = []

    def add(role: str, blocks: list[dict]) -> None:
        if not blocks:
            return
        if convo and convo[-1]["role"] == role:
            convo[-1]["content"].extend(blocks)
        else:
            convo.append({"role": role, "content": list(blocks)})

    for m in messages:
        role = m.get("role")
        text = m.get("content") or ""
        if role == "user":
            add("user", [{"type": "text", "text": text}] if text else [])
        elif role == "assistant":
            blocks: list[dict] = [{"type": "text", "text": text}] if text else []
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {}) or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {}
                blocks.append({"type": "tool_use", "id": tc.get("id", ""), "name": fn.get("name", ""), "input": args})
            add("assistant", blocks)
        elif role == "tool":
            add("user", [{
                "type": "tool_result", "tool_use_id": m.get("tool_call_id", ""),
                "content": text or "(no output)",
            }])
    if not convo or convo[0]["role"] != "user":
        convo.insert(0, {"role": "user", "content": [{"type": "text", "text": "Hello"}]})
    return system, convo


@dataclass
class LLMSettings:
    """Effective LLM configuration for a single call (org-level or platform default)."""

    provider: str = "mock"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    base_url: str = ""
    api_version: str = "2024-06-01"
    temperature: float = 0.2
    max_tokens: int = 1200

    @classmethod
    def from_global(cls) -> "LLMSettings":
        return cls(
            provider=(settings.LLM_PROVIDER or "mock").lower(),
            api_key=settings.LLM_API_KEY,
            model=settings.LLM_MODEL,
            base_url=settings.LLM_BASE_URL,
            api_version=settings.LLM_API_VERSION,
            temperature=settings.LLM_TEMPERATURE,
            max_tokens=settings.LLM_MAX_TOKENS,
        )


class LLMClient:
    """Thin, dependency-light wrapper around chat-completion style APIs."""

    def __init__(self, config: Optional[LLMSettings] = None):
        cfg = config or LLMSettings.from_global()
        self.provider = (cfg.provider or "mock").lower()
        self.model = cfg.model
        self.api_key = cfg.api_key
        self.base_url = cfg.base_url
        self.api_version = cfg.api_version
        self.temperature = cfg.temperature
        self.max_tokens = cfg.max_tokens
        self._configure()

    def reply_timeout(self) -> float:
        """Seconds to wait for a whole (not streamed) reply. A reply is written at
        tens of tokens per second, so a long allowance needs a longer wait than the
        two minutes that suit a chat answer. Capped below the point where a run
        with no heartbeat is treated as dead."""
        return float(min(600, max(120, (self.max_tokens or 0) / 15)))

    def _configure(self) -> None:
        # A configured provider without credentials silently degrades to mock.
        if self.provider != "mock" and self.provider != "ollama" and not self.api_key:
            logger.warning("LLM provider=%s but no API key set; falling back to mock", self.provider)
            self.provider = "mock"

    # ── capabilities ────────────────────────────────────────────────
    @property
    def _is_azure_foundry_anthropic(self) -> bool:
        """True when Azure Foundry is routing to a Claude deployment."""
        if self.provider != "azure_foundry":
            return False
        url = (self.base_url or "").lower()
        model = (self.model or "").lower()
        return "/anthropic" in url or model.startswith("claude")

    @property
    def supports_tools(self) -> bool:
        return self.provider in _OPENAI_COMPATIBLE or self.provider == "anthropic"

    @property
    def is_live(self) -> bool:
        return self.provider != "mock"

    def info(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model if self.is_live else "mock-heuristic",
            "supports_tools": self.supports_tools,
            "live": self.is_live,
        }

    # ── endpoint / header helpers ───────────────────────────────────
    def _openai_endpoint(self) -> str:
        if self.provider == "azure":
            base = self.base_url.rstrip("/")
            return f"{base}/openai/deployments/{self.model}/chat/completions?api-version={self.api_version}"
        if self.provider == "ollama":
            from app.core.config import settings as _settings
            base = self.base_url or _settings.LLM_BASE_URL or "http://localhost:11434/v1"
            return f"{base.rstrip('/')}/chat/completions"
        base = self.base_url or "https://api.openai.com/v1"
        return f"{base.rstrip('/')}/chat/completions"

    def _openai_headers(self) -> dict:
        if self.provider in ("azure", "azure_foundry") and not self._is_azure_foundry_anthropic:
            return {"api-key": self.api_key, "Content-Type": "application/json"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    @staticmethod
    def _is_reasoning_model(model: str) -> bool:
        """Detect reasoning/o-series models that don't support temperature or max_tokens."""
        m = model.lower()
        # o1, o3, o4-mini, gpt-5*, etc. — reasoning models only accept temperature=1
        if m.startswith(("o1", "o3", "o4")):
            return True
        if m.startswith("gpt-5"):
            return True
        return False

    def _openai_payload(self, messages: list[dict], tools: Optional[list[dict]]) -> dict:
        reasoning = self._is_reasoning_model(self.model)
        payload: dict[str, Any] = {"messages": messages}

        # Reasoning models (o-series, gpt-5*) only accept temperature=1 (default).
        if not reasoning:
            payload["temperature"] = self.temperature

        # Azure API >= 2024-10-01 uses max_completion_tokens; older uses max_tokens.
        # Reasoning models also require max_completion_tokens (not max_tokens).
        if reasoning or (self.provider == "azure" and self.api_version >= "2024-10-01"):
            payload["max_completion_tokens"] = self.max_tokens
        else:
            payload["max_tokens"] = self.max_tokens

        if self.provider != "azure":
            payload["model"] = self.model
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        return payload

    @staticmethod
    def _parse_openai(data: dict) -> LLMResponse:
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {}) or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}
            tool_calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args))
        usage = data.get("usage") or {}
        return LLMResponse(
            content=msg.get("content") or "", tool_calls=tool_calls, raw=data,
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            stop_reason=choice.get("finish_reason") or "",
        )

    # ── anthropic helpers ───────────────────────────────────────────
    def _anthropic_payload(self, messages: list[dict], tools: Optional[list[dict]]) -> dict:
        system, convo = to_anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "system": system,
            "messages": convo,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = to_anthropic_tools(tools)
        return payload

    def _anthropic_request(self, messages: list[dict], tools: Optional[list[dict]] = None) -> tuple[str, dict, dict]:
        url = (self.base_url or "https://api.anthropic.com/v1").rstrip("/") + "/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        return url, headers, self._anthropic_payload(messages, tools)

    def _azure_foundry_anthropic_request(
        self, messages: list[dict], tools: Optional[list[dict]] = None,
    ) -> tuple[str, dict, dict]:
        """Azure Foundry with a Claude deployment — same message format, Azure auth."""
        base = (self.base_url or "").rstrip("/")
        url = f"{base}/v1/messages" if "/anthropic" in base.lower() else f"{base}/anthropic/v1/messages"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        return url, headers, self._anthropic_payload(messages, tools)

    @staticmethod
    def _parse_anthropic(data: dict) -> LLMResponse:
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        tool_calls = [
            ToolCall(id=b.get("id", ""), name=b.get("name", ""), arguments=b.get("input") or {})
            for b in blocks if b.get("type") == "tool_use"
        ]
        usage = data.get("usage") or {}
        return LLMResponse(
            content=text, tool_calls=tool_calls, raw=data,
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            stop_reason=data.get("stop_reason") or "",
        )

    # ── public: async ───────────────────────────────────────────────
    async def chat(
        self, messages: list[dict], tools: Optional[list[dict]] = None, *, strict: bool = False,
    ) -> LLMResponse:
        """One completion. With ``strict`` a provider failure raises
        :class:`LLMError` instead of returning the offline answer."""
        if self.provider == "mock":
            if strict:
                raise LLMError("No language model is configured for this organization.")
            return self._mock(messages)
        try:
            # Azure Foundry with Claude deployment -> Anthropic message format
            if self._is_azure_foundry_anthropic:
                url, headers, payload = self._azure_foundry_anthropic_request(messages, tools)
                async with httpx.AsyncClient(timeout=self.reply_timeout()) as client:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code >= 400:
                        raise LLMError(f"{self.provider} returned HTTP {resp.status_code}: {resp.text[:300]}")
                    return self._parse_anthropic(resp.json())
            # OpenAI-compatible: openai, azure, azure_foundry (GPT), ollama
            if self.provider in _OPENAI_COMPATIBLE:
                payload = self._openai_payload(messages, tools if self.supports_tools else None)
                async with httpx.AsyncClient(timeout=self.reply_timeout()) as client:
                    resp = await client.post(
                        self._openai_endpoint(), headers=self._openai_headers(),
                        json=payload,
                    )
                    if resp.status_code >= 400:
                        body = resp.text
                        logger.error("LLM HTTP %s from %s - body: %s", resp.status_code, self.provider, body[:1000])
                        logger.error("LLM request payload keys: %s, tools_count: %s", list(payload.keys()), len(payload.get("tools") or []))
                        resp.raise_for_status()
                    return self._parse_openai(resp.json())
            # Native Anthropic (direct API)
            if self.provider == "anthropic":
                url, headers, payload = self._anthropic_request(messages, tools)
                async with httpx.AsyncClient(timeout=self.reply_timeout()) as client:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code >= 400:
                        raise LLMError(f"anthropic returned HTTP {resp.status_code}: {resp.text[:300]}")
                    return self._parse_anthropic(resp.json())
        except Exception as e:
            logger.error("LLM call failed (%s): %s", self.provider, e)
            if strict:
                raise e if isinstance(e, LLMError) else LLMError(f"{self.provider}: {type(e).__name__}: {e}") from e
            return self._mock(messages, error=str(e))
        if strict:
            raise LLMError(f"Unsupported provider: {self.provider}")
        return self._mock(messages)

    # ── public: async streaming ─────────────────────────────────────
    async def chat_stream(self, messages: list[dict]) -> AsyncIterator[str]:
        """Yield content tokens as they arrive. No tool-calling in streaming mode.

        For real providers, uses the OpenAI/Anthropic streaming API.
        For mock, yields the mock response word-by-word with small delays.
        """
        if self.provider == "mock":
            resp = self._mock(messages)
            for word in resp.content.split(" "):
                yield word + " "
                await asyncio.sleep(0.03)
            return

        try:
            # Azure Foundry with Claude deployment → Anthropic streaming
            if self._is_azure_foundry_anthropic:
                url, headers, payload = self._azure_foundry_anthropic_request(messages)
                payload["stream"] = True
                async with httpx.AsyncClient(timeout=120) as client:
                    async with client.stream("POST", url, headers=headers, json=payload) as resp:
                        if resp.status_code >= 400:
                            body = await resp.aread()
                            logger.error("Azure Foundry Anthropic stream HTTP %s: %s", resp.status_code, body[:500])
                            yield (
                                f"\n\n> ⚠️ **LLM Error**: Azure Foundry returned HTTP {resp.status_code}. "
                                f"Details: `{body[:200].decode(errors='replace')}`. "
                                f"Please check your provider configuration in Settings.\n"
                            )
                            return
                        async for line in resp.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            try:
                                chunk = json.loads(line[6:])
                                if chunk.get("type") == "content_block_delta":
                                    token = chunk.get("delta", {}).get("text")
                                    if token:
                                        yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
                return

            # OpenAI-compatible: openai, azure, azure_foundry (GPT), ollama
            if self.provider in _OPENAI_COMPATIBLE:
                payload = self._openai_payload(messages, tools=None)
                payload["stream"] = True
                async with httpx.AsyncClient(timeout=120) as client:
                    async with client.stream(
                        "POST",
                        self._openai_endpoint(),
                        headers=self._openai_headers(),
                        json=payload,
                    ) as resp:
                        if resp.status_code >= 400:
                            body = await resp.aread()
                            logger.error("LLM stream HTTP %s: %s", resp.status_code, body[:500])
                            yield (
                                f"\n\n> ⚠️ **LLM Error**: Provider returned HTTP {resp.status_code}. "
                                f"Details: `{body[:200].decode(errors='replace')}`. "
                                f"Please check your provider configuration in Settings.\n"
                            )
                            return
                        async for line in resp.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            data_str = line[6:].strip()
                            if data_str == "[DONE]":
                                return
                            try:
                                chunk = json.loads(data_str)
                                delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                                token = delta.get("content")
                                if token:
                                    yield token
                            except (json.JSONDecodeError, IndexError):
                                continue
                return

            # Native Anthropic (direct API) streaming
            if self.provider == "anthropic":
                url, headers, payload = self._anthropic_request(messages)
                payload["stream"] = True
                async with httpx.AsyncClient(timeout=120) as client:
                    async with client.stream("POST", url, headers=headers, json=payload) as resp:
                        if resp.status_code >= 400:
                            body = await resp.aread()
                            logger.error("Anthropic stream HTTP %s: %s", resp.status_code, body[:500])
                            yield (
                                f"\n\n> ⚠️ **LLM Error**: Anthropic returned HTTP {resp.status_code}. "
                                f"Details: `{body[:200].decode(errors='replace')}`. "
                                f"Please check your provider configuration in Settings.\n"
                            )
                            return
                        async for line in resp.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            try:
                                chunk = json.loads(line[6:])
                                if chunk.get("type") == "content_block_delta":
                                    token = chunk.get("delta", {}).get("text")
                                    if token:
                                        yield token
                            except (json.JSONDecodeError, KeyError):
                                continue
                return

        except Exception as e:
            logger.error("LLM stream failed (%s): %s", self.provider, e)
            error_msg = (
                f"\n\n> ⚠️ **LLM Error**: Could not reach {self.provider}/{self.model}. "
                f"Error: `{type(e).__name__}: {e}`. "
                f"Please check your provider configuration in Settings.\n"
            )
            yield error_msg

    # ── public: sync (for Celery workers) ───────────────────────────
    def chat_sync(self, messages: list[dict], tools: Optional[list[dict]] = None) -> LLMResponse:
        if self.provider == "mock":
            return self._mock(messages)
        try:
            # Azure Foundry with Claude deployment → Anthropic message format
            if self._is_azure_foundry_anthropic:
                url, headers, payload = self._azure_foundry_anthropic_request(messages, tools)
                with httpx.Client(timeout=60) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    return self._parse_anthropic(resp.json())
            # OpenAI-compatible: openai, azure, azure_foundry (GPT), ollama
            if self.provider in _OPENAI_COMPATIBLE:
                with httpx.Client(timeout=60) as client:
                    resp = client.post(
                        self._openai_endpoint(), headers=self._openai_headers(),
                        json=self._openai_payload(messages, tools if self.supports_tools else None),
                    )
                    resp.raise_for_status()
                    return self._parse_openai(resp.json())
            # Native Anthropic (direct API)
            if self.provider == "anthropic":
                url, headers, payload = self._anthropic_request(messages, tools)
                with httpx.Client(timeout=60) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    return self._parse_anthropic(resp.json())
        except Exception as e:
            logger.error("LLM call failed (%s): %s", self.provider, e)
            return self._mock(messages, error=str(e))
        return self._mock(messages)

    # ── offline heuristic provider ──────────────────────────────────
    def _mock(self, messages: list[dict], error: Optional[str] = None) -> LLMResponse:
        """Grounded, deterministic response built from injected context.

        The orchestrator injects live context (either as JSON CONTEXT_PACK or
        narrative LIVE SECURITY POSTURE) as a system message, so the mock
        provider can produce genuinely useful, data-driven answers without
        any external API.
        """
        user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        context = ""
        for m in messages:
            content = m.get("content") or ""
            if m["role"] == "system" and ("CONTEXT_PACK" in content or "LIVE SECURITY" in content):
                context = content
                break

        prefix = ""
        if error:
            prefix = f"_(LLM provider unavailable, using local reasoning: {error})_\n\n"

        # Handle conversational messages (e.g. "how are you") with a short warm reply + context teaser
        if _is_conversational(user_msg):
            data = _extract_context_data(context)
            score = data.get("risk_score", {}).get("overall", "N/A")
            total = data.get("total_findings", 0)
            reply = (
                f"I'm operational and monitoring your environment! 🛡️\n\n"
                f"Your current risk score is **{score}/100** with **{total}** open findings. "
                f"Want me to break those down by severity, or help prioritize remediations?"
            )
            return LLMResponse(content=prefix + reply)

        summary = _summarize_context(context, user_msg)
        return LLMResponse(content=prefix + summary)


# ── greeting detection for mock provider ────────────────────────
_GREETING_WORDS = {
    "hi", "hello", "hey", "yo", "sup", "hola", "good morning",
    "good afternoon", "good evening", "howdy",
    "hiya", "greetings", "morning", "evening",
    "hi there", "hello there", "hey there", "good day",
    "heya", "hey hey", "namaste", "bonjour", "aloha",
}

_GREETING_PREFIXES = ("hi ", "hello ", "hey ", "good morning", "good afternoon",
                      "good evening")

# Conversational phrases — respond warmly but skip the full onboarding greeting
_CONVERSATIONAL_PHRASES = ("how are you", "how's it going", "what's up", "how do you do",
                           "how have you been", "how ya doing", "howdy")


def _is_mock_greeting(msg: str) -> bool:
    clean = msg.lower().strip().rstrip("!?.;,")
    if clean in _GREETING_WORDS:
        return True
    return any(clean.startswith(p) for p in _GREETING_PREFIXES)


def _is_conversational(msg: str) -> bool:
    """Detect conversational follow-ups that shouldn't trigger full greeting."""
    clean = msg.lower().strip().rstrip("!?.;,")
    return any(clean.startswith(p) for p in _CONVERSATIONAL_PHRASES)


def _parse_narrative_context(context: str) -> dict:
    """Extract structured data from the narrative LIVE SECURITY POSTURE format.

    Handles two formats produced by _format_context_narrative():
      Format A (label-first):  "🔴 CRITICAL: 14"
      Format B (count-first):  "🔴 14 Critical"
    """
    import re
    data: dict = {"risk_score": {}, "severity_breakdown": {}, "top_risks": [], "total_findings": 0, "total_scans": 0}

    # Parse "Risk Score: 64/100"
    m = re.search(r"Risk Score:\s*(\d+)\s*/\s*100", context)
    if m:
        data["risk_score"]["overall"] = int(m.group(1))

    # Parse severity counts — supports BOTH "CRITICAL: 14" and "14 Critical"
    for sev_key, label in [("critical", "CRITICAL"), ("high", "HIGH"),
                           ("medium", "MEDIUM"), ("low", "LOW")]:
        # Format A: "CRITICAL: 14" (produced by _format_context_narrative)
        m = re.search(rf"{label}[:\s]+(\d+)", context, re.IGNORECASE)
        if m:
            data["severity_breakdown"][sev_key] = int(m.group(1))
            continue
        # Format B: "14 Critical" (alternate inline format)
        m = re.search(rf"(\d+)\s*{label}", context, re.IGNORECASE)
        if m:
            data["severity_breakdown"][sev_key] = int(m.group(1))

    # Total findings: "Total Open Findings: 58 across 9 scans"
    m = re.search(r"(?:Total\s+(?:Open\s+)?)?Findings?:\s*(\d+)", context, re.IGNORECASE)
    if not m:
        m = re.search(r"(\d+)\s*(?:active\s+)?findings?\s*(?:total)?", context, re.IGNORECASE)
    if m:
        data["total_findings"] = int(m.group(1))

    # Total scans
    m = re.search(r"across\s+(\d+)\s*scans?", context, re.IGNORECASE)
    if m:
        data["total_scans"] = int(m.group(1))

    # Top risks: "1. 🔴 CRITICAL — Title (#78) → resource_name"
    for rm in re.finditer(
        r"\d+\.\s*(?:🔴|🟠|🟡|⚪|•)?\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*[—–-]\s*(.+?)(?:\s*\(#(\d+)\))?(?:\s*→\s*(.+))?$",
        context, re.MULTILINE | re.IGNORECASE,
    ):
        sev_str = rm.group(1).upper()
        title = rm.group(2).strip()
        finding_id = rm.group(3) or ""
        resource = (rm.group(4) or "").strip()
        data["top_risks"].append({
            "severity": sev_str, "title": title,
            "id": finding_id,
            "resource_name": resource,
        })

    return data


def _summarize_context(context: str, question: str) -> str:
    """Intent-based renderer that produces enterprise-grade responses."""
    # ── 1. Greeting detection (MUST come first) ──
    if _is_mock_greeting(question):
        return _greeting_response(context)

    # ── 2. Parse context from either JSON or narrative format ──
    data = _extract_context_data(context)

    q = question.lower()
    risk = data.get("risk_score", {})
    sev = data.get("severity_breakdown", {})
    top = data.get("top_risks", []) or []
    total_findings = data.get("total_findings", 0)
    total_scans = data.get("total_scans", 0)
    totals = f"{total_findings} findings across {total_scans} scans"

    lines: list[str] = []

    # ── Triage / Priority ──
    if any(k in q for k in ("prioriti", "triage", "first", "urgent", "focus", "worst", "what should")):
        lines.append("## 🎯 Priority Triage\n")
        if top:
            lines.append("| # | Finding | Severity | Resource | Action |")
            lines.append("|---|---------|----------|----------|--------|")
            badges = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
            for i, f in enumerate(top[:5], 1):
                sev_str = f.get("severity", "MEDIUM")
                badge = badges.get(sev_str, "⚪")
                lines.append(f"| {i} | {f.get('title', 'Unknown')} | {badge} {sev_str} | "
                             f"`{f.get('resource_name') or f.get('cloud_provider') or 'N/A'}` | Fix immediately |")
            lines.append("\n**Recommended action sequence:**")
            lines.append("1. **Immediate** — Address critical-severity items; they represent active exposure")
            lines.append("2. **This sprint** — Resolve high-severity findings to reduce blast radius")
            lines.append("3. **Backlog** — Schedule medium/low items for upcoming sprints")
        else:
            lines.append("✅ No active findings to triage. Your environment looks clean — keep it that way with regular scans.")
        return "\n".join(lines)

    # ── Risk / Posture ──
    if any(k in q for k in ("risk", "score", "posture", "overall", "how are we", "how secure", "status")):
        overall = risk.get("overall", 0)
        level = "LOW" if overall < 30 else "MODERATE" if overall < 50 else "MODERATE-HIGH" if overall < 70 else "HIGH" if overall < 85 else "CRITICAL"
        lines.append("## 📊 Security Posture\n")
        lines.append(f"**Overall Risk Score:** {overall}/100 ({level})\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 Critical | {sev.get('critical', 0)} |")
        lines.append(f"| 🟠 High | {sev.get('high', 0)} |")
        lines.append(f"| 🟡 Medium | {sev.get('medium', 0)} |")
        lines.append(f"| ⚪ Low | {sev.get('low', 0)} |")
        lines.append(f"\n**Total:** {totals}")
        if top:
            lines.append(f"\n**Top risk:** {top[0].get('title', 'N/A')} ({top[0].get('severity', 'N/A')})")
        return "\n".join(lines)

    # ── Incident Response (before remediation so "how do I respond to an incident" isn't caught) ──
    if any(k in q for k in ("incident", "breach", "respond", "ir ", "containment", "forensic", "compromise")):
        lines.append("## 🚨 Incident Response Guidance\n")
        lines.append("Follow the **NIST SP 800-61** incident response lifecycle:\n")
        lines.append("### Phase 1: Preparation")
        lines.append("- Ensure your IR team has **documented runbooks** for common scenarios")
        lines.append("- Verify logging is enabled: CloudTrail, VPC Flow Logs, Azure Activity Log, GCP Audit Logs")
        lines.append(f"- Your current posture: **{total_findings} open findings** — each is a potential attack vector\n")
        lines.append("### Phase 2: Detection & Analysis")
        lines.append("- Correlate GuardNous findings with SIEM alerts")
        lines.append("- Check for **indicators of compromise (IoCs)**: unusual API calls, privilege escalation, data exfiltration patterns")
        lines.append("- Use the triage feature to identify which critical findings may have been exploited\n")
        lines.append("### Phase 3: Containment")
        lines.append("```bash")
        lines.append("# Immediate containment actions:")
        lines.append("# 1. Revoke compromised credentials")
        lines.append("aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name compromised-user")
        lines.append("# 2. Isolate affected resources")
        lines.append("aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-isolation-only")
        lines.append("# 3. Snapshot for forensics before remediation")
        lines.append("aws ec2 create-snapshot --volume-id vol-xxx --description 'IR forensic snapshot'")
        lines.append("```\n")
        lines.append("### Phase 4: Eradication & Recovery")
        lines.append("- Patch vulnerabilities identified by GuardNous scans")
        lines.append("- Rotate all potentially compromised secrets and keys")
        lines.append("- Rebuild from known-good IaC configurations\n")
        lines.append("### Phase 5: Post-Incident")
        lines.append("- Conduct a **blameless retrospective** within 72 hours")
        lines.append("- Update your security policies and IaC templates")
        lines.append("- Schedule a follow-up scan to verify all gaps are closed")
        return "\n".join(lines)

    # ── Remediation ──
    if any(k in q for k in ("fix", "remediat", "how do i", "resolve", "patch", "mitigat")):
        f = top[0] if top else None
        if f:
            lines.append("## 🔧 Remediation Guide\n")
            lines.append(f"**Top finding:** {f.get('title', 'Unknown')} — `{f.get('severity', 'N/A')}`\n")
            lines.append("**Steps:**")
            lines.append("1. Navigate to the finding detail page for the full remediation playbook")
            lines.append("2. Use the **Explain & Fix** action to generate a code-level patch")
            lines.append("3. Apply the fix and re-scan to verify resolution")
            lines.append(f"\n> 💡 Resolving this finding will reduce your risk score from **{risk.get('overall', 0)}/100**.")
        else:
            lines.append("✅ No active findings to remediate. Great job keeping your environment clean!")
        return "\n".join(lines)

    # ── Compliance (general) ──
    if any(k in q for k in ("complian", "audit", "framework")) and not any(
        k in q for k in ("soc2", "soc 2", "iso27001", "iso 27001", "pci-dss", "pci dss",
                          "hipaa", "cis", "nist")
    ):
        lines.append("## 📋 Compliance Overview\n")
        lines.append(f"Based on **{total_findings} active findings**, here's a compliance snapshot:\n")
        lines.append("| Framework | Relevance | Action |")
        lines.append("|-----------|-----------|--------|")
        lines.append(f"| CIS Benchmarks | {sev.get('critical', 0) + sev.get('high', 0)} findings may impact | Review critical controls |")
        lines.append("| SOC 2 | Access & encryption gaps | Map to Trust Services Criteria |")
        lines.append(f"| PCI DSS | {sev.get('critical', 0)} critical findings | Immediate attention required |")
        lines.append(f"| HIPAA | PHI exposure risk from {sev.get('high', 0)} high findings | Assess data classification |")
        lines.append("| ISO 27001 | ISMS gaps in access control & encryption | Map to Annex A controls |")
        lines.append("\nUse the `compliance_check` skill for a detailed framework mapping.")
        return "\n".join(lines)

    # ── SOC 2 ──
    if any(k in q for k in ("soc2", "soc 2")):
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        lines.append("## 📋 SOC 2 Compliance Guidance\n")
        lines.append("SOC 2 is built around five **Trust Services Criteria** (TSC). "
                     "Here's how your current findings map:\n")
        lines.append("| TSC | Category | Relevant Findings | Status |")
        lines.append("|-----|----------|-------------------|--------|")
        lines.append(f"| CC6 | Logical & Physical Access | {critical + high} critical/high | {'🔴 Gaps' if critical + high > 0 else '✅ OK'} |")
        lines.append(f"| CC7 | System Operations | Monitoring gaps | {'🟠 Review' if total_findings > 5 else '✅ OK'} |")
        lines.append(f"| CC8 | Change Management | IaC misconfigurations | {'🟠 Review' if total_findings > 0 else '✅ OK'} |")
        lines.append(f"| CC9 | Risk Mitigation | {total_findings} open findings | {'🔴 Action needed' if critical > 0 else '🟡 Monitor'} |")
        lines.append("| A1  | Availability | Infrastructure hardening | Review required |")
        lines.append("\n**Key actions for SOC 2 readiness:**")
        lines.append("1. **Resolve all critical findings** — auditors flag these as material exceptions")
        lines.append("2. **Enable encryption at rest and in transit** for all data stores")
        lines.append("3. **Implement least-privilege IAM** — review overly permissive roles")
        lines.append("4. **Document your change management process** — IaC scan integration helps here")
        lines.append(f"\n> 💡 With {critical} critical findings, a SOC 2 Type II audit would likely flag material exceptions. "
                     "Prioritize remediation before engaging your auditor.")
        return "\n".join(lines)

    # ── ISO 27001 ──
    if any(k in q for k in ("iso27001", "iso 27001")):
        lines.append("## 📋 ISO 27001 Guidance\n")
        lines.append("ISO 27001 requires an **Information Security Management System (ISMS)**. "
                     "Your GuardNous findings map to these Annex A controls:\n")
        lines.append("| Annex A Control | Domain | Findings Impact | Priority |")
        lines.append("|-----------------|--------|-----------------|----------|")
        lines.append(f"| A.8 | Asset Management | {total_findings} unresolved | {'High' if total_findings > 10 else 'Medium'} |")
        lines.append("| A.9 | Access Control | IAM misconfigurations | High |")
        lines.append(f"| A.10 | Cryptography | Encryption gaps | {'Critical' if sev.get('critical', 0) > 0 else 'Medium'} |")
        lines.append("| A.12 | Operations Security | Logging & monitoring | Medium |")
        lines.append("| A.14 | System Acquisition | Secure development (IaC) | Medium |")
        lines.append("\n**ISMS recommendations:**")
        lines.append("1. Maintain a **risk register** — map each finding to a risk entry with owner and timeline")
        lines.append("2. Conduct **regular internal audits** — schedule quarterly IaC scans")
        lines.append("3. Implement **Statement of Applicability (SoA)** — document which controls apply to your cloud environment")
        lines.append("4. Establish **incident response procedures** — see our incident response guidance for templates")
        return "\n".join(lines)

    # ── PCI DSS ──
    if any(k in q for k in ("pci-dss", "pci dss", "pci")):
        critical = sev.get("critical", 0)
        lines.append("## 📋 PCI DSS Compliance Guidance\n")
        lines.append("PCI DSS v4.0 has **12 requirements** across 6 goals. "
                     "Here's your cardholder data environment (CDE) risk mapping:\n")
        lines.append("| Req | Goal | Findings Risk | Status |")
        lines.append("|-----|------|---------------|--------|")
        lines.append(f"| 1-2 | Build Secure Network | Firewall/SG misconfigs | {'🔴 Critical' if critical > 0 else '🟡 Review'} |")
        lines.append(f"| 3-4 | Protect Cardholder Data | Encryption gaps | {'🔴 Critical' if critical > 0 else '🟡 Review'} |")
        lines.append(f"| 5-6 | Vulnerability Mgmt | {total_findings} open vulnerabilities | {'🔴 Non-compliant' if critical > 3 else '🟠 At risk'} |")
        lines.append("| 7-9 | Access Control | IAM & secrets exposure | Review required |")
        lines.append("| 10 | Monitoring & Testing | Audit logging | Review required |")
        lines.append(f"| 11-12 | Security Policy | Regular testing & policy | {'🟡 Schedule' if total_scans < 4 else '✅ Active'} |")
        lines.append("\n**PCI DSS quick wins:**")
        lines.append("1. **Encrypt all cardholder data** at rest (AES-256) and in transit (TLS 1.2+)")
        lines.append("2. **Never store CVV/CVC** — validate your data flow diagrams")
        lines.append("3. **Quarterly vulnerability scans** with an ASV (Approved Scanning Vendor)")
        lines.append("4. **Network segmentation** — isolate your CDE from general workloads")
        return "\n".join(lines)

    # ── HIPAA ──
    if "hipaa" in q:
        lines.append("## 📋 HIPAA Security Rule Guidance\n")
        lines.append("The HIPAA Security Rule protects **electronic Protected Health Information (ePHI)**. "
                     "Your findings map to these safeguard categories:\n")
        lines.append("| Safeguard | Category | Risk Level | Action |")
        lines.append("|-----------|----------|------------|--------|")
        lines.append(f"| Administrative | Risk Analysis | {'🔴 High' if total_findings > 10 else '🟡 Medium'} | Document risk assessment |")
        lines.append("| Administrative | Workforce Security | IAM gaps | Review access controls |")
        lines.append(f"| Technical | Access Control | {sev.get('critical', 0) + sev.get('high', 0)} findings | Enforce MFA & least privilege |")
        lines.append("| Technical | Encryption | Encryption gaps detected | Encrypt all ePHI at rest & in transit |")
        lines.append("| Physical | Facility Access | Cloud provider responsibility | Verify BAA with cloud vendor |")
        lines.append("\n**HIPAA essentials:**")
        lines.append("1. **Conduct a Risk Analysis** (§164.308(a)(1)) — use GuardNous findings as your baseline")
        lines.append("2. **Sign a BAA** with every cloud provider handling ePHI")
        lines.append("3. **Enable audit logging** — CloudTrail, VPC Flow Logs, Azure Activity Log")
        lines.append("4. **Implement encryption** — AES-256 at rest, TLS 1.2+ in transit")
        lines.append("5. **Train your workforce** — document security awareness training annually")
        return "\n".join(lines)

    # ── CIS Benchmarks ──
    if "cis" in q:
        lines.append("## 📋 CIS Benchmarks Guidance\n")
        lines.append("CIS Benchmarks provide **prescriptive configuration guidance** for cloud platforms. "
                     "GuardNous findings align with these CIS control families:\n")
        lines.append("| CIS Control | Focus Area | Your Findings | Priority |")
        lines.append("|-------------|------------|---------------|----------|")
        lines.append("| 1 | Inventory & Control of Assets | Unmanaged resources | Medium |")
        lines.append(f"| 3 | Data Protection | Encryption gaps ({sev.get('critical', 0)} critical) | {'🔴 High' if sev.get('critical', 0) > 0 else '🟡 Medium'} |")
        lines.append("| 4 | Secure Configuration | IaC misconfigurations | High |")
        lines.append("| 5 | Account Management | IAM over-privilege | High |")
        lines.append(f"| 6 | Access Control | {sev.get('high', 0)} high-severity findings | {'🔴 High' if sev.get('high', 0) > 3 else '🟡 Medium'} |")
        lines.append("| 8 | Audit Log Management | Logging configuration | Medium |")
        lines.append("\n**Getting started with CIS:**")
        lines.append("1. Run CIS benchmark scans for your specific platforms (AWS, Azure, GCP)")
        lines.append("2. Focus on **Level 1** controls first — they're the baseline for all environments")
        lines.append("3. Level 2 controls add defense-in-depth for sensitive workloads")
        lines.append("4. Use GuardNous's compliance mapping to track your CIS posture over time")
        return "\n".join(lines)

    # ── NIST ──
    if "nist" in q:
        lines.append("## 📋 NIST 800-53 / CSF Guidance\n")
        lines.append("The NIST Cybersecurity Framework organizes security into five core functions. "
                     "Your findings map across the framework:\n")
        lines.append("| Function | Category | Your Exposure | Action |")
        lines.append("|----------|----------|---------------|--------|")
        lines.append(f"| Identify | Asset Management | {total_findings} findings across assets | Catalog all assets |")
        lines.append("| Protect | Access Control | IAM misconfigurations | Enforce least privilege |")
        lines.append("| Protect | Data Security | Encryption gaps | Encrypt sensitive data |")
        lines.append(f"| Detect | Security Monitoring | {total_scans} scans configured | {'✅ Active' if total_scans > 2 else '🟡 Increase frequency'} |")
        lines.append("| Respond | Incident Response | Playbooks needed | Document IR procedures |")
        lines.append("| Recover | Recovery Planning | Backup verification | Test recovery annually |")
        lines.append("\n**NIST quick wins:**")
        lines.append("1. **Map your assets** (NIST ID.AM) — ensure all cloud resources are inventoried")
        lines.append("2. **Implement MFA everywhere** (NIST PR.AC) — especially for admin access")
        lines.append("3. **Enable continuous monitoring** (NIST DE.CM) — integrate scans into CI/CD")
        lines.append("4. **Document your incident response plan** (NIST RS.RP) — test it quarterly")
        return "\n".join(lines)

    # ── OWASP ──
    if any(k in q for k in ("owasp", "top 10", "top ten", "web vulnerabilit")):
        lines.append("## 🔐 OWASP Top 10 Guidance\n")
        lines.append("The OWASP Top 10 represents the most critical web application security risks. "
                     "Here's how your findings relate:\n")
        lines.append("| # | OWASP Category | Risk | Relevance to Your Env |")
        lines.append("|---|---------------|------|-----------------------|")
        lines.append("| A01 | Broken Access Control | 🔴 Critical | IAM misconfigurations, overly permissive policies |")
        lines.append("| A02 | Cryptographic Failures | 🔴 Critical | Unencrypted data stores, weak TLS configs |")
        lines.append("| A03 | Injection | 🟠 High | SQL/NoSQL injection in application code |")
        lines.append("| A04 | Insecure Design | 🟠 High | Architecture-level security gaps |")
        lines.append("| A05 | Security Misconfiguration | 🔴 Critical | IaC misconfigs — your top category |")
        lines.append("| A06 | Vulnerable Components | 🟠 High | Outdated dependencies with known CVEs |")
        lines.append("| A07 | Auth & Session Failures | 🟠 High | Weak credential management |")
        lines.append("| A08 | Data Integrity Failures | 🟡 Medium | CI/CD pipeline security |")
        lines.append("| A09 | Logging & Monitoring | 🟡 Medium | Insufficient audit trails |")
        lines.append("| A10 | SSRF | 🟡 Medium | Server-side request forgery risks |")
        lines.append("\n**Immediate actions:**")
        lines.append("1. **A05 (Misconfigs)** is your biggest exposure — fix critical IaC findings first")
        lines.append("2. **A01 (Access Control)** — audit IAM policies for least privilege")
        lines.append("3. **A02 (Crypto)** — enable encryption at rest for all storage resources")
        lines.append("4. Run DAST/SAST scans alongside IaC scanning for full OWASP coverage")
        return "\n".join(lines)

    # ── CVE / Vulnerability intelligence ──
    if any(k in q for k in ("cve", "vulnerabilit", "exploit", "zero-day", "zero day", "patch")):
        lines.append("## 🔍 Vulnerability Intelligence\n")
        cve_findings = [f for f in top if f.get("cve_id") or "cve" in (f.get("title", "")).lower()]
        if cve_findings:
            lines.append(f"We found **{len(cve_findings)} findings with associated CVEs** in your environment:\n")
            lines.append("| Finding | CVE | Severity | Resource | Action |")
            lines.append("|---------|-----|----------|----------|--------|")
            badges = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
            for f in cve_findings[:5]:
                badge = badges.get(f.get("severity", "MEDIUM"), "⚪")
                cve_id = f.get("cve_id", "N/A")
                lines.append(f"| {f.get('title', 'Unknown')} | {cve_id} | {badge} {f.get('severity', '?')} | "
                             f"`{f.get('resource_name', 'N/A')}` | Patch immediately |")
        else:
            lines.append("No findings with specific CVE associations were detected in the current scan.\n")
        lines.append("\n**Vulnerability management best practices:**")
        lines.append("1. **Prioritize by CVSS score** — focus on 9.0+ (Critical) first")
        lines.append("2. **Check exploitability** — CISA KEV catalog lists actively exploited vulnerabilities")
        lines.append("3. **Patch within SLA** — Critical: 24-48h, High: 7 days, Medium: 30 days")
        lines.append("4. **Use compensating controls** if patching isn't immediately possible (WAF rules, network segmentation)")
        lines.append("5. **Track CVE references** in your findings to correlate with threat intelligence feeds")
        lines.append("\n> 💡 Enable the CVE enrichment integration to automatically link findings to NVD data, "
                     "EPSS scores, and CISA Known Exploited Vulnerabilities.")
        return "\n".join(lines)

    # ── DevSecOps / CI/CD Security ──
    if any(k in q for k in ("devsecops", "ci/cd", "cicd", "pipeline", "shift left",
                             "secure development", "sdlc", "supply chain")):
        lines.append("## ⚙️ DevSecOps Best Practices\n")
        lines.append("**Shift security left** by integrating GuardNous into your development lifecycle:\n")
        lines.append("### Pipeline Integration")
        lines.append("```yaml")
        lines.append("# GitHub Actions example — scan on every PR")
        lines.append("name: Security Scan")
        lines.append("on: [pull_request]")
        lines.append("jobs:")
        lines.append("  security-scan:")
        lines.append("    runs-on: ubuntu-latest")
        lines.append("    steps:")
        lines.append("      - uses: actions/checkout@v4")
        lines.append("      - name: Run IaC Security Scan")
        lines.append("        uses: guardnous/scan-action@v1")
        lines.append("        with:")
        lines.append("          fail-on: critical,high")
        lines.append("          format: sarif")
        lines.append("      - name: Upload SARIF")
        lines.append("        uses: github/codeql-action/upload-sarif@v3")
        lines.append("        with:")
        lines.append("          sarif_file: results.sarif")
        lines.append("```\n")
        lines.append("### Security Gates")
        lines.append("| Gate | Stage | Action on Failure |")
        lines.append("|------|-------|--------------------|")
        lines.append("| Pre-commit hooks | Local dev | Block commit with secrets |")
        lines.append("| IaC scan | PR check | Fail PR if critical findings |")
        lines.append("| Container scan | Build | Block image push if CVE found |")
        lines.append("| DAST scan | Staging | Alert team, gate promotion |")
        lines.append("| Runtime monitoring | Production | Auto-remediate or alert |")
        lines.append("\n**Key principles:**")
        lines.append("1. **Fail fast** — catch issues at the earliest, cheapest stage")
        lines.append("2. **Automate everything** — manual security reviews don't scale")
        lines.append("3. **Developer-friendly** — provide fix suggestions inline, not just alerts")
        lines.append("4. **Measure MTTR** — track how quickly your team resolves findings")
        return "\n".join(lines)

    # ── Security Best Practices ──
    if any(k in q for k in ("best practice", "hardening", "security tips", "recommendation",
                             "improve security", "strengthen", "secure my")):
        overall = risk.get("overall", 0)
        lines.append("## 🛡️ Security Best Practices\n")
        lines.append(f"Based on your current risk score of **{overall}/100**, here are tailored recommendations:\n")
        lines.append("### 🔴 Immediate (This Week)")
        lines.append(f"- **Resolve {sev.get('critical', 0)} critical findings** — these represent active exposure")
        lines.append("- **Rotate any exposed secrets** — API keys, database credentials, certificates")
        lines.append("- **Enable MFA** for all administrative access\n")
        lines.append("### 🟠 Short-Term (This Sprint)")
        lines.append(f"- **Address {sev.get('high', 0)} high-severity findings** to reduce blast radius")
        lines.append("- **Enable encryption at rest** for all storage resources (S3, RDS, EBS, Blob Storage)")
        lines.append("- **Review IAM policies** — enforce least privilege across all roles")
        lines.append("- **Enable VPC Flow Logs / NSG Flow Logs** for network visibility\n")
        lines.append("### 🟡 Medium-Term (This Quarter)")
        lines.append("- **Integrate security scanning** into CI/CD pipelines (shift left)")
        lines.append("- **Implement infrastructure as code** for all deployments — no manual changes")
        lines.append("- **Set up security alerting** — CloudWatch Alarms, Azure Monitor, or Datadog")
        lines.append("- **Conduct a tabletop incident response exercise**\n")
        lines.append("### 🔵 Ongoing")
        lines.append("- **Regular scanning cadence** — weekly for production, on every PR for development")
        lines.append("- **Security training** — annual developer security awareness program")
        lines.append("- **Compliance mapping** — continuous monitoring against CIS, SOC 2, or your target framework")
        lines.append("- **Threat modeling** — review architecture for new features")
        return "\n".join(lines)

    # ── Scan / Findings queries ──
    if any(k in q for k in ("scan", "finding", "result", "latest scan", "last scan", "how many")):
        lines.append("## 📊 Scan & Findings Summary\n")
        lines.append(f"**Active scans:** {total_scans} · **Open findings:** {total_findings}\n")
        lines.append("| Severity | Count | % of Total |")
        lines.append("|----------|-------|------------|")
        for sev_name, emoji in [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "⚪")]:
            count = sev.get(sev_name, 0)
            pct = f"{count / total_findings * 100:.0f}%" if total_findings > 0 else "0%"
            lines.append(f"| {emoji} {sev_name.title()} | {count} | {pct} |")
        if top:
            lines.append(f"\n**Most critical finding:** {top[0].get('title', 'N/A')} "
                         f"(#{top[0].get('id', '?')}) — `{top[0].get('severity', 'N/A')}`")
        lines.append("\n> Use **\"triage\"** to get a prioritized action plan, or ask about a specific finding by ID.")
        return "\n".join(lines)

    # ── Default: contextual overview ──
    overall = risk.get("overall", 0)
    lines.append("## 🛡️ Security Overview\n")
    lines.append(f"**Risk Score:** {overall}/100 · **Findings:** {totals}\n")
    lines.append(f"🔴 {sev.get('critical', 0)} Critical · 🟠 {sev.get('high', 0)} High · "
                 f"🟡 {sev.get('medium', 0)} Medium · ⚪ {sev.get('low', 0)} Low\n")
    if top:
        lines.append(f"**Top priority:** {top[0].get('title', 'N/A')} (`{top[0].get('severity', 'N/A')}`)\n")
    lines.append("I can help you **prioritize findings**, **explain your risk score**, "
                 "**generate remediation steps**, or **map to compliance frameworks**. What would you like to explore?")
    return "\n".join(lines)


def _greeting_response(context: str) -> str:
    """Generate a warm, enterprise-grade greeting with a posture snapshot."""
    data = _extract_context_data(context)
    risk = data.get("risk_score", {})
    sev = data.get("severity_breakdown", {})
    total = data.get("total_findings", 0)

    overall = risk.get("overall", 0)
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)

    lines = ["👋 Hello! I'm your **GuardNous Copilot** — your AI security analyst.\n"]

    if total > 0:
        lines.append("Here's a quick look at your environment:")
        lines.append(f"- **Risk Score:** {overall}/100")
        lines.append(f"- **Active Findings:** {total} total — "
                     f"🔴 {critical} Critical · 🟠 {high} High · "
                     f"🟡 {sev.get('medium', 0)} Medium · ⚪ {sev.get('low', 0)} Low")
        if critical > 0:
            lines.append(f"\n⚠️ You have **{critical} critical findings** that need immediate attention.")
    else:
        lines.append("Your environment looks clean — no active findings detected. 🎉")

    lines.append("\n**How can I help?**")
    lines.append("- 🎯 *\"What should I fix first?\"* — priority triage")
    lines.append("- 📊 *\"How secure are we?\"* — risk posture analysis")
    lines.append("- 🔧 *\"How do I fix this?\"* — remediation playbooks")
    lines.append("- 📋 *\"Are we compliant?\"* — framework mapping")
    return "\n".join(lines)


def _extract_context_data(context: str) -> dict:
    """Extract structured data from either JSON CONTEXT_PACK or narrative format."""
    if "CONTEXT_PACK::" in context:
        try:
            return json.loads(context.split("CONTEXT_PACK::", 1)[1].strip())
        except json.JSONDecodeError:
            pass
    if "LIVE SECURITY" in context or "Risk Score" in context:
        return _parse_narrative_context(context)
    return {"risk_score": {}, "severity_breakdown": {}, "top_risks": [], "total_findings": 0, "total_scans": 0}
