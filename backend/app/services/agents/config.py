"""Per-organization LLM configuration ("bring your own model").

Resolves the effective :class:`LLMSettings` for an org: a stored, enabled
config takes precedence; otherwise the platform default (env) is used.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_token
from app.models.llm_config import LLMConfig
from app.services.agents.llm import LLMSettings

# Field metadata drives the settings UI form (single source of truth).
SUPPORTED_PROVIDERS = [
    {
        "id": "mock",
        "label": "Built-in (offline)",
        "description": "Local heuristic reasoning. No API key or data egress.",
        "fields": [],
        "defaults": {},
    },
    {
        "id": "openai",
        "label": "OpenAI",
        "description": "GPT models via the OpenAI API.",
        "fields": ["api_key", "model", "base_url"],
        "required": ["api_key"],
        "defaults": {"model": "gpt-4o-mini", "base_url": "https://api.openai.com/v1"},
        "help": {"base_url": "Optional. Override for OpenAI-compatible gateways."},
    },
    {
        "id": "azure_foundry",
        "label": "Azure AI Foundry",
        "description": "Azure-hosted GPT and Claude models via AI Foundry.",
        "fields": ["api_key", "base_url", "model", "api_version"],
        "required": ["api_key", "base_url", "model"],
        "defaults": {"api_version": "2024-12-01-preview"},
        "help": {
            "base_url": "For GPT: https://<resource>.cognitiveservices.azure.com  —  For Claude: https://<resource>.services.ai.azure.com/anthropic",
            "model": "Deployment name (e.g. gpt-4.1 or claude-opus-4-5)",
            "api_version": "Azure API version (GPT only, ignored for Claude)",
        },
    },
    {
        "id": "anthropic",
        "label": "Anthropic (Claude)",
        "description": "Claude models via the Anthropic API.",
        "fields": ["api_key", "model"],
        "required": ["api_key"],
        "defaults": {"model": "claude-3-5-sonnet-latest"},
    },
    {
        "id": "ollama",
        "label": "Ollama (self-hosted)",
        "description": "Local/self-hosted open models, OpenAI-compatible.",
        "fields": ["base_url", "model"],
        "required": ["model"],
        "defaults": {"base_url": "http://localhost:11434/v1", "model": "llama3.1"},
    },
]

PROVIDER_IDS = {p["id"] for p in SUPPORTED_PROVIDERS}


async def get_org_config(db: AsyncSession, organization_id: int) -> LLMConfig | None:
    return (await db.execute(
        select(LLMConfig).where(LLMConfig.organization_id == organization_id)
    )).scalar_one_or_none()


def settings_from_config(cfg: LLMConfig) -> LLMSettings:
    api_key = ""
    if cfg.api_key_encrypted:
        try:
            api_key = decrypt_token(cfg.api_key_encrypted)
        except ValueError:
            api_key = ""
    return LLMSettings(
        provider=(cfg.provider or "mock").lower(),
        api_key=api_key,
        model=cfg.model or "",
        base_url=cfg.base_url or "",
        api_version=cfg.api_version or "2024-06-01",
        temperature=cfg.temperature if cfg.temperature is not None else 0.2,
        max_tokens=cfg.max_tokens if cfg.max_tokens and cfg.max_tokens > 1200 else 4096,
    )


async def resolve_llm_settings(db: AsyncSession, organization_id: int) -> LLMSettings:
    """Effective settings for this org (falls back to platform default)."""
    cfg = await get_org_config(db, organization_id)
    if cfg and cfg.enabled and cfg.provider:
        return settings_from_config(cfg)
    return LLMSettings.from_global()
