"""Tests for per-org LLM configuration (BYOM)."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.agents.config import (
    SUPPORTED_PROVIDERS,
    PROVIDER_IDS,
    settings_from_config,
)
from app.services.agents.llm import LLMSettings
from app.core.encryption import encrypt_token


class _FakeLLMConfig:
    """Mimics the LLMConfig SQLAlchemy model for unit tests."""

    def __init__(self, **kwargs):
        self.provider = kwargs.get("provider", "mock")
        self.api_key_encrypted = kwargs.get("api_key_encrypted", "")
        self.model = kwargs.get("model", "")
        self.base_url = kwargs.get("base_url", "")
        self.api_version = kwargs.get("api_version", "")
        self.temperature = kwargs.get("temperature", None)
        self.max_tokens = kwargs.get("max_tokens", None)
        self.enabled = kwargs.get("enabled", True)
        self.organization_id = kwargs.get("organization_id", 1)


class TestSupportedProviders:
    def test_provider_ids_set(self):
        assert "mock" in PROVIDER_IDS
        assert "openai" in PROVIDER_IDS
        assert "azure_foundry" in PROVIDER_IDS
        assert "anthropic" in PROVIDER_IDS
        assert "ollama" in PROVIDER_IDS

    def test_each_provider_has_label(self):
        for p in SUPPORTED_PROVIDERS:
            assert "label" in p
            assert "description" in p
            assert "id" in p

    def test_openai_requires_api_key(self):
        openai = next(p for p in SUPPORTED_PROVIDERS if p["id"] == "openai")
        assert "api_key" in openai["required"]

    def test_mock_has_no_required_fields(self):
        mock = next(p for p in SUPPORTED_PROVIDERS if p["id"] == "mock")
        assert mock.get("fields", []) == []

    def test_ollama_requires_model(self):
        ollama = next(p for p in SUPPORTED_PROVIDERS if p["id"] == "ollama")
        assert "model" in ollama["required"]


class TestSettingsFromConfig:
    def test_mock_config(self):
        cfg = _FakeLLMConfig(provider="mock")
        s = settings_from_config(cfg)
        assert isinstance(s, LLMSettings)
        assert s.provider == "mock"

    def test_openai_config_with_encrypted_key(self):
        encrypted = encrypt_token("sk-test-key-123")
        cfg = _FakeLLMConfig(
            provider="openai",
            api_key_encrypted=encrypted,
            model="gpt-4o",
            base_url="https://api.openai.com/v1",
        )
        s = settings_from_config(cfg)
        assert s.provider == "openai"
        assert s.api_key == "sk-test-key-123"
        assert s.model == "gpt-4o"

    def test_invalid_encrypted_key_returns_empty(self):
        cfg = _FakeLLMConfig(
            provider="openai",
            api_key_encrypted="not-valid-fernet",
            model="gpt-4o",
        )
        s = settings_from_config(cfg)
        assert s.api_key == ""

    def test_temperature_defaults(self):
        cfg = _FakeLLMConfig(provider="mock", temperature=None)
        s = settings_from_config(cfg)
        assert s.temperature == 0.2

    def test_custom_temperature(self):
        cfg = _FakeLLMConfig(provider="mock", temperature=0.8)
        s = settings_from_config(cfg)
        assert s.temperature == 0.8

    def test_max_tokens_default(self):
        cfg = _FakeLLMConfig(provider="mock", max_tokens=None)
        s = settings_from_config(cfg)
        assert s.max_tokens == 4096

    def test_azure_api_version(self):
        cfg = _FakeLLMConfig(
            provider="azure",
            api_version="2024-06-01",
            api_key_encrypted=encrypt_token("key"),
            model="deploy-name",
            base_url="https://x.openai.azure.com",
        )
        s = settings_from_config(cfg)
        assert s.api_version == "2024-06-01"
