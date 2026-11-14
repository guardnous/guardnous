"""Tests for the provider-agnostic LLM client."""
import os
import pytest

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.agents.llm import LLMClient, LLMSettings, LLMResponse


class TestLLMSettings:
    def test_defaults(self):
        s = LLMSettings()
        assert s.provider == "mock"
        assert s.model == "gpt-4o-mini"
        assert s.temperature == 0.2
        assert s.max_tokens == 1200

    def test_from_global_returns_settings(self):
        s = LLMSettings.from_global()
        assert isinstance(s, LLMSettings)
        assert s.provider in ("mock", "openai", "azure", "anthropic", "ollama")


class TestLLMClientInit:
    def test_defaults_to_mock(self):
        client = LLMClient()
        assert client.provider == "mock"
        assert client.is_live is False
        assert client.supports_tools is False

    def test_no_api_key_falls_back_to_mock(self):
        cfg = LLMSettings(provider="openai", api_key="", model="gpt-4o")
        client = LLMClient(cfg)
        assert client.provider == "mock"

    def test_ollama_no_key_stays_ollama(self):
        cfg = LLMSettings(provider="ollama", api_key="", model="llama3.1")
        client = LLMClient(cfg)
        assert client.provider == "ollama"

    def test_supports_tools_openai(self):
        cfg = LLMSettings(provider="openai", api_key="sk-test", model="gpt-4o")
        client = LLMClient(cfg)
        assert client.supports_tools is True

    def test_anthropic_supports_tools(self):
        cfg = LLMSettings(provider="anthropic", api_key="sk-ant-test", model="claude-3")
        client = LLMClient(cfg)
        assert client.supports_tools is True

    def test_info_mock(self):
        client = LLMClient()
        info = client.info()
        assert info["provider"] == "mock"
        assert info["model"] == "mock-heuristic"
        assert info["live"] is False

    def test_info_live(self):
        cfg = LLMSettings(provider="openai", api_key="sk-test", model="gpt-4o")
        client = LLMClient(cfg)
        info = client.info()
        assert info["live"] is True
        assert info["model"] == "gpt-4o"


class TestMockProvider:
    @pytest.mark.asyncio
    async def test_mock_returns_response(self):
        client = LLMClient()
        resp = await client.chat([{"role": "user", "content": "What is my risk score?"}])
        assert isinstance(resp, LLMResponse)
        assert resp.content  # non-empty

    @pytest.mark.asyncio
    async def test_mock_risk_query_with_context(self):
        context_pack = '{"risk_score": {"overall": 42, "aws": 30, "gcp": 10, "azure": 2}, "severity_breakdown": {"critical": 1, "high": 3, "medium": 5, "low": 2}, "total_findings": 11, "total_scans": 4, "top_risks": []}'
        messages = [
            {"role": "system", "content": f"CONTEXT_PACK::{context_pack}"},
            {"role": "user", "content": "What is my overall risk score?"},
        ]
        client = LLMClient()
        resp = await client.chat(messages)
        assert "42" in resp.content

    @pytest.mark.asyncio
    async def test_mock_prioritize_query(self):
        context_pack = '{"risk_score": {}, "severity_breakdown": {}, "total_findings": 3, "total_scans": 1, "top_risks": [{"severity": "CRITICAL", "title": "Open S3", "cloud_provider": "aws", "rule_id": "SD-TF-001"}]}'
        messages = [
            {"role": "system", "content": f"CONTEXT_PACK::{context_pack}"},
            {"role": "user", "content": "Prioritize my findings"},
        ]
        client = LLMClient()
        resp = await client.chat(messages)
        assert "Open S3" in resp.content

    @pytest.mark.asyncio
    async def test_mock_remediation_query(self):
        context_pack = '{"risk_score": {}, "severity_breakdown": {}, "total_findings": 1, "total_scans": 1, "top_risks": [{"severity": "HIGH", "title": "Unencrypted DB", "cloud_provider": "aws", "rule_id": "SD-TF-005"}]}'
        messages = [
            {"role": "system", "content": f"CONTEXT_PACK::{context_pack}"},
            {"role": "user", "content": "How do I fix my top issue?"},
        ]
        client = LLMClient()
        resp = await client.chat(messages)
        assert "Unencrypted DB" in resp.content

    @pytest.mark.asyncio
    async def test_mock_with_error_shows_prefix(self):
        client = LLMClient()
        resp = client._mock([{"role": "user", "content": "hi"}], error="connection refused")
        assert "unavailable" in resp.content.lower()

    def test_sync_mock(self):
        client = LLMClient()
        resp = client.chat_sync([{"role": "user", "content": "hello"}])
        assert isinstance(resp, LLMResponse)
        assert resp.content


class TestOpenAIHelpers:
    def test_openai_endpoint(self):
        cfg = LLMSettings(provider="openai", api_key="sk-test", model="gpt-4o")
        client = LLMClient(cfg)
        assert "api.openai.com" in client._openai_endpoint()

    def test_azure_endpoint(self):
        cfg = LLMSettings(provider="azure", api_key="key", model="my-deploy",
                          base_url="https://myresource.openai.azure.com")
        client = LLMClient(cfg)
        url = client._openai_endpoint()
        assert "myresource.openai.azure.com" in url
        assert "my-deploy" in url

    def test_ollama_endpoint(self):
        cfg = LLMSettings(provider="ollama", model="llama3.1")
        client = LLMClient(cfg)
        assert "11434" in client._openai_endpoint()

    def test_parse_openai_response(self):
        data = {
            "choices": [{
                "message": {
                    "content": "Hello!",
                    "tool_calls": None,
                }
            }]
        }
        resp = LLMClient._parse_openai(data)
        assert resp.content == "Hello!"
        assert resp.tool_calls == []

    def test_parse_openai_with_tool_calls(self):
        data = {
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "function": {
                            "name": "list_findings",
                            "arguments": '{"severity": "CRITICAL"}',
                        },
                    }],
                }
            }]
        }
        resp = LLMClient._parse_openai(data)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "list_findings"
        assert resp.tool_calls[0].arguments == {"severity": "CRITICAL"}

    def test_parse_openai_malformed_arguments(self):
        data = {
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "function": {"name": "test", "arguments": "not-json"},
                    }],
                }
            }]
        }
        resp = LLMClient._parse_openai(data)
        assert resp.tool_calls[0].arguments == {}


class TestAnthropicHelpers:
    def test_parse_anthropic_response(self):
        data = {
            "content": [
                {"type": "text", "text": "Here is your analysis."},
            ]
        }
        resp = LLMClient._parse_anthropic(data)
        assert resp.content == "Here is your analysis."

    def test_parse_anthropic_empty(self):
        resp = LLMClient._parse_anthropic({})
        assert resp.content == ""
