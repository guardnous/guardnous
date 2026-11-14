"""Tests for agent tool schemas and execute_tool dispatcher."""
import os
import json
import pytest

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"

from app.services.agents.tools import TOOL_SCHEMAS, execute_tool, ToolContext


class TestToolSchemas:
    def test_schemas_is_list(self):
        assert isinstance(TOOL_SCHEMAS, list)
        assert len(TOOL_SCHEMAS) >= 5  # at least 5 tools defined

    def test_each_schema_has_required_fields(self):
        for schema in TOOL_SCHEMAS:
            assert schema["type"] == "function"
            fn = schema["function"]
            assert "name" in fn
            assert "description" in fn
            assert "parameters" in fn

    def test_known_tool_names(self):
        names = {s["function"]["name"] for s in TOOL_SCHEMAS}
        expected = {"list_findings", "get_finding", "search_cves"}
        assert expected.issubset(names)

    def test_list_findings_params(self):
        schema = next(s for s in TOOL_SCHEMAS if s["function"]["name"] == "list_findings")
        params = schema["function"]["parameters"]
        assert "severity" in params.get("properties", {})


class TestExecuteTool:
    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        ctx = ToolContext(db=None, organization_id=1)
        result = await execute_tool(ctx, "nonexistent_tool", {})
        parsed = json.loads(result)
        assert "error" in parsed

    @pytest.mark.asyncio
    async def test_risk_score_without_db(self):
        """risk_score tool should handle None db gracefully or raise."""
        ctx = ToolContext(db=None, organization_id=1)
        result = await execute_tool(ctx, "risk_score", {})
        # Either returns a valid JSON result or an error dict
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_severity_breakdown_without_db(self):
        ctx = ToolContext(db=None, organization_id=1)
        result = await execute_tool(ctx, "severity_breakdown", {})
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
