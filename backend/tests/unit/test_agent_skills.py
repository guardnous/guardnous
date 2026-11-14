from app.services.agents.skills import (
    build_skill_registry,
    build_skill_plan,
    route_user_request,
)


def test_skill_registry_contains_expected_skills():
    registry = build_skill_registry()
    expected = {"risk_overview", "findings_summary", "cve_lookup", "scan_history", "security_brief"}
    assert expected.issubset(registry.keys())
    assert registry["risk_overview"].kind == "deterministic"
    assert registry["risk_overview"].requires_approval is False
    assert registry["security_brief"].kind == "llm"
    assert registry["security_brief"].requires_approval is True


def test_route_request_for_risk_query():
    route = route_user_request("What is my overall risk score and severity breakdown?")
    assert route == "risk_overview"


def test_route_request_for_general_security_brief():
    route = route_user_request("Give me a security brief for the organization and suggest next steps")
    assert route == "security_brief"


def test_skill_manifest_is_exposed_for_deployment():
    manifest = build_skill_registry()["risk_overview"].to_manifest()
    assert manifest["name"] == "risk_overview"
    assert manifest["execution_mode"] == "sync"
    assert manifest["requires_approval"] is False


def test_build_skill_plan_creates_structured_workflow():
    plan = build_skill_plan("Show me the current risk summary", {"limit": 5})
    assert plan["skill"] == "risk_overview"
    assert plan["requires_approval"] is False
    assert plan["input_schema"]["type"] == "object"
    assert plan["status"] == "ready"
