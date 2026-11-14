"""Cloud posture: AWS collectors, rules, finding lifecycle, and the agent tools built on them.

AWS is replaced by a hand-written fake session; nothing here calls AWS.
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.cloud_resource import CloudResource
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.agents.tools import TOOL_SCHEMAS, ToolContext, execute_tool
from app.services.cloud_connectors import aws_extra
from app.services.cloud_connectors.aws_connector import AWSConnector
from app.services.cloud_posture.engine import evaluate_account
from app.services.cloud_posture.rules import RULES, evaluate
from app.services.governance.finding_policies import finding_matches
from app.services.security.policy_engine import BUILT_IN_BY_ID, CLOUD_RULES_BY_POLICY
from tests.test_agent_runtime import _user

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)
ACCOUNT = "111122223333"


# ── fake AWS ────────────────────────────────────────────────────────

class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    def __init__(self, calls: dict):
        self._calls = calls

    def __getattr__(self, name):
        def call(**kwargs):
            value = self._calls[name]
            if isinstance(value, Exception):
                raise value
            return value(**kwargs) if callable(value) else value
        return call

    def get_paginator(self, operation):
        client = self

        class Paginator:
            def paginate(self, **kwargs):
                return [getattr(client, operation)(**kwargs)]
        return Paginator()


class FakeSession:
    def __init__(self, services: dict):
        self._services = services

    def client(self, service, region_name=None):
        return FakeClient(self._services[service])


# ── collectors ──────────────────────────────────────────────────────

def test_account_collector_separates_not_configured_from_not_readable():
    session = FakeSession({
        "iam": {
            "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1, "Users": 4}},
            "get_account_password_policy": AwsError("NoSuchEntity"),           # genuinely no policy
        },
        "s3control": {"get_public_access_block": AwsError("AccessDenied")},      # we are not allowed to look
    })

    (account,) = aws_extra.discover_account(session, ACCOUNT)

    assert account.resource_type == "aws_account"
    assert account.config["summary"] == {"root_mfa_enabled": False, "root_access_keys_present": True, "users": 4}
    assert account.config["password_policy"] is None
    assert "s3_public_access_block" not in account.config
    assert account.config["_unreadable"] == ["s3_public_access_block"]

    by_rule = {r.rule.id: r for r in evaluate([_res(account)], now=NOW)}
    assert by_rule["GN-AWS-ACCT-001"].status == "fail"
    assert by_rule["GN-AWS-ACCT-002"].status == "fail"
    assert by_rule["GN-AWS-ACCT-003"].status == "fail" and "No IAM password policy" in by_rule["GN-AWS-ACCT-003"].reason
    assert by_rule["GN-AWS-ACCT-005"].status == "unknown"                        # not a finding


def test_load_balancer_collector_reads_listeners_attributes_and_waf():
    arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc"
    session = FakeSession({
        "elbv2": {
            "describe_load_balancers": {"LoadBalancers": [{
                "LoadBalancerArn": arn, "LoadBalancerName": "web", "Type": "application", "Scheme": "internet-facing",
                "DNSName": "Web-1.us-east-1.elb.amazonaws.com",
            }]},
            "describe_listeners": {"Listeners": [
                {"Port": 80, "Protocol": "HTTP", "DefaultActions": [{"Type": "forward"}]},
                {"Port": 443, "Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-2016-08", "DefaultActions": []},
            ]},
            "describe_load_balancer_attributes": {"Attributes": [{"Key": "access_logs.s3.enabled", "Value": "false"}]},
        },
        "wafv2": {"get_web_acl_for_resource": {}},
    })

    (lb,) = aws_extra.discover_load_balancers(session, ACCOUNT, "us-east-1")

    assert lb.config["internet_facing"] and lb.config["waf_web_acl"] is None
    assert lb.config["dns_name"] == "web-1.us-east-1.elb.amazonaws.com"
    failing = {r.rule.id for r in evaluate([_res(lb)], now=NOW) if r.status == "fail"}
    assert failing == {"GN-AWS-LB-001", "GN-AWS-LB-002", "GN-AWS-LB-003", "GN-AWS-LB-004"}


def test_connector_runs_the_new_collectors_and_survives_one_failing(monkeypatch):
    def boom(*a):
        raise RuntimeError("kms is down")

    monkeypatch.setitem(aws_extra.REGIONAL_COLLECTORS, "aws_kms_key", boom)
    monkeypatch.setitem(aws_extra.REGIONAL_COLLECTORS, "aws_vpc", lambda s, acct, region: [
        aws_extra._resource("aws_vpc", f"arn:vpc/{region}", "main", region, acct, {"flow_logs_enabled": False}),
    ])
    connector = AWSConnector({}, regions=["us-east-1", "eu-west-1"])
    monkeypatch.setattr(connector, "_get_session", lambda: object())
    monkeypatch.setattr(connector, "_get_account_id", lambda s: ACCOUNT)

    import asyncio

    found = asyncio.run(connector.discover(resource_types=["aws_kms_key", "aws_vpc"]))

    assert [(r.resource_type, r.region) for r in found] == [("aws_vpc", "us-east-1"), ("aws_vpc", "eu-west-1")]
    assert {"aws_account", "aws_cloudtrail_trail", "aws_eks_cluster", "aws_route53_zone"} <= set(AWSConnector.SUPPORTED_RESOURCE_TYPES)


# ── rules ───────────────────────────────────────────────────────────

def _res(discovered) -> dict:
    return {
        "resource_id": discovered.resource_id, "resource_name": discovered.resource_name,
        "resource_type": discovered.resource_type, "region": discovered.region, "account_id": discovered.account_id,
        "config": discovered.config,
    }


def _r(rtype: str, name: str, **config) -> dict:
    return {"resource_id": f"arn:{rtype}:{name}", "resource_name": name, "resource_type": rtype, "region": "us-east-1",
            "account_id": ACCOUNT, "config": config}


def _failed(resources: list[dict]) -> set[tuple[str, str]]:
    return {(r.rule.id, r.resource["resource_name"]) for r in evaluate(resources, now=NOW) if r.status == "fail"}


def test_security_group_rules_read_the_actual_ports():
    world = lambda low, high, proto="tcp": {"cidr": "0.0.0.0/0", "from_port": low, "to_port": high, "protocol": proto}  # noqa: E731
    failed = _failed([
        _r("aws_security_group", "ssh-range", group_name="a", ingress_rules=[world(20, 25)]),
        _r("aws_security_group", "web", group_name="b", ingress_rules=[world(443, 443)]),
        _r("aws_security_group", "everything", group_name="c", ingress_rules=[world(None, None, "-1")]),
        _r("aws_security_group", "db", group_name="d", ingress_rules=[world(5432, 5432)]),
        _r("aws_security_group", "internal-ssh", group_name="e",
           ingress_rules=[{"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22, "protocol": "tcp"}]),
        _r("aws_security_group", "udp-22", group_name="f", ingress_rules=[world(22, 22, "udp")]),
    ])
    assert ("GN-AWS-SG-001", "ssh-range") in failed
    assert {("GN-AWS-SG-001", "everything"), ("GN-AWS-SG-002", "everything"), ("GN-AWS-SG-003", "everything")} <= failed
    assert ("GN-AWS-SG-003", "db") in failed
    assert not {f for f in failed if f[1] in ("web", "internal-ssh", "udp-22")}


def test_bucket_is_fine_when_the_account_blocks_public_access():
    block = dict.fromkeys(("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"), True)
    bucket = _r("aws_s3_bucket", "logs", bucket_name="logs", public_access_block=None, versioning={"status": "Enabled"}, logging_enabled=True)

    assert ("GN-AWS-S3-001", "logs") in _failed([bucket])
    assert ("GN-AWS-S3-001", "logs") not in _failed([bucket, _r("aws_account", "acct", s3_public_access_block=block)])


def test_time_based_rules():
    old = (NOW - timedelta(days=120)).isoformat()
    fresh = (NOW - timedelta(days=10)).isoformat()
    failed = _failed([
        _r("aws_iam_user", "ci", access_keys=[{"access_key_id": "AKIAOLDKEY000", "status": "Active", "created": old},
                                               {"access_key_id": "AKIAINACTIVE0", "status": "Inactive", "created": old}]),
        _r("aws_iam_user", "dev", access_keys=[{"access_key_id": "AKIANEWKEY000", "status": "Active", "created": fresh}]),
        _r("aws_acm_certificate", "soon", in_use=True, not_after=(NOW + timedelta(days=12)).isoformat()),
        _r("aws_acm_certificate", "unused", in_use=False, not_after=(NOW + timedelta(days=2)).isoformat()),
        _r("aws_acm_certificate", "fine", in_use=True, not_after=(NOW + timedelta(days=200)).isoformat()),
    ])
    assert failed == {("GN-AWS-IAM-002", "ci"), ("GN-AWS-ACM-001", "soon")}


def test_dangling_dns_compares_records_with_what_exists():
    zone = _r("aws_route53_zone", "example.com", private=False, pointer_records=[
        {"name": "old.example.com", "type": "CNAME", "target": "old.example.com.s3-website-us-east-1.amazonaws.com"},
        {"name": "site.example.com", "type": "CNAME", "target": "site.example.com.s3-website-us-east-1.amazonaws.com"},
        {"name": "api.example.com", "type": "A", "target": "dualstack.gone-1.us-east-1.elb.amazonaws.com"},
        {"name": "app.example.com", "type": "A", "target": "dualstack.live-1.us-east-1.elb.amazonaws.com"},
    ])
    results = evaluate([
        zone, _r("aws_s3_bucket", "site.example.com", bucket_name="site.example.com"),
        _r("aws_lb", "live", dns_name="live-1.us-east-1.elb.amazonaws.com", listeners=[], attributes={}),
    ], now=NOW)

    reason = next(r.reason for r in results if r.rule.id == "GN-AWS-DNS-001")
    assert "old.example.com" in reason and "api.example.com" in reason
    assert "site.example.com ->" not in reason and "app.example.com" not in reason
    # without the bucket and load balancer inventory nothing can be concluded, so nothing is raised
    assert not _failed([zone])


def test_no_multi_region_trail_is_raised_on_the_account_only_when_trails_were_synced():
    account = _r("aws_account", "acct", summary={"root_mfa_enabled": True, "root_access_keys_present": False})
    region = _r("aws_region_settings", "us-east-1", ebs_encryption_by_default=True, guardduty_enabled=True, config_recorder_enabled=True)
    trail = _r("aws_cloudtrail_trail", "org", multi_region=True, is_logging=True, log_file_validation=True, kms_key_id="k")

    assert ("GN-AWS-ACCT-006", "acct") in _failed([account, region])
    assert ("GN-AWS-ACCT-006", "acct") not in _failed([account, region, trail])
    unknown = {r.rule.id for r in evaluate([account], now=NOW) if r.status == "unknown"}
    assert "GN-AWS-ACCT-006" in unknown


def test_rule_ids_are_unique_and_policies_reference_real_rules():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for policy_id, rule_ids in CLOUD_RULES_BY_POLICY.items():
        assert policy_id in BUILT_IN_BY_ID
        assert set(rule_ids) <= set(ids), policy_id
    public_bucket = [{"rule_id_prefixes": BUILT_IN_BY_ID["POL-S3-001"]["rule_id_prefixes"], "categories": []}]
    assert finding_matches(public_bucket, {"rule_id": "GN-AWS-S3-001"})
    assert not finding_matches(public_bucket, {"rule_id": "GN-AWS-S3-002"})


# ── findings lifecycle ──────────────────────────────────────────────

async def _sync(db, org_id, name, rtype="aws_security_group", **config):
    row = (await db.execute(
        select(CloudResource).where(CloudResource.organization_id == org_id, CloudResource.resource_name == name)
    )).scalar_one_or_none()
    if row is None:
        row = CloudResource(
            organization_id=org_id, provider="aws", resource_type=rtype, resource_id=f"arn:{rtype}:{name}",
            resource_name=name, region="us-east-1", account_id=ACCOUNT, status="active",
        )
        db.add(row)
    row.config = config
    await db.commit()
    return row


SSH_OPEN = [{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}]


async def test_findings_open_resolve_and_reopen_as_the_cloud_changes(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)

    first = await evaluate_account(db_session, org, "aws", ACCOUNT, account_name="Prod", now=NOW)
    assert (first["opened"], first["failed"]) == (1, 1)
    again = await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)
    assert (again["opened"], again["resolved"]) == (0, 0)                       # no duplicates

    finding = (await db_session.execute(select(Finding).where(Finding.rule_id == "GN-AWS-SG-001"))).scalar_one()
    assert (finding.organization_id, finding.severity, finding.status, finding.detected_by) == (org, "CRITICAL", "open", "guardnous-cspm")
    assert finding.metadata_["resource_id"] == "arn:aws_security_group:bastion" and finding.metadata_["cis_aws_1_4"] == "5.2"
    scan = await db_session.get(Scan, first["scan_id"])
    assert (scan.scan_type, scan.status, scan.critical_count, scan.findings_count) == ("cloud_posture", "completed", 1, 1)

    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=[])
    fixed = await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)
    await db_session.refresh(finding)
    await db_session.refresh(scan)
    assert fixed["resolved"] == 1 and (finding.status, finding.is_fixed) == ("resolved", True)
    assert scan.findings_count == 0 and scan.risk_score == 0

    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)
    back = await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)
    await db_session.refresh(finding)
    assert back["reopened"] == 1 and (finding.status, finding.is_fixed) == ("open", False)
    assert [n["text"][:8] for n in finding.notes] == ["Resolved", "Reopened"]


async def test_a_false_positive_is_left_alone(db_session, client):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)
    finding = (await db_session.execute(select(Finding).where(Finding.rule_id == "GN-AWS-SG-001"))).scalar_one()
    finding.status, finding.is_ignored = "false_positive", True
    await db_session.commit()

    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=[])
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)

    await db_session.refresh(finding)
    assert (finding.status, finding.is_ignored, finding.is_fixed) == ("false_positive", True, False)


# ── agent tools ─────────────────────────────────────────────────────

async def _tool(db, org, name, **args) -> dict:
    return json.loads(await execute_tool(ToolContext(db=db, organization_id=org), name, args))


async def test_tools_say_not_connected_instead_of_guessing(db_session, client):
    user, _ = await _user(db_session, client)
    for name in ("cloud_inventory_summary", "internet_exposure", "scan_exposed_ports", "audit_iam_permissions",
                 "check_encryption_posture", "evaluate_waf_rules", "investigate_dns", "investigate_tls",
                 "assess_endpoint_security", "detect_cost_anomalies", "enrich_ioc", "check_reputation"):
        out = await _tool(db_session, user.organization_id, name)
        assert out.get("data_source") == "not_connected", name
        assert "risk_score" not in out and "reputation_score" not in out, name


async def test_internet_exposure_joins_instances_to_their_security_groups(db_session, client):
    user, _ = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    org = user.organization_id
    await _sync(db_session, org, "open-sg", group_id="sg-open", group_name="open", ingress_rules=SSH_OPEN)
    await _sync(db_session, org, "unused-sg", group_id="sg-unused", group_name="unused", ingress_rules=SSH_OPEN)
    running = dict(state="running", metadata_options={"http_tokens": "optional", "http_endpoint": "enabled"})
    await _sync(db_session, org, "web-1", "aws_ec2_instance", has_public_ip=True, public_ip="203.0.113.9", security_groups=["sg-open"], **running)
    await _sync(db_session, org, "private-1", "aws_ec2_instance", has_public_ip=False, security_groups=["sg-open"], **running)
    await _sync(db_session, org, "orders-db", "aws_rds_instance", publicly_accessible=True, engine="postgres", storage_encrypted=False)
    await evaluate_account(db_session, org, "aws", ACCOUNT, now=NOW)

    out = await _tool(db_session, org, "internet_exposure")

    assert [(i["name"], i["open_to_internet"], i["imdsv1_allowed"]) for i in out["instances_reachable_from_internet"]] == [
        ("web-1", ["SSH (22)"], True),
    ]
    assert [d["name"] for d in out["public_databases"]] == ["orders-db"]
    attached = {g["name"]: g["attached_to_an_instance"] for g in out["open_security_groups"]}
    assert attached == {"open-sg": True, "unused-sg": False}

    posture = await _tool(db_session, org, "cloud_posture_summary")
    assert posture["by_severity"]["CRITICAL"] >= 3 and posture["accounts"][0]["resources"] == 5
    one = await _tool(db_session, org, "get_cloud_resource", resource="orders-db")
    assert {f["rule_id"] for f in one["open_findings"]} >= {"GN-AWS-RDS-001", "GN-AWS-RDS-002"}

    # another organization sees none of it
    assert (await _tool(db_session, other.organization_id, "internet_exposure"))["data_source"] == "not_connected"
    assert "error" in await _tool(db_session, other.organization_id, "get_cloud_resource", resource="orders-db")


def test_cloud_tools_are_offered_to_every_agent():
    from app.services.agents.registry import filter_tools_for_agent, get_agent

    names = {t["function"]["name"] for t in filter_tools_for_agent(get_agent("triage_agent"), TOOL_SCHEMAS)}
    assert {"cloud_posture_summary", "internet_exposure", "list_cloud_resources"} <= names


async def test_posture_is_reported_per_cloud_account(db_session, client):
    from app.models.cloud_account import CloudAccount

    user, headers = await _user(db_session, client)
    org = user.organization_id
    other_account = "999999999999"
    prod = CloudAccount(organization_id=org, provider="aws", name="Prod", account_identifier=ACCOUNT, status="connected")
    dev = CloudAccount(organization_id=org, provider="aws", name="Dev", account_identifier=other_account, status="connected")
    db_session.add_all([prod, dev])
    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)
    closed = await _sync(db_session, org, "internal", group_id="sg-2", group_name="internal", ingress_rules=[])
    closed.account_id = other_account
    await db_session.commit()
    for account in (ACCOUNT, other_account):
        await evaluate_account(db_session, org, "aws", account)

    overview = (await client.get("/api/v1/cloud-posture", headers=headers)).json()
    by_name = {a["name"]: a for a in overview["connected_accounts"]}
    assert overview["account"] is None and overview["open_findings"] == 1
    assert (by_name["Prod"]["open_findings"], by_name["Prod"]["by_severity"]["CRITICAL"], by_name["Prod"]["resources"]) == (1, 1, 1)
    assert (by_name["Dev"]["open_findings"], by_name["Dev"]["resources"], by_name["Dev"]["scan_id"] is not None) == (0, 1, True)

    one = (await client.get(f"/api/v1/cloud-posture?account_id={dev.id}", headers=headers)).json()
    assert one["account"]["account"] == other_account and one["open_findings"] == 0
    assert [e["resources"] for e in one["evaluated"]] == [1]
    assert all(r["failing"] == 0 for r in one["rules"])
    assert one["exposure"]["open_security_groups"] == []

    prod_only = (await client.get(f"/api/v1/cloud-posture?account_id={prod.id}", headers=headers)).json()
    assert [g["name"] for g in prod_only["exposure"]["open_security_groups"]] == ["bastion"]
    assert next(r for r in prod_only["rules"] if r["rule_id"] == "GN-AWS-SG-001")["failing"] == 1

    _, stranger = await _user(db_session, client, email="other@elsewhere.test", org="Elsewhere")
    assert (await client.get(f"/api/v1/cloud-posture?account_id={prod.id}", headers=stranger)).status_code == 404


async def test_the_scan_records_its_own_pipeline_stages(db_session, client):
    from app.services.cloud_posture.engine import discovery_stage

    user, _ = await _user(db_session, client)
    org = user.organization_id
    await _sync(db_session, org, "bastion", group_id="sg-1", group_name="bastion", ingress_rules=SSH_OPEN)
    read = discovery_stage(NOW, NOW + timedelta(seconds=12), 1, ["us-east-1"])

    first = await evaluate_account(db_session, org, "aws", ACCOUNT, account_name="Prod", sync_stage=read)
    scan = await db_session.get(Scan, first["scan_id"])
    stages = scan.stage_details
    assert stages["cloud_discovery"]["duration_ms"] == 12000 and "1 resources" in stages["cloud_discovery"]["summary"]
    for key in ("cloud_evaluation", "cloud_findings"):
        assert stages[key]["start_time"] <= stages[key]["end_time"] and stages[key]["summary"]
    assert "1 failed" in stages["cloud_evaluation"]["summary"] and "1 opened" in stages["cloud_findings"]["summary"]
    assert stages["checks"] >= 1 and scan.repository_name is None      # summary kept; never posed as a repository

    # A re-check reads nothing from the cloud: it keeps the last sync's discovery entry.
    await evaluate_account(db_session, org, "aws", ACCOUNT)
    await db_session.refresh(scan)
    assert scan.stage_details["cloud_discovery"] == read
    assert "0 opened" in scan.stage_details["cloud_findings"]["summary"]
