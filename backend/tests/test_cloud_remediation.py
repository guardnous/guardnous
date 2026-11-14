"""Fixing cloud findings in AWS: plan, approval, apply, verify, rollback, and the posture API.

AWS is the model-checked stand-in from tests/aws_model.py with a little state,
so every call's name and arguments are validated against the real AWS API.
"""
import json

import pytest
from sqlalchemy import select

pytest.importorskip("boto3")

from app.models.agent import AgentApproval  # noqa: E402
from app.models.cloud_resource import CloudChange  # noqa: E402
from app.models.finding import Finding  # noqa: E402
from app.services.agents import runtime  # noqa: E402
from app.services.cloud_posture import remediation  # noqa: E402
from app.services.cloud_posture.engine import evaluate_account  # noqa: E402
from tests.aws_model import AwsError, ModelSession  # noqa: E402
from tests.conftest import create_finding_in_db, create_scan_in_db  # noqa: E402
from tests.test_agent_actions import _second_admin  # noqa: E402
from tests.test_agent_runtime import ScriptedLLM, _answer, _ask, _start, _user, get_auth_headers_for  # noqa: E402
from tests.test_cloud_posture import ACCOUNT, NOW, _sync  # noqa: E402

WORLD_SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "temp"}]}
WORLD_RANGE = {"IpProtocol": "tcp", "FromPort": 20, "ToPort": 25, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
WORLD_HTTPS = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
OFFICE_SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}


class Aws:
    """Model-checked AWS with just enough state to observe changes."""

    def __init__(self):
        self.block = None
        self.permissions = [WORLD_SSH, WORLD_RANGE, WORLD_HTTPS, OFFICE_SSH]
        self.deny_writes = False
        self.session = ModelSession({
            ("s3", "get_public_access_block"): self._get_block,
            ("s3", "put_public_access_block"): self._write(lambda kw: setattr(self, "block", kw["PublicAccessBlockConfiguration"])),
            ("s3", "delete_public_access_block"): self._write(lambda kw: setattr(self, "block", None)),
            ("ec2", "describe_security_groups"): self._describe_groups,
            ("ec2", "revoke_security_group_ingress"): self._write(self._revoke),
            ("ec2", "authorize_security_group_ingress"): self._write(lambda kw: self.permissions.extend(kw["IpPermissions"])),
        })

    def _get_block(self, response, kwargs):
        if self.block is None:
            raise AwsError("NoSuchPublicAccessBlockConfiguration")
        response["PublicAccessBlockConfiguration"] = dict(self.block)

    def _describe_groups(self, response, kwargs):
        response["SecurityGroups"] = [{"GroupId": kwargs["GroupIds"][0], "IpPermissions": [dict(p) for p in self.permissions]}]

    def _revoke(self, kwargs):
        for perm in kwargs["IpPermissions"]:
            self.permissions.remove(perm)

    def _write(self, effect):
        def call(response, kwargs):
            if self.deny_writes:
                raise AwsError("AccessDenied")
            effect(kwargs)
        return call

    @property
    def writes(self) -> list[str]:
        return [m for _, m, _ in self.session.calls if m.startswith(("put_", "delete_", "revoke_", "authorize_", "enable_", "disable_"))]


@pytest.fixture
def aws(monkeypatch):
    fake = Aws()

    async def session_for(db, organization_id, provider, account_id):
        return fake.session

    monkeypatch.setattr(remediation, "session_for", session_for)
    return fake


async def _bucket_finding(db, org) -> Finding:
    await _sync(db, org, "reports", "aws_s3_bucket", bucket_name="reports", public_access_block=None,
                versioning={"status": "Enabled"}, logging_enabled=True)
    await evaluate_account(db, org, "aws", ACCOUNT, now=NOW)
    return (await db.execute(select(Finding).where(Finding.rule_id == "GN-AWS-S3-001"))).scalar_one()


async def _ssh_finding(db, org) -> Finding:
    await _sync(db, org, "bastion", group_id="sg-0123456789abcdef0", group_name="bastion",
                ingress_rules=[{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}])
    await evaluate_account(db, org, "aws", ACCOUNT, now=NOW)
    return (await db.execute(select(Finding).where(Finding.rule_id == "GN-AWS-SG-001"))).scalar_one()


# ── through an agent run ────────────────────────────────────────────

async def test_bucket_is_changed_only_after_someone_else_approves_and_can_be_rolled_back(db_session, client, aws):
    user, _ = await _user(db_session, client)
    finding = await _bucket_finding(db_session, user.organization_id)
    run = await _start(db_session, user, agent_id="remediation_agent")
    llm = ScriptedLLM(_ask("remediate_cloud_finding", finding_id=finding.id), _answer("Public access is blocked."))

    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "awaiting_approval" and aws.writes == []            # only read so far
    approval = (await db_session.execute(select(AgentApproval).where(AgentApproval.run_id == run.id))).scalar_one()
    assert approval.risk == "external_write"
    assert "Now: not set" in approval.preview and "stop being reachable" in approval.preview
    assert f"account {ACCOUNT}" in approval.summary and "rolled back" in approval.summary
    with pytest.raises(runtime.DecisionError):
        await runtime.decide_approval(db_session, approval, user, approve=True)
    assert aws.block is None

    approver = await _second_admin(db_session, client, user)
    await runtime.decide_approval(db_session, approval, approver, approve=True)
    run = await runtime.execute_run(db_session, run.id, llm=llm)

    assert run.status == "completed"
    assert aws.block == dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
    assert aws.writes == ["put_public_access_block"]
    result = json.loads(llm.calls[1][0][-1]["content"])
    assert result["status"] == "changed" and result["verified"] is True
    change = (await db_session.execute(select(CloudChange))).scalar_one()
    assert (change.status, change.before, change.run_id, change.approved_by) == ("applied", None, run.id, "approver@example.com")
    await db_session.refresh(finding)
    assert finding.status == "in_progress" and "Changed in AWS" in finding.notes[-1]["text"]

    headers = await get_auth_headers_for(client, user.email)
    undone = await client.post(f"/api/v1/cloud-posture/changes/{change.id}/rollback", headers=headers)
    assert undone.status_code == 200 and undone.json()["status"] == "rolled_back"
    assert aws.block is None and aws.writes == ["put_public_access_block", "delete_public_access_block"]
    await db_session.refresh(finding)
    assert finding.status == "open"
    again = await client.post(f"/api/v1/cloud-posture/changes/{change.id}/rollback", headers=headers)
    assert again.status_code == 409


# ── plan / apply directly ───────────────────────────────────────────

async def test_ssh_fix_removes_only_the_internet_rules_that_cover_the_port(db_session, client, aws):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    finding = await _ssh_finding(db_session, org)

    planned = await remediation.plan(db_session, org, finding.id)

    assert len(planned["before"]) == 2 and planned["after"] == []
    assert "tcp port 22 from 0.0.0.0/0" in planned["change"]
    assert "tcp ports 20-25 (the whole range, not only 22) from ::/0" in planned["change"]
    assert aws.writes == []

    result = await remediation.apply(db_session, org, planned, requested_by="a@x", approved_by="b@x")

    assert result["verified"] is True
    assert aws.permissions == [WORLD_HTTPS, OFFICE_SSH]                       # everything else untouched
    change = (await db_session.execute(select(CloudChange))).scalar_one()
    await remediation.rollback(db_session, org, change.id, by="b@x")
    assert sorted(map(json.dumps, aws.permissions)) == sorted(map(json.dumps, [WORLD_SSH, WORLD_RANGE, WORLD_HTTPS, OFFICE_SSH]))


async def test_change_is_refused_if_the_resource_changed_after_approval(db_session, client, aws):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    planned = await remediation.plan(db_session, org, (await _ssh_finding(db_session, org)).id)
    aws.permissions.append({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})      # someone edits the group

    with pytest.raises(remediation.RemediationError, match="changed in AWS after"):
        await remediation.apply(db_session, org, planned)

    assert aws.writes == [] and (await db_session.execute(select(CloudChange))).first() is None


async def test_read_only_credentials_give_a_clear_error_and_record_nothing(db_session, client, aws):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    planned = await remediation.plan(db_session, org, (await _bucket_finding(db_session, org)).id)
    aws.deny_writes = True

    with pytest.raises(remediation.RemediationError, match="read-only"):
        await remediation.apply(db_session, org, planned)

    assert aws.block is None and (await db_session.execute(select(CloudChange))).first() is None


async def test_rollback_is_refused_if_the_resource_was_changed_again(db_session, client, aws):
    user, _ = await _user(db_session, client)
    org = user.organization_id
    planned = await remediation.plan(db_session, org, (await _bucket_finding(db_session, org)).id)
    await remediation.apply(db_session, org, planned)
    change = (await db_session.execute(select(CloudChange))).scalar_one()
    aws.block = {**aws.block, "BlockPublicPolicy": False}                      # someone edits it in AWS

    with pytest.raises(remediation.RemediationError, match="changed again"):
        await remediation.rollback(db_session, org, change.id, by="x@x")

    assert aws.writes == ["put_public_access_block"]


async def test_what_cannot_be_fixed_is_refused_before_anyone_is_asked(db_session, client, aws):
    user, _ = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    org = user.organization_id
    scan = await create_scan_in_db(db_session, org)
    code_finding = await create_finding_in_db(db_session, scan.id, rule_id="CKV_AWS_20")
    await _sync(db_session, org, "orders", "aws_rds_instance", publicly_accessible=True, storage_encrypted=True,
                backup_retention_period=7, deletion_protection=True)
    bucket = await _bucket_finding(db_session, org)
    rds = (await db_session.execute(select(Finding).where(Finding.rule_id == "GN-AWS-RDS-001"))).scalar_one()

    with pytest.raises(remediation.RemediationError, match="about code"):
        await remediation.plan(db_session, org, code_finding.id)
    with pytest.raises(remediation.RemediationError, match="cannot fix GN-AWS-RDS-001"):
        await remediation.plan(db_session, org, rds.id)
    with pytest.raises(remediation.RemediationError, match="not found"):
        await remediation.plan(db_session, other.organization_id, bucket.id)      # another organization's finding
    aws.block = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
    with pytest.raises(remediation.RemediationError, match="already has the correct setting"):
        await remediation.plan(db_session, org, bucket.id)
    assert aws.writes == []


# ── posture API ─────────────────────────────────────────────────────

async def test_posture_api_lists_every_rule_with_live_counts(db_session, client, aws):
    user, _ = await _user(db_session, client)
    _, other_headers = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    await _bucket_finding(db_session, user.organization_id)
    headers = await get_auth_headers_for(client, user.email)

    body = (await client.get("/api/v1/cloud-posture", headers=headers)).json()

    from app.services.cloud_posture.rules import RULES

    assert len(body["rules"]) == len(RULES)
    first = body["rules"][0]                                                 # failing rules first, most severe first
    assert (first["rule_id"], first["failing"], first["can_auto_fix"], first["cis_aws_1_4"]) == ("GN-AWS-S3-001", 1, True, "2.1.5")
    assert first["resources"][0]["name"] == "reports"
    versioning = next(r for r in body["rules"] if r["rule_id"] == "GN-AWS-S3-002")
    assert (versioning["failing"], versioning["passing"]) == (0, 1)
    assert body["by_severity"]["CRITICAL"] == 1 and body["evaluated"][0]["resources"] == 1
    assert body["exposure"]["buckets_without_public_access_block"] == ["reports"]

    empty = (await client.get("/api/v1/cloud-posture", headers=other_headers)).json()
    assert empty["open_findings"] == 0 and empty["evaluated"] == [] and empty["exposure"] is None
    assert all(r["failing"] == 0 and r["passing"] == 0 for r in empty["rules"])

    again = await client.post("/api/v1/cloud-posture/evaluate", headers=headers)
    assert again.status_code == 200 and again.json()["accounts"][0]["opened"] == 0
