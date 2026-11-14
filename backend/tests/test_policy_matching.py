"""How security policies decide that a scan finding violates them."""
import pytest

from app.services.governance.finding_policies import finding_matches, rule_id_matches
from app.services.security.policy_engine import BUILT_IN_BY_ID, PolicyEngine, builtin_policy_rules
from tests.conftest import get_auth_headers


def _rules(policy_id: str) -> list[dict]:
    return builtin_policy_rules(BUILT_IN_BY_ID[policy_id])


def _violated(finding: dict) -> set[str]:
    return {pid for pid in BUILT_IN_BY_ID if finding_matches(_rules(pid), finding)}


class TestRuleIdMatching:
    @pytest.mark.parametrize("pattern,rule_id,expected", [
        ("CKV_AWS_20", "CKV_AWS_20", True),
        ("CKV_AWS_1", "CKV_AWS_19", False),          # not a prefix of a longer number
        ("CKV_AWS_1", "CKV_AWS_1", True),
        ("AVD-AWS-0086", "TFSEC-AVD-AWS-0086", True),  # tfsec keeps the AVD- part
        ("AVD-AWS-0086", "TRIVY-AWS-0086", True),      # trivy drops it
        ("AVD-AWS-0086", "TRIVY-AWS-0087", False),
        ("SD-TF", "SD-TF-003", True),                 # a family
        ("SD-TF", "SD-TFX-003", False),
        ("SEC-AWS-", "SEC-AWS-001", True),
        ("sg-aws-s3-public-acl", "SG-aws-s3-public-acl", True),
        ("test123", "SD-TF-003", False),
        ("", "SD-TF-003", False),
    ])
    def test_matches(self, pattern, rule_id, expected):
        assert rule_id_matches(pattern, rule_id) is expected


class TestBuiltInPolicies:
    def test_public_bucket_violates_the_public_bucket_policy_only(self):
        finding = {
            "rule_id": "SD-TF-003", "category": "iac", "resource_type": "aws_s3_bucket",
            "title": "S3 bucket has public ACL: public-read",
            "description": "Bucket ACL grants public access; data may be encrypted or not",
        }
        assert _violated(finding) == {"POL-S3-001"}

    def test_unencrypted_bucket_is_not_a_public_bucket(self):
        """The regression: any finding mentioning S3 used to violate every storage policy."""
        finding = {
            "rule_id": "SD-TF-002", "category": "iac", "resource_type": "aws_s3_bucket",
            "title": "S3 bucket 'data' uses default SSE-S3 encryption only", "description": "",
        }
        assert _violated(finding) == {"POL-S3-002"}

    def test_same_check_from_different_scanners(self):
        for rule_id in ("TFSEC-AVD-AWS-0092", "TRIVY-AWS-0092", "CKV_AWS_20", "SG-aws-s3-public-acl"):
            assert "POL-S3-001" in _violated({"rule_id": rule_id, "category": "iac"}), rule_id

    def test_secrets_policy_is_topic_wide(self):
        assert _violated({"rule_id": "SEC-AWS-001", "category": "secrets"}) == {"POL-SEC-001"}
        # A scanner the policy does not list by ID, but which classifies the finding as a secret
        assert "POL-SEC-001" in _violated({"rule_id": "NEW-SCANNER-9", "category": "secrets"})

    def test_ssh_and_rdp_are_separate(self):
        assert "POL-NET-002" in _violated({"rule_id": "SD-TF-012", "category": "iac"})
        assert "POL-NET-003" not in _violated({"rule_id": "SD-TF-012", "category": "iac"})

    def test_unrelated_finding_violates_nothing(self):
        finding = {"rule_id": "SD-TF-014", "category": "iac", "title": "Resource 'data' missing tags",
                   "resource_type": "aws_s3_bucket"}
        assert _violated(finding) == set()

    def test_scan_summary_engine_agrees(self):
        """The engine behind a scan's passed/failed policy counts uses the same matching."""
        results, _stats = PolicyEngine().evaluate([{
            "rule_id": "SD-TF-002", "category": "iac", "severity": "HIGH", "resource_type": "aws_s3_bucket",
            "title": "S3 bucket 'data' uses default SSE-S3 encryption only", "description": "",
        }])
        failed = {r.policy_id for r in results if r.status == "failed"}
        assert failed == {"POL-S3-002"}


class TestSeedRefreshesBuiltIns:
    @pytest.mark.asyncio
    async def test_reseeding_replaces_outdated_rules(self, client, db_session):
        from sqlalchemy import select
        from app.models.governance import SecurityPolicy

        headers = await get_auth_headers(client)
        first = await client.post("/api/v1/governance/policies/seed", headers=headers)
        assert first.json()["created"] == len(BUILT_IN_BY_ID)

        async with db_session as db:
            policy = (await db.execute(
                select(SecurityPolicy).where(SecurityPolicy.name == "No Public S3 Buckets")
            )).scalar_one()
            policy.rules = [{"policy_id": "POL-S3-001", "rule_id_prefixes": [], "categories": ["storage"]}]
            policy.is_enforced = True  # the organization's own choice
            await db.commit()

        again = (await client.post("/api/v1/governance/policies/seed", headers=headers)).json()
        assert again["created"] == 0 and again["updated"] == 1

        async with db_session as db:
            policy = (await db.execute(
                select(SecurityPolicy).where(SecurityPolicy.name == "No Public S3 Buckets")
            )).scalar_one()
            assert policy.rules == _rules("POL-S3-001")
            assert policy.is_enforced is True
