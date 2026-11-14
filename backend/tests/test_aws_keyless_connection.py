"""Connecting AWS without access keys: the OIDC issuer, the CloudFormation template and the API flow."""
import json

import pytest
from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.encryption import decrypt_token
from app.models.cloud_account import CloudAccount
from app.models.oidc import OidcSigningKey
from app.services.federation import aws as aws_federation
from app.services.federation import issuer
from tests.test_agent_runtime import _user

ISSUER = "https://id.guardnous.example"
ACCOUNT = "111122223333"


@pytest.fixture
def public_issuer(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", ISSUER)


# ── issuer ──────────────────────────────────────────────────────────

def test_keyless_is_off_without_a_public_https_address(monkeypatch):
    for url in ("", "http://localhost:7002", "https://localhost:7002", "http://guardnous.example"):
        monkeypatch.setattr(settings, "OIDC_ISSUER_URL", url)
        with pytest.raises(issuer.FederationUnavailable):
            issuer.issuer_url()


async def test_tokens_verify_against_the_published_keys_and_the_private_key_is_encrypted(db_session, client, public_issuer):
    token = issuer.mint_token("guardnous:org:1:aws:111122223333:abc", "sts.amazonaws.com")
    published = (await client.get("/.well-known/jwks.json")).json()
    discovery = (await client.get("/.well-known/openid-configuration")).json()

    assert discovery["issuer"] == ISSUER and discovery["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert len(published["keys"]) == 1 and set(published["keys"][0]) == {"kty", "use", "alg", "kid", "n", "e"}   # public parts only
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256" and header["kid"] == published["keys"][0]["kid"]
    claims = jwt.decode(token, published["keys"][0], algorithms=["RS256"], audience="sts.amazonaws.com", issuer=ISSUER)
    assert claims["sub"] == "guardnous:org:1:aws:111122223333:abc"
    assert 0 < claims["exp"] - claims["iat"] <= 300

    issuer.mint_token("x" * 20, "sts.amazonaws.com")                       # a second token reuses the key
    keys = (await db_session.execute(select(OidcSigningKey))).scalars().all()
    assert len(keys) == 1
    assert "PRIVATE KEY" not in keys[0].private_pem_encrypted
    assert "PRIVATE KEY" in decrypt_token(keys[0].private_pem_encrypted)


# ── template ────────────────────────────────────────────────────────

def _lint(text: str) -> list[str]:
    api = pytest.importorskip("cfnlint.api")
    return [f"{m.rule.id} {m.message}" for m in api.lint_all(text) if m.rule.id.startswith("E")]


def test_template_is_valid_cloudformation():
    rendered = aws_federation.template(
        issuer_host="id.guardnous.example", subject=f"guardnous:org:7:aws:{ACCOUNT}:abc123", role_name="GuardNous-abc123",
    )
    assert _lint(rendered) == []
    assert _lint(aws_federation.template()) == []                          # the generic, parameter-only version
    assert _lint(aws_federation.template(issuer_host="a.example/x", subject="s" * 20, role_name="GuardNous-x", allow_fixes=True)) == []


def test_template_grants_read_only_unless_fixes_are_chosen_and_never_creates_keys():
    text = aws_federation.template(issuer_host="id.guardnous.example", subject="guardnous:org:7:aws:1:abc", role_name="GuardNous-abc")
    assert "AWS::IAM::AccessKey" not in text and "AWS::IAM::User" not in text
    assert "policy/SecurityAudit" in text
    assert '"${IssuerHost}:sub": "${Subject}"' in text and '"${IssuerHost}:aud": "sts.amazonaws.com"' in text
    assert "sts:AssumeRoleWithWebIdentity" in text
    assert 'Default: "false"\n    AllowedValues: ["true", "false"]\n    Description: >-\n      false = read-only' in text
    assert "Condition: Fixes" in text                                      # the write policy exists only behind the switch
    for action in aws_federation.FIX_ACTIONS:
        assert action in text


# ── API flow ────────────────────────────────────────────────────────

async def test_connect_flow_stores_no_secret_and_returns_a_ready_template(db_session, client, public_issuer):
    user, headers = await _user(db_session, client)
    _, other_headers = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")

    status = (await client.get("/api/v1/cloud-accounts/aws/federation", headers=headers)).json()
    assert status == {"available": True, "issuer": ISSUER, "reason": None}

    resp = await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": ACCOUNT}, headers=headers)
    assert resp.status_code == 201, resp.text
    account, setup = resp.json()["account"], resp.json()["setup"]
    assert (account["status"], account["keyless"], account["name"]) == ("pending", True, f"AWS {ACCOUNT}")
    assert setup["role_arn"] == f"arn:aws:iam::{ACCOUNT}:role/{setup['role_name']}"
    assert setup["subject"].startswith(f"guardnous:org:{user.organization_id}:aws:{ACCOUNT}:")
    assert setup["cli_command"].startswith(f"aws cloudformation deploy --stack-name {setup['stack_name']} ")
    assert "CAPABILITY_NAMED_IAM" in setup["cli_command"] and setup["quick_create_url"] is None

    row = (await db_session.execute(select(CloudAccount).where(CloudAccount.id == account["id"]))).scalar_one()
    stored = json.loads(decrypt_token(row.credentials_encrypted))
    assert set(stored) == {"auth", "role_arn", "role_name", "stack_name", "subject", "issuer", "allow_fixes"}
    assert not any("secret" in k or "key" in k for k in stored)

    template = await client.get(f"/api/v1/cloud-accounts/{account['id']}/aws-template", headers=headers)
    assert template.status_code == 200 and "attachment" in template.headers["content-disposition"]
    assert f'Default: "{setup["subject"]}"' in template.text and f'Default: "{setup["role_name"]}"' in template.text
    assert 'Default: "id.guardnous.example"' in template.text
    assert (await client.get(f"/api/v1/cloud-accounts/{account['id']}/aws-setup", headers=headers)).json() == setup

    # private to the organization; no duplicates; account ID is validated
    assert (await client.get(f"/api/v1/cloud-accounts/{account['id']}/aws-template", headers=other_headers)).status_code == 404
    again = await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": ACCOUNT}, headers=headers)
    assert again.status_code == 409
    bad = await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": "12345"}, headers=headers)
    assert bad.status_code == 422


async def test_connect_is_refused_with_the_reason_when_no_public_address_is_set(db_session, client, monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", "")
    _, headers = await _user(db_session, client)

    status = (await client.get("/api/v1/cloud-accounts/aws/federation", headers=headers)).json()
    assert status["available"] is False and "public HTTPS address" in status["reason"]
    resp = await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": ACCOUNT}, headers=headers)
    assert resp.status_code == 409
    assert (await db_session.execute(select(CloudAccount))).first() is None


async def test_one_click_link_is_offered_when_a_hosted_template_is_configured(db_session, client, public_issuer, monkeypatch):
    monkeypatch.setattr(settings, "AWS_ONBOARDING_TEMPLATE_URL", "https://gn-public.s3.amazonaws.com/guardnous-access.yaml")
    _, headers = await _user(db_session, client)

    setup = (await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": ACCOUNT, "allow_fixes": True}, headers=headers)).json()["setup"]

    link = setup["quick_create_url"]
    assert link.startswith("https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL=https%3A%2F%2Fgn-public")
    assert f"&stackName={setup['stack_name']}" in link and "&param_AllowFixes=true" in link
    assert "&param_IssuerHost=id.guardnous.example" in link and f"&param_RoleName={setup['role_name']}" in link


# ── the AWS call ────────────────────────────────────────────────────

class _Refused(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


async def test_verify_exchanges_a_signed_token_for_temporary_credentials(db_session, client, public_issuer, monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from tests.aws_model import ModelSession

    _, headers = await _user(db_session, client)
    created = (await client.post("/api/v1/cloud-accounts/aws/federated", json={"account_id": ACCOUNT}, headers=headers)).json()
    account_id, setup = created["account"]["id"], created["setup"]

    model = ModelSession()                                                 # validates the STS call against the AWS API
    model.client("sts")                                                    # built before boto3 is patched below
    seen = {}

    def fake_client(service, **kwargs):
        seen["config"] = kwargs.get("config")
        return model.client(service)

    class FakeSession:
        def __init__(self, **kwargs):
            seen["session"] = kwargs

        def client(self, service, **kwargs):
            return model.client(service)

    monkeypatch.setattr(boto3, "client", fake_client)
    monkeypatch.setattr(boto3, "Session", FakeSession)

    result = (await client.post(f"/api/v1/cloud-accounts/{account_id}/test", headers=headers)).json()

    assert result["status"] == "connected", result
    service, method, kwargs = model.calls[0]
    assert (service, method) == ("sts", "assume_role_with_web_identity")
    assert kwargs["RoleArn"] == setup["role_arn"] and kwargs["DurationSeconds"] == 3600
    claims = jwt.get_unverified_claims(kwargs["WebIdentityToken"])
    assert (claims["iss"], claims["sub"], claims["aud"]) == (ISSUER, setup["subject"], "sts.amazonaws.com")
    from botocore import UNSIGNED

    assert seen["config"].signature_version is UNSIGNED                    # the call itself carries no AWS credentials
    assert set(seen["session"]) == {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
    row = (await db_session.execute(select(CloudAccount).where(CloudAccount.id == account_id))).scalar_one()
    await db_session.refresh(row)
    assert row.status == "connected"

    # before the stack exists, the error says what to do
    model.overrides[("sts", "assume_role_with_web_identity")] = _Refused(
        "InvalidIdentityToken", "No OpenIDConnect provider found in your account for https://id.guardnous.example",
    )
    pending = (await client.post(f"/api/v1/cloud-accounts/{account_id}/test", headers=headers)).json()
    assert pending["status"] == "error" and f"Deploy the CloudFormation stack '{setup['stack_name']}'" in pending["error"]
