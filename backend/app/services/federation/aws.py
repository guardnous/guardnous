"""Connecting an AWS account without access keys.

The customer deploys one CloudFormation stack. It registers GuardNous's issuer
as an identity provider and creates a read-only role that only tokens with this
connection's subject may assume. GuardNous then calls
``sts:AssumeRoleWithWebIdentity`` with a token it signs itself and receives
credentials that expire after an hour.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import quote

from app.core.config import settings
from app.services.federation import issuer

AUDIENCE = "sts.amazonaws.com"
ACCOUNT_ID = re.compile(r"^\d{12}$")

# Write actions for the fixes GuardNous can make (and undo). Granted only when the
# customer deploys the stack with AllowFixes=true.
FIX_ACTIONS = [
    "s3:PutBucketPublicAccessBlock",
    "ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress",
    "ec2:EnableEbsEncryptionByDefault", "ec2:DisableEbsEncryptionByDefault",
    "kms:EnableKeyRotation", "kms:DisableKeyRotation",
]


def new_connection(organization_id: int, account_id: str) -> dict:
    """Identifiers for a new connection. Nothing here is secret."""
    nonce = secrets.token_hex(6)
    role_name = f"GuardNous-{nonce}"
    return {
        "auth": "oidc",
        "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}",
        "role_name": role_name,
        "stack_name": f"GuardNous-{nonce}",
        "subject": f"guardnous:org:{organization_id}:aws:{account_id}:{nonce}",
        "issuer": issuer.issuer_url(),
    }


def template(*, issuer_host: str = "", subject: str = "", role_name: str = "", allow_fixes: bool = False) -> str:
    """The CloudFormation template. With empty arguments it is the generic one
    that takes everything as parameters."""
    actions = "\n".join(f"              - {a}" for a in FIX_ACTIONS)

    def default(value: str) -> str:
        # The generic template has no defaults: an empty one would break the length checks.
        return f'\n    Default: "{value}"' if value else ""

    return f"""AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  GuardNous access through OIDC federation. Creates an identity provider and one IAM role.
  No access keys or passwords are created. Delete this stack to disconnect GuardNous.

Parameters:
  IssuerHost:
    Type: String{default(issuer_host)}
    Description: GuardNous issuer address without https://. Do not change.
    AllowedPattern: "^[A-Za-z0-9.-]+(/[A-Za-z0-9._/-]*)?$"
  Subject:
    Type: String{default(subject)}
    Description: Identifies this GuardNous connection. Only tokens with exactly this subject can use the role. Do not change.
    MinLength: 20
  RoleName:
    Type: String{default(role_name)}
    Description: Name of the role GuardNous will use. Do not change.
    MinLength: 5
  CreateIdentityProvider:
    Type: String
    Default: "true"
    AllowedValues: ["true", "false"]
    Description: Set to false only if this account already has an identity provider for the GuardNous issuer.
  AllowFixes:
    Type: String
    Default: "{'true' if allow_fixes else 'false'}"
    AllowedValues: ["true", "false"]
    Description: >-
      false = read-only. true = GuardNous may also make the specific fixes it offers (block S3 public access,
      remove internet SSH/RDP rules, EBS default encryption, KMS rotation), each only after a person approves it.

Conditions:
  CreateProvider: !Equals [!Ref CreateIdentityProvider, "true"]
  Fixes: !Equals [!Ref AllowFixes, "true"]

Resources:
  GuardNousIdentityProvider:
    Type: AWS::IAM::OIDCProvider
    Condition: CreateProvider
    Properties:
      Url: !Sub "https://${{IssuerHost}}"
      ClientIdList:
        - {AUDIENCE}

  GuardNousRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Description: Used by GuardNous through OIDC federation. Read-only unless the stack was deployed with AllowFixes=true.
      MaxSessionDuration: 3600
      ManagedPolicyArns:
        - !Sub "arn:${{AWS::Partition}}:iam::aws:policy/SecurityAudit"
      AssumeRolePolicyDocument:
        Fn::Sub:
          - |
            {{
              "Version": "2012-10-17",
              "Statement": [{{
                "Effect": "Allow",
                "Principal": {{"Federated": "${{ProviderArn}}"}},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {{"StringEquals": {{
                  "${{IssuerHost}}:aud": "{AUDIENCE}",
                  "${{IssuerHost}}:sub": "${{Subject}}"
                }}}}
              }}]
            }}
          - ProviderArn: !If
              - CreateProvider
              - !Ref GuardNousIdentityProvider
              - !Sub "arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:oidc-provider/${{IssuerHost}}"

  GuardNousFixesPolicy:
    Type: AWS::IAM::Policy
    Condition: Fixes
    Properties:
      Roles:
        - !Ref GuardNousRole
      PolicyName: GuardNousApprovedFixes
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Resource: "*"
            Action:
{actions}

Outputs:
  RoleArn:
    Value: !GetAtt GuardNousRole.Arn
  Access:
    Value: !If [Fixes, "read-only plus approved fixes", "read-only"]
"""


def setup_instructions(creds: dict, account_id: str, *, allow_fixes: bool) -> dict:
    """Everything the UI shows so the customer can deploy the stack."""
    filename = f"guardnous-aws-{account_id}.yaml"
    out = {
        "account_id": account_id, "role_arn": creds["role_arn"], "role_name": creds["role_name"],
        "stack_name": creds["stack_name"], "issuer": creds["issuer"], "subject": creds["subject"],
        "access": "read-only plus approved fixes" if allow_fixes else "read-only",
        "template_filename": filename,
        "cli_command": (
            f"aws cloudformation deploy --stack-name {creds['stack_name']} --template-file {filename} "
            "--capabilities CAPABILITY_NAMED_IAM"
        ),
        "console_url": "https://console.aws.amazon.com/cloudformation/home#/stacks/create",
        "quick_create_url": None,
    }
    if settings.AWS_ONBOARDING_TEMPLATE_URL:
        params = {
            "IssuerHost": creds["issuer"].removeprefix("https://"), "Subject": creds["subject"],
            "RoleName": creds["role_name"], "AllowFixes": "true" if allow_fixes else "false",
        }
        out["quick_create_url"] = (
            "https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate"
            f"?templateURL={quote(settings.AWS_ONBOARDING_TEMPLATE_URL, safe='')}&stackName={creds['stack_name']}"
            + "".join(f"&param_{k}={quote(v, safe='')}" for k, v in params.items())
        )
    return out


def assume_role(creds: dict):
    """Exchange a freshly signed token for a boto3 session that lasts an hour."""
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config

    token = issuer.mint_token(creds["subject"], AUDIENCE)
    sts = boto3.client("sts", region_name="us-east-1", config=Config(signature_version=UNSIGNED))
    try:
        resp = sts.assume_role_with_web_identity(
            RoleArn=creds["role_arn"], RoleSessionName="guardnous", WebIdentityToken=token, DurationSeconds=3600,
        )
    except Exception as exc:  # noqa: BLE001
        raise ConnectionError(explain(exc, creds)) from exc
    temp = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=temp["AccessKeyId"], aws_secret_access_key=temp["SecretAccessKey"],
        aws_session_token=temp["SessionToken"],
    )


def explain(exc: Exception, creds: dict) -> str:
    """Why AWS refused, in terms of what the customer should check."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") or type(exc).__name__
    message = getattr(exc, "response", {}).get("Error", {}).get("Message", "") or str(exc)
    stack = creds.get("stack_name", "the GuardNous stack")
    if code == "InvalidIdentityToken" and "No OpenIDConnect provider found" in message:
        return f"AWS has no identity provider for GuardNous in this account yet. Deploy the CloudFormation stack '{stack}' and wait for it to finish."
    if code == "InvalidIdentityToken":
        return (
            f"AWS could not verify GuardNous's token ({message}). It must be able to download "
            f"{creds.get('issuer', '')}/.well-known/openid-configuration from the internet."
        )
    if code == "AccessDenied":
        return (
            f"AWS refused the role {creds.get('role_arn')}. Either the stack '{stack}' is not deployed in this account "
            "yet, or its Subject / IssuerHost parameters were changed."
        )
    return f"AWS refused the connection: {code}: {message}"
