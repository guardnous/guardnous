"""IAM posture analysis over the synced cloud inventory.

Turns IAM resources discovered by the cloud connectors into identities, posture
findings ("threats") and attack paths. Everything is derived from the resource
configuration by fixed rules; each finding carries the evidence it was derived
from, and nothing is generated when the data is absent.

Coverage:
  * AWS   — IAM users and roles (aws_iam_user, aws_iam_role): full rule set.
  * Azure — role assignments (azurerm_role_assignment): privileged principals.
  * GCP   — project IAM bindings (google_project_iam_binding): privileged and
            public members.

Posture findings describe misconfiguration, not observed attacker activity.
Behavioural detection (log ingestion, anomaly detection) is not implemented.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

IAM_RESOURCE_TYPES = {
    "aws": ("aws_iam_user", "aws_iam_role"),
    "azure": ("azurerm_role_assignment",),
    "gcp": ("google_project_iam_binding",),
}

STALE_KEY_DAYS = 90
DORMANT_DAYS = 90

# AWS managed policies that grant account-wide or IAM-wide control
_AWS_ADMIN_POLICIES = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}
_AZURE_PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator"}


@dataclass
class Threat:
    threat_type: str
    title: str
    description: str
    severity: str  # critical | high | medium | low
    weight: int  # contribution to the identity's risk score
    evidence: dict
    mitre_technique: str | None = None
    remediation: list[str] = field(default_factory=list)


@dataclass
class PathSpec:
    title: str
    description: str
    severity: str
    complexity: str
    target_resource: str
    steps: list[dict]


@dataclass
class IdentityPosture:
    provider: str
    identity_type: str  # user | role | service_account | group
    external_id: str
    display_name: str
    is_active: bool = True
    last_activity: datetime | None = None
    created_externally: datetime | None = None
    days_inactive: int = 0
    admin_access: bool = False
    mfa_enabled: bool | None = None
    has_console_access: bool | None = None
    has_programmatic_access: bool | None = None
    access_keys: list[dict] = field(default_factory=list)
    credential_age_days: int = 0
    attached_policies: list[dict] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    threats: list[Threat] = field(default_factory=list)
    paths: list[PathSpec] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        return float(min(100, sum(t.weight for t in self.threats)))

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "critical"
        if score >= 45:
            return "high"
        if score >= 20:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @property
    def risk_factors(self) -> list[dict]:
        return [{"factor": t.threat_type, "score": t.weight, "details": t.title} for t in self.threats]


def _parse_dt(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _days_since(dt: datetime | None, now: datetime) -> int | None:
    return max(0, (now - dt).days) if dt else None


# ── AWS ────────────────────────────────────────────────────────────────────────

def _aws_account_label(arn: str) -> str:
    parts = arn.split(":")
    return f"AWS account {parts[4]}" if len(parts) > 4 and parts[4] else "AWS account administration"


def _aws_user(resource_id: str, name: str, cfg: dict, now: datetime) -> IdentityPosture:
    policies = list(cfg.get("attached_policies") or [])
    admin_policies = sorted(set(policies) & _AWS_ADMIN_POLICIES)
    is_admin = bool(cfg.get("has_admin_access")) or bool(admin_policies)
    console = bool(cfg.get("has_console_access"))
    mfa = cfg.get("mfa_enabled")  # None = could not be determined

    keys = []
    oldest_active_age = 0
    active_keys = 0
    for k in cfg.get("access_keys") or []:
        age = _days_since(_parse_dt(k.get("created")), now)
        active = k.get("status") == "Active"
        if active:
            active_keys += 1
            oldest_active_age = max(oldest_active_age, age or 0)
        keys.append({"key_id": k.get("access_key_id"), "status": k.get("status"), "age_days": age})

    created = _parse_dt(cfg.get("created"))
    last_login = _parse_dt(cfg.get("password_last_used"))
    # Only console sign-in time is collected; key last-used is not, so inactivity
    # is asserted only for console users without active keys.
    days_inactive = 0
    if console and active_keys == 0:
        days_inactive = _days_since(last_login or created, now) or 0

    ident = IdentityPosture(
        provider="aws", identity_type="user", external_id=resource_id, display_name=name,
        last_activity=last_login, created_externally=created, days_inactive=days_inactive,
        admin_access=is_admin, mfa_enabled=mfa, has_console_access=console,
        has_programmatic_access=active_keys > 0, access_keys=keys,
        credential_age_days=oldest_active_age,
        attached_policies=[{"name": p, "type": "managed"} for p in policies],
        raw_data=cfg,
    )

    if console and mfa is False:
        ident.threats.append(Threat(
            "mfa_disabled",
            f"Console user without MFA: {name}",
            "The user can sign in to the AWS console with a password only."
            + (" The user has administrative policies attached." if is_admin else ""),
            "critical" if is_admin else "high",
            45 if is_admin else 30,
            {"has_console_access": True, "mfa_enabled": False, "admin_policies": admin_policies},
            "T1078.004",
            ["Enable a virtual or hardware MFA device for the user",
             "Add an IAM policy condition requiring aws:MultiFactorAuthPresent"],
        ))
    if is_admin:
        ident.threats.append(Threat(
            "excessive_permissions",
            f"IAM user with administrative access: {name}",
            "Administrative managed policies are attached directly to a long-lived IAM user.",
            "high", 25,
            {"attached_policies": policies, "admin_policies": admin_policies or ["AdministratorAccess"]},
            "T1098",
            ["Replace the user's standing admin access with a role assumed on demand",
             "Scope permissions to the actions the user needs"],
        ))
    if active_keys and oldest_active_age > STALE_KEY_DAYS:
        ident.threats.append(Threat(
            "credential_exposure",
            f"Access key not rotated for {oldest_active_age} days: {name}",
            f"An active access key is older than {STALE_KEY_DAYS} days.",
            "high" if is_admin else "medium",
            25 if is_admin else 15,
            {"active_keys": [k for k in keys if k["status"] == "Active"], "threshold_days": STALE_KEY_DAYS},
            "T1552.001",
            ["Create a new access key, update consumers, then deactivate and delete the old key"],
        ))
    if active_keys > 1:
        ident.threats.append(Threat(
            "multiple_access_keys",
            f"Multiple active access keys: {name}",
            "More than one active access key widens the credential exposure surface.",
            "low", 5, {"active_key_count": active_keys}, "T1552.001",
            ["Deactivate and delete the key that is not in use"],
        ))
    if days_inactive > DORMANT_DAYS:
        ident.threats.append(Threat(
            "dormant_admin" if is_admin else "dormant_identity",
            f"Dormant {'admin ' if is_admin else ''}user ({days_inactive} days): {name}",
            f"No console sign-in for more than {DORMANT_DAYS} days and no active access keys.",
            "high" if is_admin else "medium",
            25 if is_admin else 10,
            {"days_inactive": days_inactive, "password_last_used": cfg.get("password_last_used"),
             "created": cfg.get("created")},
            "T1078.004",
            ["Disable console access and remove the user if no longer needed"],
        ))

    if is_admin and console and mfa is False:
        ident.paths.append(PathSpec(
            f"Password compromise of {name} leads to account administration",
            "A console password with no second factor is the only barrier to administrative access.",
            "critical", "low", _aws_account_label(resource_id),
            [
                {"step_num": 1, "action": "Obtain console password (phishing, reuse, guessing)", "resource": resource_id},
                {"step_num": 2, "action": "Sign in to the console — no MFA challenge", "resource": resource_id},
                {"step_num": 3, "action": "Use attached administrative policy",
                 "resource": ", ".join(admin_policies or ["AdministratorAccess"])},
            ],
        ))
    if is_admin and active_keys and oldest_active_age > STALE_KEY_DAYS:
        ident.paths.append(PathSpec(
            f"Leaked long-lived key of {name} leads to account administration",
            "An old, never-rotated access key carries administrative permissions and needs no MFA.",
            "critical", "medium", "AWS account administration",
            [
                {"step_num": 1, "action": f"Recover access key ({oldest_active_age} days old) from code, CI logs or a workstation",
                 "resource": resource_id},
                {"step_num": 2, "action": "Call AWS APIs with the key", "resource": resource_id},
                {"step_num": 3, "action": "Use attached administrative policy",
                 "resource": ", ".join(admin_policies or ["AdministratorAccess"])},
            ],
        ))
    return ident


def _aws_role(resource_id: str, name: str, cfg: dict, now: datetime) -> IdentityPosture:
    policies = list(cfg.get("attached_policies") or [])
    admin_policies = sorted(set(policies) & _AWS_ADMIN_POLICIES)
    is_admin = bool(cfg.get("has_admin_access")) or bool(admin_policies)
    principals = [str(p) for p in cfg.get("trust_policy_principals") or []]
    wildcard = "*" in principals
    cross_account = bool(cfg.get("allows_cross_account"))
    external = [p for p in principals if p.startswith("arn:aws:iam::")] if cross_account else []

    ident = IdentityPosture(
        provider="aws", identity_type="role", external_id=resource_id, display_name=name,
        created_externally=_parse_dt(cfg.get("created")), admin_access=is_admin,
        has_console_access=False, has_programmatic_access=True,
        attached_policies=[{"name": p, "type": "managed"} for p in policies],
        raw_data=cfg,
    )

    if wildcard:
        ident.threats.append(Threat(
            "public_trust",
            f"Role assumable by any AWS principal: {name}",
            "The trust policy names '*' as principal, so any AWS account can attempt to assume the role.",
            "critical", 60, {"trust_policy_principals": principals}, "T1550.001",
            ["Restrict the trust policy to specific principals and add an sts:ExternalId condition"],
        ))
    elif cross_account:
        ident.threats.append(Threat(
            "cross_account",
            f"Role trusts another AWS account: {name}",
            "A principal outside this account can assume the role."
            + (" The role has administrative policies attached." if is_admin else ""),
            "high" if is_admin else "medium",
            35 if is_admin else 15,
            {"external_principals": external, "admin_policies": admin_policies},
            "T1550.001",
            ["Confirm the external account is expected", "Require an sts:ExternalId condition in the trust policy"],
        ))
    if is_admin:
        ident.threats.append(Threat(
            "excessive_permissions",
            f"Role with administrative access: {name}",
            "Administrative managed policies are attached to the role.",
            "medium", 20, {"attached_policies": policies, "admin_policies": admin_policies or ["AdministratorAccess"]},
            "T1098",
            ["Scope the role's permissions to what its workload needs"],
        ))

    if is_admin and (wildcard or cross_account):
        ident.paths.append(PathSpec(
            f"External principal can assume administrative role {name}",
            "The role's trust policy admits principals outside the account and the role is administrative.",
            "critical", "low" if wildcard else "medium", "AWS account administration",
            [
                {"step_num": 1, "action": "Control a trusted external principal",
                 "resource": "*" if wildcard else ", ".join(external)},
                {"step_num": 2, "action": "sts:AssumeRole", "resource": resource_id},
                {"step_num": 3, "action": "Use attached administrative policy",
                 "resource": ", ".join(admin_policies or ["AdministratorAccess"])},
            ],
        ))
    return ident


# ── Azure / GCP ────────────────────────────────────────────────────────────────

def _azure_assignments(resources: list[dict]) -> list[IdentityPosture]:
    """One identity per principal, aggregated over its role assignments."""
    by_principal: dict[str, list[dict]] = {}
    for r in resources:
        cfg = r["config"] or {}
        if cfg.get("principal_id"):
            by_principal.setdefault(cfg["principal_id"], []).append(cfg)

    out = []
    for principal_id, assignments in by_principal.items():
        ptype = (assignments[0].get("principal_type") or "").lower()
        privileged = [a for a in assignments if a.get("role_definition_name") in _AZURE_PRIVILEGED_ROLES]
        sub_scope = [a for a in privileged if a.get("is_subscription_scope")]
        ident = IdentityPosture(
            provider="azure",
            identity_type={"user": "user", "group": "group"}.get(ptype, "service_account"),
            external_id=principal_id, display_name=principal_id, admin_access=bool(sub_scope),
            attached_policies=[{"name": a.get("role_definition_name"), "scope": a.get("scope"), "type": "role_assignment"}
                               for a in assignments],
            raw_data={"assignments": assignments},
        )
        if sub_scope:
            roles = sorted({a["role_definition_name"] for a in sub_scope})
            is_sp = ident.identity_type == "service_account"
            ident.threats.append(Threat(
                "excessive_permissions",
                f"{'Service principal' if is_sp else 'Principal'} with {', '.join(roles)} on the whole subscription",
                "A privileged built-in role is assigned at subscription scope rather than a resource group or resource.",
                "high", 40 if "Owner" in roles or "User Access Administrator" in roles else 30,
                {"roles": roles, "scopes": sorted({a.get("scope") for a in sub_scope})},
                "T1098.003",
                ["Reassign the role at the narrowest scope that works",
                 "Use Privileged Identity Management for just-in-time elevation"],
            ))
        out.append(ident)
    return out


def _gcp_bindings(resources: list[dict]) -> list[IdentityPosture]:
    """One identity per member, aggregated over the project's role bindings."""
    by_member: dict[str, list[str]] = {}
    for r in resources:
        cfg = r["config"] or {}
        for member in cfg.get("members") or []:
            by_member.setdefault(member, []).append(cfg.get("role", ""))

    out = []
    for member, roles in by_member.items():
        public = member in ("allUsers", "allAuthenticatedUsers")
        privileged = sorted({r for r in roles if r in ("roles/owner", "roles/editor", "roles/iam.securityAdmin")})
        kind = member.split(":", 1)[0]
        ident = IdentityPosture(
            provider="gcp",
            identity_type={"user": "user", "group": "group", "serviceAccount": "service_account"}.get(kind, "group"),
            external_id=member, display_name=member.split(":", 1)[-1], admin_access=bool(privileged),
            attached_policies=[{"name": r, "type": "project_role"} for r in sorted(set(roles))],
            raw_data={"roles": sorted(set(roles))},
        )
        if public:
            ident.threats.append(Threat(
                "public_trust",
                f"Project role granted to {member}",
                "A project-level role is granted to everyone on the internet"
                + (" with a Google account." if member == "allAuthenticatedUsers" else "."),
                "critical", 70, {"member": member, "roles": sorted(set(roles))}, "T1078.004",
                ["Remove the public member from the project IAM policy"],
            ))
        elif privileged:
            ident.threats.append(Threat(
                "excessive_permissions",
                f"Primitive privileged role on project: {ident.display_name}",
                "Owner/Editor primitive roles grant very broad access; use predefined or custom roles.",
                "high" if "roles/owner" in privileged else "medium",
                35 if "roles/owner" in privileged else 20,
                {"roles": privileged}, "T1098",
                ["Replace primitive roles with least-privilege predefined roles"],
            ))
        out.append(ident)
    return out


# ── Entry point ────────────────────────────────────────────────────────────────

def analyze(provider: str, resources: Iterable[dict], now: datetime | None = None) -> list[IdentityPosture]:
    """Analyze IAM resources of one provider.

    ``resources`` are dicts with resource_type, resource_id, resource_name, config.
    """
    now = now or datetime.now(timezone.utc)
    rows = [r for r in resources if r.get("resource_type") in IAM_RESOURCE_TYPES.get(provider, ())]
    if provider == "aws":
        out = []
        for r in rows:
            fn = _aws_user if r["resource_type"] == "aws_iam_user" else _aws_role
            out.append(fn(r["resource_id"], r["resource_name"], r.get("config") or {}, now))
        return out
    if provider == "azure":
        return _azure_assignments(rows)
    if provider == "gcp":
        return _gcp_bindings(rows)
    raise ValueError(f"Unsupported provider: {provider}")
