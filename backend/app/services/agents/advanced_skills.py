"""Advanced production-grade investigation & triage skills — the GOLD MINE.

Extends the base investigation_skills with 12 additional deep-domain skills
covering the full spectrum of enterprise security operations:

  1.  Container Runtime Security (Docker, containerd, CRI-O, OCI)
  2.  CI/CD Pipeline Security (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines)
  3.  API Security Assessment (OWASP API Top 10, GraphQL, gRPC)
  4.  DNS & Domain Security (dangling DNS, subdomain takeover, zone transfer)
  5.  SSL/TLS Certificate Management (expiry, weak ciphers, chain issues)
  6.  Zero Trust Architecture Assessment (identity-centric, micro-segmentation)
  7.  Network Segmentation Analysis (flat networks, lateral movement paths)
  8.  Endpoint & EDR Posture (agent coverage, detection gaps, response time)
  9.  Cloud Cost Anomaly as Security Signal (crypto-mining, exfiltration)
  10. Threat Modeling (STRIDE, DREAD, attack trees)
  11. Data Loss Prevention (DLP) Assessment (classification, egress controls)
  12. Identity & Access Governance (lifecycle, orphan accounts, MFA coverage)

Each skill:
  - Queries REAL findings data from the organization's database
  - Classifies using domain-specific keyword taxonomies
  - Produces structured, actionable output (not vague advice)
  - Includes severity scoring, priority ranking, and concrete remediation
  - Is wired into the LLM tool-calling schema for autonomous invocation

Designed for enterprise SOC teams, where incomplete analysis means missed
breaches.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, Scan

logger = logging.getLogger(__name__)


class _Ctx:
    """Minimal context expected by each skill."""
    __slots__ = ("db", "organization_id")
    def __init__(self, db: AsyncSession, organization_id: int):
        self.db = db
        self.organization_id = organization_id


async def _fetch_active_findings(ctx: _Ctx) -> list:
    """Shared helper — fetch all active findings for the org."""
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == ctx.organization_id,
            Finding.is_fixed == False,
            Finding.is_ignored == False,
        )
    )
    return list((await ctx.db.execute(stmt)).scalars().all())


def _classify(finding, keywords: list[str]) -> bool:
    """Check if a finding matches any keyword in title/resource/file."""
    haystack = " ".join([
        (finding.title or "").lower(),
        (finding.resource_name or "").lower(),
        (finding.file_path or "").lower(),
        (finding.remediation or "").lower(),
    ])
    return any(kw in haystack for kw in keywords)


def _severity_rank(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
        (s or "").upper(), 5
    )


def _as_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "resource": f.resource_name,
        "file": f.file_path,
        "recommendation": (f.remediation or "")[:500],
    }


# ═══════════════════════════════════════════════════════════════════
# 1. Container Runtime Security
# ═══════════════════════════════════════════════════════════════════

_CONTAINER_KW = [
    "container", "docker", "dockerfile", "containerd", "cri-o", "podman",
    "privileged", "host network", "hostpid", "hostipc", "cap_sys_admin",
    "cap_net_raw", "seccomp", "apparmor", "selinux", "read-only root",
    "root user", "image tag", "latest tag", "healthcheck", "oci",
    "entrypoint", "user namespace", "cgroup", "no-new-privileges",
]


async def investigate_container_security(ctx: _Ctx, **kw: Any) -> dict:
    """Container runtime security — Docker, containerd, CRI-O, OCI compliance."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _CONTAINER_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    privileged = [f for f in hits if _classify(f, ["privileged", "cap_sys_admin", "hostpid"])]
    image_issues = [f for f in hits if _classify(f, ["latest tag", "image tag", "no tag"])]
    runtime_cfg = [f for f in hits if _classify(f, ["seccomp", "apparmor", "selinux", "read-only"])]
    root_user = [f for f in hits if _classify(f, ["root user", "run as root", "user root"])]

    return {
        "skill": "container_security",
        "total_findings": len(hits),
        "risk_assessment": {
            "privileged_containers": {
                "count": len(privileged),
                "severity": "CRITICAL" if privileged else "NONE",
                "impact": "Full host escape possible — attacker gains node-level access",
                "findings": [_as_dict(f) for f in privileged[:10]],
            },
            "image_hygiene": {
                "count": len(image_issues),
                "severity": "HIGH" if image_issues else "NONE",
                "impact": "Mutable tags allow silent supply-chain compromise",
                "findings": [_as_dict(f) for f in image_issues[:10]],
            },
            "runtime_hardening": {
                "count": len(runtime_cfg),
                "severity": "HIGH" if runtime_cfg else "NONE",
                "impact": "Missing seccomp/AppArmor profiles allow syscall abuse",
                "findings": [_as_dict(f) for f in runtime_cfg[:10]],
            },
            "root_execution": {
                "count": len(root_user),
                "severity": "HIGH" if root_user else "NONE",
                "impact": "Containers running as root can write to host mounts",
                "findings": [_as_dict(f) for f in root_user[:10]],
            },
        },
        "cis_docker_controls": [
            {"control": "4.1", "title": "Create a user for the container", "status": "FAIL" if root_user else "PASS"},
            {"control": "4.6", "title": "Add HEALTHCHECK instruction", "status": "REVIEW"},
            {"control": "5.3", "title": "Restrict Linux Kernel Capabilities", "status": "FAIL" if privileged else "PASS"},
            {"control": "5.4", "title": "Do not use privileged containers", "status": "FAIL" if privileged else "PASS"},
            {"control": "5.9", "title": "Do not share host network namespace", "status": "REVIEW"},
            {"control": "5.25", "title": "Restrict container from acquiring additional privileges", "status": "REVIEW"},
        ],
        "remediation_priority": [
            "1. Remove --privileged flag from all containers (CRITICAL)",
            "2. Pin image digests instead of mutable tags (HIGH)",
            "3. Apply restrictive seccomp profiles (HIGH)",
            "4. Run containers as non-root UID (HIGH)",
            "5. Enable read-only root filesystem where possible (MEDIUM)",
            "6. Drop ALL capabilities, add only needed ones (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 2. CI/CD Pipeline Security
# ═══════════════════════════════════════════════════════════════════

_CICD_KW = [
    "pipeline", "ci/cd", "cicd", "github action", "gitlab ci", "jenkins",
    "azure pipeline", "circleci", "buildkite", "workflow", "deployment",
    "artifact", "build secret", "oidc", "self-hosted runner", "runner",
    "supply chain", "sbom", "sigstore", "cosign", "provenance",
    "branch protection", "code review", "merge request", "pull request",
    "webhook", "deploy key", "github token", "actions/checkout",
]


async def investigate_cicd_security(ctx: _Ctx, **kw: Any) -> dict:
    """CI/CD pipeline security — GitHub Actions, GitLab CI, Jenkins, supply chain."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _CICD_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    secret_exposure = [f for f in hits if _classify(f, ["secret", "token", "credential", "api key"])]
    runner_risks = [f for f in hits if _classify(f, ["self-hosted runner", "runner", "agent"])]
    branch_policy = [f for f in hits if _classify(f, ["branch protection", "code review", "force push"])]
    supply_chain = [f for f in hits if _classify(f, ["supply chain", "dependency", "sbom", "provenance"])]

    return {
        "skill": "cicd_security",
        "total_findings": len(hits),
        "attack_vectors": {
            "secret_exposure_in_pipelines": {
                "count": len(secret_exposure),
                "severity": "CRITICAL" if secret_exposure else "NONE",
                "impact": "Leaked pipeline secrets enable lateral movement to production",
                "findings": [_as_dict(f) for f in secret_exposure[:10]],
            },
            "runner_compromise": {
                "count": len(runner_risks),
                "severity": "HIGH" if runner_risks else "NONE",
                "impact": "Compromised self-hosted runners execute arbitrary code in build env",
                "findings": [_as_dict(f) for f in runner_risks[:10]],
            },
            "weak_branch_policies": {
                "count": len(branch_policy),
                "severity": "HIGH" if branch_policy else "NONE",
                "impact": "Missing branch protection allows malicious code merge without review",
                "findings": [_as_dict(f) for f in branch_policy[:10]],
            },
            "supply_chain_integrity": {
                "count": len(supply_chain),
                "severity": "HIGH" if supply_chain else "NONE",
                "impact": "Missing SBOM/provenance allows undetected dependency poisoning",
                "findings": [_as_dict(f) for f in supply_chain[:10]],
            },
        },
        "slsa_level_assessment": {
            "current_level": "L1" if branch_policy else "L0",
            "target_level": "L3",
            "gaps": [
                "Hermetic builds not enforced" if not supply_chain else None,
                "Missing build provenance attestation",
                "Self-hosted runners lack ephemeral configuration",
                "No artifact signing with Sigstore/Cosign",
            ],
        },
        "remediation_priority": [
            "1. Move secrets to OIDC federation — eliminate stored pipeline credentials (CRITICAL)",
            "2. Enforce branch protection with required reviews on default branch (HIGH)",
            "3. Use ephemeral self-hosted runners or GitHub-hosted runners (HIGH)",
            "4. Generate and verify SBOM for all build artifacts (HIGH)",
            "5. Pin GitHub Actions to commit SHA, not tags (MEDIUM)",
            "6. Enable Dependabot/Renovate for automated dependency updates (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 3. API Security Assessment
# ═══════════════════════════════════════════════════════════════════

_API_KW = [
    "api", "endpoint", "rest", "graphql", "grpc", "swagger", "openapi",
    "cors", "rate limit", "authentication", "authorization", "oauth",
    "jwt", "bearer", "api key", "api gateway", "throttl", "injection",
    "broken auth", "bola", "bfla", "ssrf", "mass assignment",
    "excessive data", "broken function", "security misconfiguration",
]


async def investigate_api_security(ctx: _Ctx, **kw: Any) -> dict:
    """API security — OWASP API Top 10, GraphQL, gRPC, authentication gaps."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _API_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    auth_issues = [f for f in hits if _classify(f, ["auth", "oauth", "jwt", "bearer", "broken auth"])]
    config = [f for f in hits if _classify(f, ["cors", "rate limit", "throttl", "misconfiguration"])]

    return {
        "skill": "api_security",
        "total_findings": len(hits),
        "owasp_api_top10_mapping": {
            "API1_BOLA": {"count": len([f for f in hits if _classify(f, ["bola", "broken object"])]), "risk": "CRITICAL"},
            "API2_BrokenAuth": {"count": len(auth_issues), "risk": "CRITICAL"},
            "API3_ExcessiveData": {"count": len([f for f in hits if _classify(f, ["excessive data"])]), "risk": "HIGH"},
            "API4_ResourceConsumption": {"count": len([f for f in hits if _classify(f, ["rate limit", "throttl"])]), "risk": "MEDIUM"},
            "API5_BFLA": {"count": len([f for f in hits if _classify(f, ["bfla", "broken function"])]), "risk": "CRITICAL"},
            "API6_MassAssignment": {"count": len([f for f in hits if _classify(f, ["mass assignment"])]), "risk": "HIGH"},
            "API7_SSRF": {"count": len([f for f in hits if _classify(f, ["ssrf"])]), "risk": "HIGH"},
            "API8_Misconfiguration": {"count": len(config), "risk": "MEDIUM"},
            "API9_ImproperInventory": {"count": 0, "risk": "MEDIUM"},
            "API10_UnsafeConsumption": {"count": 0, "risk": "LOW"},
        },
        "critical_findings": [_as_dict(f) for f in hits[:15]],
        "remediation_priority": [
            "1. Implement object-level authorization checks on every endpoint (CRITICAL)",
            "2. Enforce OAuth 2.0 / OIDC with proper scope validation (CRITICAL)",
            "3. Apply rate limiting and request throttling at API gateway (HIGH)",
            "4. Validate and sanitize all input — parameterized queries only (HIGH)",
            "5. Enable CORS with explicit origin allow-list (MEDIUM)",
            "6. Implement API versioning and deprecation lifecycle (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 4. DNS & Domain Security
# ═══════════════════════════════════════════════════════════════════

_DNS_KW = [
    "dns", "domain", "subdomain", "cname", "a record", "mx record",
    "dangling", "takeover", "zone transfer", "dnssec", "spf", "dkim",
    "dmarc", "ns record", "wildcard dns", "typosquat", "homoglyph",
    "phishing domain", "certificate transparency",
]


async def investigate_dns_security(ctx: _Ctx, **kw: Any) -> dict:
    """DNS & domain security — dangling records, subdomain takeover, email auth."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _DNS_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    takeover = [f for f in hits if _classify(f, ["dangling", "takeover", "cname"])]
    email_auth = [f for f in hits if _classify(f, ["spf", "dkim", "dmarc"])]
    zone_cfg = [f for f in hits if _classify(f, ["zone transfer", "dnssec", "wildcard"])]

    return {
        "skill": "dns_security",
        "total_findings": len(hits),
        "risk_categories": {
            "subdomain_takeover": {
                "count": len(takeover),
                "severity": "CRITICAL" if takeover else "NONE",
                "impact": "Attacker claims abandoned subdomains → phishing, cookie theft, CSP bypass",
                "findings": [_as_dict(f) for f in takeover[:10]],
            },
            "email_authentication": {
                "count": len(email_auth),
                "severity": "HIGH" if email_auth else "NONE",
                "impact": "Missing SPF/DKIM/DMARC enables email spoofing and phishing",
                "findings": [_as_dict(f) for f in email_auth[:10]],
            },
            "zone_configuration": {
                "count": len(zone_cfg),
                "severity": "MEDIUM" if zone_cfg else "NONE",
                "impact": "Zone transfer or missing DNSSEC enables DNS poisoning",
                "findings": [_as_dict(f) for f in zone_cfg[:10]],
            },
        },
        "remediation_priority": [
            "1. Audit and remove dangling CNAME/A records pointing to deprovisioned services (CRITICAL)",
            "2. Enforce DMARC policy 'reject' with SPF and DKIM alignment (HIGH)",
            "3. Enable DNSSEC on all authoritative zones (MEDIUM)",
            "4. Disable zone transfers to unauthorized nameservers (MEDIUM)",
            "5. Monitor Certificate Transparency logs for unauthorized issuance (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 5. SSL/TLS Certificate Management
# ═══════════════════════════════════════════════════════════════════

_TLS_KW = [
    "ssl", "tls", "certificate", "cert", "x509", "https", "cipher",
    "weak cipher", "tls 1.0", "tls 1.1", "sslv3", "expired cert",
    "self-signed", "wildcard cert", "san", "hsts", "ocsp",
    "certificate pinning", "ca bundle", "chain", "pem", "pkcs",
]


async def investigate_tls_security(ctx: _Ctx, **kw: Any) -> dict:
    """SSL/TLS certificate management — expiry, weak ciphers, chain validation."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _TLS_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    weak_proto = [f for f in hits if _classify(f, ["tls 1.0", "tls 1.1", "sslv3", "weak cipher"])]
    cert_issues = [f for f in hits if _classify(f, ["expired", "self-signed", "chain", "untrusted"])]
    config_gaps = [f for f in hits if _classify(f, ["hsts", "ocsp", "pinning"])]

    return {
        "skill": "tls_security",
        "total_findings": len(hits),
        "risk_categories": {
            "deprecated_protocols": {
                "count": len(weak_proto),
                "severity": "CRITICAL" if weak_proto else "NONE",
                "impact": "TLS 1.0/1.1 and SSLv3 are vulnerable to POODLE, BEAST, and downgrade attacks",
                "findings": [_as_dict(f) for f in weak_proto[:10]],
            },
            "certificate_issues": {
                "count": len(cert_issues),
                "severity": "HIGH" if cert_issues else "NONE",
                "impact": "Expired or self-signed certificates break trust chains and enable MitM",
                "findings": [_as_dict(f) for f in cert_issues[:10]],
            },
            "transport_hardening": {
                "count": len(config_gaps),
                "severity": "MEDIUM" if config_gaps else "NONE",
                "impact": "Missing HSTS allows SSL stripping; no OCSP stapling slows validation",
                "findings": [_as_dict(f) for f in config_gaps[:10]],
            },
        },
        "remediation_priority": [
            "1. Disable TLS 1.0/1.1 and SSLv3 — enforce TLS 1.2+ only (CRITICAL)",
            "2. Replace expired and self-signed certificates with CA-issued certs (HIGH)",
            "3. Enable HSTS with includeSubDomains and long max-age (HIGH)",
            "4. Use AEAD cipher suites only (AES-GCM, ChaCha20-Poly1305) (MEDIUM)",
            "5. Implement automated certificate rotation via ACME/Let's Encrypt (MEDIUM)",
            "6. Enable OCSP stapling on all TLS endpoints (LOW)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 6. Zero Trust Architecture Assessment
# ═══════════════════════════════════════════════════════════════════

_ZERO_TRUST_KW = [
    "zero trust", "identity", "conditional access", "mfa", "multi-factor",
    "least privilege", "microsegment", "micro-segment", "sase", "ztna",
    "device trust", "posture check", "continuous verification",
    "implicit trust", "network perimeter", "vpn", "bastion",
    "jump host", "service mesh", "mutual tls", "mtls",
]


async def assess_zero_trust(ctx: _Ctx, **kw: Any) -> dict:
    """Zero trust architecture assessment — identity-centric, micro-segmentation."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _ZERO_TRUST_KW)]

    identity = [f for f in rows if _classify(f, ["mfa", "multi-factor", "conditional access", "identity"])]
    network = [f for f in rows if _classify(f, ["microsegment", "flat network", "vpn", "bastion", "network perimeter"])]
    device = [f for f in rows if _classify(f, ["device trust", "posture check", "endpoint"])]
    privilege = [f for f in rows if _classify(f, ["least privilege", "over-privileged", "wildcard", "admin"])]

    return {
        "skill": "zero_trust_assessment",
        "total_related_findings": len(hits),
        "maturity_pillars": {
            "identity": {
                "score": max(0, 100 - len(identity) * 15),
                "gaps": len(identity),
                "status": "CRITICAL" if len(identity) > 5 else "NEEDS_WORK" if identity else "STRONG",
                "findings": [_as_dict(f) for f in identity[:8]],
            },
            "network": {
                "score": max(0, 100 - len(network) * 15),
                "gaps": len(network),
                "status": "CRITICAL" if len(network) > 5 else "NEEDS_WORK" if network else "STRONG",
                "findings": [_as_dict(f) for f in network[:8]],
            },
            "device": {
                "score": max(0, 100 - len(device) * 20),
                "gaps": len(device),
                "status": "CRITICAL" if len(device) > 3 else "NEEDS_WORK" if device else "STRONG",
                "findings": [_as_dict(f) for f in device[:8]],
            },
            "least_privilege": {
                "score": max(0, 100 - len(privilege) * 10),
                "gaps": len(privilege),
                "status": "CRITICAL" if len(privilege) > 8 else "NEEDS_WORK" if privilege else "STRONG",
                "findings": [_as_dict(f) for f in privilege[:8]],
            },
        },
        "nist_sp_800_207_alignment": [
            "PE1: All data sources and computing services are considered resources",
            "PE2: All communication is secured regardless of network location",
            "PE3: Access to individual enterprise resources is granted on a per-session basis",
            "PE4: Access is determined by dynamic policy",
            "PE5: Enterprise monitors and measures integrity and security posture of all assets",
            "PE6: All resource authentication and authorization are dynamic and strictly enforced",
            "PE7: Enterprise collects info about current state of assets and uses it to improve security",
        ],
        "remediation_priority": [
            "1. Enforce MFA on all user and service accounts without exception (CRITICAL)",
            "2. Implement micro-segmentation — no flat network trust zones (HIGH)",
            "3. Apply least-privilege IAM — remove wildcard and admin permissions (HIGH)",
            "4. Deploy continuous device posture verification (MEDIUM)",
            "5. Replace VPN with ZTNA for application access (MEDIUM)",
            "6. Implement mutual TLS (mTLS) for service-to-service communication (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 7. Network Segmentation Analysis
# ═══════════════════════════════════════════════════════════════════

_NETWORK_SEG_KW = [
    "network", "subnet", "vlan", "firewall", "acl", "security group",
    "nsg", "nacl", "ingress", "egress", "0.0.0.0/0", "::/0",
    "any any", "allow all", "flat network", "lateral movement",
    "east-west", "north-south", "dmz", "jump box",
    "port 22", "port 3389", "port 3306", "port 5432",
    "open port", "public subnet", "private subnet",
]


async def analyze_network_segmentation(ctx: _Ctx, **kw: Any) -> dict:
    """Network segmentation — flat networks, open ports, lateral movement paths."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _NETWORK_SEG_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    public_exposure = [f for f in hits if _classify(f, ["0.0.0.0/0", "::/0", "public", "any any", "allow all"])]
    open_mgmt = [f for f in hits if _classify(f, ["port 22", "port 3389", "ssh", "rdp"])]
    open_db = [f for f in hits if _classify(f, ["port 3306", "port 5432", "port 27017", "database"])]
    lateral = [f for f in hits if _classify(f, ["lateral", "east-west", "flat network"])]

    return {
        "skill": "network_segmentation",
        "total_findings": len(hits),
        "exposure_analysis": {
            "public_internet_exposure": {
                "count": len(public_exposure),
                "severity": "CRITICAL" if public_exposure else "NONE",
                "impact": "Resources accessible from 0.0.0.0/0 — direct attack surface from internet",
                "findings": [_as_dict(f) for f in public_exposure[:10]],
            },
            "management_port_exposure": {
                "count": len(open_mgmt),
                "severity": "CRITICAL" if open_mgmt else "NONE",
                "impact": "SSH/RDP exposed to internet enables brute-force and credential stuffing",
                "findings": [_as_dict(f) for f in open_mgmt[:10]],
            },
            "database_exposure": {
                "count": len(open_db),
                "severity": "CRITICAL" if open_db else "NONE",
                "impact": "Databases exposed to non-application subnets risk data exfiltration",
                "findings": [_as_dict(f) for f in open_db[:10]],
            },
            "lateral_movement_risk": {
                "count": len(lateral),
                "severity": "HIGH" if lateral else "NONE",
                "impact": "Flat networks allow unrestricted east-west movement after initial compromise",
                "findings": [_as_dict(f) for f in lateral[:10]],
            },
        },
        "remediation_priority": [
            "1. Restrict 0.0.0.0/0 ingress — use explicit IP allow-lists (CRITICAL)",
            "2. Block SSH/RDP from internet — use bastion hosts or SSM (CRITICAL)",
            "3. Isolate databases in private subnets with no public route (CRITICAL)",
            "4. Implement micro-segmentation between application tiers (HIGH)",
            "5. Enable VPC flow logs / NSG flow logs for traffic visibility (HIGH)",
            "6. Deploy network detection and response (NDR) sensors (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 8. Endpoint & EDR Posture
# ═══════════════════════════════════════════════════════════════════

_ENDPOINT_KW = [
    "endpoint", "edr", "antivirus", "anti-malware", "defender",
    "crowdstrike", "sentinel one", "carbon black", "agent",
    "malware", "ransomware", "trojan", "virus", "worm",
    "patch", "vulnerability", "cve-", "exploit", "payload",
    "reverse shell", "backdoor", "rootkit", "keylogger",
]


async def assess_endpoint_security(ctx: _Ctx, **kw: Any) -> dict:
    """Endpoint & EDR posture — agent coverage, detection gaps, vulnerability exposure."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _ENDPOINT_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    malware = [f for f in hits if _classify(f, ["malware", "ransomware", "trojan", "backdoor", "rootkit"])]
    patching = [f for f in hits if _classify(f, ["patch", "cve-", "vulnerability", "exploit"])]
    coverage = [f for f in hits if _classify(f, ["agent", "edr", "defender", "crowdstrike"])]

    return {
        "skill": "endpoint_security",
        "total_findings": len(hits),
        "risk_categories": {
            "active_threats": {
                "count": len(malware),
                "severity": "CRITICAL" if malware else "NONE",
                "impact": "Active malware or indicators of compromise detected",
                "findings": [_as_dict(f) for f in malware[:10]],
            },
            "patch_compliance": {
                "count": len(patching),
                "severity": "CRITICAL" if any(f.severity == "CRITICAL" for f in patching) else "HIGH" if patching else "NONE",
                "impact": "Unpatched CVEs on production endpoints expose known exploitation paths",
                "findings": [_as_dict(f) for f in patching[:10]],
            },
            "edr_coverage": {
                "count": len(coverage),
                "severity": "HIGH" if coverage else "NONE",
                "impact": "Gaps in EDR agent coverage leave blind spots in detection",
                "findings": [_as_dict(f) for f in coverage[:10]],
            },
        },
        "remediation_priority": [
            "1. Quarantine and investigate any active malware indicators (CRITICAL)",
            "2. Patch all CRITICAL CVEs within 24 hours SLA (CRITICAL)",
            "3. Ensure 100% EDR agent deployment across all endpoints (HIGH)",
            "4. Enable automated threat response playbooks in EDR (HIGH)",
            "5. Patch HIGH CVEs within 7-day SLA (HIGH)",
            "6. Implement vulnerability scanning on a weekly cadence (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 9. Cloud Cost Anomaly as Security Signal
# ═══════════════════════════════════════════════════════════════════

_COST_SECURITY_KW = [
    "cost", "billing", "budget", "spend", "crypto", "mining",
    "bitcoin", "monero", "xmr", "gpu", "compute", "ec2",
    "lambda", "function", "serverless", "unusual activity",
    "anomal", "spike", "burst", "exfiltrat", "egress",
    "data transfer", "bandwidth", "storage growth",
]


async def detect_cost_anomalies(ctx: _Ctx, **kw: Any) -> dict:
    """Cloud cost anomaly detection as security signal — crypto-mining, exfiltration."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _COST_SECURITY_KW)]

    crypto = [f for f in hits if _classify(f, ["crypto", "mining", "bitcoin", "monero", "xmr"])]
    egress = [f for f in hits if _classify(f, ["exfiltrat", "egress", "data transfer", "bandwidth"])]
    compute = [f for f in hits if _classify(f, ["compute", "ec2", "gpu", "lambda", "spike", "burst"])]

    return {
        "skill": "cost_anomaly_security",
        "total_findings": len(hits),
        "threat_indicators": {
            "cryptomining": {
                "count": len(crypto),
                "severity": "CRITICAL" if crypto else "NONE",
                "impact": "Unauthorized compute usage — compromised credentials or workloads",
                "findings": [_as_dict(f) for f in crypto[:10]],
            },
            "data_exfiltration": {
                "count": len(egress),
                "severity": "CRITICAL" if egress else "NONE",
                "impact": "Abnormal egress traffic may indicate active data theft",
                "findings": [_as_dict(f) for f in egress[:10]],
            },
            "compute_abuse": {
                "count": len(compute),
                "severity": "HIGH" if compute else "NONE",
                "impact": "Unexpected compute scaling suggests compromised workloads or misuse",
                "findings": [_as_dict(f) for f in compute[:10]],
            },
        },
        "detection_signals": [
            "Monitor for sudden compute spend spikes (>200% baseline)",
            "Alert on new GPU/high-CPU instance types not in approved list",
            "Track egress data volume against historical baseline",
            "Monitor for new regions with active resources (geographic anomaly)",
            "Detect Lambda/Function invocation count anomalies",
        ],
        "remediation_priority": [
            "1. Investigate and terminate unauthorized compute instances immediately (CRITICAL)",
            "2. Rotate all credentials in the affected account/project (CRITICAL)",
            "3. Set up billing alerts and budget caps per account (HIGH)",
            "4. Restrict allowed instance types via SCP/Organization Policy (HIGH)",
            "5. Enable VPC flow logs and monitor egress patterns (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 10. Threat Modeling (STRIDE/DREAD)
# ═══════════════════════════════════════════════════════════════════

_THREAT_MODEL_KW = [
    "spoofing", "tampering", "repudiation", "information disclosure",
    "denial of service", "elevation of privilege", "threat model",
    "attack surface", "attack vector", "threat actor", "adversary",
    "mitre att&ck", "kill chain", "ttp", "tactic", "technique",
    "credential access", "initial access", "persistence",
    "defense evasion", "collection", "command and control",
    "impact", "reconnaissance", "resource development",
]


async def perform_threat_modeling(ctx: _Ctx, **kw: Any) -> dict:
    """Threat modeling — STRIDE analysis, MITRE ATT&CK mapping, kill chain assessment."""
    rows = await _fetch_active_findings(ctx)
    [_as_dict(f) for f in rows]

    stride = {
        "Spoofing": [f for f in rows if _classify(f, ["spoofing", "authentication", "impersonat", "credential"])],
        "Tampering": [f for f in rows if _classify(f, ["tampering", "integrity", "modification", "injection"])],
        "Repudiation": [f for f in rows if _classify(f, ["repudiation", "logging", "audit", "non-repudiation"])],
        "Information_Disclosure": [f for f in rows if _classify(f, ["disclosure", "exposure", "leak", "sensitive data", "pii"])],
        "Denial_of_Service": [f for f in rows if _classify(f, ["denial", "dos", "ddos", "availability", "rate limit"])],
        "Elevation_of_Privilege": [f for f in rows if _classify(f, ["privilege", "escalat", "admin", "root", "sudo"])],
    }

    mitre_mapping = {
        "Initial_Access": len([f for f in rows if _classify(f, ["public", "exposed", "open port", "phishing"])]),
        "Persistence": len([f for f in rows if _classify(f, ["backdoor", "cron", "scheduled", "startup"])]),
        "Privilege_Escalation": len([f for f in rows if _classify(f, ["privilege", "escalat", "sudo", "root"])]),
        "Defense_Evasion": len([f for f in rows if _classify(f, ["obfuscat", "disable log", "tamper"])]),
        "Credential_Access": len([f for f in rows if _classify(f, ["credential", "password", "key", "token", "secret"])]),
        "Lateral_Movement": len([f for f in rows if _classify(f, ["lateral", "pivot", "ssh", "rdp", "smb"])]),
        "Collection": len([f for f in rows if _classify(f, ["collect", "screen", "clipboard", "keylog"])]),
        "Exfiltration": len([f for f in rows if _classify(f, ["exfiltrat", "upload", "transfer", "egress"])]),
    }

    return {
        "skill": "threat_modeling",
        "total_findings": len(rows),
        "stride_analysis": {
            category: {
                "finding_count": len(findings),
                "severity": "CRITICAL" if any(f.severity == "CRITICAL" for f in findings) else
                            "HIGH" if findings else "NONE",
                "top_findings": [_as_dict(f) for f in findings[:5]],
            }
            for category, findings in stride.items()
        },
        "mitre_attck_heatmap": mitre_mapping,
        "kill_chain_risk": {
            "most_exposed_phase": max(mitre_mapping, key=mitre_mapping.get) if any(mitre_mapping.values()) else "None",
            "total_attack_paths": sum(mitre_mapping.values()),
        },
        "remediation_priority": [
            "1. Address Credential Access findings first — they enable all downstream attacks (CRITICAL)",
            "2. Close Initial Access vectors — reduce attack surface from internet (CRITICAL)",
            "3. Eliminate Privilege Escalation paths — prevent attacker empowerment (HIGH)",
            "4. Harden against Lateral Movement — implement segmentation (HIGH)",
            "5. Improve logging for Repudiation threats — ensure forensic readiness (MEDIUM)",
            "6. Deploy DDoS protection for Denial of Service resilience (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 11. Data Loss Prevention (DLP) Assessment
# ═══════════════════════════════════════════════════════════════════

_DLP_KW = [
    "data loss", "dlp", "data classification", "sensitive data",
    "pii", "phi", "pci", "cardholder", "ssn", "social security",
    "passport", "credit card", "encryption", "unencrypted",
    "public bucket", "public blob", "public storage", "acl public",
    "data retention", "backup", "disaster recovery",
    "gdpr", "ccpa", "data residency", "cross-border",
]


async def assess_dlp_posture(ctx: _Ctx, **kw: Any) -> dict:
    """Data Loss Prevention assessment — classification, encryption, egress controls."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _DLP_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    encryption = [f for f in hits if _classify(f, ["unencrypted", "encryption", "plaintext", "cleartext"])]
    public_data = [f for f in hits if _classify(f, ["public bucket", "public blob", "public storage", "acl public"])]
    sensitive = [f for f in hits if _classify(f, ["pii", "phi", "pci", "ssn", "credit card", "sensitive"])]
    retention = [f for f in hits if _classify(f, ["retention", "backup", "disaster recovery"])]

    return {
        "skill": "dlp_assessment",
        "total_findings": len(hits),
        "risk_categories": {
            "encryption_gaps": {
                "count": len(encryption),
                "severity": "CRITICAL" if encryption else "NONE",
                "impact": "Unencrypted data at rest or in transit exposes sensitive information",
                "findings": [_as_dict(f) for f in encryption[:10]],
            },
            "public_data_exposure": {
                "count": len(public_data),
                "severity": "CRITICAL" if public_data else "NONE",
                "impact": "Publicly accessible storage contains potentially sensitive data",
                "findings": [_as_dict(f) for f in public_data[:10]],
            },
            "sensitive_data_handling": {
                "count": len(sensitive),
                "severity": "HIGH" if sensitive else "NONE",
                "impact": "PII/PHI/PCI data handling gaps risk regulatory fines",
                "findings": [_as_dict(f) for f in sensitive[:10]],
            },
            "retention_compliance": {
                "count": len(retention),
                "severity": "MEDIUM" if retention else "NONE",
                "impact": "Missing retention policies violate data governance requirements",
                "findings": [_as_dict(f) for f in retention[:10]],
            },
        },
        "regulatory_exposure": {
            "GDPR": len([f for f in hits if _classify(f, ["gdpr", "pii", "data residency"])]),
            "CCPA": len([f for f in hits if _classify(f, ["ccpa", "pii", "consumer"])]),
            "HIPAA": len([f for f in hits if _classify(f, ["phi", "hipaa", "health"])]),
            "PCI_DSS": len([f for f in hits if _classify(f, ["pci", "cardholder", "credit card"])]),
        },
        "remediation_priority": [
            "1. Encrypt all data at rest with customer-managed keys (CRITICAL)",
            "2. Remove public access from all storage accounts/buckets (CRITICAL)",
            "3. Implement data classification and tagging for sensitive data (HIGH)",
            "4. Deploy DLP policies to monitor and block sensitive data egress (HIGH)",
            "5. Define and enforce data retention policies per classification tier (MEDIUM)",
            "6. Enable access logging on all data stores (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# 12. Identity & Access Governance
# ═══════════════════════════════════════════════════════════════════

_IAG_KW = [
    "identity", "access", "iam", "rbac", "abac", "role",
    "permission", "privilege", "sso", "saml", "oidc",
    "service account", "managed identity", "workload identity",
    "orphan", "stale", "inactive", "unused", "dormant",
    "mfa", "multi-factor", "2fa", "totp", "fido",
    "access review", "certification", "lifecycle", "provisioning",
    "deprovisioning", "joiner mover leaver", "jml",
]


async def assess_identity_governance(ctx: _Ctx, **kw: Any) -> dict:
    """Identity & access governance — lifecycle, orphan accounts, MFA coverage, privilege creep."""
    rows = await _fetch_active_findings(ctx)
    hits = [f for f in rows if _classify(f, _IAG_KW)]
    hits.sort(key=lambda f: _severity_rank(f.severity))

    mfa = [f for f in hits if _classify(f, ["mfa", "multi-factor", "2fa", "totp", "fido"])]
    orphan = [f for f in hits if _classify(f, ["orphan", "stale", "inactive", "unused", "dormant"])]
    privilege = [f for f in hits if _classify(f, ["privilege", "admin", "wildcard", "over-privileged"])]
    service_acct = [f for f in hits if _classify(f, ["service account", "managed identity", "workload"])]
    sso_gaps = [f for f in hits if _classify(f, ["sso", "saml", "oidc", "federation"])]

    return {
        "skill": "identity_governance",
        "total_findings": len(hits),
        "governance_pillars": {
            "mfa_coverage": {
                "count": len(mfa),
                "severity": "CRITICAL" if mfa else "NONE",
                "impact": "Accounts without MFA are 99.9% more likely to be compromised (Microsoft)",
                "findings": [_as_dict(f) for f in mfa[:10]],
            },
            "orphan_accounts": {
                "count": len(orphan),
                "severity": "HIGH" if orphan else "NONE",
                "impact": "Dormant accounts are prime targets for credential stuffing attacks",
                "findings": [_as_dict(f) for f in orphan[:10]],
            },
            "privilege_creep": {
                "count": len(privilege),
                "severity": "HIGH" if privilege else "NONE",
                "impact": "Over-privileged accounts amplify blast radius of any compromise",
                "findings": [_as_dict(f) for f in privilege[:10]],
            },
            "service_account_hygiene": {
                "count": len(service_acct),
                "severity": "HIGH" if service_acct else "NONE",
                "impact": "Service accounts with keys (vs. workload identity) create persistent attack surfaces",
                "findings": [_as_dict(f) for f in service_acct[:10]],
            },
            "sso_federation": {
                "count": len(sso_gaps),
                "severity": "MEDIUM" if sso_gaps else "NONE",
                "impact": "Non-federated access complicates offboarding and audit trails",
                "findings": [_as_dict(f) for f in sso_gaps[:10]],
            },
        },
        "remediation_priority": [
            "1. Enforce MFA for ALL human accounts — no exceptions (CRITICAL)",
            "2. Disable or delete accounts inactive >90 days (HIGH)",
            "3. Remove wildcard (*) and admin permissions — apply least privilege (HIGH)",
            "4. Migrate service accounts to workload identity federation (HIGH)",
            "5. Implement quarterly access review campaigns (MEDIUM)",
            "6. Consolidate authentication via SSO/SAML federation (MEDIUM)",
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# Registry Builder — wires all 12 advanced skills
# ═══════════════════════════════════════════════════════════════════

def build_advanced_skill_registry() -> dict:
    """Build the advanced investigation skill registry (12 skills)."""
    from app.services.agents.skills import AgentSkill

    return {
        "investigate_containers": AgentSkill(
            name="investigate_containers",
            description="Container runtime security — Docker, containerd, CRI-O, OCI image compliance, privileged container detection.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_container_security,
        ),
        "investigate_cicd": AgentSkill(
            name="investigate_cicd",
            description="CI/CD pipeline security — GitHub Actions, GitLab CI, Jenkins. Secret exposure, runner compromise, SLSA assessment.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_cicd_security,
        ),
        "investigate_api": AgentSkill(
            name="investigate_api",
            description="API security assessment — OWASP API Top 10 mapping, authentication gaps, injection risks, rate limiting.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_api_security,
        ),
        "investigate_dns": AgentSkill(
            name="investigate_dns",
            description="DNS & domain security — dangling records, subdomain takeover, SPF/DKIM/DMARC, DNSSEC, zone transfer.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_dns_security,
        ),
        "investigate_tls": AgentSkill(
            name="investigate_tls",
            description="SSL/TLS certificate management — expired certs, weak ciphers, deprecated protocols, HSTS enforcement.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=investigate_tls_security,
        ),
        "assess_zero_trust": AgentSkill(
            name="assess_zero_trust",
            description="Zero trust architecture assessment — NIST SP 800-207 alignment, identity/network/device maturity pillars.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=assess_zero_trust,
        ),
        "analyze_network_segmentation": AgentSkill(
            name="analyze_network_segmentation",
            description="Network segmentation analysis — flat networks, open ports, management port exposure, lateral movement paths.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=analyze_network_segmentation,
        ),
        "assess_endpoint_security": AgentSkill(
            name="assess_endpoint_security",
            description="Endpoint & EDR posture — agent coverage, malware indicators, patch compliance, vulnerability management.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=assess_endpoint_security,
        ),
        "detect_cost_anomalies": AgentSkill(
            name="detect_cost_anomalies",
            description="Cloud cost anomaly as security signal — cryptomining detection, data exfiltration indicators, compute abuse.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=detect_cost_anomalies,
        ),
        "threat_modeling": AgentSkill(
            name="threat_modeling",
            description="Threat modeling — STRIDE analysis, MITRE ATT&CK heatmap, kill chain assessment, attack path prioritization.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=perform_threat_modeling,
        ),
        "assess_dlp": AgentSkill(
            name="assess_dlp",
            description="Data Loss Prevention assessment — encryption gaps, public storage exposure, PII/PHI handling, regulatory risk.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=assess_dlp_posture,
        ),
        "assess_identity_governance": AgentSkill(
            name="assess_identity_governance",
            description="Identity & access governance — MFA coverage, orphan accounts, privilege creep, service account hygiene, SSO gaps.",
            kind="deterministic", execution_mode="sync", requires_approval=False,
            input_schema={"type": "object", "properties": {}},
            executor=assess_identity_governance,
        ),
    }
