"""Knowledge Base API — CRUD for organization-specific runbooks, playbooks, and knowledge.

Organizations can manage custom knowledge that gets injected into the AI agent context,
enabling triage with org-specific infrastructure knowledge.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.app_logger import app_log
from app.models.knowledge_base import KnowledgeEntry

logger = logging.getLogger(__name__)  # stdout fallback
router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────

class KnowledgeEntryCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    content: str = Field(..., min_length=1)
    category: str = Field(default="general", max_length=100)
    entry_type: str = Field(default="runbook", max_length=50)
    tags: str = Field(default="", max_length=1000)
    priority: int = Field(default=0, ge=0, le=100)


class KnowledgeEntryUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    content: Optional[str] = Field(None, min_length=1)
    category: Optional[str] = Field(None, max_length=100)
    entry_type: Optional[str] = Field(None, max_length=50)
    tags: Optional[str] = Field(None, max_length=1000)
    priority: Optional[int] = Field(None, ge=0, le=100)
    is_active: Optional[bool] = None


class KnowledgeEntryOut(BaseModel):
    id: int
    title: str
    content: str
    category: str
    entry_type: str
    tags: str
    priority: int
    is_active: bool
    created_by: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("", response_model=dict)
async def list_knowledge_entries(
    category: Optional[str] = Query(None),
    entry_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    is_active: bool = Query(True),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "read")),
):
    """List knowledge base entries for the current organization."""
    org_id = current_user.organization_id

    stmt = select(KnowledgeEntry).where(
        KnowledgeEntry.organization_id == org_id,
        KnowledgeEntry.is_active == is_active,
    )

    if category:
        stmt = stmt.where(KnowledgeEntry.category == category)
    if entry_type:
        stmt = stmt.where(KnowledgeEntry.entry_type == entry_type)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            KnowledgeEntry.title.ilike(pattern) | KnowledgeEntry.content.ilike(pattern)
        )

    # Count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = stmt.order_by(KnowledgeEntry.priority.desc(), KnowledgeEntry.updated_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).scalars().all()

    return {
        "entries": [_to_dict(e) for e in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "categories": KnowledgeEntry.CATEGORIES,
        "entry_types": KnowledgeEntry.ENTRY_TYPES,
    }


@router.post("", response_model=dict, status_code=201)
async def create_knowledge_entry(
    body: KnowledgeEntryCreate,
    db: AsyncSession = Depends(get_db),
    # Entries are fed to the agents as context, so writing one is an agent change.
    current_user=Depends(require_permission("agents", "update")),
):
    """Create a new knowledge base entry."""
    org_id = current_user.organization_id

    entry = KnowledgeEntry(
        organization_id=org_id,
        title=body.title,
        content=body.content,
        category=body.category,
        entry_type=body.entry_type,
        tags=body.tags,
        priority=body.priority,
        created_by=current_user.email,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)

    await app_log.info(db, "AI", f"Knowledge entry created: '{body.title}' (type={body.entry_type})", user=current_user, source="knowledge_base", metadata={"entry_id": entry.id, "org_id": org_id, "entry_type": body.entry_type, "tags": body.tags})
    return _to_dict(entry)


@router.get("/{entry_id}", response_model=dict)
async def get_knowledge_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "read")),
):
    """Get a single knowledge base entry."""
    org_id = current_user.organization_id
    entry = await _get_entry(db, entry_id, org_id)
    return _to_dict(entry)


@router.put("/{entry_id}", response_model=dict)
async def update_knowledge_entry(
    entry_id: int,
    body: KnowledgeEntryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "update")),
):
    """Update a knowledge base entry."""
    org_id = current_user.organization_id
    entry = await _get_entry(db, entry_id, org_id)

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(entry, key, value)

    await db.flush()
    await db.refresh(entry)

    await app_log.info(db, "AI", f"Knowledge entry updated: id={entry_id}, fields={list(update_data.keys())}", user=current_user, source="knowledge_base", metadata={"entry_id": entry_id, "org_id": org_id, "updated_fields": list(update_data.keys())})
    return _to_dict(entry)


@router.delete("/{entry_id}", response_model=dict)
async def delete_knowledge_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "manage")),
):
    """Delete a knowledge base entry (soft delete — sets is_active=False)."""
    org_id = current_user.organization_id
    entry = await _get_entry(db, entry_id, org_id)
    entry.is_active = False
    await db.flush()

    await app_log.warning(db, "AI", f"Knowledge entry deleted: id={entry_id}", user=current_user, source="knowledge_base", metadata={"entry_id": entry_id, "org_id": org_id})
    return {"status": "deleted", "id": entry_id}


@router.get("/stats/summary", response_model=dict)
async def knowledge_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "read")),
):
    """Get knowledge base statistics for the current organization."""
    org_id = current_user.organization_id

    total = (await db.execute(
        select(func.count(KnowledgeEntry.id)).where(
            KnowledgeEntry.organization_id == org_id,
            KnowledgeEntry.is_active == True,
        )
    )).scalar() or 0

    by_category = {}
    stmt = (
        select(KnowledgeEntry.category, func.count(KnowledgeEntry.id))
        .where(KnowledgeEntry.organization_id == org_id, KnowledgeEntry.is_active == True)
        .group_by(KnowledgeEntry.category)
    )
    for row in (await db.execute(stmt)).all():
        by_category[row[0]] = row[1]

    by_type = {}
    stmt = (
        select(KnowledgeEntry.entry_type, func.count(KnowledgeEntry.id))
        .where(KnowledgeEntry.organization_id == org_id, KnowledgeEntry.is_active == True)
        .group_by(KnowledgeEntry.entry_type)
    )
    for row in (await db.execute(stmt)).all():
        by_type[row[0]] = row[1]

    return {
        "total_entries": total,
        "by_category": by_category,
        "by_type": by_type,
        "categories_available": KnowledgeEntry.CATEGORIES,
        "entry_types_available": KnowledgeEntry.ENTRY_TYPES,
    }


@router.post("/seed", response_model=dict, status_code=201)
async def seed_default_knowledge(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("agents", "manage")),
):
    """Seed the knowledge base with production-grade default entries."""
    org_id = current_user.organization_id

    # Check if already seeded
    existing = (await db.execute(
        select(func.count(KnowledgeEntry.id)).where(
            KnowledgeEntry.organization_id == org_id,
        )
    )).scalar() or 0

    if existing > 0:
        return {"status": "already_seeded", "count": existing}

    defaults = _get_default_knowledge_entries(org_id, current_user.email)
    for entry in defaults:
        db.add(entry)

    await db.flush()
    await app_log.info(db, "AI", f"Seeded {len(defaults)} default knowledge entries for organization", user=current_user, source="knowledge_base.seed", metadata={"org_id": org_id, "count": len(defaults)})
    return {"status": "seeded", "count": len(defaults)}


# ── Helpers ──────────────────────────────────────────────────────────

async def _get_entry(db: AsyncSession, entry_id: int, org_id: int) -> KnowledgeEntry:
    entry = (await db.execute(
        select(KnowledgeEntry).where(
            KnowledgeEntry.id == entry_id,
            KnowledgeEntry.organization_id == org_id,
        )
    )).scalar_one_or_none()
    if not entry:
        raise HTTPException(404, "Knowledge entry not found")
    return entry


def _to_dict(entry: KnowledgeEntry) -> dict:
    return {
        "id": entry.id,
        "title": entry.title,
        "content": entry.content,
        "category": entry.category,
        "entry_type": entry.entry_type,
        "tags": entry.tags,
        "priority": entry.priority,
        "is_active": entry.is_active,
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
    }


def _get_default_knowledge_entries(org_id: int, created_by: str) -> list[KnowledgeEntry]:
    """Production-grade default knowledge entries covering major incident types."""
    entries = [
        # ── Runbooks ──
        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=90,
            title="AWS IAM Credential Compromise Response",
            category="runbook", entry_type="runbook",
            tags="aws,iam,credential,incident,P0",
            content="""## AWS IAM Credential Compromise Response Runbook

### Trigger Conditions
- Exposed AWS access key detected in code repository
- CloudTrail shows API calls from unexpected region/IP
- GuardDuty alert: UnauthorizedAccess or CredentialAccess

### Immediate Actions (< 5 minutes)
1. **Disable the compromised IAM access key** — do NOT delete (preserve for forensics)
   ```bash
   aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name <user>
   ```
2. **Revoke all temporary sessions** for the IAM user/role:
   ```bash
   aws iam put-user-policy --user-name <user> --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<NOW>"}}}]}'
   ```
3. **Check CloudTrail** for all actions taken with the compromised key in the last 90 days:
   ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
   ```

### Investigation (< 30 minutes)
4. Export CloudTrail events for the exposure window to S3 for forensic analysis
5. Check for persistence mechanisms created:
   - New IAM users, roles, or policies
   - Lambda functions or EC2 instances launched
   - S3 bucket policies modified
   - CloudFormation stacks deployed
6. Review VPC Flow Logs for data exfiltration indicators

### Recovery (< 2 hours)
7. Generate new access key with minimum required permissions
8. Store in AWS Secrets Manager with automatic rotation enabled
9. Update all services referencing the old key
10. Remove the DenyAll inline policy once new key is deployed

### Post-Incident
11. Enable AWS Access Analyzer on all accounts
12. Implement SCPs to restrict key creation to authorized pipelines only
13. Deploy pre-commit hooks (git-secrets, detect-secrets) to prevent future leaks""",
        ),

        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=90,
            title="Kubernetes Pod Security Incident Response",
            category="runbook", entry_type="runbook",
            tags="kubernetes,k8s,pod,security,container,incident",
            content="""## Kubernetes Pod Security Incident Response

### Trigger Conditions
- Container running as root detected
- Pod with hostNetwork/hostPID/hostIPC enabled
- Suspicious process execution inside container (cryptominer, reverse shell)
- Pod communicating with known C2 infrastructure

### Immediate Actions
1. **Cordon the affected node** to prevent new pod scheduling:
   ```bash
   kubectl cordon <node-name>
   ```
2. **Capture pod state** before any remediation:
   ```bash
   kubectl get pod <pod> -o yaml > /tmp/incident-pod-state.yaml
   kubectl logs <pod> --all-containers > /tmp/incident-pod-logs.txt
   ```
3. **If active compromise**, isolate the pod via NetworkPolicy:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: isolate-compromised-pod
   spec:
     podSelector:
       matchLabels:
         app: <compromised-app>
     policyTypes: [Ingress, Egress]
   ```

### Investigation
4. Check RBAC — what can the pod's service account do?
   ```bash
   kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
   ```
5. Review mounted secrets and configmaps for credential exposure
6. Check for lateral movement — any other pods using the same service account?
7. Audit the container image for known CVEs:
   ```bash
   trivy image <image:tag>
   ```

### Hardening
8. Enforce Pod Security Standards (Restricted) on all namespaces
9. Deploy OPA Gatekeeper / Kyverno policies
10. Implement runtime security (Falco, Sysdig) for behavioral detection
11. Use distroless or scratch base images to minimize attack surface""",
        ),

        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=85,
            title="Terraform State File Compromise Response",
            category="runbook", entry_type="runbook",
            tags="terraform,iac,state,security,incident",
            content="""## Terraform State File Compromise Response

### Trigger Conditions
- State file found in public S3 bucket / Git repository
- Unauthorized access to state storage backend detected
- State file contains plaintext secrets (passwords, API keys, certificates)

### Immediate Actions (< 10 minutes)
1. **Restrict access to state backend immediately**
   - S3: Apply bucket policy denying all public access
   - Azure: Restrict storage account network rules to VNet only
   - GCS: Remove allUsers/allAuthenticatedUsers bindings
2. **Rotate ALL secrets referenced in the state file** — state contains resource attributes including passwords
3. **Enable versioning** on the state backend if not already enabled

### Investigation
4. Audit access logs for the state backend:
   - S3: Check S3 access logs and CloudTrail S3 data events
   - Azure: Check Storage Analytics logs
   - GCS: Check Cloud Audit Logs
5. Identify all secrets in the state file:
   ```bash
   terraform show -json terraform.tfstate | jq -r '.. | .value? // empty' | grep -iE 'password|secret|key|token'
   ```
6. Check git history if state was ever committed:
   ```bash
   git log --all --full-history -- '*.tfstate' '*.tfstate.backup'
   ```

### Recovery
7. Rotate all exposed credentials (databases, API keys, certificates)
8. Enable state encryption at rest (S3 SSE-KMS, Azure CMK, GCS CMEK)
9. Enable state locking (DynamoDB for S3, blob lease for Azure)
10. Add `*.tfstate` and `*.tfstate.backup` to `.gitignore`

### Prevention
11. Use remote backends with encryption and access controls
12. Never store state locally or in version control
13. Use `sensitive = true` on all secret-containing outputs/variables
14. Implement Sentinel/OPA policies to enforce state backend standards""",
        ),

        # ── Playbooks ──
        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=80,
            title="Cloud Security Posture Assessment Playbook",
            category="playbook", entry_type="playbook",
            tags="cloud,security,posture,assessment,cis,benchmark",
            content="""## Cloud Security Posture Assessment Playbook

### Pre-Assessment
1. Identify all cloud accounts/subscriptions/projects in scope
2. Verify scanner access — ensure service principals have SecurityReader or equivalent
3. Define assessment scope: CIS, SOC2, PCI-DSS, HIPAA, or custom framework

### Assessment Execution
4. Run automated scans across all providers:
   - AWS: SecurityHub + Config Rules + Access Analyzer + GuardDuty
   - Azure: Defender for Cloud + Policy Compliance + Entra ID
   - GCP: Security Command Center + Policy Intelligence + IAM Recommender
5. Run IaC scans on all Terraform/CloudFormation/Pulumi code:
   - Checkov, tfsec, KICS for IaC misconfigurations
   - Trivy for container image vulnerabilities
   - Semgrep for application code secrets

### Analysis
6. Correlate findings across providers — same misconfiguration pattern across clouds
7. Map findings to compliance controls (CIS, SOC2, PCI-DSS, HIPAA, NIST 800-53)
8. Calculate risk score: (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1)
9. Identify blast radius for each critical finding — what data/systems are exposed

### Reporting
10. Generate executive summary with risk score trend (improve/degrade/stable)
11. Produce technical remediation report with fix commands for each finding
12. Create compliance gap analysis with control-level pass/fail
13. Deliver 30/60/90 day remediation roadmap prioritized by risk score""",
        ),

        # ── Known Issues ──
        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=70,
            title="Common False Positives in Cloud Security Scanning",
            category="known_issue", entry_type="pattern",
            tags="false_positive,scanner,tuning,noise_reduction",
            content="""## Common False Positives — Pattern Library

### AWS
- **S3 bucket public access** on static website buckets — intentionally public
- **Security group 0.0.0.0/0 on port 443** — expected for public-facing ALBs
- **CloudTrail not enabled** in regions with no resources — expected if not using that region
- **IAM user without MFA** — service accounts don't support MFA (use roles instead)
- **RDS publicly accessible** when behind VPN + security group restriction — check SG rules before flagging

### Azure
- **Storage account allows public blob access** — may be CDN-backed static content
- **NSG allows inbound 443 from Any** — expected for Application Gateway subnets
- **Key Vault soft delete not enabled** — may be dev/test environments
- **Managed identity with Contributor role** — may be automation service principal (verify scope)

### GCP
- **Firewall rule allows 0.0.0.0/0** on port 443 — expected for GKE ingress
- **Service account with Owner role** — Terraform service account (verify if org-level)
- **Bucket with uniform access** disabled — may be legacy bucket requiring ACLs

### IaC
- **Checkov CKV_AWS_18**: S3 access logging — not required for log destination buckets themselves
- **tfsec aws-vpc-no-public-ingress**: expected for load balancer subnets
- **KICS missing encryption**: DynamoDB tables with on-demand encryption (default AWS-managed key)

### Tuning Strategy
1. Document each false positive pattern with specific resource context
2. Add to scanner exception rules with expiry dates (max 90 days)
3. Review exceptions quarterly — remove stale ones
4. Never suppress an entire rule — suppress per-resource only""",
        ),

        # ── Escalation ──
        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=85,
            title="Security Incident Escalation Matrix",
            category="escalation", entry_type="sop",
            tags="escalation,incident,severity,notification,sop",
            content="""## Security Incident Escalation Matrix

### Severity Classification
| Severity | Response Time | Examples |
|----------|--------------|---------|
| P0 - Critical | 15 minutes | Active breach, ransomware, credential exposure in production |
| P1 - High | 1 hour | Unauthorized access attempt, public data exposure, critical vuln exploited |
| P2 - Medium | 4 hours | New critical CVE affecting production, misconfiguration with exposure potential |
| P3 - Low | 24 hours | Non-critical misconfiguration, informational finding, best practice gap |

### Escalation Path
**P0 — Critical**
1. Security on-call (PagerDuty / OpsGenie) — immediate
2. CISO + VP Engineering — within 15 minutes
3. Legal counsel — within 30 minutes if data breach suspected
4. External IR retainer (CrowdStrike / Mandiant) — if APT indicators
5. Board notification — within 24 hours if material breach

**P1 — High**
1. Security team Slack channel — immediate
2. Engineering lead for affected service — within 1 hour
3. CISO — daily summary unless escalation needed
4. Customer notification team — standby if customer data involved

**P2 — Medium**
1. Security team backlog (Jira/ADO) — next sprint
2. Engineering owner via async notification
3. Weekly security review meeting

**P3 — Low**
1. Security backlog — prioritized in quarterly planning
2. Automated remediation where possible

### Communication Templates
- Internal: "[SEVERITY] Security Incident — [BRIEF DESCRIPTION] — Response Lead: [NAME]"
- External: Use pre-approved customer notification templates from Legal
- Regulatory: Follow breach notification checklist per jurisdiction""",
        ),

        # ── Compliance ──
        KnowledgeEntry(
            organization_id=org_id, created_by=created_by, priority=75,
            title="SOC2 Type II Continuous Compliance Checklist",
            category="compliance", entry_type="checklist",
            tags="soc2,compliance,audit,continuous,checklist",
            content="""## SOC2 Type II Continuous Compliance Checklist

### Trust Service Criteria — Key Controls

**CC6 — Logical and Physical Access Controls**
- [ ] MFA enforced on all user accounts (CC6.1)
- [ ] Quarterly access reviews completed (CC6.2)
- [ ] Service account credentials rotated every 90 days (CC6.1)
- [ ] Network segmentation enforced — no flat networks (CC6.6)
- [ ] Encryption at rest enabled on all data stores (CC6.1)
- [ ] Encryption in transit (TLS 1.2+) on all communications (CC6.7)

**CC7 — System Operations**
- [ ] Intrusion detection/prevention active (CC7.1)
- [ ] Security monitoring and alerting configured (CC7.2)
- [ ] Incident response plan tested within last 12 months (CC7.3)
- [ ] Vulnerability scanning running weekly (CC7.1)
- [ ] Penetration test completed within last 12 months (CC7.1)

**CC8 — Change Management**
- [ ] All production changes go through CI/CD pipeline (CC8.1)
- [ ] Code review required before merge (CC8.1)
- [ ] Automated testing in CI pipeline (CC8.1)
- [ ] Change approval process documented and followed (CC8.1)

### Evidence Collection
- CloudTrail / Activity Logs — 365 day retention minimum
- IAM access reviews — documented quarterly
- Vulnerability scan reports — archived monthly
- Incident response drill documentation — annual
- Penetration test report — annual, from qualified third party

### Continuous Monitoring
- GuardNous automated scans — map findings to SOC2 controls
- Alert on any control regression (finding re-introduced after fix)
- Monthly compliance score trending dashboard""",
        ),
    ]
    return entries
