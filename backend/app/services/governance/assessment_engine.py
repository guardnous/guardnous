"""Assessment Engine — orchestrates policy evaluation against cloud resources.

This is the main entry point for running governance assessments.
It loads policies, loads resources, runs the evaluator, creates violations
with evidence, and produces assessment snapshots for trend tracking.
"""
from __future__ import annotations

import logging
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_resource import CloudResource, Assessment, AssessmentResult
from app.models.governance import SecurityPolicy, PolicyViolation, RiskException
from app.services.governance.policy_evaluator import PolicyEvaluator, EvaluationResult

logger = logging.getLogger(__name__)


class AssessmentEngine:
    """Runs governance assessments — evaluates policies against cloud resources.

    Usage:
        engine = AssessmentEngine(db_session)
        assessment = await engine.run_assessment(org_id, triggered_by="admin@example.com")
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.evaluator = PolicyEvaluator()

    async def run_assessment(
        self,
        organization_id: int,
        triggered_by: str | None = None,
        assessment_type: str = "full",
        provider_filter: list[str] | None = None,
        resource_type_filter: list[str] | None = None,
    ) -> Assessment:
        """Run a full governance assessment.

        1. Load all enabled policies with conditions
        2. Load all active cloud resources in scope
        3. For each (policy, matching_resources) pair, evaluate conditions
        4. Create assessment results with evidence
        5. Update/create PolicyViolation records
        6. Compute compliance scores
        7. Return assessment snapshot
        """
        started_at = datetime.now(timezone.utc)

        # Create assessment record
        assessment = Assessment(
            organization_id=organization_id,
            assessment_type=assessment_type,
            status="running",
            triggered_by=triggered_by,
            started_at=started_at,
        )
        self.db.add(assessment)
        await self.db.flush()

        try:
            # 1. Load policies
            policies = await self._load_policies(organization_id)
            # 2. Load resources
            resources = await self._load_resources(
                organization_id, provider_filter, resource_type_filter
            ) if policies else []

            if not policies or not resources:
                # Nothing to check is not the same as fully compliant: no score.
                assessment.status = "completed"
                assessment.policies_evaluated = len(policies)
                assessment.resources_evaluated = len(resources)
                assessment.compliance_score = None
                assessment.completed_at = datetime.now(timezone.utc)
                assessment.duration_seconds = int((assessment.completed_at - started_at).total_seconds())
                await self.db.commit()
                return assessment

            # 3. Load active exemptions
            exemptions = await self._load_exemptions(organization_id)
            exemption_map = self._build_exemption_map(exemptions)

            # 4. Evaluate all (policy, resource) pairs
            total_checks = 0
            passed = 0
            failed = 0
            errors = 0
            exempted = 0
            providers_seen = set()
            resource_types_seen = set()
            new_violations = 0
            resolved_count = 0

            # Track existing open violations to detect resolved ones. Scoped to the
            # policies evaluated here so finding-based violations are left alone.
            policy_ids = [p["id"] for p in policies]
            existing_violation_keys = await self._get_violation_keys(organization_id, policy_ids, "open")
            accepted_keys = await self._get_violation_keys(organization_id, policy_ids, "accepted")
            current_violation_keys = set()
            # Resources actually evaluated per policy; only those can be auto-resolved
            evaluated_keys: set[tuple] = set()

            for policy in policies:
                condition = policy.get("condition")
                if not condition:
                    continue

                policy_resource_types = policy.get("resource_types", [])

                # Find matching resources
                matching = [
                    r for r in resources
                    if not policy_resource_types or r["resource_type"] in policy_resource_types
                ]

                for resource in matching:
                    total_checks += 1
                    providers_seen.add(resource["provider"])
                    resource_types_seen.add(resource["resource_type"])

                    # Check exemptions
                    exemption = self._find_exemption(
                        exemption_map, policy["id"], resource["resource_id"], resource["resource_type"]
                    )

                    if exemption:
                        exempted += 1
                        await self._create_result(
                            assessment, policy, resource,
                            EvaluationResult(status="EXEMPTED"),
                            exemption_id=exemption["id"],
                        )
                        continue

                    # Evaluate
                    result = self.evaluator.evaluate(condition, resource["config"])
                    vkey = (policy["id"], resource["resource_id"])
                    evaluated_keys.add(vkey)

                    if result.failed and vkey in accepted_keys:
                        # Risk formally accepted on the violation: keep it accepted
                        exempted += 1
                        await self._create_result(assessment, policy, resource, result, risk_accepted=True)
                        continue

                    if result.status == "PASS":
                        passed += 1
                    elif result.status == "FAIL":
                        failed += 1
                        current_violation_keys.add(vkey)
                        if vkey not in existing_violation_keys:
                            new_violations += 1
                    elif result.status == "ERROR":
                        errors += 1

                    # Create assessment result with evidence
                    await self._create_result(assessment, policy, resource, result)

                    # Create/update violation if failed
                    if result.failed:
                        await self._upsert_violation(
                            organization_id, policy, resource, result
                        )

            # 5. Resolve violations that no longer fail
            resolved_count = await self._resolve_old_violations(
                organization_id, existing_violation_keys & evaluated_keys, current_violation_keys
            )

            # 6. Compute score
            scorable = passed + failed + exempted
            score = round((passed + exempted) / scorable * 100) if scorable > 0 else None

            # 7. Finalize assessment
            completed_at = datetime.now(timezone.utc)
            assessment.status = "completed"
            assessment.policies_evaluated = len(policies)
            assessment.resources_evaluated = len(resources)
            assessment.providers_evaluated = list(providers_seen)
            assessment.resource_types_evaluated = list(resource_types_seen)
            assessment.total_checks = total_checks
            assessment.passed = passed
            assessment.failed = failed
            assessment.errors = errors
            assessment.exempted = exempted
            assessment.compliance_score = score
            assessment.new_violations = new_violations
            assessment.resolved_violations = resolved_count
            assessment.total_violations = failed
            assessment.completed_at = completed_at
            assessment.duration_seconds = int((completed_at - started_at).total_seconds())

            await self.db.commit()

            logger.info(
                f"Assessment #{assessment.id} completed: "
                f"{total_checks} checks, {passed} passed, {failed} failed, "
                f"{exempted} exempted, score={score}%"
            )

            return assessment

        except Exception as e:
            logger.error(f"Assessment failed: {e}", exc_info=True)
            assessment.status = "failed"
            assessment.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            raise

    async def _load_policies(self, org_id: int) -> list[dict]:
        """Load all enabled policies with evaluatable conditions."""
        result = await self.db.execute(
            select(SecurityPolicy).where(
                and_(
                    SecurityPolicy.organization_id == org_id,
                    SecurityPolicy.is_enabled == True,  # noqa: E712
                )
            )
        )
        policies = result.scalars().all()

        loaded = []
        for p in policies:
            # Extract condition from the policy's rules JSON
            condition = None
            resource_types = []
            remediation_text = None

            if isinstance(p.rules, dict):
                condition = p.rules.get("condition")
                resource_types = p.rules.get("resource_types", [])
                remediation_text = p.rules.get("remediation", {}).get("description") if isinstance(p.rules.get("remediation"), dict) else None
            elif isinstance(p.rules, list):
                # Legacy format — extract from first rule with a condition
                for rule in p.rules:
                    if isinstance(rule, dict) and "condition" in rule:
                        condition = rule["condition"]
                        resource_types = rule.get("resource_types", [])
                        break

            if condition:
                loaded.append({
                    "id": p.id,
                    "name": p.name,
                    "severity": p.severity,
                    "condition": condition,
                    "resource_types": resource_types,
                    "remediation": remediation_text,
                })

        return loaded

    async def _load_resources(
        self,
        org_id: int,
        provider_filter: list[str] | None = None,
        resource_type_filter: list[str] | None = None,
    ) -> list[dict]:
        """Load active cloud resources, optionally filtered."""
        query = select(CloudResource).where(
            and_(
                CloudResource.organization_id == org_id,
                CloudResource.status == "active",
            )
        )
        if provider_filter:
            query = query.where(CloudResource.provider.in_(provider_filter))
        if resource_type_filter:
            query = query.where(CloudResource.resource_type.in_(resource_type_filter))

        result = await self.db.execute(query)
        resources = result.scalars().all()

        return [
            {
                "id": r.id,
                "provider": r.provider,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "resource_name": r.resource_name,
                "region": r.region,
                "config": r.config or {},
                "tags": r.tags or {},
            }
            for r in resources
        ]

    async def _load_exemptions(self, org_id: int) -> list[dict]:
        """Load active, approved, non-expired exemptions."""
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(RiskException).where(
                and_(
                    RiskException.organization_id == org_id,
                    RiskException.status == "approved",
                )
            )
        )
        exemptions = result.scalars().all()

        active = []
        for e in exemptions:
            # Check expiry (expiry_date is the engine field, expires_at the older API field)
            expiry = e.expiry_date or e.expires_at
            if expiry:
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry < now:
                    continue
            active.append({
                "id": e.id,
                "policy_id": e.policy_id if hasattr(e, "policy_id") else None,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "resource_name": e.resource_name,
            })
        return active

    def _build_exemption_map(self, exemptions: list[dict]) -> dict:
        """Build a lookup map: (policy_id, resource_id) → exemption."""
        emap: dict[tuple, dict] = {}
        for e in exemptions:
            # Exact match: specific policy + specific resource
            if e.get("policy_id") and e.get("resource_id"):
                emap[(e["policy_id"], e["resource_id"])] = e
            # Wildcard: specific resource, any policy
            elif e.get("resource_id"):
                emap[(None, e["resource_id"])] = e
            # Wildcard: specific policy, any resource of that type
            elif e.get("policy_id") and e.get("resource_type"):
                emap[(e["policy_id"], e["resource_type"])] = e
            # Whole policy exempted
            elif e.get("policy_id"):
                emap[(e["policy_id"], None)] = e
        return emap

    def _find_exemption(
        self, emap: dict, policy_id: int, resource_id: str, resource_type: str | None = None
    ) -> dict | None:
        """Check if a (policy, resource) pair is exempted."""
        # Exact match
        if (policy_id, resource_id) in emap:
            return emap[(policy_id, resource_id)]
        # Wildcard resource
        if (None, resource_id) in emap:
            return emap[(None, resource_id)]
        # Policy-wide exemption for a resource type
        if resource_type and (policy_id, resource_type) in emap:
            return emap[(policy_id, resource_type)]
        if (policy_id, None) in emap:
            return emap[(policy_id, None)]
        return None

    async def _create_result(
        self,
        assessment: Assessment,
        policy: dict,
        resource: dict,
        result: EvaluationResult,
        exemption_id: int | None = None,
        risk_accepted: bool = False,
    ):
        """Create an AssessmentResult record with evidence."""
        status = "EXEMPTED" if (exemption_id or risk_accepted) else result.status

        ar = AssessmentResult(
            assessment_id=assessment.id,
            organization_id=assessment.organization_id,
            policy_id=policy["id"],
            policy_name=policy["name"],
            policy_severity=policy["severity"],
            resource_id=resource.get("id"),
            resource_identifier=resource["resource_id"],
            resource_type=resource["resource_type"],
            resource_name=resource["resource_name"],
            provider=resource["provider"],
            status=status,
            is_exempted=exemption_id is not None or risk_accepted,
            exemption_id=exemption_id,
            evidence=[e.to_dict() for e in result.evidence],
            remediation=policy.get("remediation"),
            auto_fixable=False,
        )
        self.db.add(ar)

    async def _upsert_violation(
        self,
        org_id: int,
        policy: dict,
        resource: dict,
        result: EvaluationResult,
    ):
        """Create or update a PolicyViolation for a failed check."""
        # Check if violation already exists
        existing = await self.db.execute(
            select(PolicyViolation).where(
                and_(
                    PolicyViolation.organization_id == org_id,
                    PolicyViolation.policy_id == policy["id"],
                    PolicyViolation.resource_id == resource["resource_id"],
                )
            )
        )
        violation = existing.scalars().first()

        evidence_data = {
            "source": "cloud_resource",
            "evidence": [e.to_dict() for e in result.evidence],
            "last_evaluated": datetime.now(timezone.utc).isoformat(),
        }

        if violation:
            # Update existing; reopen only if it had been resolved
            violation.violation_details = evidence_data
            if violation.status == "resolved":
                violation.status = "open"
                violation.resolved_at = None
        else:
            # Create new
            violation = PolicyViolation(
                organization_id=org_id,
                policy_id=policy["id"],
                resource_type=resource["resource_type"],
                resource_id=resource["resource_id"],
                resource_name=resource["resource_name"],
                severity=policy["severity"],
                violation_details=evidence_data,
                status="open",
            )
            self.db.add(violation)

    async def _get_violation_keys(self, org_id: int, policy_ids: list[int], status: str) -> set[tuple]:
        """(policy_id, resource_id) of violations in ``status`` for the given policies."""
        if not policy_ids:
            return set()
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(
                PolicyViolation.policy_id, PolicyViolation.resource_id, PolicyViolation.acceptance_expires,
            ).where(
                and_(
                    PolicyViolation.organization_id == org_id,
                    PolicyViolation.policy_id.in_(policy_ids),
                    PolicyViolation.status == status,
                )
            )
        )
        keys = set()
        for policy_id, resource_id, acceptance_expires in result.all():
            if status == "accepted" and acceptance_expires:
                exp = acceptance_expires if acceptance_expires.tzinfo else acceptance_expires.replace(tzinfo=timezone.utc)
                if exp < now:
                    continue  # acceptance lapsed: evaluate normally
            keys.add((policy_id, resource_id))
        return keys

    async def _resolve_old_violations(
        self,
        org_id: int,
        old_keys: set[tuple],
        current_keys: set[tuple],
    ) -> int:
        """Mark violations as resolved if they no longer fail."""
        resolved_keys = old_keys - current_keys
        count = 0
        for policy_id, resource_id in resolved_keys:
            result = await self.db.execute(
                select(PolicyViolation).where(
                    and_(
                        PolicyViolation.organization_id == org_id,
                        PolicyViolation.policy_id == policy_id,
                        PolicyViolation.resource_id == resource_id,
                        PolicyViolation.status == "open",
                    )
                )
            )
            violation = result.scalars().first()
            if violation:
                violation.status = "resolved"
                violation.resolved_at = datetime.now(timezone.utc)
                count += 1
        return count

    @staticmethod
    def compute_config_hash(config: dict) -> str:
        """Compute a stable hash of resource config for drift detection."""
        canonical = json.dumps(config, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()
