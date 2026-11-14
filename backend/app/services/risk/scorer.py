import math
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.scan import Scan
from app.models.finding import Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


LINEAR_UNTIL = 250       # weight at which risk reaches 50 (25 critical findings)
SATURATES_AT = 25_000    # weight at which risk reaches 100


def risk_from_weight(weight: float) -> int:
    """Risk 0-100 from the summed severity weight of open findings.

    Up to a weight of 250 the score rises in a straight line to 50. Beyond that
    it rises with the logarithm of the weight and reaches 100 at 25,000. A
    straight line capped at 100 reported the same score for 50 and for 5,000
    critical findings, so fixing findings in a large backlog never moved it.
    """
    if weight <= 0:
        return 0
    if weight <= LINEAR_UNTIL:
        return int(weight / LINEAR_UNTIL * 50)
    if weight >= SATURATES_AT:
        return 100
    return min(99, int(50 + 50 * math.log(weight / LINEAR_UNTIL) / math.log(SATURATES_AT / LINEAR_UNTIL)))


class RiskScorer:
    """Calculates risk scores (0-100) from findings."""

    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db

    def calculate_scan_score(self, findings: list[dict]) -> int:
        """Calculate risk score from a list of findings. Returns 0-100 (100 = highest risk)."""
        if not findings:
            return 0

        total_weight = 0
        for f in findings:
            severity = f.get("severity", "LOW")
            total_weight += SEVERITY_WEIGHTS.get(severity, 0)

        return risk_from_weight(total_weight)

    async def get_organization_score(self, org_id: int) -> dict:
        """Get overall risk score and breakdown for an organization."""
        # Get active (non-fixed, non-ignored) findings from recent scans
        stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == org_id)
            .where(Finding.is_fixed == False)
            .where(Finding.is_ignored == False)
        )
        result = await self.db.execute(stmt)
        findings = result.scalars().all()

        all_findings = [{"severity": f.severity, "cloud_provider": f.cloud_provider} for f in findings]
        overall = self.calculate_scan_score(all_findings)

        # By cloud
        aws_findings = [f for f in all_findings if f.get("cloud_provider") == "aws"]
        gcp_findings = [f for f in all_findings if f.get("cloud_provider") == "gcp"]
        azure_findings = [f for f in all_findings if f.get("cloud_provider") == "azure"]

        return {
            "overall": overall,
            "aws": self.calculate_scan_score(aws_findings),
            "gcp": self.calculate_scan_score(gcp_findings),
            "azure": self.calculate_scan_score(azure_findings),
        }

    async def get_severity_breakdown(self, org_id: int) -> dict:
        """Get count of findings by severity."""
        stmt = (
            select(Finding.severity, func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == org_id)
            .where(Finding.is_fixed == False)
            .where(Finding.is_ignored == False)
            .group_by(Finding.severity)
        )
        result = await self.db.execute(stmt)
        rows = result.all()

        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for severity, count in rows:
            key = severity.lower()
            if key in breakdown:
                breakdown[key] = count

        return breakdown

    async def get_cloud_breakdown(self, org_id: int) -> dict:
        """Get count of findings by cloud provider."""
        stmt = (
            select(Finding.cloud_provider, func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == org_id)
            .where(Finding.is_fixed == False)
            .where(Finding.is_ignored == False)
            .group_by(Finding.cloud_provider)
        )
        result = await self.db.execute(stmt)
        rows = result.all()

        breakdown = {"aws": 0, "gcp": 0, "azure": 0}
        for cloud, count in rows:
            if cloud and cloud.lower() in breakdown:
                breakdown[cloud.lower()] = count

        return breakdown

    async def get_trend(self, org_id: int, days: int = 7) -> list[dict]:
        """Get risk score trend over time."""
        trend = []
        now = datetime.now(timezone.utc)

        for i in range(days, -1, -1):
            date = now - timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")

            stmt = (
                select(func.count(Finding.id))
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.organization_id == org_id)
                .where(Finding.is_fixed == False)
                .where(Finding.is_ignored == False)
                .where(Finding.created_at <= date)
            )

            result = await self.db.execute(stmt)
            count = result.scalar() or 0

            # Approximate score from count
            score = min(100, count * 3)
            trend.append({"date": date_str, "score": score, "findings": count})

        return trend

    async def get_top_risks(self, org_id: int, limit: int = 5) -> list[dict]:
        """Get top N riskiest findings."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == org_id)
            .where(Finding.is_fixed == False)
            .where(Finding.is_ignored == False)
            .order_by(Finding.severity.asc())
            .limit(limit * 3)  # Fetch extra for sorting
        )
        result = await self.db.execute(stmt)
        findings = result.scalars().all()

        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))
        return [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cloud_provider": f.cloud_provider,
                "resource_name": f.resource_name,
            }
            for f in sorted_findings[:limit]
        ]
