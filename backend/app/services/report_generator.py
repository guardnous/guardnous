from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.report import Report
from app.services.risk.scorer import RiskScorer
from app.core.config import settings
import csv
import io
import json


class ReportGenerator:
    """Generates security reports in HTML and JSON formats."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate(self, org_id: int, title: str, report_type: str, format: str, scan_ids: list[int]) -> Report:
        scorer = RiskScorer(self.db)
        risk_data = await scorer.get_organization_score(org_id)
        severity = await scorer.get_severity_breakdown(org_id)
        cloud = await scorer.get_cloud_breakdown(org_id)

        # Get findings
        stmt = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.organization_id == org_id)
            .where(Finding.is_fixed == False)
            .where(Finding.is_ignored == False)
        )
        if scan_ids:
            stmt = stmt.where(Scan.id.in_(scan_ids))
        stmt = stmt.order_by(Finding.severity.asc())

        result = await self.db.execute(stmt)
        findings = result.scalars().all()

        if format == "json":
            content = self._generate_json(title, risk_data, severity, cloud, findings)
        elif format == "csv":
            content = self._generate_csv(title, risk_data, severity, cloud, findings)
        elif format == "pdf":
            content = self._generate_pdf(title, report_type, risk_data, severity, cloud, findings)
        else:
            content = self._generate_html(title, report_type, risk_data, severity, cloud, findings)

        report = Report(
            organization_id=org_id,
            title=title,
            report_type=report_type,
            format=format,
            status="completed",
            content=content,
            scan_ids=scan_ids,
        )
        self.db.add(report)
        await self.db.commit()
        await self.db.refresh(report)
        return report

    def _generate_json(self, title, risk_data, severity, cloud, findings) -> str:
        return json.dumps({
            "title": title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk_data,
            "severity_breakdown": severity,
            "cloud_breakdown": cloud,
            "total_findings": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "cloud_provider": f.cloud_provider,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }, indent=2)

    def _generate_csv(self, title, risk_data, severity, cloud, findings) -> str:
        output = io.StringIO()
        generated_at = datetime.now(timezone.utc).isoformat()
        total_findings = len(findings)

        output.write(f"# Title: {title}\n")
        output.write(f"# Generated At: {generated_at}\n")
        output.write(f"# Risk Score: {risk_data.get('overall', 'N/A')}\n")
        output.write(f"# Total Findings: {total_findings}\n")

        writer = csv.writer(output)
        writer.writerow([
            "rule_id", "title", "severity", "category", "cloud_provider",
            "resource_type", "resource_name", "file_path", "line_number",
            "description", "remediation",
        ])
        for f in findings:
            writer.writerow([
                f.rule_id,
                f.title,
                f.severity,
                f.category,
                f.cloud_provider or "",
                f.resource_type or "",
                f.resource_name or "",
                getattr(f, "file_path", "") or "",
                getattr(f, "line_number", "") or "",
                f.description or "",
                f.remediation or "",
            ])

        return output.getvalue()

    def _generate_pdf(self, title, report_type, risk_data, severity, cloud, findings) -> str:
        """Generate a PDF report and return base64-encoded content."""
        import base64
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
        except ImportError:
            return self._generate_csv(title, risk_data, severity, cloud, findings)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph(f"<b>GuardNous — {title}</b>", styles["Title"]))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Type: {report_type}",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 20))

        score = risk_data.get("overall", 0)
        elements.append(Paragraph(f"<b>Risk Score:</b> {score}/100", styles["Heading2"]))
        elements.append(Paragraph(
            f"Critical: {severity['critical']} | High: {severity['high']} | "
            f"Medium: {severity['medium']} | Low: {severity['low']}",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 16))

        header = ["Severity", "Rule ID", "Title", "Cloud", "Resource"]
        rows = [header]
        for f in findings[:500]:
            rows.append([
                f.severity or "",
                f.rule_id or "",
                (f.title or "")[:60],
                f.cloud_provider or "",
                (f.resource_name or "")[:40],
            ])

        tbl = Table(rows, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        elements.append(tbl)

        doc.build(elements)
        return base64.b64encode(buf.getvalue()).decode()

    def _generate_html(self, title, report_type, risk_data, severity, cloud, findings) -> str:
        score = risk_data["overall"]
        score_color = "#ef4444" if score >= 70 else "#f59e0b" if score >= 40 else "#22c55e"

        findings_html = ""
        for f in findings:
            sev_color = {
                "CRITICAL": "#dc2626", "HIGH": "#ea580c",
                "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280"
            }.get(f.severity, "#6b7280")

            findings_html += f"""
            <tr>
                <td><span style="background:{sev_color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{f.severity}</span></td>
                <td>{f.rule_id}</td>
                <td>{f.title}</td>
                <td>{f.cloud_provider or 'N/A'}</td>
                <td>{f.resource_name or 'N/A'}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">{f.remediation or 'N/A'}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - GuardNous</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid #334155; }}
        .header h1 {{ font-size: 28px; color: #f1f5f9; margin-bottom: 8px; }}
        .header p {{ color: #94a3b8; }}
        .score-card {{ text-align: center; background: #1e293b; border-radius: 12px; padding: 40px; margin-bottom: 30px; }}
        .score {{ font-size: 72px; font-weight: bold; color: {score_color}; }}
        .score-label {{ font-size: 18px; color: #94a3b8; margin-top: 8px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 24px; }}
        .card h3 {{ color: #94a3b8; font-size: 14px; text-transform: uppercase; margin-bottom: 12px; }}
        .card .value {{ font-size: 32px; font-weight: bold; color: #f1f5f9; }}
        .card .sub {{ color: #64748b; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }}
        th {{ background: #334155; color: #94a3b8; text-align: left; padding: 12px 16px; font-size: 13px; text-transform: uppercase; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid #334155; font-size: 14px; }}
        tr:hover {{ background: #1e293b80; }}
        .footer {{ text-align: center; margin-top: 40px; color: #64748b; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>GuardNous - {title}</h1>
            <p>Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} | Type: {report_type.title()}</p>
        </div>

        <div class="score-card">
            <div class="score">{score}/100</div>
            <div class="score-label">Overall Risk Score</div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Severity Breakdown</h3>
                <div class="value">{severity['critical']}</div>
                <div class="sub">Critical</div>
                <p style="margin-top:8px; color:#94a3b8;">High: {severity['high']} | Medium: {severity['medium']} | Low: {severity['low']}</p>
            </div>
            <div class="card">
                <h3>Cloud Breakdown</h3>
                <div class="value">{cloud['aws'] + cloud['gcp'] + cloud['azure']}</div>
                <div class="sub">Total Findings</div>
                <p style="margin-top:8px; color:#94a3b8;">AWS: {cloud['aws']} | GCP: {cloud['gcp']} | Azure: {cloud['azure']}</p>
            </div>
            <div class="card">
                <h3>Risk by Cloud</h3>
                <p style="color:#94a3b8; margin-top: 8px;">AWS: {risk_data['aws']}/100</p>
                <p style="color:#94a3b8;">GCP: {risk_data['gcp']}/100</p>
                <p style="color:#94a3b8;">Azure: {risk_data['azure']}/100</p>
            </div>
        </div>

        <h2 style="margin-bottom:16px; color:#f1f5f9;">Findings ({len(findings)})</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Rule</th><th>Title</th><th>Cloud</th><th>Resource</th><th>Remediation</th></tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>

        <div class="footer">
            <p>GuardNous v{settings.APP_VERSION} | Cloud Security & IaC Posture Management Platform</p>
        </div>
    </div>
</body>
</html>"""
