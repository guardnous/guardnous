import html
import json
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.audit import write_audit_log
from app.core.app_logger import app_log
from app.core.config import settings
from app.core.email import send_email_with_attachment, build_report_email_html, _resolve_smtp_params
from app.core.encryption import decrypt_token
from app.models.org_settings import OrgSettings
from app.models.user import User
from app.models.report import Report
from app.schemas.report import ReportCreate, ReportResponse
from app.services.report_generator import ReportGenerator

router = APIRouter()


ALLOWED_FORMATS = {"html", "json", "pdf", "csv"}


@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(
    report_data: ReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "create")),
):
    if not report_data.title or not report_data.title.strip():
        raise HTTPException(status_code=400, detail="Report title cannot be empty")
    if report_data.format not in ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Allowed: {', '.join(ALLOWED_FORMATS)}")
    generator = ReportGenerator(db)
    report = await generator.generate(
        org_id=current_user.organization_id,
        title=report_data.title,
        report_type=report_data.report_type,
        format=report_data.format,
        scan_ids=report_data.scan_ids,
    )

    # Write audit log + auto-notification
    await write_audit_log(
        db=db,
        user=current_user,
        action="create",
        resource_type="report",
        resource_id=report.id,
        details={
            "title": report.title,
            "report_type": report.report_type,
            "format": report.format,
        },
        request=request,
    )

    # Write application log (shows under REPORT category filter)
    await app_log.info(
        db,
        "REPORT",
        f"Report generated: {report.title} ({report.report_type}, {report.format})",
        user=current_user,
        request=request,
        metadata={
            "report_id": report.id,
            "report_type": report.report_type,
            "format": report.format,
            "title": report.title,
        },
    )

    await db.commit()
    return ReportResponse.from_orm_with_pdf(report)


@router.get("")
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    result = await db.execute(
        select(Report)
        .where(Report.organization_id == current_user.organization_id)
        .order_by(Report.created_at.desc())
        .limit(50)
    )
    reports = result.scalars().all()
    return [ReportResponse.from_orm_with_pdf(r) for r in reports]


@router.get("/{report_id}")
async def get_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    result = await db.execute(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.from_orm_with_pdf(report)


@router.delete("/{report_id}", status_code=200)
async def delete_report(
    report_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "delete")),
):
    result = await db.execute(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    title = report.title
    await db.delete(report)

    await write_audit_log(
        db=db, user=current_user, action="delete",
        resource_type="report", resource_id=report_id,
        details={"title": title}, request=request,
    )
    await app_log.info(
        db, "REPORT", f"Report deleted: {title}",
        user=current_user, request=request,
        metadata={"report_id": report_id, "title": title},
    )
    await db.commit()
    return {"message": "Report deleted"}


@router.get("/{report_id}/view")
async def view_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    """View report data as structured JSON (for in-app viewer)."""
    result = await db.execute(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report_data = None
    if report.content:
        try:
            report_data = json.loads(report.content) if isinstance(report.content, str) else report.content
        except (json.JSONDecodeError, TypeError):
            report_data = {"raw_content": report.content}

    return {
        "id": report.id,
        "title": report.title,
        "report_type": report.report_type,
        "format": report.format,
        "status": report.status,
        "scan_id": report.scan_id,
        "file_name": report.file_name,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "report_data": report_data,
    }


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    format: str = Query("json", regex="^(html|json|pdf|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    result = await db.execute(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    base_name = report.file_name or f"report_{report.id}"

    if format == "csv":
        csv_content = _generate_csv_from_report(report)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.csv"'},
        )
    elif format == "pdf":
        pdf_bytes = _generate_pdf_from_report(report)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.pdf"'},
        )
    elif format == "html" or report.format == "html":
        html_content = report.content
        if report.format == "json" and report.content:
            html_content = _json_to_html(report)
        return HTMLResponse(content=html_content or "", headers={
            "Content-Disposition": f'attachment; filename="{base_name}.html"'
        })
    else:
        return Response(
            content=report.content or "{}",
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base_name}.json"'},
        )


def _generate_csv_from_report(report: Report) -> str:
    """Flatten report findings into a proper CSV."""
    import csv
    from io import StringIO

    data: dict = {}
    if report.content:
        try:
            data = json.loads(report.content) if isinstance(report.content, str) else report.content
        except (json.JSONDecodeError, TypeError):
            pass

    findings = data.get("findings", []) or data.get("iac_findings", [])
    secrets = data.get("secret_findings", [])
    all_items = list(findings) + list(secrets)
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Severity", "Rule ID", "Title", "Description", "File", "Line",
        "Resource", "Source Tool", "Compliance", "Remediation",
    ])
    for f in all_items:
        writer.writerow([
            f.get("severity", ""),
            f.get("rule_id", ""),
            f.get("title", ""),
            (f.get("description", "") or "")[:500],
            f.get("file_path", ""),
            f.get("line_number", ""),
            f.get("resource", ""),
            f.get("source", "") or f.get("metadata", {}).get("source", ""),
            ", ".join(f.get("compliance", {}).keys()) if isinstance(f.get("compliance"), dict) else "",
            (f.get("remediation", "") or "")[:300],
        ])
    return buf.getvalue()


def _generate_pdf_from_report(report: Report) -> bytes:
    """Generate a PDF from report content using xhtml2pdf."""
    html_content = _build_pdf_html(report)
    try:
        from io import BytesIO
        from xhtml2pdf import pisa
        import logging
        logger = logging.getLogger(__name__)
        buf = BytesIO()
        pisa_status = pisa.CreatePDF(html_content, dest=buf)
        pdf_bytes = buf.getvalue()
        if pisa_status.err:
            logger.warning("xhtml2pdf reported %d errors, PDF size=%d", pisa_status.err, len(pdf_bytes))
        # Even with errors pisa often produces a usable PDF — return it if non-empty
        if pdf_bytes and len(pdf_bytes) > 100:
            return pdf_bytes
        # Fallback: return HTML with a note
        logger.error("xhtml2pdf produced empty PDF, returning HTML fallback")
        return html_content.encode("utf-8")
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("PDF generation failed: %s", exc)
        return html_content.encode("utf-8")


def _report_data(report: Report) -> dict:
    """Parse report.content into dict, tolerant of str or dict storage."""
    if not report.content:
        return {}
    try:
        return json.loads(report.content) if isinstance(report.content, str) else (report.content if isinstance(report.content, dict) else {})
    except (json.JSONDecodeError, TypeError):
        return {}


def _sev_sort_key(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev.upper(), 5)


# ── PDF report (xhtml2pdf — NO flexbox/grid, tables only) ─────────────────

def _build_pdf_html(report: Report) -> str:
    """Comprehensive enterprise PDF report. Tables-only for xhtml2pdf."""
    title = report.title or "Security Scan Report"
    generated = report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "N/A"
    data = _report_data(report)
    summary = data.get("summary", {})
    findings = data.get("findings", []) or data.get("iac_findings", [])
    secrets = data.get("secret_findings", [])
    repo = data.get("repository", "")
    scan_id = data.get("scan_id", "")
    scan_type = data.get("scan_type", "")
    risk_score = data.get("risk_score", "N/A")
    compliance = data.get("compliance_mapping", {})
    policy_eval = data.get("policy_evaluation", {})
    vuln_corr = data.get("vulnerability_correlations", {})
    dep_analysis = data.get("dependency_analysis", {})
    stage_details = data.get("stage_details", {})

    SEV_COLORS = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280"}
    sorted_findings = sorted(findings, key=lambda f: _sev_sort_key(f.get("severity", "LOW")))

    # ── Aggregations ──
    from collections import Counter, defaultdict
    tool_counts: Counter = Counter()
    tool_sev: dict = {}
    cloud_counts: Counter = Counter()
    resource_type_counts: Counter = Counter()
    file_counts: Counter = Counter()
    file_sev: dict = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    category_counts: Counter = Counter()
    by_file: dict = defaultdict(list)

    for f in findings:
        src = f.get("source", "") or (f.get("metadata", {}) or {}).get("source", "") or "native"
        tool_counts[src] += 1
        if src not in tool_sev:
            tool_sev[src] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        s = f.get("severity", "LOW").upper()
        if s in tool_sev[src]:
            tool_sev[src][s] += 1
        cloud_counts[f.get("cloud_provider", "unknown")] += 1
        resource_type_counts[f.get("resource_type", "unknown")] += 1
        fp = f.get("file_path", "unknown")
        file_counts[fp] += 1
        if s in file_sev[fp]:
            file_sev[fp][s] += 1
        category_counts[f.get("category", "iac")] += 1
        by_file[fp].append(f)

    # ── Helper: severity badge (no CSS class, inline style for xhtml2pdf) ──
    def sev_badge(sev):
        s = (sev or "LOW").upper()
        c = SEV_COLORS.get(s, "#6b7280")
        return f'<span style="color:{c};font-weight:700">{html.escape(s)}</span>'

    def esc(v, maxlen=0):
        s = html.escape(str(v or ""))
        return s[:maxlen] + "…" if maxlen and len(s) > maxlen else s

    # ═══════════════════════════════════════════
    # BUILD HTML SECTIONS
    # ═══════════════════════════════════════════

    # ── 1. Stat boxes ──
    stat_cells = ""
    stats = [
        ("Total Findings", summary.get("total_findings", 0), "#f97316", "#fff7ed"),
        ("Critical", summary.get("critical", 0), "#dc2626", "#fef2f2"),
        ("High", summary.get("high", 0), "#ea580c", "#fff7ed"),
        ("Medium", summary.get("medium", 0), "#d97706", "#fffbeb"),
        ("Low", summary.get("low", 0), "#2563eb", "#eff6ff"),
        ("Secrets", summary.get("secrets_found", 0), "#7c3aed", "#f5f3ff"),
        ("Files Scanned", summary.get("files_scanned", 0), "#059669", "#ecfdf5"),
        ("Policies", policy_eval.get("total_policies", 0), "#0ea5e9", "#f0f9ff"),
    ]
    for label, val, color, bg in stats:
        stat_cells += (
            f'<td style="text-align:center;background:{bg};border:1px solid #e2e8f0;'
            f'padding:10px 6px;width:12%">'
            f'<span style="font-size:20px;font-weight:700;color:{color}">{val}</span><br/>'
            f'<span style="font-size:7px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px">{label}</span></td>'
        )

    # ── 2. Tool breakdown table ──
    tool_rows = ""
    for tn in sorted(tool_counts.keys()):
        tc = tool_counts[tn]
        ts = tool_sev.get(tn, {})
        pct = round(tc / max(len(findings), 1) * 100, 1)
        tool_rows += f'<tr><td style="font-weight:600">{esc(tn)}</td><td style="text-align:center;font-weight:700">{tc}</td><td style="text-align:center">{pct}%</td>'
        for sv in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            v = ts.get(sv, 0)
            c = SEV_COLORS.get(sv, "#6b7280")
            tool_rows += f'<td style="text-align:center;color:{c};font-weight:600">{v}</td>'
        tool_rows += '</tr>'

    # ── 3. Cloud provider breakdown ──
    cloud_rows = ""
    for cloud, cnt in cloud_counts.most_common():
        pct = round(cnt / max(len(findings), 1) * 100, 1)
        cloud_rows += f'<tr><td style="font-weight:600">{esc(cloud.upper())}</td><td style="text-align:center;font-weight:700">{cnt}</td><td style="text-align:center">{pct}%</td></tr>'

    # ── 4. Resource type breakdown (top 20) ──
    resource_rows = ""
    for rt, cnt in resource_type_counts.most_common(20):
        pct = round(cnt / max(len(findings), 1) * 100, 1)
        resource_rows += f'<tr><td style="font-size:8px">{esc(rt)}</td><td style="text-align:center;font-weight:700">{cnt}</td><td style="text-align:center">{pct}%</td></tr>'

    # ── 5. File heatmap (top 25 files) ──
    file_heatmap_rows = ""
    for fp, cnt in file_counts.most_common(25):
        fsev = file_sev[fp]
        file_heatmap_rows += (
            f'<tr><td style="font-size:8px;font-weight:600">{esc(fp)}</td>'
            f'<td style="text-align:center;font-weight:700">{cnt}</td>'
            f'<td style="text-align:center;color:#dc2626;font-weight:600">{fsev["CRITICAL"]}</td>'
            f'<td style="text-align:center;color:#ea580c;font-weight:600">{fsev["HIGH"]}</td>'
            f'<td style="text-align:center;color:#d97706;font-weight:600">{fsev["MEDIUM"]}</td>'
            f'<td style="text-align:center;color:#2563eb;font-weight:600">{fsev["LOW"]}</td></tr>'
        )

    # ── 6. Compliance framework table ──
    compliance_rows = ""
    by_fw = compliance.get("by_framework", {})
    for fw_name, fw_data in sorted(by_fw.items()):
        total_c = fw_data.get("total", 0)
        passed_c = fw_data.get("passed", 0)
        failed_c = fw_data.get("failed", 0)
        pct = round(passed_c / max(total_c, 1) * 100, 1)
        bar_color = "#dc2626" if pct < 30 else "#d97706" if pct < 70 else "#059669"
        compliance_rows += f'<tr><td style="font-weight:600">{esc(fw_name)}</td><td style="text-align:center">{total_c}</td><td style="text-align:center;color:#059669;font-weight:600">{passed_c}</td><td style="text-align:center;color:#dc2626;font-weight:600">{failed_c}</td><td style="text-align:center;color:{bar_color};font-weight:700">{pct}%</td></tr>'

    # ── 7. Policy evaluation by category ──
    policy_rows = ""
    pol_by_cat = policy_eval.get("by_category", {})
    for cat_name, cat_data in sorted(pol_by_cat.items()):
        p = cat_data.get("passed", 0)
        f_count = cat_data.get("failed", 0)
        na = cat_data.get("not_applicable", 0)
        w = cat_data.get("waived", 0)
        policy_rows += f'<tr><td style="text-transform:capitalize;font-weight:600">{esc(cat_name)}</td><td style="text-align:center;color:#059669;font-weight:600">{p}</td><td style="text-align:center;color:#dc2626;font-weight:600">{f_count}</td><td style="text-align:center;color:#6b7280">{w}</td><td style="text-align:center;color:#6b7280">{na}</td></tr>'

    # ── 8. Secrets table ──
    secret_rows = ""
    for i, s in enumerate(secrets, 1):
        sev = s.get("severity", "HIGH")
        secret_rows += (
            f'<tr><td>{i}</td><td>{sev_badge(sev)}</td>'
            f'<td style="font-size:8px">{esc(s.get("rule_id",""))}</td>'
            f'<td style="font-size:8px;font-weight:600">{esc(s.get("file_path",""))}</td>'
            f'<td style="text-align:center">{s.get("line_number","")}</td>'
            f'<td style="font-size:8px">{esc(s.get("match_preview",""))}</td>'
            f'<td style="font-size:8px">{esc(s.get("remediation",""), 120)}</td></tr>'
        )

    # ── 9. Top 30 Critical/High findings (detailed) ──
    top_findings = [f for f in sorted_findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")][:30]
    top_detail_rows = ""
    for i, f in enumerate(top_findings, 1):
        sev = f.get("severity", "LOW").upper()
        snippet = f.get("code_snippet", "")
        if isinstance(snippet, list):
            snippet = "\n".join(str(line) for line in snippet)
        snippet = str(snippet or "")
        if len(snippet) > 300:
            snippet = snippet[:300] + "..."
        remediation = f.get("remediation", "") or ""
        description = f.get("description", "") or ""
        top_detail_rows += (
            f'<tr style="border-top:2px solid #e2e8f0">'
            f'<td rowspan="3" style="text-align:center;vertical-align:top;width:3%;font-weight:700">{i}</td>'
            f'<td rowspan="3" style="vertical-align:top;width:6%">{sev_badge(sev)}</td>'
            f'<td style="width:12%"><strong>Rule:</strong> {esc(f.get("rule_id",""))}</td>'
            f'<td style="width:40%"><strong>{esc(f.get("title",""))}</strong></td>'
            f'<td style="width:20%;font-size:8px"><strong>File:</strong> {esc(f.get("file_path",""))}</td>'
            f'<td style="width:5%;text-align:center"><strong>L{f.get("line_number","")}</strong></td>'
            f'<td style="width:14%;font-size:8px"><strong>Resource:</strong> {esc(f.get("resource_name",""))}<br/><span style="color:#6b7280">{esc(f.get("resource_type",""))}</span></td></tr>'
            f'<tr><td colspan="5" style="font-size:8px;color:#334155"><strong>Description:</strong> {esc(description, 250)}</td></tr>'
        )
        if snippet:
            safe_snippet = html.escape(snippet).replace("\n", "<br/>")
            top_detail_rows += f'<tr><td colspan="5" style="background:#f1f5f9;font-family:Courier,monospace;font-size:7px;padding:4px 6px;color:#475569;white-space:pre-wrap">{safe_snippet}</td></tr>'
        else:
            top_detail_rows += f'<tr><td colspan="5" style="font-size:8px;color:#059669"><strong>Remediation:</strong> {esc(remediation, 200)}</td></tr>'

    # ── 10. PER-FILE DETAILED FINDINGS (the big section) ──
    # Group findings by file, sorted by total count desc
    per_file_html = ""
    sorted_files = sorted(by_file.keys(), key=lambda fp: -file_counts[fp])
    for fp in sorted_files:
        file_findings = sorted(by_file[fp], key=lambda f: _sev_sort_key(f.get("severity", "LOW")))
        fsev = file_sev[fp]
        sev_summary = " | ".join(
            f'<span style="color:{SEV_COLORS[s]};font-weight:600">{s[0]}:{fsev[s]}</span>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if fsev.get(s, 0) > 0
        )
        per_file_html += (
            f'<table style="margin-top:10px;border:1px solid #cbd5e1">'
            f'<tr><td colspan="7" style="background:#1e293b;color:white;padding:6px 8px;font-weight:700;font-size:10px">'
            f'📄 {esc(fp)} — {len(file_findings)} findings &nbsp; {sev_summary}</td></tr>'
            f'<tr><th style="width:3%">#</th><th style="width:6%">Severity</th>'
            f'<th style="width:10%">Rule ID</th><th style="width:20%">Title</th>'
            f'<th style="width:14%">Resource</th><th style="width:4%">Line</th>'
            f'<th style="width:43%">Description &amp; Remediation</th></tr>'
        )
        for j, f in enumerate(file_findings, 1):
            sev = f.get("severity", "LOW").upper()
            desc = f.get("description", "") or ""
            rem = f.get("remediation", "") or ""
            detail_parts = []
            if desc:
                detail_parts.append(f'<strong>Issue:</strong> {esc(desc, 200)}')
            if rem:
                detail_parts.append(f'<strong style="color:#059669">Fix:</strong> {esc(rem, 200)}')
            detail_html = "<br/>".join(detail_parts) if detail_parts else '<span style="color:#94a3b8">—</span>'
            snippet = f.get("code_snippet", "")
            if isinstance(snippet, list):
                snippet = "\n".join(str(line) for line in snippet)
            snippet = str(snippet or "")
            snippet_html = ""
            if snippet:
                short_snippet = snippet.strip()[:200]
                safe_s = html.escape(short_snippet).replace("\n", "<br/>")
                snippet_html = f'<br/><span style="background:#f1f5f9;font-family:Courier,monospace;font-size:6px;color:#475569;padding:1px 3px">{safe_s}</span>'
            per_file_html += (
                f'<tr><td style="text-align:center">{j}</td>'
                f'<td>{sev_badge(sev)}</td>'
                f'<td style="font-size:7px;font-weight:600">{esc(f.get("rule_id",""))}</td>'
                f'<td style="font-size:8px">{esc(f.get("title",""), 100)}</td>'
                f'<td style="font-size:7px">{esc(f.get("resource_name",""))}<br/><span style="color:#6b7280">{esc(f.get("resource_type",""))}</span></td>'
                f'<td style="text-align:center">{f.get("line_number","")}</td>'
                f'<td style="font-size:7px">{detail_html}{snippet_html}</td></tr>'
            )
        per_file_html += '</table>'

    # ── 11. Pipeline stage timings ──
    stage_rows = ""
    total_duration_ms = 0
    for stage_name, sd in stage_details.items():
        dur = sd.get("duration_ms", 0) if isinstance(sd, dict) else 0
        total_duration_ms += dur
        dur_str = f"{dur}ms" if dur < 1000 else f"{dur/1000:.1f}s"
        status = sd.get("status", "completed") if isinstance(sd, dict) else "completed"
        status_color = "#059669" if status == "completed" else "#d97706"
        stage_rows += f'<tr><td style="font-weight:600">{esc(stage_name)}</td><td style="text-align:center">{dur_str}</td><td style="text-align:center;color:{status_color}">{status}</td></tr>'
    total_dur_str = f"{total_duration_ms/1000:.1f}s"

    # ── 12. Dependency analysis ──
    dep_html = ""
    if dep_analysis and isinstance(dep_analysis, dict):
        dep_html = f"""
<h2>12. Dependency Analysis</h2>
<table>
    <tr><td style="width:50%"><strong>Total Dependencies</strong></td><td style="font-weight:700">{dep_analysis.get("total_dependencies", 0)}</td></tr>
    <tr><td><strong>Manifests Parsed</strong></td><td style="font-weight:700">{dep_analysis.get("manifests_parsed", 0)}</td></tr>
    <tr><td><strong>Vulnerable Dependencies</strong></td><td style="font-weight:700;color:#dc2626">{dep_analysis.get("vulnerable_count", 0)}</td></tr>
</table>"""

    safe_title = html.escape(title)
    safe_repo = html.escape(str(repo))
    finding_count = len(findings)

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
    @page {{ size: A4 landscape; margin: 12mm 10mm; }}
    body {{ font-family: Helvetica, Arial, sans-serif; color: #1e293b; font-size: 9px; margin: 0; padding: 0; }}
    h1 {{ font-size: 22px; margin: 0; color: white; }}
    h2 {{ font-size: 13px; color: #ea580c; border-bottom: 2px solid #fed7aa; padding-bottom: 4px; margin-top: 18px; margin-bottom: 6px; }}
    h3 {{ font-size: 11px; color: #334155; margin-top: 12px; margin-bottom: 4px; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
    th {{ background: #1e293b; color: white; padding: 5px 4px; text-align: left; font-size: 8px; font-weight: 600; }}
    td {{ border-bottom: 1px solid #e2e8f0; padding: 4px; font-size: 8px; vertical-align: top; word-wrap: break-word; }}
    tr:nth-child(even) td {{ background: #f8fafc; }}
    .hdr {{ background: linear-gradient(135deg, #f97316, #c2410c); padding: 16px 20px; color: white; }}
    .hdr .sub {{ font-size: 10px; color: #fed7aa; margin-top: 2px; }}
    .meta {{ background: #fff7ed; padding: 6px 20px; font-size: 8px; color: #92400e; border-bottom: 2px solid #f97316; }}
    .content {{ padding: 4px 0; }}
    .footer {{ text-align: center; color: #94a3b8; font-size: 7px; border-top: 1px solid #e2e8f0; padding-top: 6px; margin-top: 16px; }}
    .risk-box {{ background: #fef2f2; border: 2px solid #dc2626; padding: 8px 16px; text-align: center; }}
    .risk-val {{ font-size: 28px; font-weight: 800; }}
</style></head><body>

<!-- ═══ HEADER ═══ -->
<div class="hdr">
    <h1>🛡️ GuardNous — Comprehensive Security Scan Report</h1>
    <div class="sub">{safe_title} &nbsp;|&nbsp; {finding_count} findings across {len(file_counts)} files &nbsp;|&nbsp; {len(tool_counts)} scanning tools</div>
</div>
<div class="meta">
    <strong>Repository:</strong> {safe_repo} &nbsp;|&nbsp;
    <strong>Scan ID:</strong> {esc(str(scan_id))} &nbsp;|&nbsp;
    <strong>Scan Types:</strong> {esc(scan_type)} &nbsp;|&nbsp;
    <strong>Generated:</strong> {generated} &nbsp;|&nbsp;
    <strong>Risk Score:</strong> <span style="color:#dc2626;font-weight:700">{risk_score}/100</span> &nbsp;|&nbsp;
    <strong>Total Duration:</strong> {total_dur_str}
</div>

<div class="content">

<!-- ═══ 1. EXECUTIVE SUMMARY ═══ -->
<h2>1. Executive Summary</h2>
<table style="margin-bottom:12px">
    <tr>{stat_cells}</tr>
</table>
<table>
    <tr>
        <td style="width:33%;vertical-align:top;padding-right:8px">
            <h3>Governance Policies</h3>
            <table>
                <tr><td>Total</td><td style="text-align:right;font-weight:700">{policy_eval.get("total_policies", 0)}</td></tr>
                <tr><td style="color:#059669">Passed</td><td style="text-align:right;font-weight:700;color:#059669">{policy_eval.get("passed", 0)}</td></tr>
                <tr><td style="color:#dc2626">Failed</td><td style="text-align:right;font-weight:700;color:#dc2626">{policy_eval.get("failed", 0)}</td></tr>
                <tr><td style="color:#6b7280">Waived / N/A</td><td style="text-align:right;font-weight:700">{policy_eval.get("waived", 0) + policy_eval.get("not_applicable", 0)}</td></tr>
            </table>
        </td>
        <td style="width:33%;vertical-align:top;padding:0 8px">
            <h3>Vulnerability Correlations</h3>
            <table>
                <tr><td>CVEs Matched</td><td style="text-align:right;font-weight:700">{vuln_corr.get("unique_cves_matched", 0) if isinstance(vuln_corr, dict) else 0}</td></tr>
                <tr><td>Findings with CVEs</td><td style="text-align:right;font-weight:700">{vuln_corr.get("findings_with_cves", 0) if isinstance(vuln_corr, dict) else 0}</td></tr>
                <tr><td>Avg Confidence</td><td style="text-align:right;font-weight:700">{vuln_corr.get("avg_confidence", "N/A") if isinstance(vuln_corr, dict) else "N/A"}</td></tr>
            </table>
        </td>
        <td style="width:33%;vertical-align:top;padding-left:8px">
            <h3>Dependencies</h3>
            <table>
                <tr><td>Total Scanned</td><td style="text-align:right;font-weight:700">{dep_analysis.get("total_dependencies", 0) if isinstance(dep_analysis, dict) else 0}</td></tr>
                <tr><td style="color:#dc2626">Vulnerable</td><td style="text-align:right;font-weight:700;color:#dc2626">{dep_analysis.get("vulnerable_count", 0) if isinstance(dep_analysis, dict) else 0}</td></tr>
                <tr><td>Manifests</td><td style="text-align:right;font-weight:700">{dep_analysis.get("manifests_parsed", 0) if isinstance(dep_analysis, dict) else 0}</td></tr>
            </table>
        </td>
    </tr>
</table>

<!-- ═══ 2. SCANNER TOOL BREAKDOWN ═══ -->
<h2>2. Scanner Tool Breakdown</h2>
<table>
    <tr><th>Scanner</th><th style="text-align:center">Findings</th><th style="text-align:center">%</th><th style="text-align:center;background:#dc2626">Critical</th><th style="text-align:center;background:#ea580c">High</th><th style="text-align:center;background:#d97706">Medium</th><th style="text-align:center;background:#2563eb">Low</th></tr>
    {tool_rows}
</table>

<!-- ═══ 3. CLOUD PROVIDER DISTRIBUTION ═══ -->
<h2>3. Cloud Provider Distribution</h2>
<table>
    <tr><th>Cloud Provider</th><th style="text-align:center">Findings</th><th style="text-align:center">Percentage</th></tr>
    {cloud_rows}
</table>

<!-- ═══ 4. RESOURCE TYPE BREAKDOWN ═══ -->
<h2>4. Resource Type Breakdown (Top 20)</h2>
<table>
    <tr><th>Resource Type</th><th style="text-align:center">Findings</th><th style="text-align:center">%</th></tr>
    {resource_rows}
</table>

<!-- ═══ 5. FILE HEATMAP ═══ -->
<h2>5. File Risk Heatmap (Top 25)</h2>
<table>
    <tr><th>File Path</th><th style="text-align:center">Total</th><th style="text-align:center;background:#dc2626">Crit</th><th style="text-align:center;background:#ea580c">High</th><th style="text-align:center;background:#d97706">Med</th><th style="text-align:center;background:#2563eb">Low</th></tr>
    {file_heatmap_rows}
</table>

<!-- ═══ 6. COMPLIANCE FRAMEWORK COVERAGE ═══ -->
<h2>6. Compliance Framework Coverage</h2>
<table>
    <tr><th>Framework</th><th style="text-align:center">Controls</th><th style="text-align:center">Passed</th><th style="text-align:center">Failed</th><th style="text-align:center">Pass Rate</th></tr>
    {compliance_rows}
</table>

<!-- ═══ 7. GOVERNANCE POLICY RESULTS ═══ -->
<h2>7. Governance Policy Results by Category</h2>
<table>
    <tr><th>Category</th><th style="text-align:center">Passed</th><th style="text-align:center">Failed</th><th style="text-align:center">Waived</th><th style="text-align:center">N/A</th></tr>
    {policy_rows}
</table>

<!-- ═══ 8. SECRET / CREDENTIAL EXPOSURES ═══ -->
<h2>8. Secret &amp; Credential Exposures ({len(secrets)})</h2>
<table>
    <tr><th>#</th><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Preview</th><th>Remediation</th></tr>
    {secret_rows if secret_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No secrets detected</td></tr>'}
</table>

<!-- ═══ 9. TOP 30 CRITICAL/HIGH FINDINGS (DETAILED) ═══ -->
<h2>9. Top 30 Critical &amp; High Findings — Detailed View</h2>
<p style="font-size:8px;color:#64748b;margin-bottom:6px">Each finding includes rule ID, resource context, description, and code snippet where available.</p>
<table>
    {top_detail_rows}
</table>

<!-- ═══ 10. COMPLETE FINDINGS BY FILE ═══ -->
<h2>10. Complete Findings by File ({finding_count} total across {len(file_counts)} files)</h2>
<p style="font-size:8px;color:#64748b;margin-bottom:6px">Every finding from every scanner, grouped by file. Includes description, remediation guidance, and code context.</p>
{per_file_html}

<!-- ═══ 11. PIPELINE STAGE PERFORMANCE ═══ -->
<h2>11. Pipeline Stage Performance</h2>
<table>
    <tr><th>Stage</th><th style="text-align:center">Duration</th><th style="text-align:center">Status</th></tr>
    {stage_rows if stage_rows else '<tr><td colspan="3" style="text-align:center;color:#94a3b8">No stage data</td></tr>'}
    <tr style="border-top:2px solid #1e293b"><td style="font-weight:700">TOTAL</td><td style="text-align:center;font-weight:700">{total_dur_str}</td><td></td></tr>
</table>

{dep_html}

</div>

<div class="footer">
    🛡️ GuardNous v{settings.APP_VERSION} — Cloud Security &amp; IaC Posture Management Platform &nbsp;|&nbsp; Report generated {generated}<br/>
    Confidential — For authorized internal use only &nbsp;|&nbsp; {finding_count} findings | {len(secrets)} secrets | {len(tool_counts)} scanners | {len(by_fw)} compliance frameworks
</div>

</div>
</body></html>"""


# ── HTML report (interactive, beautiful, no xhtml2pdf constraints) ─────────

def _json_to_html(report: Report) -> str:
    """Enterprise-grade interactive HTML report with full CSS/JS."""
    data = _report_data(report)
    if not data:
        return f"<html><body><pre>{html.escape(str(report.content or ''))}</pre></body></html>"

    title = report.title or "Security Scan Report"
    generated = report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "N/A"
    summary = data.get("summary", {})
    findings = data.get("findings", []) or data.get("iac_findings", [])
    secrets = data.get("secret_findings", [])
    repo = data.get("repository", "")
    scan_id = data.get("scan_id", "")
    risk_score = data.get("risk_score", "N/A")
    compliance = data.get("compliance_mapping", {})
    policy_eval = data.get("policy_evaluation", {})
    stage_details = data.get("stage_details", {})


    sorted_findings = sorted(findings, key=lambda f: _sev_sort_key(f.get("severity", "LOW")))

    from collections import Counter
    tool_counts: Counter = Counter()
    tool_sev: dict = {}
    for f in findings:
        src = f.get("metadata", {}).get("source", "") if isinstance(f.get("metadata"), dict) else ""
        src = src or f.get("source", "") or "native"
        tool_counts[src] += 1
        if src not in tool_sev:
            tool_sev[src] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        s = f.get("severity", "LOW").upper()
        if s in tool_sev[src]:
            tool_sev[src][s] += 1

    cloud_counts: Counter = Counter(f.get("cloud_provider", "unknown") for f in findings)

    # ── Build tool breakdown rows ──
    tool_rows_html = ""
    for tool_name in sorted(tool_counts.keys()):
        tc = tool_counts[tool_name]
        ts = tool_sev.get(tool_name, {})
        tool_rows_html += f'<tr><td class="font-semibold">{html.escape(tool_name)}</td><td class="text-center font-bold">{tc}</td>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            v = ts.get(s, 0)
            if v > 0:
                tool_rows_html += f'<td class="text-center"><span class="sev-badge sev-{s.lower()}">{v}</span></td>'
            else:
                tool_rows_html += '<td class="text-center text-muted">0</td>'
        tool_rows_html += '</tr>'

    # ── Cloud rows ──
    cloud_rows_html = ""
    for cloud, cnt in cloud_counts.most_common():
        pct = round(cnt / max(len(findings), 1) * 100, 1)
        bar_w = min(pct, 100)
        cloud_rows_html += f'''<tr>
            <td class="font-semibold" style="text-transform:uppercase">{html.escape(cloud)}</td>
            <td class="text-center">{cnt}</td>
            <td><div class="bar-track"><div class="bar-fill" style="width:{bar_w}%"></div></div></td>
            <td class="text-center">{pct}%</td>
        </tr>'''

    # ── Compliance ──
    compliance_rows_html = ""
    by_fw = compliance.get("by_framework", {})
    for fw_name, fw_data in sorted(by_fw.items()):
        total_c = fw_data.get("total", 0)
        passed_c = fw_data.get("passed", 0)
        failed_c = fw_data.get("failed", 0)
        pct = round(passed_c / max(total_c, 1) * 100, 1)
        bar_color = "#dc2626" if pct < 30 else "#d97706" if pct < 70 else "#059669"
        compliance_rows_html += f'''<tr>
            <td class="font-semibold">{html.escape(fw_name)}</td>
            <td class="text-center">{total_c}</td>
            <td class="text-center" style="color:#059669;font-weight:600">{passed_c}</td>
            <td class="text-center" style="color:#dc2626;font-weight:600">{failed_c}</td>
            <td><div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{bar_color}"></div></div></td>
            <td class="text-center" style="color:{bar_color};font-weight:700">{pct}%</td>
        </tr>'''

    # ── Policy ──
    policy_rows_html = ""
    pol_by_cat = policy_eval.get("by_category", {})
    for cat_name, cat_data in sorted(pol_by_cat.items()):
        p = cat_data.get("passed", 0)
        f_count = cat_data.get("failed", 0)
        na = cat_data.get("not_applicable", 0)
        total = p + f_count + na
        pct = round(p / max(total, 1) * 100, 1)
        policy_rows_html += f'''<tr>
            <td class="font-semibold" style="text-transform:capitalize">{html.escape(cat_name)}</td>
            <td class="text-center" style="color:#059669">{p}</td>
            <td class="text-center" style="color:#dc2626">{f_count}</td>
            <td class="text-center text-muted">{na}</td>
            <td class="text-center" style="font-weight:600">{pct}%</td>
        </tr>'''

    # ── Secrets ──
    secret_rows_html = ""
    for i, s in enumerate(secrets, 1):
        sev = s.get("severity", "HIGH").upper()
        secret_rows_html += f'''<tr>
            <td>{i}</td>
            <td><span class="sev-badge sev-{sev.lower()}">{html.escape(sev)}</span></td>
            <td class="font-mono text-sm">{html.escape(s.get("rule_id",""))}</td>
            <td class="font-mono text-sm">{html.escape(s.get("file_path",""))}</td>
            <td class="text-center">{s.get("line_number","")}</td>
            <td class="font-mono text-sm">{html.escape(s.get("match_preview",""))}</td>
            <td class="text-sm">{html.escape((s.get("remediation","") or "")[:150])}</td>
        </tr>'''

    # ── All findings as JSON for JS table ──
    findings_json_items = []
    for f in sorted_findings:
        src = ""
        if isinstance(f.get("metadata"), dict):
            src = f["metadata"].get("source", "")
        findings_json_items.append({
            "s": f.get("severity", "LOW"),
            "r": f.get("rule_id", ""),
            "t": f.get("title", ""),
            "f": f.get("file_path", ""),
            "l": f.get("line_number", ""),
            "c": f.get("cloud_provider", ""),
            "src": src or f.get("source", ""),
            "rem": (f.get("remediation", "") or "")[:200],
        })
    import json as _json
    findings_js = _json.dumps(findings_json_items)

    # ── Stage timings ──
    stage_rows_html = ""
    for stage_name, sd in stage_details.items():
        dur = sd.get("duration_ms", 0)
        dur_str = f"{dur}ms" if dur < 1000 else f"{dur/1000:.1f}s"
        stage_rows_html += f'<tr><td>{html.escape(stage_name)}</td><td class="text-center">{dur_str}</td></tr>'

    safe_title = html.escape(title)
    safe_repo = html.escape(str(repo))
    total = summary.get("total_findings", 0)
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title} — GuardNous</title>
<style>
:root {{
  --orange-500: #f97316; --orange-600: #ea580c; --orange-700: #c2410c;
  --red-600: #dc2626; --amber-600: #d97706; --blue-600: #2563eb;
  --green-600: #059669; --purple-600: #7c3aed; --slate-700: #334155;
  --slate-500: #64748b; --slate-300: #cbd5e1; --slate-100: #f1f5f9;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.5; }}

/* Header */
.header {{ background: linear-gradient(135deg, #f97316 0%, #c2410c 100%); color: white; padding: 32px 48px; }}
.header h1 {{ font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
.header .subtitle {{ opacity: 0.9; font-size: 14px; margin-top: 4px; }}
.meta-bar {{ background: #1e293b; color: #cbd5e1; padding: 10px 48px; font-size: 12px; display: flex; gap: 24px; flex-wrap: wrap; }}
.meta-bar strong {{ color: white; }}

/* Navigation */
.nav {{ background: white; border-bottom: 1px solid #e2e8f0; padding: 0 48px; position: sticky; top: 0; z-index: 100; box-shadow: 0 1px 3px rgba(0,0,0,.05); }}
.nav-inner {{ display: flex; gap: 0; overflow-x: auto; }}
.nav a {{ padding: 12px 18px; text-decoration: none; color: var(--slate-500); font-size: 13px; font-weight: 500; border-bottom: 2px solid transparent; white-space: nowrap; transition: all .15s; }}
.nav a:hover {{ color: var(--orange-600); background: #fff7ed; }}
.nav a.active {{ color: var(--orange-600); border-bottom-color: var(--orange-600); }}

/* Container */
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px 48px 60px; }}

/* Cards */
.card {{ background: white; border-radius: 10px; border: 1px solid #e2e8f0; margin-bottom: 24px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.04); }}
.card-header {{ padding: 16px 24px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 10px; }}
.card-header h2 {{ font-size: 16px; font-weight: 700; color: var(--slate-700); }}
.card-header .num {{ background: var(--orange-600); color: white; width: 26px; height: 26px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; }}
.card-body {{ padding: 20px 24px; }}

/* Stat grid */
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }}
.stat-card {{ border-radius: 8px; padding: 20px; text-align: center; border: 1px solid #e2e8f0; }}
.stat-val {{ font-size: 36px; font-weight: 800; line-height: 1; }}
.stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--slate-500); margin-top: 6px; }}

/* Tables */
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #1e293b; color: white; padding: 10px 12px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; font-size: 12px; vertical-align: top; }}
tr:hover td {{ background: #fff7ed; }}
.text-center {{ text-align: center; }}
.text-muted {{ color: var(--slate-500); }}
.font-semibold {{ font-weight: 600; }}
.font-bold {{ font-weight: 700; }}
.font-mono {{ font-family: 'SF Mono', 'Fira Code', monospace; }}
.text-sm {{ font-size: 11px; }}

/* Severity badges */
.sev-badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: white; }}
.sev-critical {{ background: var(--red-600); }}
.sev-high {{ background: var(--orange-600); }}
.sev-medium {{ background: var(--amber-600); }}
.sev-low {{ background: var(--blue-600); }}
.sev-info {{ background: var(--slate-500); }}

/* Progress bar */
.bar-track {{ background: #e2e8f0; border-radius: 4px; height: 8px; overflow: hidden; }}
.bar-fill {{ background: var(--orange-500); height: 100%; border-radius: 4px; transition: width .3s; }}

/* Search/filter */
.filter-bar {{ display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
.filter-bar input, .filter-bar select {{ padding: 8px 12px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 12px; background: white; }}
.filter-bar input {{ flex: 1; min-width: 200px; }}
.filter-bar select {{ min-width: 120px; }}
.count-badge {{ background: var(--slate-100); padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; color: var(--slate-700); }}

/* Pagination */
.pagination {{ display: flex; gap: 6px; justify-content: center; align-items: center; margin-top: 16px; }}
.pagination button {{ padding: 6px 14px; border: 1px solid #e2e8f0; border-radius: 6px; background: white; cursor: pointer; font-size: 12px; }}
.pagination button:hover {{ background: #fff7ed; border-color: var(--orange-500); }}
.pagination button.active {{ background: var(--orange-600); color: white; border-color: var(--orange-600); }}
.pagination button:disabled {{ opacity: 0.4; cursor: not-allowed; }}

/* Print */
.footer {{ text-align: center; color: var(--slate-500); font-size: 11px; padding: 24px; border-top: 2px solid var(--orange-500); margin-top: 32px; }}
@media print {{
  .nav, .filter-bar, .pagination {{ display: none !important; }}
  .container {{ padding: 0 20px; }}
  .card {{ box-shadow: none; page-break-inside: avoid; }}
}}
</style>
</head>
<body>

<!-- ═══ HEADER ═══ -->
<div class="header">
    <h1>&#x1f6e1;&#xfe0f; GuardNous Security Report</h1>
    <div class="subtitle">{safe_title}</div>
</div>
<div class="meta-bar">
    <span>Repository: <strong>{safe_repo}</strong></span>
    <span>Scan ID: <strong>{html.escape(str(scan_id))}</strong></span>
    <span>Generated: <strong>{generated}</strong></span>
    <span>Risk Score: <strong>{risk_score}</strong></span>
</div>

<!-- ═══ NAV ═══ -->
<div class="nav"><div class="nav-inner">
    <a href="#summary" class="active">Summary</a>
    <a href="#tools">Tools</a>
    <a href="#cloud">Cloud</a>
    <a href="#compliance">Compliance</a>
    <a href="#policies">Policies</a>
    <a href="#secrets">Secrets</a>
    <a href="#findings">All Findings</a>
    <a href="#stages">Pipeline</a>
</div></div>

<div class="container">

<!-- ═══ 1. EXECUTIVE SUMMARY ═══ -->
<div class="card" id="summary">
    <div class="card-header"><div class="num">1</div><h2>Executive Summary</h2></div>
    <div class="card-body">
        <div class="stat-grid">
            <div class="stat-card" style="background:#fff7ed;border-color:#fdba74"><div class="stat-val" style="color:#f97316">{total}</div><div class="stat-label">Total Findings</div></div>
            <div class="stat-card" style="background:#fef2f2;border-color:#fecaca"><div class="stat-val" style="color:#dc2626">{crit}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card" style="background:#fff7ed;border-color:#fed7aa"><div class="stat-val" style="color:#ea580c">{high}</div><div class="stat-label">High</div></div>
            <div class="stat-card" style="background:#fffbeb;border-color:#fde68a"><div class="stat-val" style="color:#d97706">{med}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card" style="background:#eff6ff;border-color:#bfdbfe"><div class="stat-val" style="color:#2563eb">{low}</div><div class="stat-label">Low</div></div>
            <div class="stat-card" style="background:#f5f3ff;border-color:#ddd6fe"><div class="stat-val" style="color:#7c3aed">{summary.get("secrets_found",0)}</div><div class="stat-label">Secrets</div></div>
            <div class="stat-card" style="background:#ecfdf5;border-color:#a7f3d0"><div class="stat-val" style="color:#059669">{summary.get("files_scanned",0)}</div><div class="stat-label">Files Scanned</div></div>
        </div>
    </div>
</div>

<!-- ═══ 2. TOOL BREAKDOWN ═══ -->
<div class="card" id="tools">
    <div class="card-header"><div class="num">2</div><h2>Scanner Tool Breakdown</h2></div>
    <div class="card-body">
        <table>
            <tr><th>Tool</th><th class="text-center">Total</th><th class="text-center">Critical</th><th class="text-center">High</th><th class="text-center">Medium</th><th class="text-center">Low</th></tr>
            {tool_rows_html}
        </table>
    </div>
</div>

<!-- ═══ 3. CLOUD DISTRIBUTION ═══ -->
<div class="card" id="cloud">
    <div class="card-header"><div class="num">3</div><h2>Cloud Provider Distribution</h2></div>
    <div class="card-body">
        <table>
            <tr><th>Provider</th><th class="text-center">Findings</th><th style="width:40%">Distribution</th><th class="text-center">Share</th></tr>
            {cloud_rows_html}
        </table>
    </div>
</div>

<!-- ═══ 4. COMPLIANCE ═══ -->
<div class="card" id="compliance">
    <div class="card-header"><div class="num">4</div><h2>Compliance Framework Coverage</h2></div>
    <div class="card-body">
        <table>
            <tr><th>Framework</th><th class="text-center">Controls</th><th class="text-center">Passed</th><th class="text-center">Failed</th><th style="width:25%">Coverage</th><th class="text-center">Rate</th></tr>
            {compliance_rows_html}
        </table>
    </div>
</div>

<!-- ═══ 5. POLICIES ═══ -->
<div class="card" id="policies">
    <div class="card-header"><div class="num">5</div><h2>Governance Policy Results</h2>
        <span class="count-badge" style="margin-left:auto">
            {policy_eval.get("passed",0)} passed / {policy_eval.get("failed",0)} failed of {policy_eval.get("total_policies",0)}
        </span>
    </div>
    <div class="card-body">
        <table>
            <tr><th>Category</th><th class="text-center">Passed</th><th class="text-center">Failed</th><th class="text-center">N/A</th><th class="text-center">Pass Rate</th></tr>
            {policy_rows_html}
        </table>
    </div>
</div>

<!-- ═══ 6. SECRETS ═══ -->
<div class="card" id="secrets">
    <div class="card-header"><div class="num">6</div><h2>Secret &amp; Credential Exposures</h2><span class="count-badge" style="margin-left:auto">{len(secrets)} found</span></div>
    <div class="card-body">
        <table>
            <tr><th>#</th><th>Severity</th><th>Rule</th><th>File</th><th class="text-center">Line</th><th>Preview</th><th>Remediation</th></tr>
            {secret_rows_html if secret_rows_html else '<tr><td colspan="7" class="text-center text-muted" style="padding:20px">No secrets detected — great job!</td></tr>'}
        </table>
    </div>
</div>

<!-- ═══ 7. ALL FINDINGS (interactive) ═══ -->
<div class="card" id="findings">
    <div class="card-header"><div class="num">7</div><h2>All Findings</h2><span id="fcount" class="count-badge" style="margin-left:auto">{len(sorted_findings)} total</span></div>
    <div class="card-body">
        <div class="filter-bar">
            <input type="text" id="fsearch" placeholder="Search by rule, title, file..." oninput="filterFindings()">
            <select id="fsev" onchange="filterFindings()"><option value="">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>
            <select id="ftool" onchange="filterFindings()"><option value="">All Tools</option>{''.join(f'<option value="{html.escape(t)}">{html.escape(t)}</option>' for t in sorted(tool_counts.keys()))}</select>
        </div>
        <table>
            <thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Title</th><th>File</th><th class="text-center">Line</th><th>Tool</th></tr></thead>
            <tbody id="ftbody"></tbody>
        </table>
        <div class="pagination" id="fpag"></div>
    </div>
</div>

<!-- ═══ 8. PIPELINE ═══ -->
<div class="card" id="stages">
    <div class="card-header"><div class="num">8</div><h2>Pipeline Stage Performance</h2></div>
    <div class="card-body">
        <table>
            <tr><th>Stage</th><th class="text-center">Duration</th></tr>
            {stage_rows_html if stage_rows_html else '<tr><td colspan="2" class="text-center text-muted">No timing data</td></tr>'}
        </table>
    </div>
</div>

</div><!-- /container -->

<div class="footer">
    GuardNous v{settings.APP_VERSION} — Cloud Security &amp; IaC Posture Management<br/>
    Report generated {generated} &nbsp;|&nbsp; Confidential — For internal use only
</div>

<script>
// ── Smooth‑scroll nav ──
document.querySelectorAll('.nav a').forEach(a => {{
    a.addEventListener('click', e => {{
        e.preventDefault();
        document.querySelector(a.getAttribute('href')).scrollIntoView({{behavior:'smooth'}});
        document.querySelectorAll('.nav a').forEach(x => x.classList.remove('active'));
        a.classList.add('active');
    }});
}});

// ── Intersection observer for nav highlight ──
const sections = document.querySelectorAll('.card[id]');
const obs = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
        if (e.isIntersecting) {{
            document.querySelectorAll('.nav a').forEach(a => {{
                a.classList.toggle('active', a.getAttribute('href') === '#' + e.target.id);
            }});
        }}
    }});
}}, {{threshold: 0.3}});
sections.forEach(s => obs.observe(s));

// ── Interactive findings table ──
const ALL_F = {findings_js};
const PER_PAGE = 50;
let filtered = ALL_F;
let page = 0;

const sevColors = {{"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#2563eb","INFO":"#6b7280"}};
const sevBg = {{"CRITICAL":"#fef2f2","HIGH":"#fff7ed","MEDIUM":"#fffbeb","LOW":"#eff6ff","INFO":"#f9fafb"}};

function filterFindings() {{
    const q = document.getElementById('fsearch').value.toLowerCase();
    const sev = document.getElementById('fsev').value;
    const tool = document.getElementById('ftool').value;
    filtered = ALL_F.filter(f => {{
        if (sev && f.s !== sev) return false;
        if (tool && f.src !== tool) return false;
        if (q && !(f.r+' '+f.t+' '+f.f).toLowerCase().includes(q)) return false;
        return true;
    }});
    page = 0;
    renderFindings();
}}

function renderFindings() {{
    const tbody = document.getElementById('ftbody');
    const start = page * PER_PAGE;
    const slice = filtered.slice(start, start + PER_PAGE);
    const totalPages = Math.ceil(filtered.length / PER_PAGE);

    document.getElementById('fcount').textContent = filtered.length + ' shown';

    tbody.innerHTML = slice.map((f, i) => {{
        const sev = f.s.toUpperCase();
        return '<tr>' +
            '<td>' + (start+i+1) + '</td>' +
            '<td><span class="sev-badge sev-' + sev.toLowerCase() + '">' + sev + '</span></td>' +
            '<td class="font-mono text-sm">' + escH(f.r) + '</td>' +
            '<td>' + escH(f.t) + '</td>' +
            '<td class="font-mono text-sm">' + escH(f.f) + '</td>' +
            '<td class="text-center">' + (f.l||'') + '</td>' +
            '<td class="text-sm">' + escH(f.src) + '</td>' +
        '</tr>';
    }}).join('');

    const pag = document.getElementById('fpag');
    if (totalPages <= 1) {{ pag.innerHTML = ''; return; }}
    let btns = '<button ' + (page===0?'disabled':'') + ' onclick="page=0;renderFindings()">&#171;</button>';
    btns += '<button ' + (page===0?'disabled':'') + ' onclick="page--;renderFindings()">&#8249;</button>';
    const startP = Math.max(0, page - 3);
    const endP = Math.min(totalPages, startP + 7);
    for (let p = startP; p < endP; p++) {{
        btns += '<button class="' + (p===page?'active':'') + '" onclick="page='+p+';renderFindings()">' + (p+1) + '</button>';
    }}
    btns += '<button ' + (page>=totalPages-1?'disabled':'') + ' onclick="page++;renderFindings()">&#8250;</button>';
    btns += '<button ' + (page>=totalPages-1?'disabled':'') + ' onclick="page=totalPages-1;renderFindings()">&#187;</button>';
    pag.innerHTML = btns;
}}

function escH(s) {{ const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }}

filterFindings();
</script>
</body></html>"""


# ---------------------------------------------------------------------------
# On-demand email delivery
# ---------------------------------------------------------------------------

class EmailReportRequest(BaseModel):
    recipient_email: Optional[str] = Field(None, description="Override email. Defaults to current user's email.")


@router.post("/{report_id}/email")
async def email_report(
    report_id: int,
    body: Optional[EmailReportRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("reports", "read")),
):
    """Email a report as a PDF attachment to the requesting user (or a specified recipient)."""
    result = await db.execute(
        select(Report).where(
            Report.id == report_id,
            Report.organization_id == current_user.organization_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    recipient = (body.recipient_email if body and body.recipient_email else None) or current_user.email
    if not recipient:
        raise HTTPException(status_code=400, detail="No recipient email available")

    pdf_bytes = _generate_pdf_from_report(report)

    data = {}
    if report.content:
        try:
            data = json.loads(report.content) if isinstance(report.content, str) else {}
        except Exception:
            pass
    summary = data.get("summary", {})

    email_html = build_report_email_html(
        report_title=report.title or "Security Report",
        report_type=report.report_type or "security_posture",
        generated_at=report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "N/A",
        total_findings=summary.get("total_findings", 0),
        critical=summary.get("critical", 0),
        high=summary.get("high", 0),
        medium=summary.get("medium", 0),
        low=summary.get("low", 0),
        risk_score=summary.get("risk_score", 0),
    )

    # Resolve SMTP config: prefer DB-stored org settings over env vars
    smtp_cfg = None
    try:
        org_id = getattr(current_user, "organization_id", None)
        if org_id:
            row = (await db.execute(select(OrgSettings).where(OrgSettings.organization_id == org_id))).scalar_one_or_none()
            if row and row.smtp_host:
                password = ""
                if row.smtp_password_encrypted:
                    try:
                        password = decrypt_token(row.smtp_password_encrypted)
                    except Exception:
                        pass
                smtp_cfg = {
                    "host": row.smtp_host, "port": row.smtp_port, "user": row.smtp_user,
                    "password": password, "use_tls": row.smtp_use_tls,
                    "from_email": row.smtp_from_email, "from_name": row.smtp_from_name,
                }
    except Exception:
        pass
    params = _resolve_smtp_params(smtp_cfg)
    if not params:
        raise HTTPException(status_code=400, detail="SMTP is not configured. Please set up email in Settings.")

    try:
        await send_email_with_attachment(
            to_email=recipient,
            subject=f"GuardNous Report: {report.title or 'Security Report'}",
            html_body=email_html,
            attachment_data=pdf_bytes,
            attachment_filename=f"guardnous-report-{report.id}.pdf",
            attachment_mime="application/pdf",
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to send email: {str(e)}")

    await write_audit_log(db=db, user=current_user, action="email", resource_type="report", resource_id=report.id, details={"recipient": recipient})
    return {"status": "sent", "recipient": recipient, "report_id": report.id}
