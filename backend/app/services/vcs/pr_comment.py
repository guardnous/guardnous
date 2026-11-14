"""Format scan results as PR/MR comments."""


def format_pr_comment(
    scan_id: int,
    risk_score: int,
    findings: list[dict],
    repo: str,
    dashboard_url: str = "",
) -> str:
    """Format scan findings into a GitHub PR comment body."""
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]

    # Risk badge
    if risk_score >= 70:
        badge = "🔴"
        verdict = "CRITICAL RISK"
    elif risk_score >= 40:
        badge = "🟡"
        verdict = "MEDIUM RISK"
    else:
        badge = "🟢"
        verdict = "LOW RISK"

    lines = [
        f"## {badge} GuardNous Scan Results — {verdict}",
        "",
        f"**Risk Score:** {risk_score}/100 | "
        f"**Findings:** {len(findings)} total",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {len(critical)} |",
        f"| 🟠 High | {len(high)} |",
        f"| 🟡 Medium | {len(medium)} |",
        f"| 🔵 Low | {len(low)} |",
        "",
    ]

    # Show critical & high findings
    top_findings = (critical + high)[:10]
    if top_findings:
        lines.append("### Top Findings")
        lines.append("")
        for f in top_findings:
            severity = f.get("severity", "")
            icon = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(severity, "⚪")
            title = f.get("title", "Unknown")
            file_path = f.get("file_path", "")
            line = f.get("line_number", "")
            loc = f" (`{file_path}:{line}`)" if file_path else ""
            lines.append(f"- {icon} **{title}**{loc}")
        lines.append("")

    # Footer
    if dashboard_url:
        lines.append(f"[View full report in GuardNous]({dashboard_url})")
    lines.append("")
    lines.append("---")
    lines.append("*Powered by [GuardNous](https://guardnous.com) — IaC Security Platform*")

    return "\n".join(lines)


def format_commit_status_description(risk_score: int, findings_count: int) -> str:
    """One-line description for GitHub commit status."""
    if findings_count == 0:
        return "No security issues found"
    return f"Risk: {risk_score}/100 — {findings_count} finding(s)"
