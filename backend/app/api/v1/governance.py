"""Enterprise Governance API — real evaluation engine backed by scan findings."""
import logging
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.rbac import require_permission
from app.core.audit import write_audit_log
from app.models.user import User
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.governance import (
    ComplianceFramework, ComplianceControl, SecurityPolicy, PolicyViolation, RiskException,
)
from app.schemas.governance import (
    FrameworkResponse, ControlResponse,
    PolicyResponse, PolicyCreate, PolicyUpdate,
    ViolationResponse, ExceptionResponse, ExceptionCreate, ExceptionUpdate,
    GovernanceDashboardStats,
)
from app.services.security.policy_engine import BUILT_IN_POLICIES
from app.services.governance.compliance import ComplianceEvaluator
from app.services.governance.finding_policies import (
    active_exemption_keys, applies_to_repo, finding_matches, finding_rules, is_cloud_policy, is_exempt,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORK REFERENCE URLS — where controls come from
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK_REFS = {
    "SOC2": "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report",
    "ISO27001": "https://www.iso.org/standard/27001",
    "PCI-DSS": "https://www.pcisecuritystandards.org/document_library/?category=pcidss",
    "HIPAA": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
    "CIS": "https://www.cisecurity.org/cis-benchmarks",
    "NIST 800-53": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
}

# ─────────────────────────────────────────────────────────────────────────────
# CONTROL → FINDING CATEGORY MAP
#
# Each control maps to finding categories (from Finding.category) and optionally
# severity thresholds. The evaluation engine checks:
#   - Are there open (not fixed, not ignored) findings matching these categories?
#   - If 0 matching findings → PASSING
#   - If >0 matching findings → FAILING
#   - If no scans have ever run → NOT_ASSESSED
#
# Math:
#   compliance_score = (passing / (passing + failing)) * 100
#   Controls marked not_applicable or not_assessed are excluded from the ratio.
# ─────────────────────────────────────────────────────────────────────────────

CONTROL_FINDING_MAP: dict[str, dict[str, list[str]]] = {
    # SOC2 Trust Services Criteria
    "CC6.1": {"categories": ["secrets", "iam"], "desc": "Checks for hardcoded secrets and IAM misconfigs"},
    "CC6.2": {"categories": ["iam", "secrets"], "desc": "Checks authentication credential exposure"},
    "CC6.3": {"categories": ["iam"], "desc": "Checks for stale access / overprivileged roles"},
    "CC6.6": {"categories": ["network", "iac"], "desc": "Checks network boundary rules (SG, firewall)"},
    "CC6.7": {"categories": ["encryption", "network"], "desc": "Checks data-in-transit encryption"},
    "CC6.8": {"categories": ["cve", "sca"], "desc": "Checks for malicious / vulnerable dependencies"},
    "CC7.1": {"categories": ["cve", "sca", "iac"], "desc": "Checks vulnerability scanning coverage"},
    "CC7.2": {"categories": ["logging", "monitoring"], "desc": "Checks logging & monitoring configs"},
    "CC7.3": {"categories": ["logging", "iac"], "desc": "Checks incident detection capabilities"},
    "CC8.1": {"categories": ["iac"], "desc": "Checks IaC change management controls"},
    "CC9.1": {"categories": ["iac", "cve"], "desc": "Checks third-party risk (supply chain)"},
    "CC1.1": {"categories": ["iac"], "desc": "Checks governance controls in IaC"},
    "CC2.1": {"categories": ["logging"], "desc": "Checks information flow controls"},
    "CC3.1": {"categories": ["iac", "cve"], "desc": "Checks risk assessment coverage"},
    "CC4.1": {"categories": ["monitoring", "logging"], "desc": "Checks monitoring activities"},
    "CC5.1": {"categories": ["iac"], "desc": "Checks control activity implementation"},
    # ISO 27001 Annex A
    "A.5.1":  {"categories": ["iac"], "desc": "Checks policy-as-code implementation"},
    "A.6.1":  {"categories": ["iam"], "desc": "Checks organizational security structure"},
    "A.7.1":  {"categories": ["iam"], "desc": "Checks HR security controls"},
    "A.8.1":  {"categories": ["iac", "sca"], "desc": "Checks asset inventory & management"},
    "A.9.1":  {"categories": ["iam", "network"], "desc": "Checks access control policies"},
    "A.9.2":  {"categories": ["iam", "secrets"], "desc": "Checks user access management"},
    "A.10.1": {"categories": ["encryption", "secrets"], "desc": "Checks cryptographic controls"},
    "A.11.1": {"categories": ["iac"], "desc": "Checks physical/logical security"},
    "A.12.1": {"categories": ["iac", "logging"], "desc": "Checks operational procedures"},
    "A.12.4": {"categories": ["logging", "monitoring"], "desc": "Checks logging & monitoring"},
    "A.13.1": {"categories": ["network", "iac"], "desc": "Checks network security controls"},
    "A.14.1": {"categories": ["sca", "cve"], "desc": "Checks secure development lifecycle"},
    "A.16.1": {"categories": ["logging", "iac"], "desc": "Checks incident management"},
    "A.17.1": {"categories": ["iac"], "desc": "Checks business continuity controls"},
    "A.18.1": {"categories": ["iac", "cve"], "desc": "Checks legal compliance"},
    # PCI-DSS v4.0
    "1.1":  {"categories": ["network", "iac"], "desc": "Checks network security controls (firewalls, SGs)"},
    "2.1":  {"categories": ["iac"], "desc": "Checks secure system configurations"},
    "3.1":  {"categories": ["encryption", "secrets"], "desc": "Checks data-at-rest protection"},
    "4.1":  {"categories": ["encryption", "network"], "desc": "Checks data-in-transit encryption"},
    "5.1":  {"categories": ["cve", "sca"], "desc": "Checks malware protection"},
    "6.1":  {"categories": ["cve", "sca", "iac"], "desc": "Checks secure SDLC"},
    "7.1":  {"categories": ["iam"], "desc": "Checks need-to-know access restriction"},
    "8.1":  {"categories": ["iam", "secrets"], "desc": "Checks user identification & auth"},
    "9.1":  {"categories": ["iac"], "desc": "Checks physical access controls"},
    "10.1": {"categories": ["logging", "monitoring"], "desc": "Checks audit logging"},
    "11.1": {"categories": ["cve", "sca"], "desc": "Checks security testing coverage"},
    "12.1": {"categories": ["iac"], "desc": "Checks security policy documentation"},
    # HIPAA Security Rule
    "164.308(a)(1)": {"categories": ["iac", "cve"], "desc": "Checks security management process"},
    "164.308(a)(3)": {"categories": ["iam"], "desc": "Checks workforce access controls"},
    "164.308(a)(4)": {"categories": ["iam", "secrets"], "desc": "Checks information access management"},
    "164.308(a)(5)": {"categories": ["iac"], "desc": "Checks security awareness program"},
    "164.310(a)(1)": {"categories": ["iac"], "desc": "Checks facility access controls"},
    "164.310(d)(1)": {"categories": ["iac", "encryption"], "desc": "Checks device & media controls"},
    "164.312(a)(1)": {"categories": ["iam", "network"], "desc": "Checks technical access controls"},
    "164.312(b)":    {"categories": ["logging", "monitoring"], "desc": "Checks audit mechanisms"},
    "164.312(c)(1)": {"categories": ["encryption"], "desc": "Checks data integrity controls"},
    "164.312(d)":    {"categories": ["iam", "secrets"], "desc": "Checks authentication controls"},
    "164.312(e)(1)": {"categories": ["encryption", "network"], "desc": "Checks transmission security"},
    # CIS Benchmarks
    "CIS-1":  {"categories": ["iac", "sca"], "desc": "Checks software/hardware inventory"},
    "CIS-2":  {"categories": ["iac", "sca"], "desc": "Checks software inventory"},
    "CIS-3":  {"categories": ["encryption", "secrets"], "desc": "Checks data protection"},
    "CIS-4":  {"categories": ["iac"], "desc": "Checks secure configurations"},
    "CIS-5":  {"categories": ["iam"], "desc": "Checks account management"},
    "CIS-6":  {"categories": ["iam"], "desc": "Checks access control management"},
    "CIS-7":  {"categories": ["cve", "sca"], "desc": "Checks vulnerability management"},
    "CIS-8":  {"categories": ["logging", "monitoring"], "desc": "Checks audit log management"},
    "CIS-9":  {"categories": ["iam", "secrets"], "desc": "Checks email/browser protections"},
    "CIS-10": {"categories": ["cve", "sca"], "desc": "Checks malware defenses"},
    "CIS-11": {"categories": ["iac"], "desc": "Checks data recovery capabilities"},
    "CIS-12": {"categories": ["network", "iac"], "desc": "Checks network infrastructure"},
    "CIS-13": {"categories": ["network"], "desc": "Checks network monitoring/defense"},
    "CIS-14": {"categories": ["iac"], "desc": "Checks security awareness training"},
    "CIS-15": {"categories": ["iac"], "desc": "Checks service provider management"},
    "CIS-16": {"categories": ["sca", "iac"], "desc": "Checks application software security"},
    "CIS-17": {"categories": ["logging", "iac"], "desc": "Checks incident response"},
    "CIS-18": {"categories": ["cve", "sca"], "desc": "Checks penetration testing"},
    # NIST SP 800-53 Rev 5
    "AC-2":  {"categories": ["iam"], "desc": "Checks account management"},
    "AC-3":  {"categories": ["iam"], "desc": "Checks access enforcement"},
    "AC-6":  {"categories": ["iam"], "desc": "Checks least privilege"},
    "AU-2":  {"categories": ["logging"], "desc": "Checks event logging"},
    "AU-6":  {"categories": ["logging", "monitoring"], "desc": "Checks audit review/analysis"},
    "CM-2":  {"categories": ["iac"], "desc": "Checks baseline configuration"},
    "CM-6":  {"categories": ["iac"], "desc": "Checks configuration settings"},
    "CM-7":  {"categories": ["iac", "network"], "desc": "Checks least functionality"},
    "IA-2":  {"categories": ["iam"], "desc": "Checks identification & authentication"},
    "IA-5":  {"categories": ["secrets", "iam"], "desc": "Checks authenticator management"},
    "IR-4":  {"categories": ["logging", "monitoring"], "desc": "Checks incident handling"},
    "RA-5":  {"categories": ["cve", "sca"], "desc": "Checks vulnerability monitoring"},
    "SC-7":  {"categories": ["network"], "desc": "Checks boundary protection"},
    "SC-8":  {"categories": ["encryption", "network"], "desc": "Checks transmission confidentiality"},
    "SC-13": {"categories": ["encryption"], "desc": "Checks cryptographic protection"},
    "SC-28": {"categories": ["encryption"], "desc": "Checks protection of data at rest"},
    "SI-2":  {"categories": ["cve", "sca"], "desc": "Checks flaw remediation"},
    "SI-3":  {"categories": ["sca", "cve"], "desc": "Checks malicious code protection"},
    "SI-4":  {"categories": ["monitoring", "network"], "desc": "Checks system monitoring"},
    "SI-7":  {"categories": ["secrets", "sca"], "desc": "Checks software/firmware integrity"},
}

# Seed data — controls per framework
FRAMEWORK_SEEDS = {
    "SOC2": {
        "description": "Service Organization Control 2 — Trust Services Criteria",
        "version": "2017",
        "controls": [
            ("CC1.1", "Control Environment", "Organization demonstrates commitment to integrity and ethical values", "Governance", "high"),
            ("CC2.1", "Information & Communication", "Uses relevant quality information", "Communication", "medium"),
            ("CC3.1", "Risk Assessment", "Specifies suitable objectives", "Risk Management", "high"),
            ("CC4.1", "Monitoring Activities", "Selects and develops monitoring", "Monitoring", "medium"),
            ("CC5.1", "Control Activities", "Selects and develops control activities", "Control Activities", "medium"),
            ("CC6.1", "Logical Access Controls", "Restricts logical access to information assets", "Access Control", "critical"),
            ("CC6.2", "User Authentication", "Prior to issuing system credentials, registers authorized users", "Access Control", "critical"),
            ("CC6.3", "Access Removal", "Removes access to protected information when appropriate", "Access Control", "high"),
            ("CC6.6", "System Boundaries", "Restricts access based on boundary definitions", "Access Control", "high"),
            ("CC6.7", "Data Transmission", "Restricts transmission of data to authorized channels", "Data Protection", "high"),
            ("CC6.8", "Malicious Software", "Restricts software installation to authorized sources", "Security", "high"),
            ("CC7.1", "Vulnerability Management", "Detects and monitors configuration changes and vulnerabilities", "Security", "critical"),
            ("CC7.2", "Incident Monitoring", "Monitors system components for anomalies", "Monitoring", "high"),
            ("CC7.3", "Security Incident Evaluation", "Evaluates security events to determine incidents", "Incident Response", "high"),
            ("CC8.1", "Change Management", "Authorizes, designs, and implements changes", "Change Management", "medium"),
            ("CC9.1", "Risk Mitigation", "Identifies and assesses risks from business relationships", "Risk Management", "medium"),
        ],
    },
    "ISO27001": {
        "description": "ISO/IEC 27001 — Information Security Management System",
        "version": "2022",
        "controls": [
            ("A.5.1", "Information Security Policies", "Management direction for information security", "Governance", "high"),
            ("A.6.1", "Organization of Information Security", "Internal organization security framework", "Governance", "medium"),
            ("A.7.1", "Human Resource Security", "Prior to employment security checks", "HR Security", "medium"),
            ("A.8.1", "Asset Management", "Responsibility for assets", "Asset Management", "high"),
            ("A.9.1", "Access Control", "Business requirements of access control", "Access Control", "critical"),
            ("A.9.2", "User Access Management", "Ensure authorized user access", "Access Control", "critical"),
            ("A.10.1", "Cryptography", "Proper use of cryptographic controls", "Encryption", "critical"),
            ("A.11.1", "Physical Security", "Secure areas and equipment", "Physical", "medium"),
            ("A.12.1", "Operations Security", "Operational procedures and responsibilities", "Operations", "high"),
            ("A.12.4", "Logging & Monitoring", "Recording events and generating evidence", "Monitoring", "high"),
            ("A.13.1", "Network Security", "Network controls and management", "Network", "critical"),
            ("A.14.1", "System Acquisition", "Security requirements for information systems", "Development", "high"),
            ("A.16.1", "Incident Management", "Management of security incidents", "Incident Response", "high"),
            ("A.17.1", "Business Continuity", "Information security continuity", "BCP", "medium"),
            ("A.18.1", "Compliance", "Compliance with legal requirements", "Compliance", "high"),
        ],
    },
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard v4.0",
        "version": "4.0",
        "controls": [
            ("1.1", "Network Security Controls", "Install and maintain network security controls", "Network", "critical"),
            ("2.1", "Secure Configurations", "Apply secure configurations to all system components", "Configuration", "high"),
            ("3.1", "Stored Account Data", "Protect stored account data", "Data Protection", "critical"),
            ("4.1", "Data Transmission", "Protect data with strong cryptography during transmission", "Encryption", "critical"),
            ("5.1", "Malware Protection", "Protect systems against malware", "Security", "high"),
            ("6.1", "Secure Development", "Develop and maintain secure systems", "Development", "critical"),
            ("7.1", "Access Restriction", "Restrict access by business need-to-know", "Access Control", "high"),
            ("8.1", "User Identification", "Identify users and authenticate access", "Authentication", "critical"),
            ("9.1", "Physical Access", "Restrict physical access to cardholder data", "Physical", "medium"),
            ("10.1", "Logging", "Log and monitor all access to system components", "Monitoring", "high"),
            ("11.1", "Security Testing", "Regularly test security of systems and networks", "Testing", "high"),
            ("12.1", "Information Security Policy", "Support information security with organizational policies", "Governance", "medium"),
        ],
    },
    "HIPAA": {
        "description": "Health Insurance Portability and Accountability Act — Security Rule",
        "version": "2013",
        "controls": [
            ("164.308(a)(1)", "Security Management Process", "Implement policies to prevent security violations", "Governance", "critical"),
            ("164.308(a)(3)", "Workforce Security", "Policies for workforce access to ePHI", "Access Control", "critical"),
            ("164.308(a)(4)", "Information Access Management", "Policies for authorizing access to ePHI", "Access Control", "critical"),
            ("164.308(a)(5)", "Security Awareness Training", "Security awareness and training program", "Training", "high"),
            ("164.310(a)(1)", "Facility Access Controls", "Limit physical access to systems", "Physical", "medium"),
            ("164.310(d)(1)", "Device & Media Controls", "Policies for hardware and electronic media", "Asset Management", "high"),
            ("164.312(a)(1)", "Access Control", "Technical policies for access to ePHI systems", "Access Control", "critical"),
            ("164.312(b)", "Audit Controls", "Hardware, software, and procedural audit mechanisms", "Monitoring", "high"),
            ("164.312(c)(1)", "Integrity", "Policies to protect ePHI from improper alteration", "Data Protection", "critical"),
            ("164.312(d)", "Authentication", "Verify identity of persons seeking access to ePHI", "Authentication", "critical"),
            ("164.312(e)(1)", "Transmission Security", "Technical measures to guard against unauthorized access", "Encryption", "critical"),
        ],
    },
    "CIS": {
        "description": "CIS Controls v8 — Center for Internet Security",
        "version": "8.0",
        "controls": [
            ("CIS-1", "Enterprise Asset Inventory", "Actively manage all hardware assets", "Asset Management", "high"),
            ("CIS-2", "Software Asset Inventory", "Actively manage all software on the network", "Asset Management", "high"),
            ("CIS-3", "Data Protection", "Develop processes to identify, classify, and handle data", "Data Protection", "critical"),
            ("CIS-4", "Secure Configuration", "Establish secure configurations for enterprise assets", "Configuration", "critical"),
            ("CIS-5", "Account Management", "Use processes and tools to manage accounts", "Access Control", "critical"),
            ("CIS-6", "Access Control Management", "Use processes and tools to assign access", "Access Control", "critical"),
            ("CIS-7", "Continuous Vulnerability Management", "Develop a plan to continuously assess vulnerabilities", "Vulnerability", "critical"),
            ("CIS-8", "Audit Log Management", "Collect, alert, review, and retain audit logs", "Monitoring", "high"),
            ("CIS-9", "Email & Browser Protections", "Improve protections and detections of email threats", "Security", "medium"),
            ("CIS-10", "Malware Defenses", "Prevent or control installation of malicious software", "Security", "high"),
            ("CIS-11", "Data Recovery", "Establish and maintain data recovery practices", "BCP", "high"),
            ("CIS-12", "Network Infrastructure Management", "Establish and maintain network infrastructure", "Network", "high"),
            ("CIS-13", "Network Monitoring & Defense", "Operate network monitoring and defense processes", "Network", "high"),
            ("CIS-14", "Security Awareness Training", "Establish a security awareness program", "Training", "medium"),
            ("CIS-15", "Service Provider Management", "Develop processes to evaluate service providers", "Vendor", "medium"),
            ("CIS-16", "Application Software Security", "Manage the lifecycle of internally developed software", "Development", "high"),
            ("CIS-17", "Incident Response Management", "Establish an incident response program", "Incident Response", "high"),
            ("CIS-18", "Penetration Testing", "Test the effectiveness of security controls", "Testing", "high"),
        ],
    },
    "NIST 800-53": {
        "description": "NIST SP 800-53 Rev 5 — Security and Privacy Controls",
        "version": "Rev 5",
        "controls": [
            ("AC-2", "Account Management", "Manage system accounts, group, and role membership", "Access Control", "critical"),
            ("AC-3", "Access Enforcement", "Enforce approved authorizations for logical access", "Access Control", "critical"),
            ("AC-6", "Least Privilege", "Employ the principle of least privilege", "Access Control", "high"),
            ("AU-2", "Event Logging", "Identify the types of events the system is capable of logging", "Monitoring", "high"),
            ("AU-6", "Audit Record Review", "Review and analyze system audit records", "Monitoring", "high"),
            ("CM-2", "Baseline Configuration", "Develop and maintain a baseline configuration", "Configuration", "high"),
            ("CM-6", "Configuration Settings", "Establish and enforce secure configuration settings", "Configuration", "critical"),
            ("CM-7", "Least Functionality", "Configure the system to provide only essential capabilities", "Configuration", "high"),
            ("IA-2", "Identification & Authentication", "Uniquely identify and authenticate users", "Authentication", "critical"),
            ("IA-5", "Authenticator Management", "Manage system authenticators and secrets", "Authentication", "critical"),
            ("IR-4", "Incident Handling", "Implement an incident handling capability", "Incident Response", "high"),
            ("RA-5", "Vulnerability Monitoring", "Monitor and scan for vulnerabilities", "Vulnerability", "critical"),
            ("SC-7", "Boundary Protection", "Monitor and control communications at external boundaries", "Network", "critical"),
            ("SC-8", "Transmission Confidentiality", "Protect the confidentiality of transmitted information", "Encryption", "critical"),
            ("SC-13", "Cryptographic Protection", "Implement required cryptographic protections", "Encryption", "critical"),
            ("SC-28", "Protection of Information at Rest", "Protect the confidentiality and integrity of data at rest", "Encryption", "critical"),
            ("SI-2", "Flaw Remediation", "Identify, report, and correct system flaws", "Vulnerability", "critical"),
            ("SI-3", "Malicious Code Protection", "Implement malicious code protection mechanisms", "Security", "high"),
            ("SI-4", "System Monitoring", "Monitor the system to detect attacks and indicators", "Monitoring", "high"),
            ("SI-7", "Software & Information Integrity", "Employ integrity verification tools", "Data Protection", "high"),
        ],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# EVALUATION ENGINE — see app/services/governance/compliance.py for the rules.
# Every compliance number in this module comes from ComplianceEvaluator so the
# dashboard, framework list and control drill-down always agree.
#   score = passing / (passing + failing) * 100, or None when nothing is assessed
#   (not_assessed and manual controls are excluded from the denominator)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Evaluator status → value stored in ComplianceControl.status
_STATUS_FOR_STORAGE = {
    "passed": "passed",
    "failed": "failed",
    "not_assessed": "not_assessed",
    "manual": "not_applicable",
}

async def _evaluate_controls(db: AsyncSession, org_id: int) -> dict:
    """Evaluate all controls against open findings and persist the result."""
    evaluator = await ComplianceEvaluator.load(db, org_id, CONTROL_FINDING_MAP)
    frameworks = (await db.execute(
        select(ComplianceFramework).where(ComplianceFramework.organization_id == org_id)
    )).scalars().all()

    now = datetime.now(timezone.utc)
    total_passing = total_failing = total_not_assessed = total_manual = 0
    framework_results = []

    for fw in frameworks:
        controls = (await db.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == fw.id)
        )).scalars().all()

        for ctrl in controls:
            res = evaluator.evaluate(ctrl.control_id)
            ctrl.status = _STATUS_FOR_STORAGE[res.status]
            ctrl.automated = res.status != "manual"
            ctrl.finding_categories = res.categories
            ctrl.evidence = res.evidence
            if res.status in ("passed", "failed"):
                ctrl.last_checked = now

        summary = evaluator.summarize(c.control_id for c in controls)
        fw.passing_controls = summary["passed"]
        fw.failing_controls = summary["failed"]
        fw.not_applicable = summary["manual"]
        fw.compliance_score = summary["score"] or 0.0
        if summary["assessed"]:
            fw.last_assessed = now

        if fw.is_enabled:
            total_passing += summary["passed"]
            total_failing += summary["failed"]
            total_not_assessed += summary["not_assessed"]
            total_manual += summary["manual"]

        framework_results.append({
            "name": fw.name,
            "enabled": fw.is_enabled,
            "score": summary["score"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "not_assessed": summary["not_assessed"],
            "manual": summary["manual"],
        })

    await db.flush()

    total_assessed = total_passing + total_failing
    return {
        "scans_available": evaluator.scan_count,
        "open_findings": len(evaluator.findings),
        "domains_with_findings": evaluator.domain_counts,
        "total_passing": total_passing,
        "total_failing": total_failing,
        "total_not_assessed": total_not_assessed,
        "total_manual": total_manual,
        "overall_score": round((total_passing / total_assessed) * 100, 1) if total_assessed > 0 else None,
        "frameworks": framework_results,
    }


async def _live_frameworks(db: AsyncSession, org_id: int) -> list[dict]:
    """Current control counts and score for each of the org's frameworks, by name."""
    evaluator = await ComplianceEvaluator.load(db, org_id, CONTROL_FINDING_MAP)
    frameworks = (await db.execute(
        select(ComplianceFramework)
        .where(ComplianceFramework.organization_id == org_id)
        .order_by(ComplianceFramework.name)
    )).scalars().all()
    rows = (await db.execute(
        select(ComplianceControl.framework_id, ComplianceControl.control_id)
        .where(ComplianceControl.organization_id == org_id)
    )).all()
    by_fw: dict[int, list[str]] = {}
    for fw_id, control_id in rows:
        by_fw.setdefault(fw_id, []).append(control_id)

    out = []
    for fw in frameworks:
        control_ids = by_fw.get(fw.id, [])
        out.append({"fw": fw, "total": len(control_ids), **evaluator.summarize(control_ids)})
    return out


# ─── Evaluate Endpoint ─────────────────────────────────────────────────────────

@router.post("/evaluate")
async def evaluate_compliance(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Run the real evaluation engine against actual scan findings.

    Math:
      For each control → look up mapped finding categories →
      count open findings → 0 = PASSING, >0 = FAILING.
      Score = passing / (passing + failing) × 100
    """
    result = await _evaluate_controls(db, current_user.organization_id)
    return {
        "status": "evaluated",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }


# ─── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/dashboard", response_model=GovernanceDashboardStats)
async def governance_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get governance dashboard statistics."""
    org_id = current_user.organization_id

    # Live figures for enabled frameworks, from the same evaluator as the Frameworks tab
    live = await _live_frameworks(db, org_id)
    enabled = [f for f in live if f["fw"].is_enabled]
    fw_count = len(live)
    total_ctrl = sum(f["total"] for f in enabled)
    passing_ctrl = sum(f["passed"] for f in enabled)
    failing_ctrl = sum(f["failed"] for f in enabled)
    not_assessed_ctrl = sum(f["not_assessed"] for f in enabled)
    manual_ctrl = sum(f["manual"] for f in enabled)
    assessed_ctrl = passing_ctrl + failing_ctrl
    avg_score = round(passing_ctrl / assessed_ctrl * 100, 1) if assessed_ctrl else None

    pol_count = await db.scalar(
        select(sa_func.count(SecurityPolicy.id)).where(SecurityPolicy.organization_id == org_id)
    ) or 0
    active_pol = await db.scalar(
        select(sa_func.count(SecurityPolicy.id)).where(
            SecurityPolicy.organization_id == org_id, SecurityPolicy.is_enabled == True
        )
    ) or 0

    total_viol = await db.scalar(
        select(sa_func.count(PolicyViolation.id)).where(PolicyViolation.organization_id == org_id)
    ) or 0
    open_viol = await db.scalar(
        select(sa_func.count(PolicyViolation.id)).where(
            PolicyViolation.organization_id == org_id, PolicyViolation.status == "open"
        )
    ) or 0
    crit_viol = await db.scalar(
        select(sa_func.count(PolicyViolation.id)).where(
            PolicyViolation.organization_id == org_id, PolicyViolation.severity == "critical"
        )
    ) or 0

    pending_exc = await db.scalar(
        select(sa_func.count(RiskException.id)).where(
            RiskException.organization_id == org_id, RiskException.status == "pending"
        )
    ) or 0
    approved_exc = await db.scalar(
        select(sa_func.count(RiskException.id)).where(
            RiskException.organization_id == org_id, RiskException.status == "approved"
        )
    ) or 0

    fw_list = [{"name": f["fw"].name, "enabled": f["fw"].is_enabled, "score": f["score"],
                "total": f["total"], "passed": f["passed"], "failed": f["failed"],
                "not_assessed": f["not_assessed"], "manual": f["manual"],
                "reference_url": f["fw"].reference_url} for f in live]

    return GovernanceDashboardStats(
        frameworks_count=fw_count,
        avg_compliance_score=avg_score,
        total_controls=total_ctrl,
        passing_controls=passing_ctrl,
        failing_controls=failing_ctrl,
        not_assessed_controls=not_assessed_ctrl,
        manual_controls=manual_ctrl,
        policies_count=pol_count,
        active_policies=active_pol,
        total_violations=total_viol,
        open_violations=open_viol,
        critical_violations=crit_viol,
        exceptions_pending=pending_exc,
        exceptions_approved=approved_exc,
        frameworks=fw_list,
    )


# ─── Frameworks CRUD ──────────────────────────────────────────────────────────

@router.get("/frameworks", response_model=list[FrameworkResponse])
async def list_frameworks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List compliance frameworks with live pass/fail counts."""
    live = await _live_frameworks(db, current_user.organization_id)
    enriched = []
    for f in live[(page - 1) * page_size: page * page_size]:
        resp = FrameworkResponse.model_validate(f["fw"])
        resp.passing_controls = f["passed"]
        resp.failing_controls = f["failed"]
        resp.not_applicable = f["manual"]
        resp.not_assessed = f["not_assessed"]
        resp.compliance_score = f["score"]
        enriched.append(resp)
    return enriched


@router.post("/frameworks/seed", response_model=list[FrameworkResponse])
async def seed_frameworks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Seed compliance frameworks with real controls — no fake scores.

    All controls start as NOT_ASSESSED. Run POST /evaluate to compute
    real scores from scan findings.
    """
    org_id = current_user.organization_id
    created = []

    for name, data in FRAMEWORK_SEEDS.items():
        existing = await db.scalar(
            select(sa_func.count(ComplianceFramework.id)).where(
                ComplianceFramework.organization_id == org_id,
                ComplianceFramework.name == name,
            )
        )
        if existing:
            continue

        controls_data = data["controls"]
        total = len(controls_data)

        fw = ComplianceFramework(
            organization_id=org_id,
            name=name,
            version=data.get("version", "latest"),
            description=data["description"],
            total_controls=total,
            passing_controls=0,
            failing_controls=0,
            not_applicable=0,
            compliance_score=0.0,
            reference_url=FRAMEWORK_REFS.get(name),
        )
        db.add(fw)
        await db.flush()

        for ctrl_id, title, desc, category, severity in controls_data:
            mapping = CONTROL_FINDING_MAP.get(ctrl_id, {})
            ctrl = ComplianceControl(
                framework_id=fw.id,
                organization_id=org_id,
                control_id=ctrl_id,
                title=title,
                description=desc,
                category=category,
                status="not_assessed",
                severity=severity,
                finding_categories=mapping.get("categories", []),
            )
            db.add(ctrl)

        created.append(fw)

    await db.flush()
    return [FrameworkResponse.model_validate(fw) for fw in created]


@router.get("/frameworks/{framework_id}", response_model=FrameworkResponse)
async def get_framework(
    framework_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get framework details."""
    fw = await db.get(ComplianceFramework, framework_id)
    if not fw or fw.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Framework not found")
    return FrameworkResponse.model_validate(fw)


@router.get("/frameworks/{framework_id}/controls")
async def list_controls(
    framework_id: int,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List controls for a framework with affected resource counts."""
    q = select(ComplianceControl).where(
        ComplianceControl.framework_id == framework_id,
        ComplianceControl.organization_id == current_user.organization_id,
    )
    result = await db.execute(q.order_by(ComplianceControl.control_id))
    controls = result.scalars().all()

    # Build per-category sets of DISTINCT failing resource files so control
    # counts reflect resources (files), not raw finding counts. A resource is
    # a scanned file; it "fails" a control if it has an open finding in one of
    # the control's mapped categories, otherwise it "passes".
    org_id = current_user.organization_id
    evaluator = await ComplianceEvaluator.load(db, org_id, CONTROL_FINDING_MAP)

    # Universe of scanned resource files (distinct files with any finding)
    all_files_rows = (await db.execute(
        select(sa_func.distinct(Finding.file_path))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == org_id,
            Scan.status == "completed",
            Finding.file_path.isnot(None),
        )
    )).all()
    total_files = len({r[0] for r in all_files_rows if r[0]})

    enriched = []
    for ctrl in controls:
        c = ControlResponse.model_validate(ctrl)
        res = evaluator.evaluate(ctrl.control_id)
        # Live status, so the list always agrees with the framework summary
        c.status = _STATUS_FOR_STORAGE[res.status]
        c.automated = res.status != "manual"
        c.finding_categories = res.categories
        c.evidence = res.evidence
        if res.status in ("passed", "failed"):
            failed = len({f.file_path for f in evaluator.matching_findings(ctrl.control_id) if f.file_path})
            c.failed_resources = failed
            c.total_resources = total_files
            c.passed_resources = max(total_files - failed, 0)
        else:
            c.failed_resources = 0
            c.passed_resources = 0
            c.total_resources = 0
        enriched.append(c)
    if status:
        enriched = [c for c in enriched if c.status == status]
    return enriched


@router.get("/controls/{control_id}/affected-resources")
async def get_control_affected_resources(
    control_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None),  # "failed" or "passed"
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get affected resources for a control — both passing and failing files.

    A resource is a scanned file. It *fails* the control if it has an open
    finding in one of the control's mapped categories; otherwise it *passes*.
    This lets the UI show *which* resources comply, not just a count.
    """
    org_id = current_user.organization_id

    ctrl = await db.get(ComplianceControl, control_id)
    if not ctrl or ctrl.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Control not found")

    evaluator = await ComplianceEvaluator.load(db, org_id, CONTROL_FINDING_MAP)
    mapping = CONTROL_FINDING_MAP.get(ctrl.control_id) or {}
    cats = evaluator.categories_for(ctrl.control_id)
    if not cats or evaluator.scan_count == 0:
        return {"items": [], "total": 0, "page": page, "page_size": page_size,
                "control_id": ctrl.control_id, "control_title": ctrl.title,
                "description": ctrl.description,
                "assessment": "manual" if not cats else "not_assessed",
                "passed_count": 0, "failed_count": 0}

    # Universe of scanned resource files + a representative scan per file (for repo link)
    file_scan_rows = (await db.execute(
        select(Finding.file_path, Finding.scan_id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == org_id,
            Scan.status == "completed",
            Finding.file_path.isnot(None),
        )
    )).all()
    file_scan_map: dict[str, int] = {}
    for fp, sid in file_scan_rows:
        if fp and fp not in file_scan_map:
            file_scan_map[fp] = sid
    all_files = set(file_scan_map.keys())

    # Open findings in this control's categories → failing files + evidence
    fail_findings = sorted(
        (f for f in evaluator.matching_findings(ctrl.control_id) if f.file_path),
        key=lambda f: (_SEVERITY_ORDER.get((f.severity or "").upper(), 9), f.file_path),
    )

    fail_by_file: dict = {}
    for f in fail_findings:
        if f.file_path and f.file_path not in fail_by_file:
            fail_by_file[f.file_path] = f

    failed_files = set(fail_by_file.keys())
    passed_files = sorted(all_files - failed_files)

    # Repo URLs for link building
    scan_ids = list({sid for sid in file_scan_map.values()})
    repo_map: dict[int, str] = {}
    if scan_ids:
        scan_rows = (await db.execute(
            select(Scan.id, Scan.repository_url).where(Scan.id.in_(scan_ids))
        )).all()
        repo_map = {r[0]: r[1] for r in scan_rows if r[1]}

    def _link(file_path: str, scan_id: int | None, line: int | None = None) -> str:
        repo_url = repo_map.get(scan_id, "") if scan_id else ""
        if repo_url and file_path:
            lnk = f"{repo_url}/blob/main/{file_path}"
            if line:
                lnk += f"#L{line}"
            return lnk
        return ""

    resources: list[dict] = []
    # Failing resources first (worst → best already via sort of findings)
    for fp in sorted(failed_files):
        f = fail_by_file[fp]
        resources.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "resource_type": f.resource_type or f.category,
            "resource_name": fp,
            "file_path": fp,
            "line_number": f.line_number,
            "file_link": _link(fp, f.scan_id, f.line_number),
            "rule_id": f.rule_id,
            "status": "Failed",
        })
    # Passing resources
    for fp in passed_files:
        sid = file_scan_map.get(fp)
        resources.append({
            "id": None,
            "title": "Compliant — no violations for this control",
            "severity": None,
            "category": cats[0] if cats else None,
            "resource_type": "file",
            "resource_name": fp,
            "file_path": fp,
            "line_number": None,
            "file_link": _link(fp, sid),
            "rule_id": None,
            "status": "Passed",
        })

    # Optional status filter
    if status_filter == "failed":
        resources = [r for r in resources if r["status"] == "Failed"]
    elif status_filter == "passed":
        resources = [r for r in resources if r["status"] == "Passed"]

    total = len(resources)
    start = (page - 1) * page_size
    items = resources[start:start + page_size]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "control_id": ctrl.control_id,
        "control_title": ctrl.title,
        "description": ctrl.description,
        "remediation_notes": mapping.get("desc", ""),
        "passed_count": len(passed_files),
        "failed_count": len(failed_files),
    }


# ─── Policies CRUD ─────────────────────────────────────────────────────────────

def _require_evaluable_rules(rules) -> None:
    """A policy that matches nothing can never be violated; refuse to store it."""
    if finding_rules(rules) or is_cloud_policy(rules):
        return
    raise HTTPException(
        status_code=400,
        detail="A policy needs at least one rule: finding categories or rule-ID prefixes "
               "(rules: [{categories, rule_id_prefixes}]), or a cloud-resource condition.",
    )


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    result = await db.execute(
        select(SecurityPolicy)
        .where(SecurityPolicy.organization_id == current_user.organization_id)
        .order_by(SecurityPolicy.name)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return [PolicyResponse.model_validate(p) for p in result.scalars().all()]


@router.post("/policies", response_model=PolicyResponse)
async def create_policy(
    body: PolicyCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    if not body.name or not body.name.strip():
        raise HTTPException(status_code=400, detail="Policy name cannot be empty")
    _require_evaluable_rules(body.rules)
    policy = SecurityPolicy(organization_id=current_user.organization_id, **body.model_dump())
    db.add(policy)
    await db.flush()
    await write_audit_log(
        db, action="create", resource_type="policy", resource_id=policy.id,
        details={"name": body.name, "severity": body.severity},
        user=current_user, request=request,
    )
    return PolicyResponse.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    policy = await db.get(SecurityPolicy, policy_id)
    if not policy or policy.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    updates = body.model_dump(exclude_unset=True)
    if "rules" in updates:
        _require_evaluable_rules(updates["rules"])
    for field, val in updates.items():
        setattr(policy, field, val)
    await db.commit()
    await db.refresh(policy)
    return PolicyResponse.model_validate(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "delete")),
):
    policy = await db.get(SecurityPolicy, policy_id)
    if not policy or policy.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    await write_audit_log(
        db, action="delete", resource_type="policy", resource_id=policy_id,
        details={"name": policy.name},
        user=current_user, request=request,
    )
    await db.delete(policy)
    await db.commit()
    return {"status": "deleted"}


@router.post("/policies/{policy_id}/toggle")
async def toggle_policy(
    policy_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Toggle a policy's enabled state."""
    policy = await db.get(SecurityPolicy, policy_id)
    if not policy or policy.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_enabled = not policy.is_enabled
    await write_audit_log(
        db, action="update", resource_type="policy", resource_id=policy_id,
        details={"name": policy.name, "is_enabled": policy.is_enabled},
        user=current_user, request=request,
    )
    await db.commit()
    await db.refresh(policy)
    return {
        "id": policy.id,
        "name": policy.name,
        "is_enabled": policy.is_enabled,
    }


# ─── Seed & Evaluate Policies ─────────────────────────────────────────────────

@router.post("/policies/seed")
async def seed_policies(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Seed the 20+ built-in security policies from the PolicyEngine.

    Each built-in policy is stored as a SecurityPolicy DB record with its
    matching rules (rule_id_prefixes, categories, resource_types, cloud_providers)
    serialised into the ``rules`` JSON column. Duplicates (by name) are skipped.
    """
    from app.services.security.policy_engine import builtin_policy_rules

    org_id = current_user.organization_id
    created = 0
    skipped = 0
    updated = 0

    for bp in BUILT_IN_POLICIES:
        existing = (await db.execute(
            select(SecurityPolicy).where(
                SecurityPolicy.organization_id == org_id,
                SecurityPolicy.name == bp["name"],
            )
        )).scalars().first()
        if existing:
            # A built-in keeps the rules that ship with this version; whether it
            # is enabled or enforced stays the organization's choice.
            if existing.is_builtin and existing.rules != builtin_policy_rules(bp):
                existing.rules = builtin_policy_rules(bp)
                updated += 1
            else:
                skipped += 1
            continue

        policy = SecurityPolicy(
            organization_id=org_id,
            name=bp["name"],
            description=bp.get("description", ""),
            policy_type=bp.get("category", "security"),
            severity=bp.get("severity", "medium").lower(),
            is_enabled=bp.get("enabled", True),
            # Monitor-only until an admin opts in: enforced policies fail CI scans
            is_enforced=False,
            is_builtin=True,
            rules=builtin_policy_rules(bp),
            target_repos=None,  # org-wide
        )
        db.add(policy)
        created += 1

    await db.flush()
    await write_audit_log(
        db, action="seed", resource_type="policies",
        details={"created": created, "updated": updated, "skipped": skipped},
        user=current_user, request=request,
    )

    return {"status": "seeded", "created": created, "updated": updated, "skipped": skipped}


@router.post("/policies/evaluate")
async def evaluate_policies(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Evaluate all enabled security policies against real scan findings.

    For each enabled policy, load its matching rules from the ``rules`` JSON,
    find open findings that match (by rule_id prefix OR category), and create
    PolicyViolation records for each match. Existing open violations for the
    same policy+resource are not duplicated.
    """
    org_id = current_user.organization_id

    # Load all enabled policies
    policies = (await db.execute(
        select(SecurityPolicy).where(
            SecurityPolicy.organization_id == org_id,
            SecurityPolicy.is_enabled == True,
        )
    )).scalars().all()

    if not policies:
        return {"status": "no_policies", "message": "No enabled policies. Seed policies first."}

    # Load all open findings from completed scans, with the repo they came from
    findings_rows = (await db.execute(
        select(Finding, Scan.repository_name)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.organization_id == org_id,
            Scan.status == "completed",
            Finding.is_fixed == False,
            Finding.is_ignored == False,
        )
    )).all()

    findings = [
        {
            "id": f.id,
            "rule_id": f.rule_id or "",
            "title": f.title or "",
            "description": f.description or "",
            "severity": (f.severity or "INFO").upper(),
            "category": f.category or "",
            "resource_type": f.resource_type or "",
            # Findings have no cloud resource ID; the resource is the IaC block or file
            "resource_id": f.resource_name or f.file_path or f"finding-{f.id}",
            "resource_name": f.resource_name or f.file_path or "",
            "file_path": f.file_path or "",
            "repository": repo_name,
            "cloud_provider": getattr(f, "cloud_provider", "") or "",
        }
        for f, repo_name in findings_rows
    ]

    exempt_keys = active_exemption_keys((await db.execute(
        select(RiskException).where(
            RiskException.organization_id == org_id, RiskException.status == "approved",
        )
    )).scalars().all())

    total_violations_created = 0
    total_violations_skipped = 0
    total_exempted = 0
    policy_results = []
    policies_evaluated = 0

    for policy in policies:
        rules_list = finding_rules(policy.rules)
        if not rules_list:
            # Cloud-condition policies are evaluated by "Run Assessment";
            # policies without any rule cannot be evaluated at all.
            policy_results.append({
                "policy": policy.name,
                "severity": policy.severity,
                "matched": 0,
                "violations_created": 0,
                "skipped_reason": "cloud_resource_policy" if is_cloud_policy(policy.rules) else "no_rules",
            })
            continue
        policies_evaluated += 1

        in_scope = [f for f in findings if applies_to_repo(policy.target_repos, f["repository"])]
        matched_finding_ids = {f["id"] for f in in_scope if finding_matches(rules_list, f)}

        # Create violations for matched findings; one per policy+resource, and
        # never on top of an open or risk-accepted one.
        violations_created = 0
        seen_resources: set[str] = set()
        for f in in_scope:
            if f["id"] not in matched_finding_ids or f["resource_id"] in seen_resources:
                continue
            seen_resources.add(f["resource_id"])
            if is_exempt(exempt_keys, policy.id, f["resource_id"]):
                total_exempted += 1
                continue

            evidence = {
                "source": "finding",
                "finding_id": f["id"],
                "rule_id": f["rule_id"],
                "title": f["title"],
                "category": f["category"],
                "file_path": f["file_path"],
                "repository": f["repository"],
            }
            existing = (await db.execute(
                select(PolicyViolation).where(
                    PolicyViolation.organization_id == org_id,
                    PolicyViolation.policy_id == policy.id,
                    PolicyViolation.resource_id == f["resource_id"],
                    PolicyViolation.status.in_(("open", "accepted")),
                )
            )).scalars().first()
            if existing:
                # Same resource, still in violation. If the finding it was recorded
                # for no longer matches the policy, point it at one that does.
                recorded = (existing.violation_details or {}).get("finding_id")
                if recorded not in matched_finding_ids:
                    existing.violation_details = evidence
                total_violations_skipped += 1
                continue

            violation = PolicyViolation(
                organization_id=org_id,
                policy_id=policy.id,
                resource_type=f["resource_type"],
                resource_id=f["resource_id"],
                resource_name=f["resource_name"],
                cloud_provider=f["cloud_provider"],
                violation_details=evidence,
                severity=policy.severity,
                status="open",
            )
            db.add(violation)
            violations_created += 1
            total_violations_created += 1

        # Close open violations whose finding has since been fixed or ignored
        still_violating = {
            f["resource_id"] for f in in_scope
            if f["id"] in matched_finding_ids and not is_exempt(exempt_keys, policy.id, f["resource_id"])
        }
        stale = (await db.execute(
            select(PolicyViolation).where(
                PolicyViolation.organization_id == org_id,
                PolicyViolation.policy_id == policy.id,
                PolicyViolation.status == "open",
            )
        )).scalars().all()
        for v in stale:
            if v.resource_id not in still_violating:
                v.status = "resolved"
                v.resolved_at = datetime.now(timezone.utc)

        # Update policy stats
        policy.violations_count = await db.scalar(
            select(sa_func.count(PolicyViolation.id)).where(
                PolicyViolation.policy_id == policy.id,
                PolicyViolation.status == "open",
            )
        ) or 0
        policy.last_evaluated = datetime.now(timezone.utc)
        policy.resources_in_scope = len({f["resource_id"] for f in in_scope})

        policy_results.append({
            "policy": policy.name,
            "severity": policy.severity,
            "matched": len(matched_finding_ids),
            "violations_created": violations_created,
        })

    await db.flush()
    await write_audit_log(
        db, action="evaluate", resource_type="policies",
        details={"violations_created": total_violations_created, "policies_evaluated": policies_evaluated},
        user=current_user, request=request,
    )

    return {
        "status": "evaluated",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "policies_evaluated": policies_evaluated,
        "policies_skipped": len(policies) - policies_evaluated,
        "total_findings": len(findings),
        "violations_created": total_violations_created,
        "violations_skipped": total_violations_skipped,
        "exempted": total_exempted,
        "policy_results": policy_results,
    }


# ─── Violations ────────────────────────────────────────────────────────────────

@router.get("/violations", response_model=dict)
async def list_violations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    q = select(PolicyViolation).where(PolicyViolation.organization_id == current_user.organization_id)
    if severity:
        q = q.where(PolicyViolation.severity == severity)
    if status:
        q = q.where(PolicyViolation.status == status)

    count_q = select(sa_func.count()).select_from(q.subquery())
    total = await db.scalar(count_q) or 0

    q = q.order_by(PolicyViolation.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = result.scalars().all()

    return {
        "items": [ViolationResponse.model_validate(v) for v in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# ─── Risk Exceptions ──────────────────────────────────────────────────────────

@router.get("/exceptions", response_model=list[ExceptionResponse])
async def list_exceptions(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    q = select(RiskException).where(RiskException.organization_id == current_user.organization_id)
    if status:
        q = q.where(RiskException.status == status)
    result = await db.execute(
        q.order_by(RiskException.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return [ExceptionResponse.model_validate(e) for e in result.scalars().all()]


@router.post("/exceptions", response_model=ExceptionResponse)
async def create_exception(
    body: ExceptionCreate,
    db: AsyncSession = Depends(get_db),
    # Anyone who triages findings may request an exception; approving needs findings:manage
    current_user: User = Depends(require_permission("findings", "update")),
):
    # An exception with no scope would exempt nothing
    if not body.policy_id and not (body.resource_id and body.resource_id.strip()):
        raise HTTPException(
            status_code=400,
            detail="An exception must name the policy and/or the resource it applies to.",
        )
    await _check_exception_policy(db, body.policy_id, current_user.organization_id)
    data = body.model_dump()
    data["expiry_date"] = data.get("expires_at")
    exc = RiskException(
        organization_id=current_user.organization_id,
        requested_by=current_user.email,
        **data,
    )
    db.add(exc)
    await db.commit()
    await db.refresh(exc)
    return ExceptionResponse.model_validate(exc)


async def _check_exception_policy(db: AsyncSession, policy_id: int | None, org_id: int) -> None:
    if policy_id is None:
        return
    policy = await db.get(SecurityPolicy, policy_id)
    if not policy or policy.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Policy not found")


@router.put("/exceptions/{exception_id}", response_model=ExceptionResponse)
async def update_exception(
    exception_id: int,
    body: ExceptionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    exc = await db.get(RiskException, exception_id)
    if not exc or exc.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Exception not found")
    updates = body.model_dump(exclude_unset=True)
    await _check_exception_policy(db, updates.get("policy_id"), current_user.organization_id)
    for k, v in updates.items():
        setattr(exc, k, v)
    if "expires_at" in updates:
        exc.expiry_date = updates["expires_at"]
    # A changed exception is a new request: it needs approving again
    if updates and exc.status in ("approved", "rejected"):
        exc.status = "pending"
        exc.approved_by = None
    await db.commit()
    await db.refresh(exc)
    return ExceptionResponse.model_validate(exc)


@router.patch("/exceptions/{exception_id}/approve")
async def approve_exception(
    exception_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "manage")),
):
    exc = await db.get(RiskException, exception_id)
    if not exc or exc.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Exception not found")
    if exc.status != "pending":
        raise HTTPException(status_code=400, detail=f"Exception is already {exc.status}")
    # Separation of duties: the requester cannot approve their own exception
    if (exc.requested_by or "").lower() == current_user.email.lower():
        raise HTTPException(status_code=403, detail="You cannot approve an exception you requested")
    exc.status = "approved"
    exc.approved_by = current_user.email
    await db.commit()
    return {"status": "approved", "id": exception_id}


@router.patch("/exceptions/{exception_id}/reject")
async def reject_exception(
    exception_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "manage")),
):
    exc = await db.get(RiskException, exception_id)
    if not exc or exc.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Exception not found")
    exc.status = "rejected"
    await db.commit()
    return {"status": "rejected", "id": exception_id}


@router.delete("/exceptions/{exception_id}")
async def delete_exception(
    exception_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "delete")),
):
    exc = await db.get(RiskException, exception_id)
    if not exc or exc.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Exception not found")
    await db.delete(exc)
    await db.commit()
    await write_audit_log(
        db, action="delete", resource_type="risk_exception", resource_id=exception_id,
        user=current_user, details={"title": exc.title},
    )
    return {"status": "deleted", "id": exception_id}


# ═════════════════════════════════════════════════════════════════════════════
# NEW GOVERNANCE ENGINE — Real policy-as-code evaluation
# ═════════════════════════════════════════════════════════════════════════════

from app.models.cloud_resource import CloudResource, Assessment, AssessmentResult
from app.services.governance.assessment_engine import AssessmentEngine
from app.services.governance.seed_governance import seed_governance_data


# ─── Cloud Resources ────────────────────────────────────────────────────────

@router.get("/resources")
async def list_cloud_resources(
    provider: str | None = None,
    resource_type: str | None = None,
    status: str = "active",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List cloud resources with filtering and pagination."""
    query = select(CloudResource).where(
        CloudResource.organization_id == current_user.organization_id,
    )
    if provider:
        query = query.where(CloudResource.provider == provider)
    if resource_type:
        query = query.where(CloudResource.resource_type == resource_type)
    if status:
        query = query.where(CloudResource.status == status)

    # Count
    count_q = select(sa_func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Page
    query = query.order_by(CloudResource.resource_name).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    resources = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "resources": [
            {
                "id": r.id,
                "provider": r.provider,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "resource_name": r.resource_name,
                "region": r.region,
                "account_id": r.account_id,
                "status": r.status,
                "tags": r.tags,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_synced": r.last_synced.isoformat() if r.last_synced else None,
                "last_evaluated": r.last_evaluated.isoformat() if r.last_evaluated else None,
            }
            for r in resources
        ],
    }


@router.get("/resources/summary")
async def cloud_resources_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get summary counts of cloud resources by provider and type."""
    org_id = current_user.organization_id

    # By provider
    provider_q = await db.execute(
        select(CloudResource.provider, sa_func.count(CloudResource.id))
        .where(CloudResource.organization_id == org_id, CloudResource.status == "active")
        .group_by(CloudResource.provider)
    )
    by_provider = {row[0]: row[1] for row in provider_q.all()}

    # By type
    type_q = await db.execute(
        select(CloudResource.resource_type, sa_func.count(CloudResource.id))
        .where(CloudResource.organization_id == org_id, CloudResource.status == "active")
        .group_by(CloudResource.resource_type)
    )
    by_type = {row[0]: row[1] for row in type_q.all()}

    total = sum(by_provider.values())

    return {
        "total_resources": total,
        "by_provider": by_provider,
        "by_type": by_type,
    }


@router.get("/resources/{resource_id}")
async def get_cloud_resource(
    resource_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get cloud resource detail including config and evaluation history."""
    resource = await db.get(CloudResource, resource_id)
    if not resource or resource.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Get recent evaluation results for this resource
    results_q = await db.execute(
        select(AssessmentResult)
        .where(
            AssessmentResult.resource_id == resource.id,
            AssessmentResult.organization_id == current_user.organization_id,
        )
        .order_by(AssessmentResult.evaluated_at.desc())
        .limit(50)
    )
    results = results_q.scalars().all()

    return {
        "id": resource.id,
        "provider": resource.provider,
        "resource_type": resource.resource_type,
        "resource_id": resource.resource_id,
        "resource_name": resource.resource_name,
        "region": resource.region,
        "account_id": resource.account_id,
        "config": resource.config,
        "tags": resource.tags,
        "status": resource.status,
        "source": resource.source,
        "first_seen": resource.first_seen.isoformat() if resource.first_seen else None,
        "last_synced": resource.last_synced.isoformat() if resource.last_synced else None,
        "last_evaluated": resource.last_evaluated.isoformat() if resource.last_evaluated else None,
        "evaluation_results": [
            {
                "id": r.id,
                "assessment_id": r.assessment_id,
                "policy_name": r.policy_name,
                "policy_severity": r.policy_severity,
                "status": r.status,
                "is_exempted": r.is_exempted,
                "evidence": r.evidence,
                "remediation": r.remediation,
                "evaluated_at": r.evaluated_at.isoformat() if r.evaluated_at else None,
            }
            for r in results
        ],
    }


# ─── Assessments ────────────────────────────────────────────────────────────

@router.post("/assessments/run")
async def run_assessment(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Run a governance assessment — evaluates all enabled policies against cloud resources."""
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}

    engine = AssessmentEngine(db)
    assessment = await engine.run_assessment(
        organization_id=current_user.organization_id,
        triggered_by=current_user.email,
        assessment_type=body.get("assessment_type", "full"),
        provider_filter=body.get("providers"),
        resource_type_filter=body.get("resource_types"),
    )

    # The same button refreshes the persisted framework/control status from findings
    compliance = await _evaluate_controls(db, current_user.organization_id)
    note = None
    if assessment.total_checks == 0:
        note = (
            "No cloud-resource checks ran: "
            + ("no cloud-resource policies are enabled." if not assessment.policies_evaluated
               else "no cloud resources are in the inventory. Connect and sync a cloud account.")
        )

    await write_audit_log(
        db, action="create", resource_type="assessment", resource_id=assessment.id,
        user=current_user, details={
            "type": assessment.assessment_type,
            "score": assessment.compliance_score,
            "checks": assessment.total_checks,
            "passed": assessment.passed,
            "failed": assessment.failed,
        },
    )

    return {
        "id": assessment.id,
        "status": assessment.status,
        "compliance_score": assessment.compliance_score,
        "total_checks": assessment.total_checks,
        "passed": assessment.passed,
        "failed": assessment.failed,
        "errors": assessment.errors,
        "exempted": assessment.exempted,
        "new_violations": assessment.new_violations,
        "resolved_violations": assessment.resolved_violations,
        "policies_evaluated": assessment.policies_evaluated,
        "resources_evaluated": assessment.resources_evaluated,
        "providers_evaluated": assessment.providers_evaluated,
        "duration_seconds": assessment.duration_seconds,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
        "note": note,
        "framework_compliance": {
            "overall_score": compliance["overall_score"],
            "passing": compliance["total_passing"],
            "failing": compliance["total_failing"],
            "not_assessed": compliance["total_not_assessed"],
            "manual": compliance["total_manual"],
        },
    }


@router.get("/assessments")
async def list_assessments(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """List assessments with trend data."""
    org_id = current_user.organization_id

    count_q = select(sa_func.count()).select_from(
        select(Assessment).where(Assessment.organization_id == org_id).subquery()
    )
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Assessment)
        .where(Assessment.organization_id == org_id)
        .order_by(Assessment.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    assessments = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "assessments": [
            {
                "id": a.id,
                "assessment_type": a.assessment_type,
                "status": a.status,
                "compliance_score": a.compliance_score,
                "total_checks": a.total_checks,
                "passed": a.passed,
                "failed": a.failed,
                "errors": a.errors,
                "exempted": a.exempted,
                "new_violations": a.new_violations,
                "resolved_violations": a.resolved_violations,
                "policies_evaluated": a.policies_evaluated,
                "resources_evaluated": a.resources_evaluated,
                "providers_evaluated": a.providers_evaluated,
                "triggered_by": a.triggered_by,
                "duration_seconds": a.duration_seconds,
                "started_at": a.started_at.isoformat() if a.started_at else None,
                "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            }
            for a in assessments
        ],
    }


@router.get("/assessments/{assessment_id}")
async def get_assessment_detail(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get assessment detail including all results grouped by status."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment or assessment.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Get all results
    results_q = await db.execute(
        select(AssessmentResult)
        .where(AssessmentResult.assessment_id == assessment.id)
        .order_by(AssessmentResult.status, AssessmentResult.policy_severity)
    )
    results = results_q.scalars().all()

    # Group by status
    by_status = {}
    for r in results:
        status = r.status
        if status not in by_status:
            by_status[status] = []
        by_status[status].append({
            "id": r.id,
            "policy_name": r.policy_name,
            "policy_severity": r.policy_severity,
            "resource_name": r.resource_name,
            "resource_type": r.resource_type,
            "resource_identifier": r.resource_identifier,
            "provider": r.provider,
            "is_exempted": r.is_exempted,
            "evidence": r.evidence,
            "remediation": r.remediation,
            "evaluated_at": r.evaluated_at.isoformat() if r.evaluated_at else None,
        })

    return {
        "id": assessment.id,
        "assessment_type": assessment.assessment_type,
        "status": assessment.status,
        "compliance_score": assessment.compliance_score,
        "total_checks": assessment.total_checks,
        "passed": assessment.passed,
        "failed": assessment.failed,
        "errors": assessment.errors,
        "exempted": assessment.exempted,
        "new_violations": assessment.new_violations,
        "resolved_violations": assessment.resolved_violations,
        "policies_evaluated": assessment.policies_evaluated,
        "resources_evaluated": assessment.resources_evaluated,
        "providers_evaluated": assessment.providers_evaluated,
        "triggered_by": assessment.triggered_by,
        "duration_seconds": assessment.duration_seconds,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
        "results_by_status": by_status,
        "total_results": len(results),
    }


# ─── Seed Data ──────────────────────────────────────────────────────────────

@router.post("/seed")
async def seed_governance(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "create")),
):
    """Load the built-in cloud-resource policies (S3, RDS, IAM, storage, compute).

    Idempotent. Outside demo mode (DEMO_DATA_ENABLED) no resources are created,
    and sample resources left by earlier versions are removed; real resources
    come from connected cloud accounts.
    """
    stats = await seed_governance_data(db, current_user.organization_id)

    await write_audit_log(
        db, action="create", resource_type="governance_seed", resource_id=0,
        user=current_user, details=stats,
    )

    return {"status": "seeded", **stats}


# ─── Violation Detail & Management ──────────────────────────────────────────

@router.get("/violations/{violation_id}")
async def get_violation_detail(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get violation detail including evidence, policy info, and resource config."""
    violation = await db.get(PolicyViolation, violation_id)
    if not violation or violation.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Violation not found")

    # Get the associated policy
    policy = await db.get(SecurityPolicy, violation.policy_id) if violation.policy_id else None

    # Get the cloud resource if it exists
    resource_detail = None
    if violation.resource_id:
        res_q = await db.execute(
            select(CloudResource).where(
                CloudResource.organization_id == current_user.organization_id,
                CloudResource.resource_id == violation.resource_id,
            ).limit(1)
        )
        cloud_res = res_q.scalars().first()
        if cloud_res:
            resource_detail = {
                "id": cloud_res.id,
                "provider": cloud_res.provider,
                "resource_type": cloud_res.resource_type,
                "resource_name": cloud_res.resource_name,
                "region": cloud_res.region,
                "account_id": cloud_res.account_id,
                "config": cloud_res.config,
                "tags": cloud_res.tags,
            }

    # Get latest assessment result for this violation's resource+policy pair
    assessment_evidence = None
    if violation.resource_id and violation.policy_id:
        ar_q = await db.execute(
            select(AssessmentResult).where(
                AssessmentResult.organization_id == current_user.organization_id,
                AssessmentResult.resource_identifier == violation.resource_id,
                AssessmentResult.policy_id == violation.policy_id,
            ).order_by(AssessmentResult.evaluated_at.desc()).limit(1)
        )
        ar = ar_q.scalars().first()
        if ar:
            assessment_evidence = {
                "status": ar.status,
                "evidence": ar.evidence,
                "remediation": ar.remediation,
                "evaluated_at": ar.evaluated_at.isoformat() if ar.evaluated_at else None,
            }

    return {
        "id": violation.id,
        "policy_id": violation.policy_id,
        "policy_name": policy.name if policy else None,
        "policy_description": policy.description if policy else None,
        "policy_severity": policy.severity if policy else None,
        "resource_type": violation.resource_type,
        "resource_id": violation.resource_id,
        "resource_name": violation.resource_name,
        "cloud_provider": violation.cloud_provider,
        "violation_details": violation.violation_details,
        "severity": violation.severity,
        "status": violation.status,
        "accepted_by": violation.accepted_by,
        "accepted_at": violation.accepted_at.isoformat() if violation.accepted_at else None,
        "acceptance_reason": violation.acceptance_reason,
        "acceptance_expires": violation.acceptance_expires.isoformat() if violation.acceptance_expires else None,
        "created_at": violation.created_at.isoformat() if violation.created_at else None,
        "resolved_at": violation.resolved_at.isoformat() if violation.resolved_at else None,
        "resource_detail": resource_detail,
        "assessment_evidence": assessment_evidence,
    }


@router.post("/violations/{violation_id}/accept")
async def accept_violation(
    violation_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Accept a violation (risk acceptance)."""
    violation = await db.get(PolicyViolation, violation_id)
    if not violation or violation.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Violation not found")

    body = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()

    violation.status = "accepted"
    violation.accepted_by = current_user.email
    violation.accepted_at = datetime.now(timezone.utc)
    violation.acceptance_reason = body.get("reason", "Risk accepted by user")
    await db.commit()

    await write_audit_log(
        db, action="update", resource_type="policy_violation", resource_id=violation_id,
        user=current_user, details={"action": "accept", "reason": violation.acceptance_reason},
    )

    return {"status": "accepted", "id": violation_id}


@router.post("/violations/{violation_id}/reject")
async def reopen_violation(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Re-open/reject an accepted violation."""
    violation = await db.get(PolicyViolation, violation_id)
    if not violation or violation.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Violation not found")

    violation.status = "open"
    violation.accepted_by = None
    violation.accepted_at = None
    violation.acceptance_reason = None
    await db.commit()

    return {"status": "open", "id": violation_id}


# ─── Framework Toggle ───────────────────────────────────────────────────────

@router.post("/frameworks/{framework_id}/toggle")
async def toggle_framework(
    framework_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Toggle a compliance framework enabled/disabled."""
    fw = await db.get(ComplianceFramework, framework_id)
    if not fw or fw.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Framework not found")

    fw.is_enabled = not fw.is_enabled
    await db.commit()

    return {"id": framework_id, "name": fw.name, "is_enabled": fw.is_enabled}
