"""SMTP email sending utility for GuardNous notifications."""
import asyncio
import logging
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


def _resolve_smtp_params(smtp_config: Optional[dict] = None) -> Optional[dict]:
    """Resolve SMTP parameters: caller-provided smtp_config > env vars.

    Returns a dict with keys: host, port, user, password, use_tls, from_email,
    from_name.  Returns ``None`` when SMTP is not configured at all (no host).
    Handles Gmail/Google from_email override automatically.
    """
    from app.core.config import settings

    cfg = smtp_config or {}
    host = cfg.get("host") or settings.SMTP_HOST
    if not host:
        return None

    port = cfg.get("port") or settings.SMTP_PORT
    user = cfg.get("user") or settings.SMTP_USER
    password = cfg.get("password") or settings.SMTP_PASSWORD
    use_tls = cfg.get("use_tls")
    if use_tls is None:
        use_tls = settings.SMTP_USE_TLS
    from_email = cfg.get("from_email") or settings.SMTP_FROM_EMAIL
    from_name = cfg.get("from_name") or settings.SMTP_FROM_NAME

    # Gmail/Google reject From addresses that don't match the authenticated user.
    if user:
        host_l = host.lower()
        if not from_email or "gmail" in host_l or "googlemail" in host_l:
            from_email = user

    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password or "",
        "use_tls": use_tls,
        "from_email": from_email,
        "from_name": from_name,
    }


def _smtp_send(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_tls: bool,
    from_email: str,
    msg: MIMEMultipart,
    to_email: str,
):
    """Low-level SMTP send (blocking)."""
    if smtp_use_tls:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(from_email, [to_email], msg.as_string())


async def send_email(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_tls: bool,
    from_email: str,
    from_name: str,
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
) -> dict:
    """Send an email via SMTP. Runs blocking smtplib in a thread."""

    def _send():
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        _smtp_send(smtp_host, smtp_port, smtp_user, smtp_password, smtp_use_tls, from_email, msg, to_email)
        return {"status": "ok", "message": f"Email sent to {to_email}"}

    return await asyncio.to_thread(_send)


async def send_email_with_attachment(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_tls: bool,
    from_email: str,
    from_name: str,
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    attachment_data: bytes = b"",
    attachment_filename: str = "report.pdf",
    attachment_mime: str = "application/pdf",
) -> dict:
    """Send an email with a file attachment. Runs smtplib in a thread."""

    def _send():
        msg = MIMEMultipart("mixed")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject

        body_part = MIMEMultipart("alternative")
        if text_body:
            body_part.attach(MIMEText(text_body, "plain"))
        body_part.attach(MIMEText(html_body, "html"))
        msg.attach(body_part)

        if attachment_data:
            maintype, subtype = attachment_mime.split("/", 1)
            part = MIMEBase(maintype, subtype)
            part.set_payload(attachment_data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=attachment_filename)
            msg.attach(part)

        _smtp_send(smtp_host, smtp_port, smtp_user, smtp_password, smtp_use_tls, from_email, msg, to_email)
        return {"status": "ok", "message": f"Email with attachment sent to {to_email}"}

    return await asyncio.to_thread(_send)


async def test_smtp_connection(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_tls: bool,
) -> dict:
    """Test SMTP connection without sending an email."""

    def _test():
        try:
            if smtp_use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.ehlo()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
            return {"status": "ok", "message": "SMTP connection successful"}
        except smtplib.SMTPAuthenticationError:
            return {"status": "error", "message": "Authentication failed — check username and password"}
        except smtplib.SMTPConnectError:
            return {"status": "error", "message": f"Could not connect to {smtp_host}:{smtp_port}"}
        except TimeoutError:
            return {"status": "error", "message": f"Connection timed out to {smtp_host}:{smtp_port}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    return await asyncio.to_thread(_test)


def build_test_email_html(platform_name: str = "GuardNous") -> str:
    """Build a styled test email body matching the app's blue/indigo theme."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f1f5f9; padding: 40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width: 560px; width: 100%;">

        <!-- Header -->
        <tr><td style="background: linear-gradient(135deg, #f97316, #ea580c); border-radius: 12px 12px 0 0; padding: 28px 32px; text-align: center;">
          <h1 style="margin: 0; font-size: 22px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px;">{platform_name}</h1>
          <p style="margin: 6px 0 0; font-size: 13px; color: rgba(255,255,255,0.85); font-weight: 400;">Cloud Security Posture Management</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color: #ffffff; padding: 32px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0;">

          <!-- Status badge -->
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
            <tr><td style="background-color: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 6px; padding: 8px 14px;">
              <span style="color: #065f46; font-size: 13px; font-weight: 600;">SMTP Configuration Verified</span>
            </td></tr>
          </table>

          <h2 style="margin: 0 0 12px; font-size: 18px; font-weight: 600; color: #1e293b;">Email Notifications Active</h2>
          <p style="margin: 0 0 16px; font-size: 14px; line-height: 1.7; color: #475569;">
            This is a test email from <strong style="color: #1e293b;">{platform_name}</strong>. Your SMTP configuration is working correctly.
          </p>
          <p style="margin: 0 0 24px; font-size: 14px; line-height: 1.7; color: #475569;">
            You will now receive the following notifications at this address:
          </p>

          <!-- Notification types -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 24px;">
            <tr><td style="padding: 10px 14px; background-color: #fff7ed; border-left: 3px solid #f97316;">
              <span style="font-size: 13px; color: #334155; font-weight: 500;">Security scan results and alerts</span>
            </td></tr>
            <tr><td style="height: 4px;"></td></tr>
            <tr><td style="padding: 10px 14px; background-color: #fff7ed; border-left: 3px solid #ea580c;">
              <span style="font-size: 13px; color: #334155; font-weight: 500;">Compliance reports and policy violations</span>
            </td></tr>
            <tr><td style="height: 4px;"></td></tr>
            <tr><td style="padding: 10px 14px; background-color: #fff7ed; border-left: 3px solid #c2410c;">
              <span style="font-size: 13px; color: #334155; font-weight: 500;">Incident investigation summaries</span>
            </td></tr>
          </table>

          <p style="margin: 0; font-size: 13px; color: #94a3b8; line-height: 1.6;">
            You can manage notification preferences in Settings &gt; Notifications.
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; padding: 20px 32px; text-align: center;">
          <p style="margin: 0; font-size: 12px; color: #94a3b8; line-height: 1.5;">
            {platform_name} &middot; Cloud Security Posture Management
          </p>
          <p style="margin: 6px 0 0; font-size: 11px; color: #cbd5e1;">
            This is an automated test email. No action is required.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_report_email_html(
    *,
    report_title: str,
    report_type: str,
    generated_at: str,
    total_findings: int,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    risk_score: int = 0,
    platform_name: str = "GuardNous",
) -> str:
    """Build a branded email body for report delivery with PDF attachment."""
    score_color = "#ef4444" if risk_score >= 70 else "#f59e0b" if risk_score >= 40 else "#22c55e"
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">{platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">Security Report Delivery</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <h2 style="margin:0 0 6px;font-size:18px;font-weight:600;color:#1e293b;">{report_title}</h2>
          <p style="margin:0 0 20px;font-size:13px;color:#94a3b8;">Type: {report_type} &middot; Generated: {generated_at}</p>

          <!-- Risk score -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center;">
              <span style="font-size:36px;font-weight:700;color:{score_color};">{risk_score}</span>
              <span style="font-size:18px;color:#94a3b8;">/100</span>
              <p style="margin:4px 0 0;font-size:13px;color:#64748b;">Risk Score</p>
            </td></tr>
          </table>

          <!-- Severity boxes -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr>
              <td width="25%" style="padding:0 4px 0 0;">
                <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px;text-align:center;">
                  <div style="font-size:24px;font-weight:700;color:#dc2626;">{critical}</div>
                  <div style="font-size:11px;color:#991b1b;text-transform:uppercase;font-weight:600;">Critical</div>
                </div>
              </td>
              <td width="25%" style="padding:0 4px;">
                <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:12px;text-align:center;">
                  <div style="font-size:24px;font-weight:700;color:#ea580c;">{high}</div>
                  <div style="font-size:11px;color:#9a3412;text-transform:uppercase;font-weight:600;">High</div>
                </div>
              </td>
              <td width="25%" style="padding:0 4px;">
                <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px;text-align:center;">
                  <div style="font-size:24px;font-weight:700;color:#d97706;">{medium}</div>
                  <div style="font-size:11px;color:#92400e;text-transform:uppercase;font-weight:600;">Medium</div>
                </div>
              </td>
              <td width="25%" style="padding:0 0 0 4px;">
                <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px;text-align:center;">
                  <div style="font-size:24px;font-weight:700;color:#2563eb;">{low}</div>
                  <div style="font-size:11px;color:#1e40af;text-transform:uppercase;font-weight:600;">Low</div>
                </div>
              </td>
            </tr>
          </table>

          <p style="margin:0 0 8px;font-size:14px;color:#475569;">
            <strong>{total_findings}</strong> open findings across your infrastructure.
          </p>
          <p style="margin:0 0 20px;font-size:13px;color:#94a3b8;">
            The full report is attached as a PDF. Review the findings and take action on critical items.
          </p>

          <!-- CTA -->
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
            <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:8px;padding:12px 28px;">
              <span style="font-size:14px;font-weight:600;color:#fff;">📎 PDF Report Attached</span>
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">{platform_name} &middot; Cloud Security Posture Management</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">This report was generated automatically. Manage schedules in Settings.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_invitation_email_html(
    *,
    invite_url: str,
    invitee_email: str,
    inviter_name: str,
    role: str = "viewer",
    org_name: str = "",
    expires_days: int = 7,
    platform_name: str = "GuardNous",
) -> str:
    """Build a branded invitation email matching the GuardNous orange theme."""
    org_line = f" to <strong>{org_name}</strong>" if org_name else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">🛡️ {platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">You&rsquo;ve Been Invited</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1e293b;line-height:1.6;">
            Hi there! 👋
          </p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            <strong>{inviter_name}</strong> has invited you{org_line} as a
            <span style="background:#fff7ed;color:#ea580c;padding:2px 8px;border-radius:4px;font-weight:600;font-size:13px;">{role}</span>
            on {platform_name} &mdash; an enterprise cloud security &amp; IaC posture management platform.
          </p>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="{invite_url}" target="_blank"
                 style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 40px;border-radius:10px;letter-spacing:0.3px;">
                Accept Invitation &rarr;
              </a>
            </td></tr>
          </table>

          <p style="margin:20px 0 0;font-size:13px;color:#94a3b8;line-height:1.5;">
            Or copy and paste this link into your browser:<br>
            <a href="{invite_url}" style="color:#f97316;word-break:break-all;">{invite_url}</a>
          </p>

          <!-- Expiry -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:24px;">
            <tr><td style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;">
              <p style="margin:0;font-size:13px;color:#92400e;">
                ⏳ This invitation expires in <strong>{expires_days} days</strong>. After that, your admin will need to send a new one.
              </p>
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">Sent by {platform_name} &middot; Cloud Security Platform</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">If you didn&rsquo;t expect this invitation, you can safely ignore this email.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_password_reset_email_html(
    *,
    user_name: str,
    reset_url: str,
    platform_name: str = "GuardNous",
) -> str:
    """Branded HTML email for password reset."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">🛡️ {platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">Password Reset Request</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1e293b;line-height:1.6;">
            Hi {user_name},
          </p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            We received a request to reset your password. Click the button below to create a new password. This link expires in 1 hour.
          </p>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="{reset_url}" target="_blank"
                 style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 40px;border-radius:10px;letter-spacing:0.3px;">
                Reset Password &rarr;
              </a>
            </td></tr>
          </table>

          <p style="margin:20px 0 0;font-size:13px;color:#94a3b8;line-height:1.5;">
            If you didn't request this, you can safely ignore this email. Your password will remain unchanged.
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">Sent by {platform_name} &middot; Cloud Security Platform</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">You received this because a password reset was requested for your account.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def send_password_reset_email(
    *,
    to_email: str,
    user_name: str,
    reset_url: str,
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send password reset email. Gracefully skips if SMTP not configured."""
    params = _resolve_smtp_params(smtp_config)
    if not params:
        logger.info("SMTP not configured — skipping password reset email for %s", to_email)
        return {"status": "skipped", "message": "SMTP not configured"}

    from app.core.config import settings
    platform_name = getattr(settings, "APP_NAME", "GuardNous")
    html = build_password_reset_email_html(
        user_name=user_name,
        reset_url=reset_url,
        platform_name=platform_name,
    )
    try:
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"Reset your password — {platform_name}",
            html_body=html,
            text_body=f"Hi {user_name}, reset your password: {reset_url} (expires in 1 hour)",
        )
        return result
    except Exception as e:
        logger.warning("Failed to send password reset email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


async def send_invitation_email(
    *,
    to_email: str,
    invite_url: str,
    inviter_name: str,
    role: str = "viewer",
    org_name: str = "",
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send a branded invitation email. Returns {status, message}.

    ``smtp_config`` may contain keys: host, port, user, password, use_tls,
    from_email, from_name.  When provided, these override the global env-var
    settings.  This allows callers to pass DB-stored SMTP configuration
    (from organization_settings) so emails work even when env vars are empty.
    """
    params = _resolve_smtp_params(smtp_config)
    if not params:
        return {"status": "skipped", "message": "SMTP not configured — share the link manually"}

    html = build_invitation_email_html(
        invite_url=invite_url,
        invitee_email=to_email,
        inviter_name=inviter_name,
        role=role,
        org_name=org_name,
    )
    try:
        from app.core.config import settings
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"You're invited to {settings.APP_NAME if hasattr(settings, 'APP_NAME') else 'GuardNous'}",
            html_body=html,
            text_body=f"{inviter_name} has invited you as a {role}. Accept here: {invite_url}",
        )
        return result
    except Exception as e:
        logger.warning("Failed to send invitation email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


def build_welcome_email_html(
    *,
    user_name: str,
    org_name: str,
    login_url: str,
    platform_name: str = "GuardNous",
) -> str:
    """Build a branded welcome email for new organization creators."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">🛡️ {platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">Welcome to Your Security Platform</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1e293b;line-height:1.6;">
            Hi {user_name}! 🎉
          </p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            Your organization <strong>{org_name}</strong> has been created on {platform_name}.
            You&rsquo;re set up as the <span style="background:#fff7ed;color:#ea580c;padding:2px 8px;border-radius:4px;font-weight:600;font-size:13px;">Platform Admin</span>.
          </p>

          <p style="margin:0 0 16px;font-size:14px;color:#475569;font-weight:600;">Here&rsquo;s what you can do next:</p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr><td style="padding:6px 0;font-size:14px;color:#475569;">✅ Connect cloud integrations (AWS, Azure, GCP)</td></tr>
            <tr><td style="padding:6px 0;font-size:14px;color:#475569;">✅ Run your first security scan</td></tr>
            <tr><td style="padding:6px 0;font-size:14px;color:#475569;">✅ Invite team members from Admin &rarr; Users</td></tr>
            <tr><td style="padding:6px 0;font-size:14px;color:#475569;">✅ Enable 2FA for enterprise security</td></tr>
            <tr><td style="padding:6px 0;font-size:14px;color:#475569;">✅ Configure AI Copilot for remediation guidance</td></tr>
          </table>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="{login_url}" target="_blank"
                 style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 40px;border-radius:10px;letter-spacing:0.3px;">
                Go to Dashboard &rarr;
              </a>
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">Sent by {platform_name} &middot; Cloud Security Platform</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">You received this because you created an organization on {platform_name}.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def send_welcome_email(
    *,
    to_email: str,
    user_name: str,
    org_name: str,
    login_url: str = "",
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send a branded welcome email to a new org creator.
    Returns {status, message}. Gracefully skips if SMTP is not configured."""
    from app.core.config import settings

    params = _resolve_smtp_params(smtp_config)
    if not params:
        logger.info("SMTP not configured — skipping welcome email for %s", to_email)
        return {"status": "skipped", "message": "SMTP not configured"}

    if not login_url:
        login_url = f"{settings.FRONTEND_URL}/login"

    platform_name = getattr(settings, "APP_NAME", "GuardNous")
    html = build_welcome_email_html(
        user_name=user_name,
        org_name=org_name,
        login_url=login_url,
        platform_name=platform_name,
    )
    try:
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"Welcome to {platform_name} — Your organization is ready!",
            html_body=html,
            text_body=f"Hi {user_name}, your organization '{org_name}' has been created on {platform_name}. Log in at {login_url}",
        )
        return result
    except Exception as e:
        logger.warning("Failed to send welcome email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


# ─── Account Created + Email Verification ────────────────────────────

def build_account_created_email_html(
    *,
    user_name: str,
    org_name: str,
    role: str,
    verify_url: str,
    platform_name: str = "GuardNous",
) -> str:
    """Branded email sent to users after their account is created (invitation acceptance)."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">🛡️ {platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">Account Created Successfully</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1e293b;line-height:1.6;">
            Hi {user_name}! 👋
          </p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            Your account has been created on <strong>{platform_name}</strong> under the
            <strong>{org_name}</strong> organization. You've been assigned the
            <span style="background:#fff7ed;color:#ea580c;padding:2px 8px;border-radius:4px;font-weight:600;font-size:13px;">{role}</span> role.
          </p>

          <p style="margin:0 0 16px;font-size:14px;color:#475569;line-height:1.6;">
            Please verify your email address by clicking the button below. This link expires in <strong>24 hours</strong>.
          </p>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="{verify_url}" target="_blank"
                 style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 40px;border-radius:10px;letter-spacing:0.3px;">
                ✅ Verify My Email &rarr;
              </a>
            </td></tr>
          </table>

          <p style="margin:16px 0 0;font-size:12px;color:#94a3b8;line-height:1.5;">
            If you didn't create this account, you can safely ignore this email.<br>
            Or copy this link: <a href="{verify_url}" style="color:#f97316;word-break:break-all;">{verify_url}</a>
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">Sent by {platform_name} &middot; Cloud Security Platform</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">You received this because an account was created for you on {platform_name}.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def send_account_created_email(
    *,
    to_email: str,
    user_name: str,
    org_name: str,
    role: str,
    verify_url: str,
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send account-created + email-verification email. Gracefully skips if SMTP not configured."""
    params = _resolve_smtp_params(smtp_config)
    if not params:
        logger.info("SMTP not configured — skipping account-created email for %s", to_email)
        return {"status": "skipped", "message": "SMTP not configured"}

    from app.core.config import settings
    platform_name = getattr(settings, "APP_NAME", "GuardNous")
    html = build_account_created_email_html(
        user_name=user_name,
        org_name=org_name,
        role=role,
        verify_url=verify_url,
        platform_name=platform_name,
    )
    try:
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"Verify your email — {platform_name}",
            html_body=html,
            text_body=f"Hi {user_name}, your account on {platform_name} ({org_name}) is ready. Verify your email: {verify_url}",
        )
        return result
    except Exception as e:
        logger.warning("Failed to send account-created email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


# ─── Tenant Created Notification ─────────────────────────────────────

def build_tenant_created_email_html(
    *,
    admin_name: str,
    tenant_name: str,
    tenant_plan: str,
    login_url: str,
    platform_name: str = "GuardNous",
) -> str:
    """Branded email sent to the admin who created a new tenant."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#f97316,#ea580c);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;font-weight:700;color:#fff;letter-spacing:0.5px;">🛡️ {platform_name}</h1>
          <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.85);">New Tenant Created</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:#fff;padding:32px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">
          <p style="margin:0 0 16px;font-size:15px;color:#1e293b;line-height:1.6;">
            Hi {admin_name}! 🏢
          </p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            A new tenant has been successfully created on {platform_name}.
          </p>

          <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:20px;width:100%;">
            <tr>
              <td style="padding:10px 16px;font-size:13px;color:#64748b;border-bottom:1px solid #f1f5f9;width:120px;font-weight:600;">Tenant Name</td>
              <td style="padding:10px 16px;font-size:14px;color:#1e293b;border-bottom:1px solid #f1f5f9;font-weight:600;">{tenant_name}</td>
            </tr>
            <tr>
              <td style="padding:10px 16px;font-size:13px;color:#64748b;border-bottom:1px solid #f1f5f9;font-weight:600;">Plan</td>
              <td style="padding:10px 16px;font-size:14px;color:#1e293b;border-bottom:1px solid #f1f5f9;">
                <span style="background:#fff7ed;color:#ea580c;padding:2px 8px;border-radius:4px;font-weight:600;font-size:13px;">{tenant_plan}</span>
              </td>
            </tr>
          </table>

          <p style="margin:0 0 16px;font-size:14px;color:#475569;line-height:1.6;">
            You can now invite users, create organizations, and configure settings for this tenant.
          </p>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="{login_url}" target="_blank"
                 style="display:inline-block;background:linear-gradient(135deg,#f97316,#ea580c);color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:14px 40px;border-radius:10px;letter-spacing:0.3px;">
                Manage Tenant &rarr;
              </a>
            </td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">Sent by {platform_name} &middot; Cloud Security Platform</p>
          <p style="margin:6px 0 0;font-size:11px;color:#cbd5e1;">You received this because you created a tenant on {platform_name}.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def send_tenant_created_email(
    *,
    to_email: str,
    admin_name: str,
    tenant_name: str,
    tenant_plan: str = "free",
    login_url: str = "",
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send tenant-created notification email. Gracefully skips if SMTP not configured."""
    from app.core.config import settings

    params = _resolve_smtp_params(smtp_config)
    if not params:
        logger.info("SMTP not configured — skipping tenant-created email for %s", to_email)
        return {"status": "skipped", "message": "SMTP not configured"}

    if not login_url:
        login_url = f"{settings.FRONTEND_URL}/admin/tenants"

    platform_name = getattr(settings, "APP_NAME", "GuardNous")
    html = build_tenant_created_email_html(
        admin_name=admin_name,
        tenant_name=tenant_name,
        tenant_plan=tenant_plan,
        login_url=login_url,
        platform_name=platform_name,
    )
    try:
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"Tenant '{tenant_name}' created — {platform_name}",
            html_body=html,
            text_body=f"Hi {admin_name}, tenant '{tenant_name}' ({tenant_plan} plan) has been created on {platform_name}. Manage it at {login_url}",
        )
        return result
    except Exception as e:
        logger.warning("Failed to send tenant-created email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


async def send_org_assignment_email(
    to_email: str,
    user_name: str,
    org_name: str,
    role: str = "member",
    added_by_name: str = "an administrator",
    smtp_config: Optional[dict] = None,
):
    """Notify a user they've been added to an organization."""
    params = _resolve_smtp_params(smtp_config)
    if not params:
        logger.info("SMTP not configured — skipping org assignment email for %s", to_email)
        return {"status": "skipped", "message": "SMTP not configured"}

    try:
        platform_name = "GuardNous"
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <div style="background:linear-gradient(135deg,#f97316,#ea580c);padding:30px;text-align:center;border-radius:12px 12px 0 0">
                <h1 style="color:#fff;margin:0;font-size:24px">🔗 {platform_name}</h1>
            </div>
            <div style="background:#fff;padding:30px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px">
                <h2 style="color:#111827;margin-top:0">Organization Assignment</h2>
                <p style="color:#374151">Hi {user_name},</p>
                <p style="color:#374151">You have been added to <strong>{org_name}</strong> as a <strong>{role}</strong> by {added_by_name}.</p>
                <p style="color:#374151">You can switch to this organization from your dashboard at any time.</p>
                <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0"/>
                <p style="color:#9ca3af;font-size:12px">This is an automated notification from {platform_name}.</p>
            </div>
        </div>
        """
        return await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"You've been added to {org_name} — {platform_name}",
            html_body=html,
            text_body=f"Hi {user_name}, you've been added to {org_name} as {role} by {added_by_name}.",
        )
    except Exception as e:
        logger.warning("Failed to send org assignment email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}


async def send_org_invite_email(
    to_email: str,
    org_name: str,
    inviter_name: str,
    invite_link: str,
    role: str = "member",
    smtp_config: Optional[dict] = None,
) -> dict:
    """Send an organization invitation email with a join link.

    Unlike ``send_invitation_email`` (which is for platform sign-up invites),
    this targets users being invited to join a specific organization.
    """
    params = _resolve_smtp_params(smtp_config)
    if not params:
        return {"status": "skipped", "message": "SMTP not configured — share the link manually"}

    platform_name = "GuardNous"
    html = f"""<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f9fafb">
<div style="max-width:600px;margin:0 auto;padding:20px">
  <div style="background:linear-gradient(135deg,#f97316,#ea580c);padding:30px;text-align:center;border-radius:12px 12px 0 0">
    <h1 style="color:#fff;margin:0;font-size:24px">🛡️ {platform_name}</h1>
  </div>
  <div style="background:#fff;padding:30px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px">
    <h2 style="color:#111827;margin-top:0">You're Invited!</h2>
    <p style="color:#374151"><strong>{inviter_name}</strong> has invited you to join
       <strong>{org_name}</strong> as a <strong>{role}</strong>.</p>
    <p style="color:#374151">Click below to accept the invitation and get started:</p>
    <div style="text-align:center;margin:24px 0">
      <a href="{invite_link}"
         style="background:#f97316;color:#fff;padding:12px 32px;border-radius:8px;
                text-decoration:none;font-weight:600;display:inline-block">
        Join {org_name}
      </a>
    </div>
    <p style="color:#6b7280;font-size:13px">Or copy this link: {invite_link}</p>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0"/>
    <p style="color:#9ca3af;font-size:12px">
      This invitation was sent by {inviter_name} via {platform_name}.
      If you weren't expecting this, you can safely ignore it.
    </p>
  </div>
</div>
</body>
</html>"""

    try:
        result = await send_email(
            smtp_host=params["host"],
            smtp_port=params["port"],
            smtp_user=params["user"],
            smtp_password=params["password"],
            smtp_use_tls=params["use_tls"],
            from_email=params["from_email"],
            from_name=params["from_name"],
            to_email=to_email,
            subject=f"{inviter_name} invited you to {org_name} — {platform_name}",
            html_body=html,
            text_body=(
                f"{inviter_name} has invited you to join {org_name} as a {role}. "
                f"Accept here: {invite_link}"
            ),
        )
        return result
    except Exception as e:
        logger.warning("Failed to send org invite email to %s: %s", to_email, e)
        return {"status": "error", "message": str(e)}
