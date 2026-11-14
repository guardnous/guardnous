"""
Enterprise Notification Dispatcher — sends scan completion notifications
via webhook, Slack, and email channels.

Supports multiple notification targets per organization. Gracefully degrades
when targets are unreachable (logs warning, continues).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """Dispatches scan completion/failure notifications to configured targets."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def dispatch(
        self,
        scan_id: int,
        repository: str,
        account: str,
        status: str,
        severity_counts: dict,
        stage_details: dict | None = None,
        webhook_urls: list[str] | None = None,
        slack_webhook_url: str | None = None,
        email_targets: list[str] | None = None,
    ) -> dict:
        """
        Send notifications to all configured channels.
        Returns dict with delivery results per channel.
        """
        payload = self._build_payload(
            scan_id, repository, account, status, severity_counts, stage_details
        )

        results: dict[str, Any] = {
            "channels_attempted": 0,
            "channels_succeeded": 0,
            "channels_failed": 0,
            "details": [],
        }

        # Webhooks
        for url in (webhook_urls or []):
            results["channels_attempted"] += 1
            success = self._send_webhook(url, payload)
            if success:
                results["channels_succeeded"] += 1
                results["details"].append({"channel": "webhook", "target": url[:50], "success": True})
            else:
                results["channels_failed"] += 1
                results["details"].append({"channel": "webhook", "target": url[:50], "success": False})

        # Slack
        if slack_webhook_url:
            results["channels_attempted"] += 1
            success = self._send_slack(slack_webhook_url, payload)
            if success:
                results["channels_succeeded"] += 1
                results["details"].append({"channel": "slack", "success": True})
            else:
                results["channels_failed"] += 1
                results["details"].append({"channel": "slack", "success": False})

        # Email is delivered by scan_notify.notify_scan_complete, which has the
        # organization's SMTP settings. It is not sent from here.
        for email in (email_targets or []):
            results["channels_attempted"] += 1
            results["channels_failed"] += 1
            results["details"].append({
                "channel": "email", "target": email, "success": False,
                "note": "email is not delivered by this dispatcher",
            })

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        scan_id: int,
        repository: str,
        account: str,
        status: str,
        severity_counts: dict,
        stage_details: dict | None,
    ) -> dict:
        total_findings = sum(severity_counts.get(k, 0) for k in ["critical", "high", "medium", "low"])
        emoji = "✅" if status == "completed" and total_findings == 0 else (
            "⚠️" if status == "completed" else "❌"
        )
        return {
            "event": "scan_completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "account": account,
            "repository": repository,
            "status": status,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "summary": f"{emoji} GuardNous scan #{scan_id} on {account}/{repository}: "
                       f"{status} — {total_findings} findings",
            "stage_details": stage_details,
        }

    def _send_webhook(self, url: str, payload: dict) -> bool:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Webhook delivery failed for %s: %s", url[:50], exc)
            return False

    def _send_slack(self, webhook_url: str, payload: dict) -> bool:
        slack_msg = {
            "text": payload["summary"],
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "GuardNous Scan Result"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n{payload['account']}/{payload['repository']}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{payload['status']}"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{payload['total_findings']}"},
                    {"type": "mrkdwn", "text": f"*Critical:* {payload['severity_counts'].get('critical', 0)} | "
                                               f"*High:* {payload['severity_counts'].get('high', 0)}"},
                ]},
            ],
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(webhook_url, json=slack_msg)
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("Slack delivery failed: %s", exc)
            return False
