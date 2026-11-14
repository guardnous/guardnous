"""Chat tool that turns an answer into a PDF the user can download."""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select

from app.models.agent import AgentMessage, ChatFile
from app.models.organization import Organization
from app.models.user import User
from app.services.agents.pdf_export import markdown_to_pdf, safe_filename

MAX_REPORT_CHARS = 200_000


async def render_pdf_file(db, *, organization_id: int, user_id: int | None, message_id: int | None,
                          title: str, markdown: str) -> ChatFile:
    """Render ``markdown`` to PDF and store it as a download on ``message_id``."""
    organization = await db.get(Organization, organization_id)
    user = await db.get(User, user_id) if user_id else None
    pdf = await asyncio.to_thread(
        markdown_to_pdf, title, markdown[:MAX_REPORT_CHARS],
        organization=getattr(organization, "name", "") or "", author=getattr(user, "email", "") or "",
    )
    record = ChatFile(
        organization_id=organization_id, user_id=user_id, message_id=message_id, kind="generated",
        filename=safe_filename(title), content_type="application/pdf", size_bytes=len(pdf), data=pdf,
    )
    db.add(record)
    await db.flush()
    return record


async def export_pdf_report(ctx, title: str = "", content: str = "", **_: Any) -> dict:
    message_id, conversation_id = ctx.meta.get("message_id"), ctx.meta.get("conversation_id")
    if not message_id:
        return {"error": "A PDF can be created from the chat only."}

    content = (content or "").strip()
    if not content:                      # "send me that as a PDF": use the last answer in this conversation
        content = (await ctx.db.execute(
            select(AgentMessage.content).where(
                AgentMessage.conversation_id == conversation_id, AgentMessage.role == "assistant",
                AgentMessage.status == "completed", AgentMessage.id < message_id, AgentMessage.content != "",
            ).order_by(AgentMessage.id.desc()).limit(1)
        )).scalar_one_or_none() or ""
        if not content.strip():
            return {"error": "There is no earlier answer to export. Pass the report text in `content`."}

    record = await render_pdf_file(
        ctx.db, organization_id=ctx.organization_id, user_id=ctx.meta.get("user_id"), message_id=message_id,
        title=(title or "GuardNous report").strip()[:150], markdown=content,
    )
    await ctx.db.commit()
    return {
        "created": True, "file_id": record.id, "filename": record.filename, "size_bytes": record.size_bytes,
        "note": "The PDF is attached to your reply as a download button; do not write a link or a URL. "
                "Still answer the user's question in the chat: the short answer if they asked for one, otherwise "
                "the key points in a few sentences. Then say that the PDF is attached. Do not paste the whole "
                "document again.",
    }


EXECUTORS = {"export_pdf_report": export_pdf_report}

SCHEMAS = [{"type": "function", "function": {
    "name": "export_pdf_report",
    "description": (
        "Create a PDF document and attach it to your reply for the user to download. Use it whenever the user asks "
        "for a PDF, a document, a downloadable report, or to export an answer. Gather the data with other tools "
        "first, then pass the finished report as Markdown in `content`. To export your previous answer unchanged, "
        "leave `content` empty."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Document title, e.g. 'Cloud security posture report'"},
            "content": {"type": "string", "description": "The full report in Markdown: headings, paragraphs, lists, tables. "
                                                          "Leave empty to export your previous answer."},
        },
        "required": ["title"],
        "additionalProperties": False,
    },
}}]
