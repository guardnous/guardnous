import asyncio
import json
import logging

import re

from fastapi import APIRouter, Body, Depends, File, HTTPException, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import StreamingResponse

from app.core.config import settings
from app.core.database import get_db
from app.core.encryption import encrypt_token
from app.core.rbac import require_permission
from app.models.agent import AgentConversation, AgentMessage, AgentInsight, ChatFile
from app.models.organization import Organization
from app.schemas.agent import ChatFileResponse
from app.services.agents.attachments import (
    ACCEPT, MAX_FILE_BYTES, MAX_FILES_PER_MESSAGE, SUPPORTED, UnsupportedFile, extract_text, history_with_attachments,
    redact_sensitive,
)
from app.services.agents.pdf_export import markdown_to_pdf, safe_filename
from app.models.finding import Finding
from app.models.llm_config import LLMConfig
from app.models.scan import Scan
from app.models.user import User
from app.schemas.agent import (
    AgentInfo, AgentStatus,
    AutoFixRequest, AutoFixResponse, AutoFixResultItem,
    AutoTriageRequest, AutoTriageResponse, AutoTriageResultItem,
    ChatHistoryResponse, ChatHistoryMessage,
    ChatRequest, ChatResponse, ConversationDetail, ConversationSummary,
    InsightResponse, KnowledgeStatsResponse,
    LLMConfigResponse, LLMConfigUpdate, LLMTestResult, ProviderInfo,
    RemediationResponse, SkillExecutionRequest, SkillExecutionResponse,
    SkillManifestItem, SkillPlanRequest, SkillPlanResponse, TriageRequest, TriageResponse,
)
from app.services.agents.config import (
    PROVIDER_IDS, SUPPORTED_PROVIDERS, get_org_config, resolve_llm_settings, settings_from_config,
)
from app.services.agents.llm import LLMClient, LLMSettings
from app.services.agents.orchestrator import run_agent
from app.services.agents.remediation import generate_remediation
from app.services.agents.skills import build_skill_plan, build_skill_registry, execute_skill, skill_manifest
from app.services.agents.tools import ToolContext
from app.services.agents.triage import triage_findings
from app.services.agents.triage_tools import test_path_hint
from app.services.triage_memory import decide

logger = logging.getLogger(__name__)

router = APIRouter()


async def _provider_info(db: AsyncSession, org_id: int) -> ProviderInfo:
    return ProviderInfo(**LLMClient(await resolve_llm_settings(db, org_id)).info())


@router.get("/status", response_model=AgentStatus)
async def agent_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    return AgentStatus(
        enabled=settings.AGENT_ENABLED,
        provider=await _provider_info(db, current_user.organization_id),
    )


@router.get("/", response_model=list[AgentInfo])
async def list_agents(
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Return available AI agents from the registry."""
    from app.services.agents.registry import list_agents as registry_list

    agents = []
    for a in registry_list():
        agents.append(AgentInfo(
            id=a["id"],
            name=a["name"],
            description=a["description"],
            avatar=a.get("icon", "🤖"),
            capabilities=[],
            status="available" if settings.AGENT_ENABLED else "disabled",
        ))
    return agents


@router.get("/manifest")
async def agent_manifest(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Return the full agent catalog for the UI."""
    from app.services.agents.registry import list_agents as registry_list
    from app.services.agents.registry import AGENTS

    return [{
        "id": a["id"],
        "name": a["name"],
        "description": a["description"],
        "icon": a.get("icon", "🤖"),
        "tags": a.get("tags", []),
        "can_delegate": a.get("can_delegate", False),
        "tool_count": len(AGENTS[a["id"]].tool_whitelist) if a["id"] in AGENTS and AGENTS[a["id"]].tool_whitelist else 0,
    } for a in registry_list()]


@router.get("/skills", response_model=list[SkillManifestItem])
async def list_skills(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    return [SkillManifestItem(**item) for item in skill_manifest()]


@router.post("/skills/plan", response_model=SkillPlanResponse)
async def plan_skill(
    body: SkillPlanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    plan = build_skill_plan(body.message, body.params)
    return SkillPlanResponse(**plan)


@router.post("/skills/{skill_name}/execute", response_model=SkillExecutionResponse)
async def execute_skill_endpoint(
    skill_name: str,
    body: SkillExecutionRequest = Body(default_factory=SkillExecutionRequest),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")

    registry = build_skill_registry()
    skill = registry.get(skill_name)
    if skill is None:
        raise HTTPException(status_code=404, detail=f"Unknown skill: {skill_name}")
    if skill.requires_approval:
        raise HTTPException(status_code=403, detail=f"Skill '{skill_name}' requires approval before execution")

    ctx = ToolContext(db=db, organization_id=current_user.organization_id)
    result = await execute_skill(ctx, skill_name, **(body.params or {}))
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return SkillExecutionResponse(skill=skill_name, status="ok", result=result)


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    if not body.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Resolve or create the conversation (org-scoped).
    conversation = None
    if body.conversation_id:
        conversation = (await db.execute(
            select(AgentConversation).where(
                AgentConversation.id == body.conversation_id,
                AgentConversation.organization_id == current_user.organization_id,
                AgentConversation.user_id == current_user.id,
            )
        )).scalar_one_or_none()
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
    if conversation is None:
        conversation = AgentConversation(
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            title=body.message[:60],
        )
        db.add(conversation)
        await db.flush()

    # Build history from persisted messages.
    prior = (await db.execute(
        select(AgentMessage).where(AgentMessage.conversation_id == conversation.id)
        .order_by(AgentMessage.id)
    )).scalars().all()
    history = [{"role": m.role, "content": m.content or ""} for m in prior]
    history.append({"role": "user", "content": body.message})

    db.add(AgentMessage(conversation_id=conversation.id, role="user", content=body.message))

    result = await run_agent(
        db, current_user.organization_id, history,
        agent_id=body.agent_id if hasattr(body, "agent_id") else None,
        user_id=current_user.id,
    )

    db.add(AgentMessage(
        conversation_id=conversation.id, role="assistant",
        content=result["content"], tool_trace=result["tool_trace"],
    ))
    await db.flush()

    return ChatResponse(
        conversation_id=conversation.id,
        message=result["content"],
        tool_trace=result["tool_trace"],
        provider=ProviderInfo(**result["provider"]),
    )


@router.post("/chat/stream")
async def chat_stream(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    """ChatGPT-like direct SSE streaming.

    1. Saves user message + assistant placeholder to DB
    2. Returns SSE stream directly (first event = meta with IDs)
    3. Tokens flow: LLM → orchestrator → SSE → client (one connection)
    4. DB is saved progressively as a side-effect
    5. If client disconnects, background asyncio.Task continues and saves to DB
    """
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    org_id = current_user.organization_id

    # Files uploaded for this message: the uploader's own, not yet used elsewhere.
    attachments: list[ChatFile] = []
    if body.attachment_ids:
        if len(body.attachment_ids) > MAX_FILES_PER_MESSAGE:
            raise HTTPException(status_code=400, detail=f"Attach at most {MAX_FILES_PER_MESSAGE} files to one message")
        attachments = list((await db.execute(
            select(ChatFile).where(
                ChatFile.id.in_(body.attachment_ids), ChatFile.organization_id == org_id,
                ChatFile.user_id == current_user.id, ChatFile.kind == "upload", ChatFile.message_id.is_(None),
            ).order_by(ChatFile.id)
        )).scalars().all())
        if len(attachments) != len(set(body.attachment_ids)):
            raise HTTPException(status_code=400, detail="An attached file was not found. Attach it again.")

    if not body.message.strip():
        if not attachments:
            raise HTTPException(status_code=400, detail="Message cannot be empty")
        body.message = "Read the attached file and tell me what it contains and what matters in it."

    # Resolve or create conversation
    conversation = None
    if body.conversation_id:
        conversation = (await db.execute(
            select(AgentConversation).where(
                AgentConversation.id == body.conversation_id,
                AgentConversation.organization_id == org_id,
                AgentConversation.user_id == current_user.id,
            )
        )).scalar_one_or_none()
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")
    if conversation is None:
        conversation = AgentConversation(
            organization_id=org_id,
            user_id=current_user.id,
            title=body.message[:60],
        )
        db.add(conversation)
        await db.flush()

    conv_id = conversation.id

    # Build history from prior messages; a message's attached files go with it.
    prior = (await db.execute(
        select(AgentMessage).where(
            AgentMessage.conversation_id == conv_id,
            AgentMessage.status == "completed",
        ).order_by(AgentMessage.id)
    )).scalars().all()
    history = history_with_attachments(
        [(m.role, m.content or "", m.files) for m in prior] + [("user", body.message, attachments)]
    )

    # Save user message
    user_msg = AgentMessage(
        conversation_id=conv_id, role="user", content=body.message, status="completed",
    )
    db.add(user_msg)
    await db.flush()
    user_msg_id = user_msg.id  # capture BEFORE commit (expire_on_commit=True wipes attrs)
    for attachment in attachments:
        attachment.message_id = user_msg_id

    # Create assistant placeholder (status=processing)
    assistant_msg = AgentMessage(
        conversation_id=conv_id, role="assistant", content="", status="processing",
    )
    db.add(assistant_msg)
    await db.flush()
    assistant_msg_id = assistant_msg.id

    await db.commit()

    # Detect supervisor mode
    user_message = body.message.strip()
    use_supervisor = False
    if user_message and len(user_message) > 80:
        multi_indicators = [
            "and also", "additionally", "compare", "comprehensive", "full analysis",
            "end to end", "everything about", "all aspects", "deep dive", "investigate",
        ]
        if any(ind in user_message.lower() for ind in multi_indicators):
            use_supervisor = True
    # Files are read and written by the single-agent path only.
    if attachments or re.search(r"\b(pdf|download|export)\b", user_message, re.IGNORECASE):
        use_supervisor = False

    # Queue bridges the background task to the SSE generator
    queue: asyncio.Queue = asyncio.Queue(maxsize=2000)

    # Launch background task — survives client disconnect
    asyncio.create_task(
        _process_chat_background(
            queue, assistant_msg_id, conv_id, org_id, history,
            body.agent_id if hasattr(body, "agent_id") else None,
            use_supervisor,
            user_id=current_user.id,
        )
    )

    async def _sse_generator():
        # First event: meta with IDs so frontend can track the message
        yield f"data: {json.dumps({'type': 'meta', 'message_id': assistant_msg_id, 'user_message_id': user_msg_id, 'conversation_id': conv_id})}\n\n"
        try:
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=180)
                if event is None:  # sentinel — stream complete
                    break
                yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            pass  # Client disconnected — background task continues saving to DB
        except asyncio.TimeoutError:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Response timeout', 'done': True})}\n\n"
        except GeneratorExit:
            pass  # Client disconnected

    return StreamingResponse(
        _sse_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


async def _process_chat_background(
    queue: asyncio.Queue,
    assistant_msg_id: int,
    conv_id: int,
    org_id: int,
    history: list[dict],
    agent_id: str | None,
    use_supervisor: bool,
    user_id: int | None = None,
):
    """Background task: runs orchestrator, pushes events to queue, saves to DB.

    This runs as an asyncio.Task in FastAPI's event loop. If the client
    disconnects, this task keeps running and saves the full response to DB.
    """
    import time as _time
    from app.core.database import async_session
    from app.services.agents.orchestrator import run_agent_stream
    from sqlalchemy import update as sa_update

    full_content: list[str] = []
    tool_trace: list[dict] = []
    last_flush = _time.monotonic()
    FLUSH_INTERVAL = 2.0

    async def _push(event: dict):
        """Push to queue if client is still reading; silently drop if not."""
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Client disconnected or not reading — content saved to DB

    async with async_session() as db:
        try:
            if use_supervisor:
                from app.services.agents.supervisor import run_supervised
                from app.services.agents.config import resolve_llm_settings
                llm_settings = await resolve_llm_settings(db, org_id)
                event_source = run_supervised(
                    db, organization_id=org_id, history=history,
                    llm_settings=llm_settings, conversation_id=conv_id,
                )
            else:
                event_source = run_agent_stream(
                    db, org_id, history, agent_id=agent_id, user_id=user_id,
                    chat={"conversation_id": conv_id, "message_id": assistant_msg_id},
                )

            async for event in event_source:
                etype = event.get("type", "")

                if etype == "routing":
                    await _push({
                        "type": "routing",
                        "agent_id": event.get("agent_id"),
                        "agent_name": event.get("agent_name"),
                        "confidence": event.get("confidence"),
                        "done": False,
                    })

                elif etype == "tool_start":
                    await _push({
                        "type": "tool_start",
                        "tool": event.get("tool"),
                        "step": event.get("step", 0),
                        "done": False,
                    })

                elif etype == "tool_result":
                    tool_trace.append({"tool": event.get("tool")})
                    await _push({
                        "type": "tool_result",
                        "tool": event.get("tool"),
                        "step": event.get("step", 0),
                        "done": False,
                    })

                elif etype == "token":
                    token = event.get("content", "")
                    full_content.append(token)
                    await _push({"token": token, "done": False})

                elif etype == "done":
                    made = (await db.execute(
                        select(ChatFile).where(ChatFile.message_id == assistant_msg_id).order_by(ChatFile.id)
                    )).scalars().all()
                    await _push({
                        "token": "",
                        "done": True,
                        "files": [ChatFileResponse.model_validate(f).model_dump() for f in made],
                        "conversation_id": conv_id,
                        "provider": event.get("provider", {}).get("provider", "mock"),
                        "model": event.get("provider", {}).get("model"),
                        "tool_trace": event.get("tool_trace", tool_trace),
                    })

                elif etype == "error":
                    await _push({
                        "type": "error",
                        "message": event.get("message", "Unknown error"),
                        "done": True,
                    })

                elif etype in (
                    "plan", "plan_update", "agent_spawn", "agent_thinking",
                    "agent_tool", "agent_finding", "agent_handoff",
                    "agent_complete", "progress", "synthesis",
                ):
                    payload = {k: v for k, v in event.items()}
                    payload["done"] = False
                    await _push(payload)

                # Periodic flush to DB (crash resilience)
                now = _time.monotonic()
                if now - last_flush >= FLUSH_INTERVAL:
                    content_so_far = "".join(full_content)
                    if content_so_far.strip():
                        await db.execute(
                            sa_update(AgentMessage)
                            .where(AgentMessage.id == assistant_msg_id)
                            .values(content=content_so_far, tool_trace=tool_trace)
                        )
                        await db.commit()
                    last_flush = now

        except Exception as exc:
            logger.exception("Chat processing error for message %s", assistant_msg_id)
            await db.execute(
                sa_update(AgentMessage)
                .where(AgentMessage.id == assistant_msg_id)
                .values(status="failed", content="An error occurred. Please try again.")
            )
            await db.commit()
            await _push({"type": "error", "message": str(exc), "done": True})
        else:
            # Final save — mark completed
            content = "".join(full_content)
            await db.execute(
                sa_update(AgentMessage)
                .where(AgentMessage.id == assistant_msg_id)
                .values(
                    content=content if content.strip() else "I wasn't able to generate a response. Please try again.",
                    tool_trace=tool_trace,
                    status="completed",
                )
            )
            await db.commit()
        finally:
            # Sentinel — tells the SSE generator to stop
            await _push(None)


@router.get("/chat/files/accepted")
async def chat_file_types(current_user: User = Depends(require_permission("agents", "read"))):
    """What the chat accepts as an attachment."""
    return {
        "accept": ACCEPT, "supported": SUPPORTED, "max_file_bytes": MAX_FILE_BYTES,
        "max_files_per_message": MAX_FILES_PER_MESSAGE,
    }


@router.post("/chat/files", response_model=ChatFileResponse, status_code=201)
async def upload_chat_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    """Attach a file to the next chat message. Its text is extracted now; the file itself is not kept."""
    data = await file.read(MAX_FILE_BYTES + 1)
    filename = (file.filename or "file").replace("\\", "/").rsplit("/", 1)[-1][:255]
    try:
        text, truncated = await run_in_threadpool(extract_text, filename, data)
    except UnsupportedFile as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    text, redactions = redact_sensitive(text)      # before anything is stored or sent to a model
    record = ChatFile(
        organization_id=current_user.organization_id, user_id=current_user.id, kind="upload", filename=filename,
        content_type=(file.content_type or "")[:120], size_bytes=len(data), text=text, truncated=truncated,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return {**ChatFileResponse.model_validate(record).model_dump(), "redactions": redactions}


def _pdf_response(filename: str, data: bytes) -> Response:
    return Response(
        content=data, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


@router.get("/chat/files/{file_id}/download")
async def download_chat_file(
    file_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Download a file the assistant produced in one of your conversations."""
    record = (await db.execute(
        select(ChatFile).where(
            ChatFile.id == file_id, ChatFile.organization_id == current_user.organization_id,
            ChatFile.user_id == current_user.id, ChatFile.kind == "generated",
        )
    )).scalar_one_or_none()
    if not record or not record.data:
        raise HTTPException(status_code=404, detail="File not found")
    return _pdf_response(record.filename, record.data)


@router.get("/messages/{message_id}/pdf")
async def message_as_pdf(
    message_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Any answer in your own conversations as a PDF document."""
    row = (await db.execute(
        select(AgentMessage, AgentConversation.title)
        .join(AgentConversation, AgentMessage.conversation_id == AgentConversation.id)
        .where(
            AgentMessage.id == message_id, AgentMessage.role == "assistant",
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,
        )
    )).first()
    if not row or not (row[0].content or "").strip():
        raise HTTPException(status_code=404, detail="Message not found")
    message, conversation_title = row
    heading = re.match(r"\s*#{1,3}\s+(.+)", message.content)
    title = (heading.group(1) if heading else conversation_title or "GuardNous answer").strip()[:150]
    organization = await db.get(Organization, current_user.organization_id)
    pdf = await run_in_threadpool(
        markdown_to_pdf, title, message.content,
        organization=getattr(organization, "name", "") or "", author=current_user.email,
    )
    return _pdf_response(safe_filename(title), pdf)


@router.get("/chat/progress/{message_id}")
async def chat_progress(
    message_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Reconnection endpoint — used when page reloads during processing.

    - If completed: replays content with typewriter chunking
    - If still processing: polls DB and streams new content as it appears
    """
    org_id = current_user.organization_id

    msg = (await db.execute(
        select(AgentMessage)
        .join(AgentConversation, AgentMessage.conversation_id == AgentConversation.id)
        .where(
            AgentMessage.id == message_id,
            AgentConversation.organization_id == org_id,
            AgentConversation.user_id == current_user.id,
        )
    )).scalar_one_or_none()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    if msg.status in ("completed", "failed"):
        # Replay with typewriter effect
        async def _replay():
            content = msg.content or ""
            CHUNK = 4
            for i in range(0, len(content), CHUNK):
                yield f"data: {json.dumps({'token': content[i:i+CHUNK], 'done': False})}\n\n"
                await asyncio.sleep(0.008)
            yield f"data: {json.dumps({'token': '', 'done': True, 'conversation_id': msg.conversation_id, 'provider': 'cached', 'tool_trace': msg.tool_trace or []})}\n\n"
        return StreamingResponse(
            _replay(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )

    # Still processing — poll DB for new content
    async def _poll_stream():
        from app.core.database import async_session as _sf
        last_len = 0
        # Send whatever content exists right now as catchup
        current = msg.content or ""
        if current:
            yield f"data: {json.dumps({'type': 'catchup', 'content': current})}\n\n"
            last_len = len(current)

        for _ in range(600):  # max 5 minutes (600 * 0.5s)
            await asyncio.sleep(0.5)
            async with _sf() as poll_db:
                check = (await poll_db.execute(
                    select(AgentMessage).where(AgentMessage.id == message_id)
                )).scalar_one_or_none()
                if not check:
                    break

                content = check.content or ""
                if len(content) > last_len:
                    new_chunk = content[last_len:]
                    yield f"data: {json.dumps({'token': new_chunk, 'done': False})}\n\n"
                    last_len = len(content)

                if check.status in ("completed", "failed"):
                    # Send any remaining content
                    remaining = (check.content or "")[last_len:]
                    if remaining:
                        yield f"data: {json.dumps({'token': remaining, 'done': False})}\n\n"
                    yield f"data: {json.dumps({'token': '', 'done': True, 'conversation_id': check.conversation_id, 'provider': 'cached', 'tool_trace': check.tool_trace or []})}\n\n"
                    break

    return StreamingResponse(
        _poll_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/chat/history", response_model=ChatHistoryResponse)
async def chat_history(
    limit: int = 50,
    conversation_id: int | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """Return the current user's own recent chat messages."""
    stmt = (
        select(AgentMessage)
        .join(AgentConversation, AgentMessage.conversation_id == AgentConversation.id)
        .where(
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,
        )
    )
    if conversation_id:
        stmt = stmt.where(AgentMessage.conversation_id == conversation_id)
    stmt = stmt.order_by(desc(AgentMessage.created_at)).limit(min(limit, 200))

    rows = (await db.execute(stmt)).scalars().all()
    messages = [
        ChatHistoryMessage(
            id=m.id,
            conversation_id=m.conversation_id,
            role=m.role,
            content=m.content,
            status=getattr(m, "status", "completed") or "completed",
            task_id=getattr(m, "task_id", None),
            created_at=m.created_at,
        )
        for m in reversed(rows)  # chronological order
    ]
    return ChatHistoryResponse(messages=messages, total=len(messages))


@router.get("/conversations", response_model=list[ConversationSummary])
async def list_conversations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    rows = (await db.execute(
        select(AgentConversation)
        .where(
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,       # chats are private to the person who had them
        )
        .order_by(desc(AgentConversation.updated_at))
        .limit(50)
    )).scalars().all()
    return rows


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(
    conversation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    conversation = (await db.execute(
        select(AgentConversation)
        .options(selectinload(AgentConversation.messages))
        .where(
            AgentConversation.id == conversation_id,
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,
        )
    )).scalar_one_or_none()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


@router.patch("/conversations/{conversation_id}")
async def rename_conversation(
    conversation_id: int,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "update")),
):
    conversation = (await db.execute(
        select(AgentConversation).where(
            AgentConversation.id == conversation_id,
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,
        )
    )).scalar_one_or_none()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if "title" in body:
        conversation.title = body["title"][:200]
    await db.flush()
    return {"id": conversation.id, "title": conversation.title}


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(
    conversation_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "delete")),
):
    conversation = (await db.execute(
        select(AgentConversation).where(
            AgentConversation.id == conversation_id,
            AgentConversation.organization_id == current_user.organization_id,
            AgentConversation.user_id == current_user.id,
        )
    )).scalar_one_or_none()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    await db.delete(conversation)
    return {"status": "deleted"}


async def _active_findings(db: AsyncSession, org_id: int, scan_id: int | None, limit: int) -> list[dict]:
    stmt = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.organization_id == org_id)
        .where(Finding.is_fixed == False)  # noqa: E712
        .where(Finding.is_ignored == False)  # noqa: E712
    )
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    stmt = stmt.order_by(Finding.severity.asc(), desc(Finding.created_at)).limit(min(limit, 50))
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
         "category": f.category, "cloud_provider": f.cloud_provider,
         "resource_name": f.resource_name, "cve_id": f.cve_id}
        for f in rows
    ]


@router.post("/triage", response_model=TriageResponse)
async def triage(
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    findings = await _active_findings(db, current_user.organization_id, body.scan_id, body.limit)
    llm_settings = await resolve_llm_settings(db, current_user.organization_id)
    result = await run_in_threadpool(triage_findings, findings, llm_settings)

    db.add(AgentInsight(
        organization_id=current_user.organization_id,
        kind="triage",
        content=f"Triaged {len(result['items'])} findings",
        data={"items": result["items"]},
        provider=result["provider"]["provider"],
        model=result["provider"]["model"],
    ))
    return TriageResponse(items=result["items"], provider=ProviderInfo(**result["provider"]),
                          count=len(result["items"]))


@router.post("/findings/{finding_id}/remediate", response_model=RemediationResponse)
async def remediate(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=403, detail="Agentic features are disabled")
    f = (await db.execute(
        select(Finding).join(Scan, Finding.scan_id == Scan.id).where(
            Finding.id == finding_id, Scan.organization_id == current_user.organization_id,
        )
    )).scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "id": f.id, "rule_id": f.rule_id, "title": f.title, "description": f.description,
        "severity": f.severity, "cloud_provider": f.cloud_provider, "resource_type": f.resource_type,
        "resource_name": f.resource_name, "file_path": f.file_path, "line_number": f.line_number,
        "code_snippet": f.code_snippet, "remediation": f.remediation, "cve_id": f.cve_id,
    }
    llm_settings = await resolve_llm_settings(db, current_user.organization_id)
    result = await run_in_threadpool(generate_remediation, finding_dict, llm_settings)

    db.add(AgentInsight(
        organization_id=current_user.organization_id,
        finding_id=f.id,
        kind="remediation",
        content=result["content"],
        data={"provider": result["provider"]},
        provider=result["provider"]["provider"],
        model=result["provider"]["model"],
    ))
    return RemediationResponse(finding_id=f.id, content=result["content"],
                               provider=ProviderInfo(**result["provider"]))


@router.get("/insights", response_model=list[InsightResponse])
async def list_insights(
    kind: str = None,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    stmt = select(AgentInsight).where(AgentInsight.organization_id == current_user.organization_id)
    if kind:
        stmt = stmt.where(AgentInsight.kind == kind)
    stmt = stmt.order_by(desc(AgentInsight.created_at)).limit(min(limit, 100))
    return (await db.execute(stmt)).scalars().all()


# ── Bring Your Own Model (per-org LLM configuration) ────────────────────

async def _config_response(db: AsyncSession, org_id: int) -> LLMConfigResponse:
    cfg = await get_org_config(db, org_id)
    effective = ProviderInfo(**LLMClient(await resolve_llm_settings(db, org_id)).info())
    if cfg:
        return LLMConfigResponse(
            provider=cfg.provider, model=cfg.model, base_url=cfg.base_url,
            api_version=cfg.api_version, temperature=cfg.temperature, max_tokens=cfg.max_tokens,
            enabled=cfg.enabled, has_api_key=bool(cfg.api_key_encrypted),
            source="org", providers=SUPPORTED_PROVIDERS, effective=effective,
        )
    default = LLMSettings.from_global()
    return LLMConfigResponse(
        provider=default.provider, model=default.model, base_url=default.base_url,
        api_version=default.api_version, temperature=default.temperature,
        max_tokens=default.max_tokens, enabled=True, has_api_key=bool(default.api_key),
        source="platform", providers=SUPPORTED_PROVIDERS, effective=effective,
    )


@router.get("/config", response_model=LLMConfigResponse)
async def get_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    return await _config_response(db, current_user.organization_id)


@router.put("/config", response_model=LLMConfigResponse)
async def update_config(
    body: LLMConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "manage")),
):
    provider = body.provider.lower()
    if provider not in PROVIDER_IDS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {body.provider}")

    cfg = await get_org_config(db, current_user.organization_id)
    if cfg is None:
        cfg = LLMConfig(organization_id=current_user.organization_id)
        db.add(cfg)

    cfg.provider = provider
    cfg.model = body.model
    cfg.base_url = body.base_url
    cfg.api_version = body.api_version
    cfg.temperature = body.temperature if body.temperature is not None else 0.2
    cfg.max_tokens = body.max_tokens or 1200
    cfg.enabled = body.enabled
    # Only overwrite the stored key when a new one is supplied (blank keeps existing).
    if body.api_key:
        cfg.api_key_encrypted = encrypt_token(body.api_key)
    elif provider == "mock":
        cfg.api_key_encrypted = None

    await db.flush()
    return await _config_response(db, current_user.organization_id)


@router.delete("/config", response_model=LLMConfigResponse)
async def delete_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("settings", "manage")),
):
    cfg = await get_org_config(db, current_user.organization_id)
    if cfg:
        await db.delete(cfg)
        await db.flush()
    return await _config_response(db, current_user.organization_id)


@router.post("/config/test", response_model=LLMTestResult)
async def test_config(
    body: LLMConfigUpdate | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "execute")),
):
    """Test connectivity. Uses the supplied draft config if provided, else the stored one."""
    import time
    logger.info("TEST_CONFIG called: body=%s", body)

    if body is not None and body.provider:
        provider = body.provider.lower()
        if provider not in PROVIDER_IDS:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {body.provider}")
        api_key = body.api_key or ""
        if not api_key:  # fall back to the stored key for the same provider
            cfg = await get_org_config(db, current_user.organization_id)
            if cfg and cfg.provider == provider and cfg.api_key_encrypted:
                api_key = settings_from_config(cfg).api_key
        llm_settings = LLMSettings(
            provider=provider, api_key=api_key, model=body.model or "",
            base_url=body.base_url or "", api_version=body.api_version or "2024-06-01",
        )
    else:
        llm_settings = await resolve_llm_settings(db, current_user.organization_id)

    client = LLMClient(llm_settings)
    messages = [
        {"role": "system", "content": "You are a connectivity probe. Reply with a single short word."},
        {"role": "user", "content": "Reply with the word: pong"},
    ]
    start = time.monotonic()
    try:
        resp = await run_in_threadpool(client.chat_sync, messages)
        latency = int((time.monotonic() - start) * 1000)
        logger.info("TEST_CONFIG success: latency=%dms sample=%s", latency, (resp.content or "")[:80])
        return LLMTestResult(
            ok=True, provider=ProviderInfo(**client.info()), latency_ms=latency,
            sample=(resp.content or "")[:120],
        )
    except Exception as e:  # noqa: BLE001 - report failure to the user
        logger.error("TEST_CONFIG failed: %s", e)
        return LLMTestResult(ok=False, provider=ProviderInfo(**client.info()), error=str(e))


# ---------------------------------------------------------------------------
# Agentic Auto-Fix Endpoints
# ---------------------------------------------------------------------------

@router.post("/autofix", response_model=AutoFixResponse)
async def autofix_findings(
    req: AutoFixRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "write")),
):
    """Preview code fixes for findings from connected repositories.

    Reads each file from its repository and returns the diff. Nothing is
    committed: to open a pull request, give the task to an agent on the Agent
    Runs page, where the diff is approved first.
    """
    from app.services.agents.fix_pr import FixError, prepare_fix

    results: list[AutoFixResultItem] = []
    for fid in req.finding_ids[:20]:
        try:
            fix = await prepare_fix(db, current_user.organization_id, fid)
        except FixError as exc:
            results.append(AutoFixResultItem(finding_id=fid, status="no_fix", explanation=str(exc)))
            continue
        except Exception as exc:  # noqa: BLE001 - one bad finding must not fail the batch
            logger.exception("autofix failed for finding %s", fid)
            await db.rollback()
            results.append(AutoFixResultItem(finding_id=fid, status="error", error=str(exc)))
            continue
        results.append(AutoFixResultItem(
            finding_id=fid, status="fix_generated", file_path=fix["file_path"], diff=fix["diff"],
            pr_title=fix["pr_title"], commit_message=fix["commit_message"], confidence=fix["confidence"],
            breaking_change=fix["breaking_change"], explanation=fix["explanation"],
        ))

    return AutoFixResponse(total=len(results), results=results, dry_run=True)


@router.post("/auto-triage", response_model=AutoTriageResponse)
async def auto_triage_findings(
    req: AutoTriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("findings", "update")),
):
    """Triage open findings with fixed rules: each gets a priority score and is
    marked triaged. A finding on a test or example path is left open and
    reported as a possible false positive for a person to confirm; a path is
    never enough to hide a finding."""
    stmt = select(Finding).where(
        Finding.organization_id == current_user.organization_id,
        Finding.status == "open",
    )
    if req.severity_filter:
        stmt = stmt.where(Finding.severity == req.severity_filter)
    stmt = stmt.limit(req.limit)
    rows = await db.execute(stmt)
    findings = list(rows.scalars().all())

    results: list[AutoTriageResultItem] = []
    changed = 0
    for f in findings:
        prev = f.status or "open"
        new_status, reason, score = _classify_for_triage(f)
        if new_status != prev:
            await decide(db, f, new_status, reason=reason, author=f"Triage rules (run by {current_user.email})")
            changed += 1
        results.append(AutoTriageResultItem(
            finding_id=f.id,
            previous_status=prev,
            new_status=new_status,
            reason=reason,
            priority_score=score,
        ))
    await db.commit()

    return AutoTriageResponse(
        total=len(findings),
        triaged=changed,
        results=sorted(results, key=lambda r: r.priority_score, reverse=True),
    )


def _classify_for_triage(finding: Finding) -> tuple[str, str, int]:
    """Rule-based triage classification. Returns (status, reason, priority_score)."""
    title = (finding.title or "").lower()
    path = (finding.file_path or "").lower()
    severity = (finding.severity or "").lower()

    # Priority scoring
    score = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 10}.get(severity, 30)

    # A test or example path is only a hint. The finding stays open for a person to confirm.
    hint = test_path_hint(path)
    if hint:
        return "open", f"Possible false positive ({hint}). Left open: confirm it yourself before hiding it.", score

    exploitable_keywords = ("exposed", "public", "leaked", "unencrypted", "open to", "0.0.0.0")
    if any(k in title for k in exploitable_keywords):
        score = min(score + 15, 100)

    if score >= 80:
        return "triaged", f"High-risk finding: {severity.upper()} severity, requires attention", score
    return "triaged", f"Classified as {severity.upper()} priority", score


@router.get("/knowledge/stats", response_model=KnowledgeStatsResponse)
async def get_knowledge_stats(
    current_user: User = Depends(require_permission("findings", "read")),
):
    """Get AI knowledge store statistics."""
    from app.services.agents.knowledge import get_knowledge_store
    ks = get_knowledge_store()
    # export_json() returns a JSON string of {rule_id: [pattern, ...]}; flatten it.
    by_rule = json.loads(ks.export_json())
    stats = [pattern for patterns in by_rule.values() for pattern in patterns]

    total_s = sum(p.get("success_count", 0) for p in stats)
    total_f = sum(p.get("failure_count", 0) for p in stats)
    confidences = [p.get("confidence", 0) for p in stats if p.get("confidence")]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    rule_ids = {p.get("rule_id") for p in stats if p.get("rule_id")}
    top = sorted(stats, key=lambda p: p.get("confidence", 0), reverse=True)[:10]

    return KnowledgeStatsResponse(
        total_rules_covered=len(rule_ids),
        total_patterns=len(stats),
        total_successes=total_s,
        total_failures=total_f,
        avg_confidence=round(avg_conf, 3),
        top_patterns=top,
    )
