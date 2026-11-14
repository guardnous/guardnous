"""Durable agent runs and the approvals they wait on."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.audit import write_audit_log
from app.core.config import settings
from app.core.database import get_db
from app.core.rbac import require_permission
from app.models.agent import AgentApproval, AgentRun
from app.models.user import User
from app.services.agents import runtime
from app.services.agents.config import resolve_llm_settings
from app.services.agents.llm import LLMClient
from app.services.agents.registry import get_agent

router = APIRouter()


# ── schemas ─────────────────────────────────────────────────────────

class RunCreate(BaseModel):
    goal: str = Field(min_length=5, max_length=4000)
    agent_id: Optional[str] = None


class Decision(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)


class StepOut(BaseModel):
    seq: int
    kind: str
    tool_name: Optional[str] = None
    risk: Optional[str] = None
    arguments: Optional[dict] = None
    output: Optional[str] = None
    status: str
    duration_ms: Optional[int] = None
    input_tokens: int = 0
    output_tokens: int = 0
    created_at: Optional[datetime] = None


class ApprovalOut(BaseModel):
    id: int
    run_id: int
    agent_id: Optional[str] = None
    goal: Optional[str] = None
    tool_name: str
    risk: str
    arguments: Optional[dict] = None
    summary: Optional[str] = None
    preview: Optional[str] = None
    reasoning: Optional[str] = None
    status: str
    requested_by: Optional[str] = None
    decided_by: Optional[str] = None
    decision_note: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    decided_at: Optional[datetime] = None
    can_decide: bool = False
    blocked_reason: Optional[str] = None


class RunOut(BaseModel):
    id: int
    agent_id: str
    agent_name: str
    goal: str
    status: str
    trigger: str
    parent_run_id: Optional[int] = None
    requested_by: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    step_count: int
    max_steps: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Optional[float] = None
    pending_approvals: int = 0
    error: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class RunDetail(RunOut):
    result: Optional[str] = None
    steps: list[StepOut] = []
    approvals: list[ApprovalOut] = []
    children: list[RunOut] = []


class UsageOut(BaseModel):
    tokens_this_month: int
    monthly_budget: int
    estimated_cost_usd: Optional[float] = None
    runs_this_month: int
    model_configured: bool
    provider: str
    model: str


# ── helpers ─────────────────────────────────────────────────────────

async def _emails(db: AsyncSession, ids: set[Optional[int]]) -> dict[int, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = await db.execute(select(User.id, User.email).where(User.id.in_(ids)))
    return {uid: email for uid, email in rows.all()}


def _run_out(run: AgentRun, emails: dict[int, str], pending: int = 0) -> dict:
    agent = get_agent(run.agent_id)
    return dict(
        id=run.id, agent_id=run.agent_id, agent_name=agent.name if agent else run.agent_id, goal=run.goal,
        status=run.status, trigger=run.trigger, parent_run_id=run.parent_run_id,
        requested_by=emails.get(run.user_id) or ("GuardNous, after an assessment" if run.trigger == "scan" else None),
        provider=run.provider, model=run.model,
        step_count=run.step_count, max_steps=run.max_steps,
        input_tokens=run.input_tokens, output_tokens=run.output_tokens,
        estimated_cost_usd=runtime.estimated_cost_usd(run.input_tokens, run.output_tokens),
        pending_approvals=pending, error=run.error,
        created_at=run.created_at, started_at=run.started_at, finished_at=run.finished_at,
    )


def _decide_block(approval: AgentApproval, user: User, perms) -> Optional[str]:
    """Why this user cannot approve this request, or None if they can."""
    if approval.status != "pending":
        return f"Already {approval.status}."
    needed = runtime.TOOL_PERMISSION.get(approval.tool_name)
    if needed and not runtime.has_permission(perms, *needed):
        return f"Needs {needed[0]}:{needed[1]}."
    own = approval.requested_by == user.id
    if approval.risk == runtime.EXTERNAL_WRITE:
        if not runtime.has_permission(perms, "agents", "manage"):
            return "Needs agents:manage."
        if own and not settings.AGENT_ALLOW_SELF_APPROVAL:
            return "You requested this action, so someone else must approve it."
    elif not own and not runtime.has_permission(perms, "agents", "manage"):
        return "Only the requester or someone with agents:manage can decide this."
    return None


def _approval_out(a: AgentApproval, run: Optional[AgentRun], emails: dict[int, str], user: User, perms) -> ApprovalOut:
    blocked = _decide_block(a, user, perms)
    return ApprovalOut(
        id=a.id, run_id=a.run_id, agent_id=run.agent_id if run else None, goal=run.goal if run else None,
        tool_name=a.tool_name, risk=a.risk, arguments=runtime._public(a.arguments), summary=a.summary,
        preview=a.preview, reasoning=a.reasoning,
        status=a.status, decided_by=emails.get(a.decided_by),
        requested_by=emails.get(a.requested_by)
        or ("GuardNous, after an assessment" if run is not None and run.trigger == "scan" else None),
        decision_note=a.decision_note, created_at=a.created_at, expires_at=a.expires_at, decided_at=a.decided_at,
        can_decide=blocked is None, blocked_reason=blocked,
    )


async def _visible_run(db: AsyncSession, run_id: int, user: User, perms) -> AgentRun:
    run = (await db.execute(
        select(AgentRun)
        .where(AgentRun.id == run_id, AgentRun.organization_id == user.organization_id)
        .options(selectinload(AgentRun.steps), selectinload(AgentRun.approvals))
        .execution_options(populate_existing=True)
    )).scalar_one_or_none()
    if run is None or not (run.user_id == user.id or runtime.has_permission(perms, "agents", "manage")):
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def _enqueue(run_id: int) -> None:
    from app.tasks.agent_runs import enqueue_run

    enqueue_run(run_id)


# ── runs ────────────────────────────────────────────────────────────

@router.post("/runs", response_model=RunOut, status_code=201)
async def start_run(
    body: RunCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "create")),
):
    """Give an agent a task to work on in the background."""
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=409, detail="Agents are disabled on this installation.")
    if body.agent_id and get_agent(body.agent_id) is None:
        raise HTTPException(status_code=422, detail=f"Unknown agent '{body.agent_id}'.")
    llm = LLMClient(await resolve_llm_settings(db, user.organization_id))
    if not llm.is_live:
        raise HTTPException(
            status_code=409,
            detail="No language model is configured. Add a provider and API key under Settings before starting a run.",
        )
    budget = settings.AGENT_MONTHLY_TOKEN_BUDGET
    if budget and await runtime.tokens_used_this_month(db, user.organization_id) >= budget:
        raise HTTPException(status_code=409, detail=f"The monthly agent budget of {budget:,} tokens is used up.")

    run = await runtime.create_run(
        db, organization_id=user.organization_id, user_id=user.id, agent_id=body.agent_id, goal=body.goal,
    )
    await write_audit_log(
        db, action="agent_run.start", resource_type="agent_run", resource_id=run.id,
        details={"agent_id": run.agent_id, "goal": run.goal[:300]}, user=user,
    )
    await db.commit()
    _enqueue(run.id)
    return _run_out(run, {user.id: user.email})


@router.get("/runs", response_model=list[RunOut])
async def list_runs(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    """Runs you started; everyone's if you hold agents:manage."""
    perms = await runtime.user_permissions(db, user)
    q = select(AgentRun).where(
        AgentRun.organization_id == user.organization_id, AgentRun.parent_run_id.is_(None),
    )
    if not runtime.has_permission(perms, "agents", "manage"):
        q = q.where(AgentRun.user_id == user.id)
    if status:
        q = q.where(AgentRun.status == status)
    runs = (await db.execute(q.order_by(desc(AgentRun.id)).limit(limit))).scalars().all()
    pending = dict((await db.execute(
        select(AgentApproval.run_id, func.count(AgentApproval.id))
        .where(AgentApproval.run_id.in_([r.id for r in runs] or [0]), AgentApproval.status == "pending")
        .group_by(AgentApproval.run_id)
    )).all())
    emails = await _emails(db, {r.user_id for r in runs})
    return [_run_out(r, emails, pending.get(r.id, 0)) for r in runs]


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    perms = await runtime.user_permissions(db, user)
    run = await _visible_run(db, run_id, user, perms)
    children = (await db.execute(
        select(AgentRun).where(AgentRun.parent_run_id == run.id).order_by(AgentRun.id)
    )).scalars().all()
    emails = await _emails(
        db, {run.user_id, *(a.requested_by for a in run.approvals), *(a.decided_by for a in run.approvals)},
    )
    return RunDetail(
        **_run_out(run, emails, sum(1 for a in run.approvals if a.status == "pending")),
        result=run.result,
        steps=[StepOut.model_validate(s, from_attributes=True) for s in run.steps],
        approvals=[_approval_out(a, run, emails, user, perms) for a in run.approvals],
        children=[RunOut(**_run_out(c, emails)) for c in children],
    )


@router.post("/runs/{run_id}/cancel", response_model=RunOut)
async def cancel_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    """Stop a run. One that is mid-step stops before its next step."""
    perms = await runtime.user_permissions(db, user)
    run = await _visible_run(db, run_id, user, perms)
    if run.status in runtime.FINAL_STATUSES:
        raise HTTPException(status_code=409, detail=f"This run is already {run.status}.")
    await runtime.request_cancel(db, run)
    await write_audit_log(
        db, action="agent_run.cancel", resource_type="agent_run", resource_id=run.id, details={}, user=user,
    )
    await db.commit()
    return _run_out(run, await _emails(db, {run.user_id}))


# ── approvals ───────────────────────────────────────────────────────

@router.get("/approvals", response_model=list[ApprovalOut])
async def list_approvals(
    status: Optional[str] = Query("pending"),
    limit: int = Query(100, ge=1, le=300),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    """Actions agents are waiting on. You see your own; everyone's with agents:manage."""
    perms = await runtime.user_permissions(db, user)
    q = (
        select(AgentApproval, AgentRun)
        .join(AgentRun, AgentRun.id == AgentApproval.run_id)
        .where(AgentApproval.organization_id == user.organization_id)
    )
    if not runtime.has_permission(perms, "agents", "manage"):
        q = q.where(AgentApproval.requested_by == user.id)
    if status and status != "all":
        q = q.where(AgentApproval.status == status)
    rows = (await db.execute(q.order_by(desc(AgentApproval.id)).limit(limit))).all()
    emails = await _emails(db, {x for a, _ in rows for x in (a.requested_by, a.decided_by)})
    return [_approval_out(a, run, emails, user, perms) for a, run in rows]


@router.post("/approvals/{approval_id}/decision", response_model=ApprovalOut)
async def decide(
    approval_id: int,
    body: Decision,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    """Approve or reject an action an agent wants to take."""
    row = (await db.execute(
        select(AgentApproval, AgentRun)
        .join(AgentRun, AgentRun.id == AgentApproval.run_id)
        .where(AgentApproval.id == approval_id, AgentApproval.organization_id == user.organization_id)
    )).first()
    perms = await runtime.user_permissions(db, user)
    if row is None or not (
        row[0].requested_by == user.id or runtime.has_permission(perms, "agents", "manage")
    ):
        raise HTTPException(status_code=404, detail="Approval request not found")
    approval, run = row
    if not body.approve and not body.note.strip():
        raise HTTPException(status_code=422, detail="Say why you are rejecting this, so the agent and the requester know.")
    try:
        approval, resumed = await runtime.decide_approval(db, approval, user, approve=body.approve, note=body.note)
    except runtime.DecisionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    await write_audit_log(
        db, action=f"agent_approval.{approval.status}", resource_type="agent_approval", resource_id=approval.id,
        details={"run_id": approval.run_id, "tool": approval.tool_name, "arguments": runtime._public(approval.arguments),
                 "note": approval.decision_note},
        user=user,
    )
    await db.commit()
    if resumed:
        _enqueue(approval.run_id)
    emails = await _emails(db, {approval.requested_by, approval.decided_by})
    return _approval_out(approval, run, emails, user, perms)


@router.get("/usage", response_model=UsageOut)
async def usage(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("agents", "read")),
):
    """Model tokens this organization's agent runs used this calendar month."""
    from datetime import timezone

    start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    tokens_in, tokens_out, count = (await db.execute(
        select(
            func.coalesce(func.sum(AgentRun.input_tokens), 0),
            func.coalesce(func.sum(AgentRun.output_tokens), 0),
            func.count(AgentRun.id),
        ).where(AgentRun.organization_id == user.organization_id, AgentRun.created_at >= start)
    )).one()
    llm = LLMClient(await resolve_llm_settings(db, user.organization_id))
    return UsageOut(
        tokens_this_month=int(tokens_in) + int(tokens_out),
        monthly_budget=settings.AGENT_MONTHLY_TOKEN_BUDGET,
        estimated_cost_usd=runtime.estimated_cost_usd(int(tokens_in), int(tokens_out)),
        runs_this_month=int(count), model_configured=llm.is_live,
        provider=llm.provider, model=llm.model if llm.is_live else "",
    )
