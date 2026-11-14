from sqlalchemy import Boolean, Column, Integer, LargeBinary, String, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class AgentConversation(Base):
    __tablename__ = "agent_conversations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    title = Column(String(300), default="New conversation")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    messages = relationship(
        "AgentMessage", back_populates="conversation",
        cascade="all, delete-orphan", order_by="AgentMessage.id",
    )


class AgentMessage(Base):
    __tablename__ = "agent_messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("agent_conversations.id"), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # user, assistant
    content = Column(Text)
    tool_trace = Column(JSON, default=list)  # [{tool, arguments}]
    status = Column(String(20), default="completed", server_default="completed", nullable=False)  # pending, processing, completed, failed
    task_id = Column(String(255), nullable=True)  # Celery task ID for background processing
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    conversation = relationship("AgentConversation", back_populates="messages")
    files = relationship("ChatFile", lazy="selectin", order_by="ChatFile.id", viewonly=True)


class ChatFile(Base):
    """A file in a chat: one the user attached (only its extracted text is kept)
    or one the assistant produced for download (the bytes are kept)."""

    __tablename__ = "chat_files"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    message_id = Column(Integer, ForeignKey("agent_messages.id", ondelete="CASCADE"), index=True)
    kind = Column(String(20), nullable=False)  # upload, generated
    filename = Column(String(255), nullable=False)
    content_type = Column(String(120))
    size_bytes = Column(Integer, nullable=False, default=0)
    text = Column(Text)                       # upload: text extracted from the file
    truncated = Column(Boolean, nullable=False, default=False, server_default="false")
    data = Column(LargeBinary)                # generated: the file itself
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AgentRun(Base):
    """One durable agent task. Executed by a worker, survives restarts, and
    pauses while an action waits for a human decision."""

    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    parent_run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True)
    agent_id = Column(String(100), nullable=False)
    goal = Column(Text, nullable=False)
    trigger = Column(String(20), nullable=False, default="user", server_default="user")  # user, delegation
    # queued, running, awaiting_approval, completed, failed, cancelled
    status = Column(String(30), nullable=False, default="queued", server_default="queued", index=True)
    result = Column(Text)
    error = Column(Text)
    messages = Column(JSON, default=list)          # model conversation, kept so a run can resume
    pending_outputs = Column(JSON, default=dict)   # tool_call_id -> output, while a batch waits on approval
    provider = Column(String(50))
    model = Column(String(120))
    step_count = Column(Integer, nullable=False, default=0, server_default="0")
    max_steps = Column(Integer, nullable=False, default=12, server_default="12")
    input_tokens = Column(Integer, nullable=False, default=0, server_default="0")
    output_tokens = Column(Integer, nullable=False, default=0, server_default="0")
    cancel_requested = Column(Boolean, nullable=False, default=False, server_default="false")
    task_id = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    heartbeat_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))

    steps = relationship(
        "AgentStep", back_populates="run", cascade="all, delete-orphan", order_by="AgentStep.seq",
    )
    approvals = relationship(
        "AgentApproval", back_populates="run", cascade="all, delete-orphan", order_by="AgentApproval.id",
    )


class AgentStep(Base):
    """One thing a run did: a model call, a tool call, a delegation."""

    __tablename__ = "agent_steps"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    kind = Column(String(20), nullable=False)      # model, tool, delegation
    tool_name = Column(String(100))
    risk = Column(String(20))                      # read, internal_write, external_write
    arguments = Column(JSON)
    output = Column(Text)
    status = Column(String(20), nullable=False, default="ok", server_default="ok")  # ok, error, denied
    duration_ms = Column(Integer)
    input_tokens = Column(Integer, nullable=False, default=0, server_default="0")
    output_tokens = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    run = relationship("AgentRun", back_populates="steps")


class AgentApproval(Base):
    """A human decision an agent is waiting on before it changes something."""

    __tablename__ = "agent_approvals"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_call_id = Column(String(120), nullable=False)
    tool_name = Column(String(100), nullable=False)
    risk = Column(String(20), nullable=False)
    arguments = Column(JSON)
    summary = Column(Text)                         # plain statement of what will change
    preview = Column(Text)                         # the exact change, e.g. a diff
    reasoning = Column(Text)                       # what the agent said when it asked
    status = Column(String(20), nullable=False, default="pending", server_default="pending", index=True)
    requested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    decided_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    decision_note = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    decided_at = Column(DateTime(timezone=True))

    run = relationship("AgentRun", back_populates="approvals")


class AgentInsight(Base):
    __tablename__ = "agent_insights"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind = Column(String(30), nullable=False, index=True)  # triage, remediation
    content = Column(Text)  # markdown (remediation) or summary
    data = Column(JSON, default=dict)  # structured payload (triage items, provider info)
    provider = Column(String(50))
    model = Column(String(120))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
