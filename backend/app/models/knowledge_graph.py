"""Knowledge Graph models — entity-relationship graph for blast radius & dependency tracking."""
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Index, Float
from sqlalchemy.orm import relationship as sa_relationship
from sqlalchemy.sql import func
from app.core.database import Base


class KGNode(Base):
    """A node (entity) in the knowledge graph."""
    __tablename__ = "kg_nodes"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    entity_id = Column(String(500), nullable=False)  # e.g. "arn:aws:s3:::my-bucket", "CVE-2024-1234"
    entity_type = Column(String(100), nullable=False, index=True)  # resource, finding, cve, identity, service, region
    label = Column(String(500), nullable=False)  # human-readable name
    properties = Column(JSON, default=dict)  # arbitrary metadata
    severity = Column(String(20))  # for findings/CVEs: CRITICAL, HIGH, etc.
    source = Column(String(100))  # scan, manual, agent, import
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    outgoing_edges = sa_relationship("KGEdge", foreign_keys="KGEdge.source_id", back_populates="source_node", cascade="all, delete-orphan")
    incoming_edges = sa_relationship("KGEdge", foreign_keys="KGEdge.target_id", back_populates="target_node", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_kg_nodes_org_entity", "organization_id", "entity_id", unique=True),
        Index("ix_kg_nodes_org_type", "organization_id", "entity_type"),
    )


class KGEdge(Base):
    """A directed edge (relationship) between two nodes."""
    __tablename__ = "kg_edges"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    source_id = Column(Integer, ForeignKey("kg_nodes.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(Integer, ForeignKey("kg_nodes.id", ondelete="CASCADE"), nullable=False)
    relationship = Column(String(100), nullable=False)  # affects, depends_on, exposes, mitigates, owns, contains
    weight = Column(Float, default=1.0)  # edge weight for traversal priority
    properties = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    source_node = sa_relationship("KGNode", foreign_keys=[source_id], back_populates="outgoing_edges")
    target_node = sa_relationship("KGNode", foreign_keys=[target_id], back_populates="incoming_edges")

    __table_args__ = (
        Index("ix_kg_edges_org_rel", "organization_id", "relationship"),
        Index("ix_kg_edges_source", "source_id"),
        Index("ix_kg_edges_target", "target_id"),
    )
