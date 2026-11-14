"""Knowledge Graph service — CRUD + BFS traversal for blast radius analysis.

Provides:
  - Node/edge CRUD (upsert-aware, idempotent)
  - BFS traversal for blast-radius and dependency chains
  - Subgraph extraction for investigation context
  - Bulk ingest from scan findings (auto-links resources → findings → CVEs)
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge_graph import KGNode, KGEdge

logger = logging.getLogger(__name__)

# ── Relationship vocabulary ──────────────────────────────────
RELATIONSHIPS = {
    "affects",       # finding → resource
    "depends_on",    # resource → resource
    "exposes",       # CVE → resource
    "mitigates",     # policy/control → finding
    "owns",          # identity → resource
    "contains",      # region/account → resource
    "triggers",      # finding → finding (cascading risk)
    "resolves",      # remediation → finding
}


class KnowledgeGraphService:
    """Async service for knowledge graph operations."""

    def __init__(self, db: AsyncSession, organization_id: int):
        self.db = db
        self.org_id = organization_id

    # ── Node operations ──────────────────────────────────────

    async def upsert_node(
        self,
        entity_id: str,
        entity_type: str,
        label: str,
        properties: dict | None = None,
        severity: str | None = None,
        source: str | None = None,
    ) -> KGNode:
        """Insert or update a node, returning the persisted instance."""
        stmt = pg_insert(KGNode).values(
            organization_id=self.org_id,
            entity_id=entity_id,
            entity_type=entity_type,
            label=label,
            properties=properties or {},
            severity=severity,
            source=source,
        ).on_conflict_do_update(
            index_elements=["organization_id", "entity_id"],
            set_=dict(
                label=label,
                entity_type=entity_type,
                properties=properties or {},
                severity=severity,
                source=source,
            ),
        ).returning(KGNode.id)
        result = await self.db.execute(stmt)
        node_id = result.scalar_one()
        await self.db.flush()
        return await self.db.get(KGNode, node_id)

    async def get_node(self, entity_id: str) -> KGNode | None:
        result = await self.db.execute(
            select(KGNode).where(
                KGNode.organization_id == self.org_id,
                KGNode.entity_id == entity_id,
            )
        )
        return result.scalar_one_or_none()

    async def search_nodes(
        self,
        entity_type: str | None = None,
        severity: str | None = None,
        label_contains: str | None = None,
        limit: int = 50,
    ) -> list[KGNode]:
        q = select(KGNode).where(KGNode.organization_id == self.org_id)
        if entity_type:
            q = q.where(KGNode.entity_type == entity_type)
        if severity:
            q = q.where(KGNode.severity == severity)
        if label_contains:
            q = q.where(KGNode.label.ilike(f"%{label_contains}%"))
        q = q.limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all())

    # ── Edge operations ──────────────────────────────────────

    async def add_edge(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship: str,
        weight: float = 1.0,
        properties: dict | None = None,
    ) -> KGEdge | None:
        """Add a directed edge between two nodes (by entity_id). Nodes must exist."""
        src = await self.get_node(source_entity_id)
        tgt = await self.get_node(target_entity_id)
        if not src or not tgt:
            logger.warning("Cannot add edge: missing node(s) %s → %s", source_entity_id, target_entity_id)
            return None

        # Avoid duplicate edges
        existing = await self.db.execute(
            select(KGEdge).where(
                KGEdge.organization_id == self.org_id,
                KGEdge.source_id == src.id,
                KGEdge.target_id == tgt.id,
                KGEdge.relationship == relationship,
            )
        )
        if existing.scalar_one_or_none():
            return None

        edge = KGEdge(
            organization_id=self.org_id,
            source_id=src.id,
            target_id=tgt.id,
            relationship=relationship,
            weight=weight,
            properties=properties or {},
        )
        self.db.add(edge)
        await self.db.flush()
        return edge

    # ── Traversal ────────────────────────────────────────────

    async def bfs(
        self,
        start_entity_id: str,
        max_depth: int = 3,
        relationship_filter: set[str] | None = None,
        direction: str = "outgoing",  # "outgoing", "incoming", "both"
    ) -> list[dict[str, Any]]:
        """BFS traversal from a starting node. Returns nodes with depth info.

        Useful for:
          - Blast radius: start from a finding, traverse "affects" edges outward
          - Dependency chain: start from a resource, traverse "depends_on" edges
          - Impact analysis: start from a CVE, find all affected resources
        """
        start = await self.get_node(start_entity_id)
        if not start:
            return []

        visited: set[int] = {start.id}
        queue: deque[tuple[int, int]] = deque([(start.id, 0)])  # (node_id, depth)
        results: list[dict[str, Any]] = [{
            "node_id": start.id,
            "entity_id": start.entity_id,
            "entity_type": start.entity_type,
            "label": start.label,
            "severity": start.severity,
            "depth": 0,
            "properties": start.properties,
        }]

        while queue:
            current_id, depth = queue.popleft()
            if depth >= max_depth:
                continue

            neighbors = await self._get_neighbors(current_id, direction, relationship_filter)
            for neighbor_id, edge_rel, edge_weight in neighbors:
                if neighbor_id in visited:
                    continue
                visited.add(neighbor_id)
                node = await self.db.get(KGNode, neighbor_id)
                if node:
                    results.append({
                        "node_id": node.id,
                        "entity_id": node.entity_id,
                        "entity_type": node.entity_type,
                        "label": node.label,
                        "severity": node.severity,
                        "depth": depth + 1,
                        "via_relationship": edge_rel,
                        "edge_weight": edge_weight,
                        "properties": node.properties,
                    })
                    queue.append((neighbor_id, depth + 1))

        return results

    async def blast_radius(self, entity_id: str, max_depth: int = 3) -> dict[str, Any]:
        """Find all entities affected by a given entity (outgoing traversal)."""
        nodes = await self.bfs(entity_id, max_depth=max_depth, direction="outgoing")
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for n in nodes:
            if n.get("severity"):
                severity_counts[n["severity"]] = severity_counts.get(n["severity"], 0) + 1
            type_counts[n["entity_type"]] = type_counts.get(n["entity_type"], 0) + 1

        return {
            "origin": entity_id,
            "total_affected": len(nodes) - 1,  # exclude origin
            "max_depth_reached": max(n["depth"] for n in nodes) if nodes else 0,
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "nodes": nodes,
        }

    # ── Bulk ingest from scan findings ───────────────────────

    async def ingest_findings(self, findings: list[dict]) -> dict[str, int]:
        """Auto-populate the graph from scan findings.

        Creates nodes for: findings, resources, CVEs
        Creates edges: finding→affects→resource, CVE→exposes→resource
        """
        stats = {"nodes_created": 0, "edges_created": 0}

        for f in findings:
            fid = f.get("id")
            rule = f.get("rule_id", "unknown")
            title = f.get("title", "Untitled finding")
            severity = f.get("severity", "MEDIUM")
            resource = f.get("resource_name") or f.get("file_path") or "unknown"

            # Finding node
            finding_eid = f"finding:{fid}" if fid else f"finding:{rule}:{resource}"
            await self.upsert_node(finding_eid, "finding", title, severity=severity, source="scan",
                                   properties={"rule_id": rule, "category": f.get("category")})
            stats["nodes_created"] += 1

            # Resource node
            res_type = f.get("resource_type") or "unknown"
            await self.upsert_node(f"resource:{resource}", "resource", resource,
                                   properties={"resource_type": res_type, "cloud": f.get("cloud_provider")},
                                   source="scan")
            stats["nodes_created"] += 1

            # Finding → affects → Resource
            edge = await self.add_edge(finding_eid, f"resource:{resource}", "affects")
            if edge:
                stats["edges_created"] += 1

            # CVE node + edge
            cve = f.get("cve_id")
            if cve:
                await self.upsert_node(f"cve:{cve}", "cve", cve, severity=severity, source="scan")
                stats["nodes_created"] += 1
                edge = await self.add_edge(f"cve:{cve}", f"resource:{resource}", "exposes")
                if edge:
                    stats["edges_created"] += 1

        await self.db.commit()
        logger.info("KG ingest: %d nodes, %d edges from %d findings", stats["nodes_created"], stats["edges_created"], len(findings))
        return stats

    # ── Graph stats ──────────────────────────────────────────

    async def stats(self) -> dict[str, Any]:
        """Get graph statistics for the organization."""
        from sqlalchemy import func as sa_func

        node_count = await self.db.execute(
            select(sa_func.count(KGNode.id)).where(KGNode.organization_id == self.org_id)
        )
        edge_count = await self.db.execute(
            select(sa_func.count(KGEdge.id)).where(KGEdge.organization_id == self.org_id)
        )
        type_dist = await self.db.execute(
            select(KGNode.entity_type, sa_func.count(KGNode.id))
            .where(KGNode.organization_id == self.org_id)
            .group_by(KGNode.entity_type)
        )

        return {
            "total_nodes": node_count.scalar() or 0,
            "total_edges": edge_count.scalar() or 0,
            "node_types": dict(type_dist.all()),
        }

    # ── Internal helpers ─────────────────────────────────────

    async def _get_neighbors(
        self,
        node_id: int,
        direction: str,
        rel_filter: set[str] | None,
    ) -> list[tuple[int, str, float]]:
        """Get neighbor node IDs with edge info."""
        conditions = [KGEdge.organization_id == self.org_id]
        if rel_filter:
            conditions.append(KGEdge.relationship.in_(rel_filter))

        results = []

        if direction in ("outgoing", "both"):
            q = select(KGEdge.target_id, KGEdge.relationship, KGEdge.weight).where(
                KGEdge.source_id == node_id, *conditions
            )
            rows = await self.db.execute(q)
            results.extend((r[0], r[1], r[2]) for r in rows.all())

        if direction in ("incoming", "both"):
            q = select(KGEdge.source_id, KGEdge.relationship, KGEdge.weight).where(
                KGEdge.target_id == node_id, *conditions
            )
            rows = await self.db.execute(q)
            results.extend((r[0], r[1], r[2]) for r in rows.all())

        return results
