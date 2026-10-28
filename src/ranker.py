"""Implements the scoring table from spec section 3. Pure function of DB
state so it can be re-run cheaply as new evidence comes in.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .db import Database

HIGH_VALUE_TYPES = {"invoice", "document", "profile", "order", "project", "attachment", "tenant"}

WEIGHTS = {
    "cross_owned_sibling": 30,
    "high_value_type": 15,
    "alternate_path_to_tested_object": 20,
    "opaque_or_graphql_id": 10,
    "nested_tenant_scoped": 10,
    "already_settled": -100,
    "write_without_test_owned_target": -25,
}


@dataclass
class ScoredEndpoint:
    endpoint_id: str
    score: int
    reasons: list[str]


def _has_cross_owned_sibling(db: Database, endpoint_id: str) -> bool:
    row = db.conn.execute(
        """SELECT COUNT(DISTINCT o.owner_subject_id) AS n
           FROM native_ids ni JOIN objects o ON ni.object_id = o.object_id
           WHERE ni.endpoint_id = ?""",
        (endpoint_id,),
    ).fetchone()
    return bool(row and row["n"] and row["n"] >= 2)


def _is_alternate_path_to_tested_object(db: Database, endpoint_id: str) -> bool:
    row = db.conn.execute(
        """SELECT COUNT(*) AS n FROM relationships
           WHERE (from_id = ? AND from_kind = 'endpoint')
              OR (to_id = ? AND to_kind = 'endpoint')""",
        (endpoint_id, endpoint_id),
    ).fetchone()
    return bool(row and row["n"])


def _is_nested_tenant_scoped(path_template: str) -> bool:
    segs = [s for s in path_template.strip("/").split("/") if s and s != "{id}"]
    return len(segs) >= 2 and path_template.count("{id}") >= 2


def _has_opaque_or_graphql_id(db: Database, endpoint_id: str) -> bool:
    row = db.conn.execute(
        """SELECT COUNT(*) AS n FROM id_locations
           WHERE endpoint_id = ? AND value_type IN ('opaque', 'graphql_global_id')""",
        (endpoint_id,),
    ).fetchone()
    return bool(row and row["n"])


def _is_settled(db: Database, endpoint_id: str) -> bool:
    row = db.conn.execute(
        """SELECT COUNT(*) AS n FROM test_results
           WHERE endpoint_id = ? AND verdict IN ('confirmed', 'rejected')""",
        (endpoint_id,),
    ).fetchone()
    return bool(row and row["n"])


def _has_test_owned_target(db: Database, endpoint_id: str) -> bool:
    row = db.conn.execute(
        """SELECT COUNT(*) AS n FROM native_ids ni
           JOIN objects o ON ni.object_id = o.object_id
           WHERE ni.endpoint_id = ? AND o.created_by_harness = 1""",
        (endpoint_id,),
    ).fetchone()
    return bool(row and row["n"])


def score_endpoint(db: Database, endpoint: sqlite3.Row) -> ScoredEndpoint:
    eid = endpoint["endpoint_id"]
    score = 0
    reasons: list[str] = []

    if _is_settled(db, eid):
        return ScoredEndpoint(eid, WEIGHTS["already_settled"], ["already_settled"])

    if _has_cross_owned_sibling(db, eid):
        score += WEIGHTS["cross_owned_sibling"]
        reasons.append("cross_owned_sibling")

    if (endpoint["object_type_guess"] or "") in HIGH_VALUE_TYPES:
        score += WEIGHTS["high_value_type"]
        reasons.append("high_value_type")

    if _is_alternate_path_to_tested_object(db, eid):
        score += WEIGHTS["alternate_path_to_tested_object"]
        reasons.append("alternate_path_to_tested_object")

    if _has_opaque_or_graphql_id(db, eid):
        score += WEIGHTS["opaque_or_graphql_id"]
        reasons.append("opaque_or_graphql_id")

    if _is_nested_tenant_scoped(endpoint["path_template"]):
        score += WEIGHTS["nested_tenant_scoped"]
        reasons.append("nested_tenant_scoped")

    tags = json.loads(endpoint["tags"] or "[]")
    if "write" in tags and not _has_test_owned_target(db, eid):
        score += WEIGHTS["write_without_test_owned_target"]
        reasons.append("write_without_test_owned_target")

    return ScoredEndpoint(eid, score, reasons)


def rank_candidates(db: Database, object_type: str | None = None,
                     limit: int = 25) -> list[ScoredEndpoint]:
    rows = db.list_endpoints(object_type=object_type)
    scored = [score_endpoint(db, r) for r in rows]
    scored = [s for s in scored if s.score > -100]  # drop settled ones
    scored.sort(key=lambda s: (-s.score, s.endpoint_id))
    return scored[:limit]
