"""The tool surface described in spec section 2. Wrap these functions with
whatever MCP server framework you're using to expose them to the local LLM
through Burp MCP. The model only ever sees these — never raw DB access or a
raw HTTP client.

This file is deliberately framework-agnostic; plug in your MCP SDK's
decorator/registration calls where marked.
"""
from __future__ import annotations

import json
from pathlib import Path

from .db import Database
from .differential_tester import ScopeGuard, SendFn, execute_test as _execute_test, adjudicate as _adjudicate
from .models import TestResult
from .ranker import rank_candidates


class ToolContext:
    """Bundles the dependencies each tool needs. Construct one per run and
    pass it into the registration layer."""

    def __init__(self, db: Database, guard: ScopeGuard, send_fn: SendFn, evidence_root: Path):
        self.db = db
        self.guard = guard
        self.send_fn = send_fn
        self.evidence_root = evidence_root


# ---- read-only tools ---------------------------------------------------

def list_candidate_endpoints(ctx: ToolContext, object_type: str | None = None,
                              min_score: int = 0, limit: int = 25) -> list[dict]:
    scored = rank_candidates(ctx.db, object_type=object_type, limit=limit)
    out = []
    for s in scored:
        if s.score < min_score:
            continue
        row = ctx.db.get_endpoint(s.endpoint_id)
        out.append({
            "endpoint_id": s.endpoint_id,
            "score": s.score,
            "reasons": s.reasons,
            "method": row["method"],
            "path_template": row["path_template"],
            "host": row["host"],
            "object_type_guess": row["object_type_guess"],
        })
    return out


def get_endpoint_detail(ctx: ToolContext, endpoint_id: str) -> dict:
    row = ctx.db.get_endpoint(endpoint_id)
    if row is None:
        return {"error": f"no such endpoint: {endpoint_id}"}
    id_locs = ctx.db.conn.execute(
        "SELECT in_part, name_or_path, value_type FROM id_locations WHERE endpoint_id=?",
        (endpoint_id,),
    ).fetchall()
    return {
        "endpoint_id": row["endpoint_id"],
        "method": row["method"],
        "path_template": row["path_template"],
        "host": row["host"],
        "object_type_guess": row["object_type_guess"],
        "tags": json.loads(row["tags"] or "[]"),
        "id_locations": [dict(r) for r in id_locs],
    }


def get_object_graph(ctx: ToolContext, object_id: str, depth: int = 1) -> dict:
    # Minimal one-hop version; extend to real BFS if depth > 1 is needed.
    edges = ctx.db.conn.execute(
        """SELECT * FROM relationships
           WHERE (from_id=? AND from_kind='object') OR (to_id=? AND to_kind='object')""",
        (object_id, object_id),
    ).fetchall()
    return {"object_id": object_id, "edges": [dict(e) for e in edges]}


def get_known_auth_facts(ctx: ToolContext, subject_id: str, object_id: str) -> list[dict]:
    facts = ctx.db.get_auth_facts(subject_id, object_id)
    return [dict(f) for f in facts]


def get_test_result(ctx: ToolContext, test_id: str) -> dict:
    row = ctx.db.get_test_result(test_id)
    return dict(row) if row else {"error": f"no such test: {test_id}"}


# ---- the model's one write action: propose ------------------------------

def propose_test(ctx: ToolContext, hypothesis: str, endpoint_id: str,
                  subject_id: str, object_id: str, action: str) -> dict:
    """Records the hypothesis. Does NOT send anything. Returns a test_id
    that the operator/harness later passes to execute_test."""
    t = TestResult(
        hypothesis=hypothesis, endpoint_id=endpoint_id,
        subject_id=subject_id, object_id=object_id, action=action,
    )
    test_id = ctx.db.insert_test_result(t)
    return {"test_id": test_id, "status": "proposed"}


# ---- harness-gated execution ---------------------------------------------

def execute_test(ctx: ToolContext, test_id: str, method: str, host: str,
                  built_url: str, headers: dict, body: bytes = b"",
                  operator_approved_write: bool = False,
                  baseline_test_id: str | None = None) -> dict:
    """The model can call this, but ScopeGuard inside still enforces host
    allow-list, rate limit, and write-approval — a model proposing an
    out-of-scope or unapproved-write test gets a ScopeError, not a sent
    request."""
    _execute_test(
        ctx.db, ctx.guard, test_id, method, host, built_url, headers, body,
        ctx.send_fn, ctx.evidence_root,
        operator_approved_write=operator_approved_write,
        baseline_test_id=baseline_test_id,
    )
    return dict(ctx.db.get_test_result(test_id))


# ---- verdict -------------------------------------------------------------

def record_verdict(ctx: ToolContext, test_id: str, rationale: str) -> dict:
    """Model states its reasoning; the actual verdict is computed by
    adjudicate() against the auth_facts oracle, not taken from the model
    directly (spec section 1.5 / 1.6)."""
    ctx.db.update_test_result(test_id, model_rationale=rationale)
    verdict = _adjudicate(ctx.db, test_id)
    return {"test_id": test_id, "verdict": verdict}
