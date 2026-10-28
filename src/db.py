"""Thin SQLite wrapper. No ORM on purpose — the schema is small and we want
every query inspectable with plain `sqlite3 harness.db`.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import models as m

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


class Database:
    def __init__(self, path: str = "harness.db", check_same_thread: bool = True):
        # check_same_thread=False is for the MCP server, which dispatches tool
        # calls from HTTP handler threads. Its dispatch is serialized behind a
        # lock (see src/mcp_server.py), so the connection is never used
        # concurrently — this only lifts sqlite3's same-thread assertion.
        self.conn = sqlite3.connect(path, check_same_thread=check_same_thread)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA_PATH.read_text())
        self.conn.commit()

    # ---- endpoints -------------------------------------------------
    def upsert_endpoint(self, e: m.Endpoint) -> str:
        cur = self.conn.execute(
            "SELECT endpoint_id, observed_count FROM endpoints "
            "WHERE method=? AND path_template=? AND host=?",
            (e.method, e.path_template, e.host),
        )
        row = cur.fetchone()
        if row:
            self.conn.execute(
                "UPDATE endpoints SET observed_count=?, last_seen=? WHERE endpoint_id=?",
                (row["observed_count"] + 1, e.last_seen, row["endpoint_id"]),
            )
            self.conn.commit()
            return row["endpoint_id"]

        self.conn.execute(
            """INSERT INTO endpoints
               (endpoint_id, method, path_template, host, source, content_type,
                auth_scheme, observed_count, first_seen, last_seen,
                object_type_guess, tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                e.endpoint_id, e.method, e.path_template, e.host, e.source,
                e.content_type, e.auth_scheme, e.observed_count, e.first_seen,
                e.last_seen, e.object_type_guess, json.dumps(e.tags),
            ),
        )
        self.conn.commit()
        return e.endpoint_id

    def add_id_location(self, loc: m.IdLocation) -> None:
        self.conn.execute(
            """INSERT INTO id_locations
               (id_location_id, endpoint_id, in_part, name_or_path, value_type)
               VALUES (?,?,?,?,?)""",
            (loc.id_location_id, loc.endpoint_id, loc.in_part, loc.name_or_path, loc.value_type),
        )
        self.conn.commit()

    def get_endpoint(self, endpoint_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)
        ).fetchone()

    def list_endpoints(self, object_type: str | None = None,
                        min_observed: int = 0) -> list[sqlite3.Row]:
        q = "SELECT * FROM endpoints WHERE observed_count >= ?"
        params: list = [min_observed]
        if object_type:
            q += " AND object_type_guess = ?"
            params.append(object_type)
        return self.conn.execute(q, params).fetchall()

    # ---- subjects / objects ----------------------------------------
    def insert_subject(self, s: m.Subject) -> str:
        self.conn.execute(
            """INSERT INTO subjects
               (subject_id, label, role, tenant_id, session_ref, created_for_test)
               VALUES (?,?,?,?,?,?)""",
            (s.subject_id, s.label, s.role, s.tenant_id, s.session_ref, int(s.created_for_test)),
        )
        self.conn.commit()
        return s.subject_id

    def insert_object(self, o: m.HarnessObject) -> str:
        self.conn.execute(
            """INSERT INTO objects
               (object_id, object_type, owner_subject_id, tenant_id, created_by_harness)
               VALUES (?,?,?,?,?)""",
            (o.object_id, o.object_type, o.owner_subject_id, o.tenant_id, int(o.created_by_harness)),
        )
        self.conn.commit()
        return o.object_id

    def add_native_id(self, n: m.NativeId) -> None:
        self.conn.execute(
            """INSERT INTO native_ids
               (native_id_id, object_id, endpoint_id, value, value_type)
               VALUES (?,?,?,?,?)""",
            (n.native_id_id, n.object_id, n.endpoint_id, n.value, n.value_type),
        )
        self.conn.commit()

    # ---- auth facts --------------------------------------------------
    def add_auth_fact(self, f: m.AuthFact) -> str:
        self.conn.execute(
            """INSERT INTO auth_facts
               (fact_id, subject_id, object_id, action, expected, basis)
               VALUES (?,?,?,?,?,?)""",
            (f.fact_id, f.subject_id, f.object_id, f.action, f.expected, f.basis),
        )
        self.conn.commit()
        return f.fact_id

    def get_auth_facts(self, subject_id: str, object_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM auth_facts WHERE subject_id=? AND object_id=?",
            (subject_id, object_id),
        ).fetchall()

    # ---- test results -------------------------------------------------
    def insert_test_result(self, t: m.TestResult) -> str:
        self.conn.execute(
            """INSERT INTO test_results
               (test_id, hypothesis, endpoint_id, subject_id, object_id, action,
                evidence_dir, response_status, response_fingerprint, diff_against,
                verdict, verdict_basis_fact_id, confidence, model_rationale,
                created_at, executed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                t.test_id, t.hypothesis, t.endpoint_id, t.subject_id, t.object_id,
                t.action, t.evidence_dir, t.response_status, t.response_fingerprint,
                t.diff_against, t.verdict, t.verdict_basis_fact_id, t.confidence,
                t.model_rationale, t.created_at, t.executed_at,
            ),
        )
        self.conn.commit()
        return t.test_id

    def update_test_result(self, test_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self.conn.execute(
            f"UPDATE test_results SET {cols} WHERE test_id=?",
            (*fields.values(), test_id),
        )
        self.conn.commit()

    def get_test_result(self, test_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM test_results WHERE test_id=?", (test_id,)
        ).fetchone()
