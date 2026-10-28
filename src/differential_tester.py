"""Executes a `propose_test` → `execute_test` pair. This is the only module
that is allowed to send live HTTP. Everything else only reads/writes SQLite.

Scope/rate-limit/write-approval enforcement lives in `ScopeGuard` — keep it
here, not scattered through the model-facing tool layer, so there's one
place to audit.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .db import Database
from .evidence import write_evidence
from .models import AuthFact, TestResult, now_iso

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class ScopeError(Exception):
    pass


@dataclass
class ScopeGuard:
    allowed_hosts: set[str]
    max_requests_per_minute: int = 30
    require_approval_for_writes: bool = True
    _request_times: list[float] = None

    def __post_init__(self):
        self._request_times = []

    def check_host(self, host: str) -> None:
        if host not in self.allowed_hosts:
            raise ScopeError(f"host {host!r} is outside the configured scope")

    def check_rate(self) -> None:
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= self.max_requests_per_minute:
            raise ScopeError("rate limit exceeded; backing off")
        self._request_times.append(now)

    def check_write_approval(self, method: str, approved: bool) -> None:
        if method in WRITE_METHODS and self.require_approval_for_writes and not approved:
            raise ScopeError("write action requires explicit operator approval")


# A SendFn takes a fully-built request description and returns
# (status_code, response_headers, response_body_bytes). Wire this to the
# Burp MCP "send request" tool, or to `requests`/`httpx` for a non-Burp
# runner. Keeping it injectable makes the tester testable without a live
# target.
SendFn = Callable[[str, str, dict, bytes], tuple[int, dict, bytes]]


def fingerprint_response(body: bytes) -> str:
    """Very rough structural fingerprint: strip likely-dynamic fields
    before hashing. Replace with a real JSON-structure normalizer before
    relying on this for verdicts (see spec section 6, open items)."""
    try:
        data = json.loads(body)
        normalized = _strip_dynamic_fields(data)
        return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return hashlib.sha256(body).hexdigest()


_DYNAMIC_KEYS = {"timestamp", "created_at", "updated_at", "request_id", "trace_id", "nonce"}


def _strip_dynamic_fields(obj):
    if isinstance(obj, dict):
        return {k: _strip_dynamic_fields(v) for k, v in obj.items() if k not in _DYNAMIC_KEYS}
    if isinstance(obj, list):
        return [_strip_dynamic_fields(v) for v in obj]
    return obj


def execute_test(
    db: Database,
    guard: ScopeGuard,
    test_id: str,
    method: str,
    host: str,
    built_url: str,
    headers: dict,
    body: bytes,
    send_fn: SendFn,
    evidence_root: Path,
    operator_approved_write: bool = False,
    baseline_test_id: Optional[str] = None,
) -> None:
    """Runs one already-proposed test. Verdict is left as 'needs_review' —
    turning that into 'confirmed' is a separate step that checks the
    auth_facts oracle (see `adjudicate`)."""
    guard.check_host(host)
    guard.check_rate()
    guard.check_write_approval(method, operator_approved_write)

    status, resp_headers, resp_body = send_fn(method, built_url, headers, body)
    fp = fingerprint_response(resp_body)

    evidence_dir = write_evidence(
        evidence_root, test_id,
        request_text=f"{method} {built_url}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()),
        response_text=f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
                      + "\n\n" + resp_body.decode(errors="replace"),
    )

    diff_summary = None
    if baseline_test_id:
        baseline = db.get_test_result(baseline_test_id)
        if baseline and baseline["response_fingerprint"] != fp:
            diff_summary = "structural_mismatch"
        elif baseline:
            diff_summary = "structural_match"

    db.update_test_result(
        test_id,
        response_status=status,
        response_fingerprint=fp,
        diff_against=baseline_test_id,
        evidence_dir=str(evidence_dir),
        verdict="needs_review",
        executed_at=now_iso(),
    )
    if diff_summary:
        db.update_test_result(test_id, model_rationale=diff_summary)


def adjudicate(db: Database, test_id: str) -> str:
    """Promote 'needs_review' to 'confirmed'/'rejected' only when a
    grounded auth_fact supports it. See spec section 1.5 — this is the
    rule that keeps 'unknown' from silently becoming 'unauthorized'."""
    test = db.get_test_result(test_id)
    if test is None:
        raise ValueError(f"no such test: {test_id}")

    facts = db.get_auth_facts(test["subject_id"], test["object_id"])
    acceptable_basis = {"ownership", "explicit_share", "observed_test", "declared_by_operator"}
    grounded = [f for f in facts if f["action"] == test["action"] and f["basis"] in acceptable_basis]

    if not grounded:
        db.update_test_result(test_id, verdict="inconclusive")
        return "inconclusive"

    fact = grounded[0]
    success = 200 <= (test["response_status"] or 0) < 300
    contradicts = (fact["expected"] == "denied" and success) or (fact["expected"] == "allowed" and not success)

    verdict = "confirmed" if contradicts else "rejected"
    db.update_test_result(test_id, verdict=verdict, verdict_basis_fact_id=fact["fact_id"])
    return verdict
