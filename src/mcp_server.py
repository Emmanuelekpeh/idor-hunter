"""MCP server exposing the harness tool surface (spec section 2) to LLM clients.

Transport mirrors Burp's official MCP server: SSE downlink (GET /) + JSON-RPC
POST uplink (/message?sessionId=...), so the existing zero-dependency Node
client (agent/mcp.mjs), the verify scripts, and Kilo all connect unmodified.
The spec's "expose the tools through Burp MCP" line was a design error —
PortSwigger's server only serves Burp's own tools — so the harness serves its
own; Burp stays the traffic/session source alongside it.

Policy layer (deliberately NOT model-controllable):
- `operator_approved_write` comes from server config (--approve-writes /
  HARNESS_APPROVE_WRITES env), never from tool arguments. Without it, every
  write-method execute_test fails closed with a ScopeError.
- `allowed_hosts` comes from --allow / HARNESS_ALLOWED_HOSTS. An empty list
  fails closed: every execute_test is rejected.
- Per-session tool-call budget (--max-tool-calls) with MAPTA-style usage
  logging: every call is logged with latency; over-budget calls are refused.
  MAPTA found success correlates negatively with resource burn, so budgets are
  a feature, not a guardrail afterthought.

Usage (from the repo root):
    python -m src.mcp_server --allow localhost,target.example.com --db harness.db
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import queue
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import mcp_tools
from .config import HarnessConfig
from .db import Database
from .differential_tester import ScopeGuard
from .mcp_tools import ToolContext
from .send_fn import make_httpx_send_fn

SERVER_INFO = {"name": "idor-harness", "version": "0.1.0"}
PROTOCOL_VERSION = "2024-11-05"

# ---------------------------------------------------------------------------
# Tool schemas — the model's entire action space (spec section 2).
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "list_candidate_endpoints",
        "description": "Return ranked IDOR candidate endpoints, highest score first. "
                       "Call this first. Optional filters: object_type (e.g. 'invoice'), "
                       "min_score, limit (default 25).",
        "inputSchema": {"type": "object", "properties": {
            "object_type": {"type": "string"},
            "min_score": {"type": "integer"},
            "limit": {"type": "integer"},
        }, "required": []},
    },
    {
        "name": "get_endpoint_detail",
        "description": "Full record for one endpoint: method, path template, host, id "
                       "locations, tags, object-type guess.",
        "inputSchema": {"type": "object", "properties": {
            "endpoint_id": {"type": "string"},
        }, "required": ["endpoint_id"]},
    },
    {
        "name": "get_object_graph",
        "description": "Relationship edges touching one object — use to spot alternate "
                       "paths (download/export/share) to the same object.",
        "inputSchema": {"type": "object", "properties": {
            "object_id": {"type": "string"},
            "depth": {"type": "integer"},
        }, "required": ["object_id"]},
    },
    {
        "name": "get_known_auth_facts",
        "description": "What is already established about (subject, object): expected "
                       "allowed/denied per action and the basis for it. ALWAYS check "
                       "before proposing a test — a confirmed finding must contradict "
                       "a grounded fact (ownership / explicit_share / observed_test).",
        "inputSchema": {"type": "object", "properties": {
            "subject_id": {"type": "string"},
            "object_id": {"type": "string"},
        }, "required": ["subject_id", "object_id"]},
    },
    {
        "name": "get_test_result",
        "description": "Retrieve one test's evidence: response status, fingerprint, "
                       "verdict, verdict basis, model rationale.",
        "inputSchema": {"type": "object", "properties": {
            "test_id": {"type": "string"},
        }, "required": ["test_id"]},
    },
    {
        "name": "propose_test",
        "description": "Record an IDOR hypothesis. Sends NOTHING — returns a test_id "
                       "for execute_test. State clearly what result would support or "
                       "reject the hypothesis.",
        "inputSchema": {"type": "object", "properties": {
            "hypothesis": {"type": "string"},
            "endpoint_id": {"type": "string"},
            "subject_id": {"type": "string"},
            "object_id": {"type": "string"},
            "action": {"type": "string", "description": "read|update|delete|download|share|export"},
        }, "required": ["hypothesis", "endpoint_id", "subject_id", "object_id", "action"]},
    },
    {
        "name": "execute_test",
        "description": "Harness-gated replay of a proposed test — the ONLY tool that "
                       "sends live HTTP. Host scope, rate limit, and write approval are "
                       "enforced server-side and cannot be bypassed from here. "
                       "body_b64 is the base64 of the raw request body (optional).",
        "inputSchema": {"type": "object", "properties": {
            "test_id": {"type": "string"},
            "method": {"type": "string"},
            "host": {"type": "string"},
            "built_url": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body_b64": {"type": "string"},
            "baseline_test_id": {"type": "string"},
        }, "required": ["test_id", "method", "host", "built_url"]},
    },
    {
        "name": "record_verdict",
        "description": "State your conclusion with rationale. The harness adjudicates "
                       "against the auth_facts oracle — 'confirmed' is only accepted "
                       "when the evidence contradicts a grounded fact.",
        "inputSchema": {"type": "object", "properties": {
            "test_id": {"type": "string"},
            "rationale": {"type": "string"},
        }, "required": ["test_id", "rationale"]},
    },
]
TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}

# ---------------------------------------------------------------------------
# Session plumbing
# ---------------------------------------------------------------------------

class Session:
    def __init__(self):
        self.events: queue.Queue = queue.Queue()
        self.calls = 0


SESSIONS: dict[str, Session] = {}
SESSIONS_LOCK = threading.Lock()
DISPATCH_LOCK = threading.Lock()   # serializes tool dispatch (sqlite is one connection)

# Set by serve():
CTX: ToolContext | None = None
APPROVE_WRITES = False
MAX_CALLS = 200


def _sse(handler: BaseHTTPRequestHandler, status: int = 200) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()


def _push(session: Session, obj: dict) -> None:
    session.events.put(json.dumps(obj, default=str))


def _coerce_args(name: str, raw: dict) -> dict:
    """Best-effort type coercion per the tool schema (str->int, JSON str->dict).
    Clients like the Node agent already validate; this catches other clients."""
    args = dict(raw or {})
    props = TOOLS_BY_NAME[name]["inputSchema"]["properties"]
    for key, spec in props.items():
        if key not in args:
            continue
        t = spec.get("type")
        v = args[key]
        if t == "integer" and isinstance(v, str) and v.strip().lstrip("-").isdigit():
            args[key] = int(v)
        if t == "object" and isinstance(v, str):
            try:
                args[key] = json.loads(v)
            except json.JSONDecodeError:
                pass
        if t == "string" and not isinstance(v, str):
            args[key] = str(v)
    return args


def dispatch_tool(name: str, raw_args: dict, session: Session) -> tuple[str, bool]:
    """Returns (text, is_error). Policy lives here, not in mcp_tools."""
    global CTX
    assert CTX is not None
    if name not in TOOLS_BY_NAME:
        raise KeyError(name)
    if name == "execute_test":
        # Budget + scope + write-approval checks run inside execute_test
        # (ScopeGuard); here we only add the server's policy flags.
        args = _coerce_args(name, raw_args)
        body = base64.b64decode(args.pop("body_b64", "") or "") or b""
        args.pop("operator_approved_write", None)  # never model-settable
        args["body"] = body
        args["operator_approved_write"] = APPROVE_WRITES
    else:
        args = _coerce_args(name, raw_args)

    missing = [k for k in TOOLS_BY_NAME[name]["inputSchema"].get("required", []) if k not in args]
    if missing:
        return (f"error: missing required argument(s) for {name}: {', '.join(missing)}. "
                f"Schema: {json.dumps(TOOLS_BY_NAME[name]['inputSchema'])}"), True

    t0 = time.perf_counter()
    try:
        fn = getattr(mcp_tools, name)
        with DISPATCH_LOCK:  # one tool at a time: sqlite conn + ScopeGuard state
            result = fn(CTX, **args)
        ms = (time.perf_counter() - t0) * 1000
        print(f"[usage] {name} ok in {ms:.0f}ms (session calls: {session.calls})", flush=True)
        return json.dumps(result, default=str), False
    except Exception as e:  # ScopeError, KeyError from db lookups, httpx errors...
        ms = (time.perf_counter() - t0) * 1000
        print(f"[usage] {name} ERROR in {ms:.0f}ms: {type(e).__name__}: {e}", flush=True)
        return f"error: {type(e).__name__}: {e}", True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):  # default logging is noisy per-POST
        pass

    # -- SSE downlink ------------------------------------------------------
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        session = Session()
        session_id = uuid.uuid4().hex
        with SESSIONS_LOCK:
            SESSIONS[session_id] = session
        _sse(self)
        self.wfile.write(f"event: endpoint\ndata: /message?sessionId={session_id}\n\n".encode())
        self.wfile.flush()
        try:
            while True:
                try:
                    item = session.events.get(timeout=15)
                    self.wfile.write(f"event: message\ndata: {item}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")  # detect dead sockets
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with SESSIONS_LOCK:
                SESSIONS.pop(session_id, None)

    # -- JSON-RPC uplink ----------------------------------------------------
    def do_POST(self):
        if not self.path.startswith("/message"):
            self.send_error(404)
            return
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        sid = (qs.get("sessionId") or [None])[0]
        with SESSIONS_LOCK:
            session = SESSIONS.get(sid)
        if session is None:
            self.send_error(400, "unknown sessionId — open the SSE stream first")
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "bad JSON")
            return
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

        if msg.get("id") is None:  # notification (notifications/initialized etc.)
            return
        method = msg.get("method", "")
        req_id = msg["id"]

        if method == "initialize":
            _push(session, {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }})
        elif method == "tools/list":
            _push(session, {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            args = (msg.get("params") or {}).get("arguments") or {}
            if name not in TOOLS_BY_NAME:
                _push(session, {"jsonrpc": "2.0", "id": req_id, "error": {
                    "code": -32602, "message": f"unknown tool: {name}"}})
                return
            with SESSIONS_LOCK:
                session.calls += 1
                calls = session.calls
            if calls > MAX_CALLS:
                _push(session, {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text",
                                 "text": f"error: tool-call budget exceeded ({MAX_CALLS} calls "
                                         f"this session). Start a new session or restart the "
                                         f"server with --max-tool-calls."}],
                    "isError": True}})
                return
            text, is_err = dispatch_tool(name, args, session)
            _push(session, {"jsonrpc": "2.0", "id": req_id, "result": {
                "content": [{"type": "text", "text": text}], "isError": is_err}})
        elif method == "ping":
            _push(session, {"jsonrpc": "2.0", "id": req_id, "result": {}})
        else:
            _push(session, {"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601, "message": f"method not found: {method}"}})


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def serve(cfg: HarnessConfig, guard: ScopeGuard, ctx: ToolContext,
          host: str = "127.0.0.1", port: int = 8765,
          approve_writes: bool = False, max_calls: int = 200) -> ThreadingHTTPServer:
    """Programmatic entry (used by tests). Blocks never — returns the server."""
    global CTX, APPROVE_WRITES, MAX_CALLS
    CTX = ctx
    APPROVE_WRITES = approve_writes
    MAX_CALLS = max_calls
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def main(argv=None) -> int:
    global APPROVE_WRITES, MAX_CALLS
    ap = argparse.ArgumentParser(description="IDOR harness MCP server (SSE transport, Burp-compatible).")
    ap.add_argument("--db", default="harness.db")
    ap.add_argument("--evidence", default="./evidence")
    ap.add_argument("--allow", default=os.environ.get("HARNESS_ALLOWED_HOSTS", ""),
                    help="comma-separated in-scope hosts. Empty = execute_test fails closed.")
    ap.add_argument("--host", default="127.0.0.1", help="listen address")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--max-rpm", type=int, default=30)
    ap.add_argument("--approve-writes", action="store_true",
                    default=os.environ.get("HARNESS_APPROVE_WRITES", "") == "1",
                    help="operator grants write-test approval for this server run")
    ap.add_argument("--max-tool-calls", type=int, default=200,
                    help="per-session tool-call budget (MAPTA-style)")
    args = ap.parse_args(argv)

    allowed = {h.strip() for h in args.allow.split(",") if h.strip()}
    cfg = HarnessConfig(allowed_hosts=allowed, db_path=args.db,
                        evidence_root=Path(args.evidence),
                        max_requests_per_minute=args.max_rpm)
    APPROVE_WRITES = args.approve_writes
    MAX_CALLS = args.max_tool_calls

    db = Database(cfg.db_path, check_same_thread=False)
    guard = ScopeGuard(allowed_hosts=cfg.allowed_hosts,
                       max_requests_per_minute=cfg.max_requests_per_minute,
                       require_approval_for_writes=cfg.require_approval_for_writes)
    send_fn = make_httpx_send_fn()
    ctx = ToolContext(db, guard, send_fn, cfg.evidence_root)

    httpd = serve(cfg, guard, ctx, host=args.host, port=args.port,
                  approve_writes=args.approve_writes, max_calls=args.max_tool_calls)
    print(f"idor-harness MCP server {SERVER_INFO['version']} on http://{args.host}:{args.port}/")
    print(f"  db: {cfg.db_path}   evidence: {cfg.evidence_root}")
    print(f"  allowed hosts: {', '.join(sorted(allowed)) or '(NONE — execute_test will fail closed)'}")
    print(f"  write approval: {'GRANTED (--approve-writes)' if args.approve_writes else 'required per call (writes fail closed)'}")
    print(f"  budget: {MAX_CALLS} tool calls/session, {guard.max_requests_per_minute} req/min")
    print("  tools: " + ", ".join(TOOLS_BY_NAME))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        httpd.shutdown()
        send_fn.close()
        db.conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())