"""Automated tests for the IDOR harness + wiring. Everything here runs against
REAL round-trips: a local in-process HTTP target app, the real httpx send_fn,
and the real SSE MCP server over localhost. No mocks of the seams under test.

Run from the repo root:
    python -m unittest tests.test_harness -v
"""
from __future__ import annotations

import http.client
import json
import queue
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import mcp_tools                                   # noqa: E402
from src.config import HarnessConfig                        # noqa: E402
from src.db import Database                                 # noqa: E402
from src.differential_tester import ScopeError, ScopeGuard  # noqa: E402
from src.ingest import main as ingest_main                  # noqa: E402
from src.models import AuthFact, HarnessObject, Subject     # noqa: E402
from src.mcp_server import serve as serve_mcp               # noqa: E402
from src.endpoint_discovery import ingest_raw_request       # noqa: E402
from src.mcp_tools import ToolContext                       # noqa: E402
from src.ranker import rank_candidates                      # noqa: E402
from src.send_fn import make_httpx_send_fn                  # noqa: E402


# ---------------------------------------------------------------------------
# Real local "target app" — two accounts, bob's invoice is protected in the
# oracle's ground truth, but the app (deliberately, like crAPI) serves it to
# anyone: that gap is exactly what the harness must detect.
# ---------------------------------------------------------------------------

class TargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/invoices/"):
            # BOLA: no ownership check — any session gets any invoice.
            self._json(200, {"invoice_id": 202, "owner": "bob", "total": 100})
        elif self.path.startswith("/api/products"):
            self._json(200, {"products": []})
        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self):
        self._json(404, {"error": "not found"})


class HarnessTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="harness-test-", ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        # target app
        self.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        self.target_port = self.target.server_address[1]
        self.target_thread = threading.Thread(target=self.target.serve_forever, daemon=True)
        self.target_thread.start()
        # harness state
        self.cfg = HarnessConfig(allowed_hosts={"127.0.0.1"},
                                 db_path=str(self.root / "harness.db"),
                                 evidence_root=self.root / "evidence",
                                 max_requests_per_minute=120)
        self.db = Database(self.cfg.db_path, check_same_thread=False)
        self.guard = ScopeGuard(allowed_hosts=self.cfg.allowed_hosts,
                                max_requests_per_minute=self.cfg.max_requests_per_minute,
                                require_approval_for_writes=self.cfg.require_approval_for_writes)
        self.send_fn = make_httpx_send_fn()
        self.ctx = ToolContext(self.db, self.guard, self.send_fn, self.cfg.evidence_root)

    def tearDown(self):
        self.send_fn.close()
        self.db.conn.close()
        self.target.shutdown()
        self.target.server_close()
        self.tmp.cleanup()

    def seed(self):
        """Endpoints + two subjects + bob-owned invoice + ownership fact."""
        eid = ingest_raw_request(self.db, "GET",
                                 f"http://127.0.0.1:{self.target_port}/api/invoices/202",
                                 source="burp_history")
        subj_a = self.db.insert_subject(Subject(label="alice", role="standard_user", session_ref="sess-alice"))
        subj_b = self.db.insert_subject(Subject(label="bob", role="standard_user", session_ref="sess-bob"))
        obj = self.db.insert_object(HarnessObject(object_type="invoice",
                                                  owner_subject_id=subj_b, created_by_harness=True))
        self.db.add_auth_fact(AuthFact(subject_id=subj_a, object_id=obj, action="read",
                                       expected="denied", basis="ownership"))
        return eid, subj_a, subj_b, obj


class TestDiscoveryAndRanking(HarnessTestBase):
    def test_schema_loads_and_ingest_upserts(self):
        # SCHEMA_PATH resolves to the repo-root schema.sql (the src/ layout fix).
        self.assertTrue((ROOT / "schema.sql").exists())
        eid1 = ingest_raw_request(self.db, "GET", f"http://127.0.0.1:{self.target_port}/api/invoices/101", "burp_history")
        eid2 = ingest_raw_request(self.db, "GET", f"http://127.0.0.1:{self.target_port}/api/invoices/202", "burp_history")
        self.assertEqual(eid1, eid2, "same template must upsert, not duplicate")
        row = self.db.get_endpoint(eid1)
        self.assertEqual(row["observed_count"], 2)
        self.assertEqual(row["object_type_guess"], "invoice")

    def test_ranker_scores_high_value_and_drops_settled(self):
        ingest_raw_request(self.db, "GET", f"http://127.0.0.1:{self.target_port}/api/invoices/101", "burp_history")
        ingest_raw_request(self.db, "GET", f"http://127.0.0.1:{self.target_port}/api/products", "burp_history")
        ranked = rank_candidates(self.db)
        self.assertTrue(ranked, "expected at least one candidate")
        top = ranked[0]
        self.assertIn("high_value_type", top.reasons)
        # simulate a settled endpoint: verdict confirmed on the products one
        eid, subj_a, subj_b, obj = self.seed()
        t = mcp_tools.propose_test(self.ctx, hypothesis="x", endpoint_id=eid,
                                   subject_id=subj_a, object_id=obj, action="read")
        self.db.update_test_result(t["test_id"], verdict="confirmed")
        remaining = [s for s in rank_candidates(self.db)]
        self.assertNotIn(eid, [s.endpoint_id for s in remaining],
                         "settled endpoints must be excluded from candidates")


class TestExecuteAndOracle(HarnessTestBase):
    def test_full_flow_confirms_bola(self):
        eid, subj_a, subj_b, obj = self.seed()
        proposed = mcp_tools.propose_test(
            self.ctx,
            hypothesis="alice can read bob's invoice 202 via GET /api/invoices/{id}",
            endpoint_id=eid, subject_id=subj_a, object_id=obj, action="read")
        test_id = proposed["test_id"]
        self.assertEqual(proposed["status"], "proposed")

        out = mcp_tools.execute_test(
            self.ctx, test_id=test_id, method="GET", host="127.0.0.1",
            built_url=f"http://127.0.0.1:{self.target_port}/api/invoices/202",
            headers={"Cookie": "session=alice", "Accept": "application/json"}, body=b"")
        self.assertEqual(out["response_status"], 200)
        self.assertEqual(out["verdict"], "needs_review")
        # evidence written + credentials redacted
        ev = Path(out["evidence_dir"])
        self.assertTrue((ev / "request.txt").exists())
        self.assertIn("[REDACTED]", (ev / "request.txt").read_text())
        self.assertTrue((ev / "response.txt").exists())

        verdict = mcp_tools.record_verdict(self.ctx, test_id=test_id,
                                           rationale="200 with bob's data despite ownership fact")
        self.assertEqual(verdict["verdict"], "confirmed")
        row = self.db.get_test_result(test_id)
        self.assertIsNotNone(row["verdict_basis_fact_id"], "confirmation must cite the oracle fact")

    def test_no_facts_is_inconclusive_never_confirmed(self):
        eid, subj_a, subj_b, obj = self.seed()
        # remove the ground truth: unknown stays unknown
        self.db.conn.execute("DELETE FROM auth_facts")
        self.db.conn.commit()
        test_id = mcp_tools.propose_test(self.ctx, hypothesis="h", endpoint_id=eid,
                                         subject_id=subj_a, object_id=obj, action="read")["test_id"]
        mcp_tools.execute_test(self.ctx, test_id=test_id, method="GET", host="127.0.0.1",
                               built_url=f"http://127.0.0.1:{self.target_port}/api/invoices/202",
                               headers={}, body=b"")
        verdict = mcp_tools.record_verdict(self.ctx, test_id=test_id, rationale="no ground truth")
        self.assertEqual(verdict["verdict"], "inconclusive")

    def test_out_of_scope_host_fails_closed(self):
        eid, subj_a, subj_b, obj = self.seed()
        test_id = mcp_tools.propose_test(self.ctx, hypothesis="h", endpoint_id=eid,
                                         subject_id=subj_a, object_id=obj, action="read")["test_id"]
        with self.assertRaises(ScopeError):
            mcp_tools.execute_test(self.ctx, test_id=test_id, method="GET", host="evil.example",
                                   built_url="http://evil.example/api/invoices/202",
                                   headers={}, body=b"")

    def test_unapproved_write_rejected_approved_write_executes(self):
        eid, subj_a, subj_b, obj = self.seed()
        test_id = mcp_tools.propose_test(self.ctx, hypothesis="delete bob's invoice",
                                         endpoint_id=eid, subject_id=subj_a,
                                         object_id=obj, action="delete")["test_id"]
        url = f"http://127.0.0.1:{self.target_port}/api/invoices/202"
        with self.assertRaises(ScopeError):
            mcp_tools.execute_test(self.ctx, test_id=test_id, method="DELETE", host="127.0.0.1",
                                   built_url=url, headers={}, body=b"",
                                   operator_approved_write=False)
        out = mcp_tools.execute_test(self.ctx, test_id=test_id, method="DELETE", host="127.0.0.1",
                                     built_url=url, headers={}, body=b"",
                                     operator_approved_write=True)
        self.assertEqual(out["response_status"], 404)  # executed (needs_review), not blocked


class TestIngestCli(HarnessTestBase):
    def test_ingest_main_reads_jsonl(self):
        cap = self.root / "captures"
        cap.mkdir()
        f = cap / "burp-history-test.jsonl"
        f.write_text("\n".join([
            json.dumps({"method": "GET", "url": f"http://127.0.0.1:{self.target_port}/api/invoices/101"}),
            json.dumps({"method": "GET", "url": f"http://127.0.0.1:{self.target_port}/api/invoices/202"}),
            "{ not json at all",
            json.dumps({"method": "", "url": "missing-method.example.com"}),
        ]) + "\n")
        rc = ingest_main(["--db", str(self.root / "ing.db"), str(cap)])
        self.assertEqual(rc, 0)
        db = Database(str(self.root / "ing.db"))
        rows = db.list_endpoints()
        self.assertEqual(len(rows), 1, "two requests collapse into one endpoint")
        self.assertEqual(rows[0]["observed_count"], 2)
        self.assertEqual(rows[0]["source"], "burp_history")


# ---------------------------------------------------------------------------
# MCP server over the real wire (SSE + JSON-RPC), with a minimal client that
# mirrors agent/mcp.mjs — this is the seam the Node coordinator depends on.
# ---------------------------------------------------------------------------

class MiniMcpClient:
    def __init__(self, port):
        self.port = port
        self._id = 0
        self.buf = ""
        self.resp = None

    def connect(self):
        self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.conn.request("GET", "/", headers={"Accept": "text/event-stream"})
        self.resp = self.conn.getresponse()
        assert self.resp.status == 200, self.resp.status
        ev = self._next_event()
        assert ev["event"] == "endpoint", ev
        self.post_path = ev["data"]

    def _read_more(self):
        chunk = self.resp.fp.read(1)
        if not chunk:
            raise AssertionError("SSE stream closed")
        self.buf += chunk.decode()

    def _next_event(self, timeout=10.0):
        import time as _t
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            if "\n\n" in self.buf.replace("\r\n", "\n"):
                raw, self.buf = self.buf.replace("\r\n", "\n").split("\n\n", 1)
                ev, data = "message", []
                for line in raw.split("\n"):
                    if line.startswith("event:"):
                        ev = line[6:].strip()
                    elif line.startswith("data:"):
                        data.append(line[5:].lstrip(" "))
                return {"event": ev, "data": "\n".join(data)}
            self._read_more()
        raise AssertionError("timeout waiting for SSE event")

    def rpc(self, method, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": params or {}})
        post = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        post.request("POST", self.post_path, body=body,
                     headers={"Content-Type": "application/json"})
        r = post.getresponse()
        assert r.status == 202, (r.status, r.read())
        r.read()
        post.close()
        while True:
            ev = self._next_event()
            if ev["event"] != "message":
                continue
            m = json.loads(ev["data"])
            if m.get("id") == self._id:
                return m

    def call(self, name, args):
        return self.rpc("tools/call", {"name": name, "arguments": args})


class TestMcpServerOverTheWire(HarnessTestBase):
    def start_server(self, **kw):
        httpd = serve_mcp(self.cfg, self.guard, self.ctx, host="127.0.0.1", port=0, **kw)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        return port

    def test_handshake_list_tools_and_full_loop(self):
        port = self.start_server(approve_writes=False, max_calls=50)
        c = MiniMcpClient(port)
        c.connect()
        init = c.rpc("initialize", {"protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "0"}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "idor-harness")
        tools = c.rpc("tools/list")
        self.assertEqual(len(tools["result"]["tools"]), 8)

        # seed ground truth, then run the model's whole loop over the wire
        eid, subj_a, subj_b, obj = self.seed()
        r = c.call("list_candidate_endpoints", {})
        cands = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["path_template"], "/api/invoices/{id}")
        r = c.call("get_known_auth_facts", {"subject_id": subj_a, "object_id": obj})
        facts = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(facts[0]["expected"], "denied")

        r = c.call("propose_test", {
            "hypothesis": "alice can read bob's invoice 202",
            "endpoint_id": eid, "subject_id": subj_a, "object_id": obj, "action": "read"})
        self.assertFalse(r["result"].get("isError"))
        test_id = json.loads(r["result"]["content"][0]["text"])["test_id"]

        r = c.call("execute_test", {
            "test_id": test_id, "method": "GET", "host": "127.0.0.1",
            "built_url": f"http://127.0.0.1:{self.target_port}/api/invoices/202",
            "headers": {"Cookie": "session=alice"}})
        self.assertFalse(r["result"].get("isError"), r["result"])
        executed = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(executed["response_status"], 200)
        self.assertEqual(executed["verdict"], "needs_review")

        # write test must fail closed: approval is server config, not a tool arg
        r = c.call("execute_test", {
            "test_id": test_id, "method": "DELETE", "host": "127.0.0.1",
            "built_url": f"http://127.0.0.1:{self.target_port}/api/invoices/202",
            "headers": {}, "operator_approved_write": True})  # model tries to self-approve
        self.assertTrue(r["result"].get("isError"), "self-approval must not work")

        r = c.call("record_verdict", {"test_id": test_id, "rationale": "got bob's data"})
        verdict = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(verdict["verdict"], "confirmed")

        r = c.call("get_test_result", {"test_id": test_id})
        row = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(row["verdict"], "confirmed")

        # out-of-scope host over the wire
        r = c.call("execute_test", {"test_id": test_id, "method": "GET",
                                    "host": "evil.example",
                                    "built_url": "http://evil.example/x", "headers": {}})
        self.assertTrue(r["result"].get("isError"))

        # unknown tool -> JSON-RPC error, not a crash
        r = c.call("not_a_tool", {})
        self.assertIn("error", r)

        # budget enforcement
        for _ in range(60):
            c.call("list_candidate_endpoints", {})
        r = c.call("list_candidate_endpoints", {})
        self.assertTrue(r["result"].get("isError"), "budget must eventually be exceeded")


if __name__ == "__main__":
    unittest.main(verbosity=2)