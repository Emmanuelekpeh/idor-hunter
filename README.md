# IDOR / BOLA Testing Harness

**A safety-first harness for authorized differential authorization testing, with a narrow MCP tool surface for LLM-driven agents.**

> **Status: research prototype.** It detects and ranks IDOR/BOLA candidates, executes differential tests against an auth-facts oracle, and stores evidence — but several pieces are deliberately stubbed (see [What is not implemented](#what-is-not-implemented)). Unfinished code is labelled, not hidden.

> **Authorized use only.** This is a testing instrument for bug-bounty programs and client engagements where you have written authorization. There is a deliberately vulnerable app in `target/` for local development — point the harness there. Do not point it at systems you do not have permission to test.

---

## Why this exists

Most "IDOR scanner" projects are payload lists. The interesting engineering problem is not sending requests — it is **staying inside scope while remaining useful**, and producing evidence a triager will accept.

So the design puts constraints first:

- **`ScopeGuard`** (`src/differential_tester.py`) refuses any request to a host outside the engagement's allow-list, enforces per-host rate limits, and blocks write-method tests unless the operator has explicitly approved them.
- **Read-only by default.** Passive analysis is unrestricted; mutating tests are gated.
- **Evidence capture is first-class** (`src/evidence.py`) — every candidate finding stores the request, the response, and the reason it was flagged, so a report can be assembled from artifacts rather than memory.
- **A narrow MCP tool surface** (`src/mcp_tools.py`) gives an LLM agent a small allow-list of operations it may call. The model cannot reach the network directly; it can only ask for the operations the harness exposes. That is the point — the harness, not the model, holds the authority.

That last design choice is what makes the agent layer safe to run at all, and it is the part I would most want reviewed.

## Architecture

```
schema.sql               # SQLite schema for engagements, endpoints, candidates, evidence
src/
  models.py              # dataclasses mirroring schema.sql
  db.py                  # SQLite persistence, no ORM
  endpoint_discovery.py  # raw request -> normalized Endpoint / IdLocation (Pass 1-2)
  ranker.py              # candidate scoring with human-readable reasons
  differential_tester.py # execute_test + adjudicate against the auth_facts oracle, ScopeGuard
  evidence.py            # on-disk request/response storage
  mcp_tools.py           # the narrow tool surface an agent is allowed to call
  mcp_server.py          # MCP server wiring
  config.py              # per-engagement operator config
agent/                   # LLM agent loop over the MCP tool surface
docs/methodology.md      # operating playbook the agent is seeded with
idor-hunter-spec.md      # the design spec this was built against
tests/test_harness.py    # unit tests, including ScopeGuard refusal cases
target/vuln-app.mjs      # deliberately vulnerable local app for development only
```

## How detection works

1. **Ingest** captured traffic (Burp history export or MCP read) into normalized endpoints, identifying parameters and path segments that carry object identifiers.
2. **Rank** candidates by how IDOR-shaped they are — identifier type, auth boundary crossed, object sensitivity, sibling-endpoint patterns — each with an explicit reason string rather than an opaque score.
3. **Test** a candidate by replaying the request as two different identities and comparing against the auth-facts oracle: same resource returned to a principal who should not have it is the signal.
4. **Adjudicate** with response fingerprinting that strips dynamic fields before comparison, so timestamps and request IDs do not produce false positives.
5. **Store** evidence for every verdict.

## What is not implemented

Deliberately stubbed, and labelled as such in code:

- **A real `send_fn`.** `execute_test` takes `send_fn` as an injected dependency; the Burp MCP wiring exists (`scripts/verify-burp-mcp.mjs`, `run-burp-mcp.ps1`) but the default path is a stub so tests stay hermetic.
- **Response fingerprinting heuristics** are a rough structural hash. `_strip_dynamic_fields` needs tuning against real targets before verdicts should be trusted.
- **GraphQL global ID decoding** — not implemented.
- **Operator-approval UI** for write tests. `operator_approved_write` is a boolean today; it should be backed by a confirm prompt.
- **Calibration suite** against OWASP crAPI is designed (spec §5) but not automated.

## Quick start

```bash
pip install -r requirements.txt

# Run the local vulnerable target
node target/vuln-app.mjs

python -c "
from src.db import Database
from src.config import HarnessConfig
from src.endpoint_discovery import ingest_raw_request
from src.ranker import rank_candidates

cfg = HarnessConfig(allowed_hosts={'127.0.0.1'})
db = Database(cfg.db_path)
ingest_raw_request(db, 'GET', 'http://127.0.0.1:3000/api/invoices/101', source='burp_history')
for c in rank_candidates(db, limit=10):
    print(c.score, c.reasons)
"
```

```bash
python -m pytest tests/ -v
```

## Responsible use

- Only test systems you have **written authorization** to test, and stay inside the program's stated scope.
- Prefer **non-destructive proof**: demonstrate access with your own account or canary values rather than exfiltrating real user data.
- If you hit a WAF or rate limit, **stop** — do not hammer the target.
- Report findings through the program's disclosure channel. Do not publish another party's data.
- The `ScopeGuard` exists to make these rules enforceable rather than aspirational. Do not bypass it.

## License

MIT — see [LICENSE](LICENSE). The license grants use of the software; it does not grant authorization to test any particular system.
