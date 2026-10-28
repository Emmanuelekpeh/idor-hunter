# IDOR/BOLA Hunting Harness — Prototype Specification

Scope: authorized bug bounty / pentest engagements only. This system never
widens target scope on its own and never fires state-changing requests
without explicit operator approval.

## 0. Design principles (carried over from the research conversation)

- The LLM is a **hypothesis generator and interpreter**, not the detector.
  Deterministic code owns discovery, bookkeeping, request replay, and diffing.
- Persistent state (SQLite) means the model never re-reads raw Burp history;
  it queries normalized records.
- "Unknown" is a first-class permission state. The system never infers
  "unauthorized" just because a response differs — it has to be grounded in
  a known ownership/sharing fact.
- Every finding carries the evidence that produced it (raw request/response
  pair, identities used, ownership facts) so it's reproducible without the
  model.

---

## 1. Data model

### 1.1 Endpoint record

One row per **normalized operation**, not per raw request. Several captured
requests collapse into one endpoint record via path templating (`/invoices/101`
and `/invoices/202` → `/invoices/{id}`).

```python
Endpoint = {
    "endpoint_id": "uuid",
    "method": "GET|POST|PATCH|PUT|DELETE",
    "path_template": "/api/invoices/{id}",         # params templated out
    "host": "target.example.com",
    "source": "burp_history|katana|openapi|graphql_introspection|js_route",
    "id_locations": [                              # where object refs live
        {"in": "path", "name": "id", "type": "int|uuid|opaque"},
        {"in": "query", "name": "invoiceId", "type": "int"},
        {"in": "json_body", "path": "$.invoice_id", "type": "int"},
        {"in": "graphql_variable", "name": "invoiceId", "type": "global_id"},
        {"in": "header", "name": "X-Account-Id", "type": "uuid"},
    ],
    "content_type": "application/json|graphql|form",
    "auth_scheme": "cookie|bearer|api_key|none",
    "observed_count": 7,                            # how many raw requests collapsed in
    "first_seen": "iso8601",
    "last_seen": "iso8601",
    "object_type_guess": "invoice",                 # heuristic, confirmed later
    "related_endpoint_ids": ["uuid", "uuid"],        # same-object cluster (see 1.4)
    "tags": ["read", "write", "export", "admin"],
}
```

### 1.2 Subject (identity) model

```python
Subject = {
    "subject_id": "uuid",
    "label": "test_account_A",
    "role": "standard_user|admin|anonymous|service",
    "tenant_id": "uuid|null",
    "session_ref": "burp_session_handle",           # harness looks up live creds; never in prompts
    "created_for_test": true,
}
```

### 1.3 Object model

```python
Object = {
    "object_id": "uuid",                            # harness-assigned, stable
    "object_type": "invoice",
    "native_ids": [                                  # the app's own identifiers for this object
        {"endpoint_id": "uuid", "value": "101", "value_type": "int"},
        {"endpoint_id": "uuid", "value": "VXZ...==", "value_type": "graphql_global_id"},
    ],
    "owner_subject_id": "uuid|null",
    "tenant_id": "uuid|null",
    "sharing": [                                     # explicit grants, so "success" isn't auto-flagged
        {"subject_id": "uuid", "permission": "read", "source": "observed|declared"}
    ],
    "created_by_harness": true,                       # prefer test-owned objects for write tests
}
```

### 1.4 Relationship model (endpoint/object graph)

Edges between endpoints or objects, typed per the taxonomy from the research
(direct, nested/relationship, action-level, indirect/alternate-path):

```python
Relationship = {
    "relationship_id": "uuid",
    "from_id": "uuid",            # endpoint_id or object_id
    "from_kind": "endpoint|object",
    "to_id": "uuid",
    "to_kind": "endpoint|object",
    "relation": "creates|reads|updates|deletes|downloads|shares|belongs_to|references",
    "confidence": 0.0-1.0,
    "evidence_ref": "uuid",       # points at the observation that suggested this edge
}
```

Store in SQLite as plain tables (`endpoints`, `objects`, `relationships`,
`sharing_grants`) with a join query for traversal. No graph DB needed at
this scale.

### 1.5 Authorization oracle

The source of truth the differential tester and the model both check
against before calling anything a finding:

```python
AuthFact = {
    "fact_id": "uuid",
    "subject_id": "uuid",
    "object_id": "uuid",
    "action": "read|update|delete|download|share|export",
    "expected": "allowed|denied|unknown",
    "basis": "ownership|explicit_share|role|observed_test|declared_by_operator",
}
```

Rule: a test result can only become a **confirmed finding** if the observed
outcome contradicts an `AuthFact` whose basis is `ownership`, `explicit_share`,
or `observed_test` — never `unknown`.

### 1.6 Test / evidence record

```python
TestResult = {
    "test_id": "uuid",
    "hypothesis": "subject B can read object owned by subject A via GET /api/invoices/{id}",
    "endpoint_id": "uuid",
    "subject_id": "uuid",
    "object_id": "uuid",
    "action": "read",
    "request_raw": "base64 or stored file ref",
    "response_raw": "base64 or stored file ref",
    "response_status": 200,
    "response_fingerprint": "normalized structural hash",
    "diff_against": "test_id of the baseline comparison, if any",
    "verdict": "confirmed|rejected|inconclusive|needs_review",
    "verdict_basis_fact_id": "uuid|null",
    "confidence": 0.0-1.0,
    "model_rationale": "free text, logged separately from the verdict",
    "timestamp": "iso8601",
}
```

Keep `request_raw`/`response_raw` as files on disk (referenced by hash), not
inline blobs in SQLite — keeps the DB small and evidence inspectable with
normal tools.

---

## 2. Tool interfaces (what the model is allowed to call)

Expose a **narrow, typed** tool surface through Burp MCP. The model never
gets raw HTTP send capability — only these:

| Tool | Purpose | Notes |
|---|---|---|
| `list_candidate_endpoints(filter)` | Pull ranked, unexplored endpoints | Paginated; filter by object_type, tag, min_score |
| `get_endpoint_detail(endpoint_id)` | Full endpoint record + related objects/relationships | Read-only |
| `get_object_graph(object_id, depth)` | Local neighborhood of an object | For spotting alternate-path candidates |
| `get_known_auth_facts(subject_id, object_id)` | What's already established | Model must check before hypothesizing |
| `propose_test(hypothesis, endpoint_id, subject_id, object_id, action)` | Model's only "write" action | Returns a `test_id`, does **not** execute anything yet |
| `execute_test(test_id)` | Harness-gated replay of the proposed test | Enforces scope, rate limit, method allow-list; write actions require operator approval flag |
| `get_test_result(test_id)` | Retrieve evidence + fingerprint diff | Read-only |
| `record_verdict(test_id, verdict, rationale, basis_fact_id)` | Model states its conclusion | Harness still validates against the oracle before accepting `confirmed` |

This mirrors the "model proposes, harness executes" split from the original
plan — `propose_test` and `execute_test` are deliberately separate calls so
scope/rate-limit/approval checks sit between hypothesis and action.

---

## 3. Candidate ranking rules

Score each unexplored endpoint (0–100) before it's surfaced to the model:

| Factor | Weight | Rationale |
|---|---|---|
| Has an ID-bearing param with a known sibling object owned by a different test subject | +30 | Direct cross-account test is immediately runnable |
| Object type matches a high-value pattern (invoice, document, profile, order, attachment, tenant) | +15 | From the taxonomy's highest-yield categories |
| Endpoint is an alternate path to an already-tested object (download/export/share variant of a protected read) | +20 | Action-level BOLA was ~42% of confirmed cases in the cited empirical sample — worth the weight |
| GraphQL global ID or opaque identifier present | +10 | Under-covered by naive sequential-ID scanners |
| Nested/tenant-scoped path (`/orgs/{id}/projects/{id}`) | +10 | Relationship-authorization category |
| Already has a `confirmed` or `rejected` verdict for this subject/object/action triple | −100 (exclude) | No point re-testing a settled fact |
| Write/destructive method without a test-owned target object available | −25 | Push write tests toward harness-created objects only |

Ties broken by `observed_count` descending (prefer endpoints seen in real
authenticated workflows over ones only found by a crawler).

---

## 4. Evidence format (on-disk)

```
/evidence/{test_id}/
    request.txt          # raw HTTP, redacted of credentials in any copy shown to the model
    response.txt
    meta.json             # TestResult record
    diff.json             # structural diff vs. baseline test_id, if applicable
```

`meta.json` is the only thing that goes in the report; `request.txt`/
`response.txt` are the reproduction artifact for human review and must never
be deleted on a `confirmed` or `needs_review` verdict.

---

## 5. Benchmark plan

Target: OWASP crAPI (and optionally a second deliberately-vulnerable app) run
locally.

**5.1 Known-vulnerability map.** Before running anything, hand-catalog
crAPI's known IDOR/BOLA cases into the four categories (direct, nested,
action-level, indirect/alternate-path) — this is the ground truth the
pipeline is scored against.

**5.2 Experiment 1 — baseline detection.** Direct-object differential testing
only (category A). Record true positives, false positives, requests per
confirmed case, wall-clock time.

**5.3 Experiment 2 — action-graph addition.** Add the object/relationship
graph and alternate-path candidate generation (categories B–D). Measure
incremental confirmed findings over Experiment 1, and whether false-positive
rate changes.

**5.4 Experiment 3 — model ablation.** Same pipeline, three conditions:
no LLM (rules-only ranking + auto-diff), 3B/4B model, 8B model. Metrics:
confirmed findings per 100 requests sent, false-positive rate, p50/p95
latency per test, peak RSS.

**5.5 Pass criteria before expanding scope.** Don't build multi-agent
orchestration, embeddings, or fine-tuning until Experiment 3 shows the model
condition beats rules-only on confirmed-findings-per-request by a margin
that's worth the added latency/memory — otherwise the model's role should
stay narrow (hypothesis text + rationale) rather than growing.

---

## 6. Open items (gaps to close during build, not before)

- Response fingerprinting rule for "same structure, different owner's data"
  vs. "generic success/error page" — needs a few real crAPI responses to
  tune before it's trustworthy.
- GraphQL global ID decoding (most are base64 of `Type:native_id`) as a
  first-class `id_locations` type rather than opaque.
- Rate-limit/backoff policy shared between `execute_test` and any Nuclei/
  Katana discovery pass so the two don't double up on request volume.
- Operator-approval UI for write-action `execute_test` calls — out of scope
  for the prototype; stub it as a CLI confirm prompt first.
