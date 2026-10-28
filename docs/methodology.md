# Bug-bounty methodology (seed reference for the agent)

This is the agent's starting playbook. Extend it — the agent can read it with
`read_doc("methodology")` and you can drop more `.md`/`.txt` files into `docs/`.

## Operating principles
1. **Authorization first.** Only test in-scope targets from the program brief.
   Record scope in memory (`remember`) as soon as it is known.
2. **Recon before traffic.** Read `get_proxy_http_history` / organizer state
   before sending anything. Understand what Burp already saw.
3. **Read-only first, gated writes.** Passive analysis is free; intercept,
   replay, intruder, and engine changes require operator approval (gates).
4. **One hypothesis per burst.** Form a hypothesis, test it, record the result
   with `remember()`, then move on. Hand off with `ask_user` at decision points.

## Workflow sketch
1. **Scope & target** — confirm with operator; record program rules (rate
   limits, out-of-scope hosts, safe-harbor).
2. **Map** — proxy history → sitemap-ish picture: hosts, endpoints, params,
   auth flow, interesting content types.
3. **Triage** — rank attack surface: authz boundaries, IDOR-shaped endpoints,
   file upload, redirectors, injection sinks, JWT/session handling.
4. **Test** — use Repeater for single careful probes; Intruder only with
   operator sign-off and a rate plan. Encode payloads with Burp's codec tools.
5. **Evidence** — for every candidate finding, capture: request, response,
   why it matters, repro steps. `remember()` the durable facts.
6. **Report shape** — title, severity guess, impact, repro, evidence, fix
   suggestion. Hand off to the operator for review before any disclosure.

## Notes
- Keep payloads non-destructive; no exfil of real user data — prove with the
  minimum (e.g. your own account, canary values).
- If blocked (WAF, rate limit), stop and ask the operator rather than hammering.
