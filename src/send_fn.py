"""The harness's live-HTTP backend. `differential_tester.execute_test` takes
`send_fn` as an injected dependency so the sending layer is swappable; this is
the default production implementation over httpx (direct, works headless —
good for the crAPI benchmark loop).

A Burp-backed variant (routing through Burp MCP's `send_http1_request` so all
harness traffic stays visible in Burp) is the planned second backend — see
backlog.md. Both must satisfy `differential_tester.SendFn`:

    (method, built_url, headers, body) -> (status_code, response_headers, body_bytes)
"""
from __future__ import annotations

from typing import Callable

import httpx

SendFn = Callable[[str, str, dict, bytes], tuple[int, dict, bytes]]


def make_httpx_send_fn(timeout: float = 30.0, follow_redirects: bool = False,
                       verify: bool = True) -> SendFn:
    """Build a SendFn over a pooled httpx client.

    `follow_redirects` defaults False on purpose: for differential testing a
    302-to-login is itself evidence, and following it would mask the raw
    status the oracle adjudicates against.
    """
    client = httpx.Client(timeout=timeout, follow_redirects=follow_redirects, verify=verify)

    def send(method: str, url: str, headers: dict, body: bytes) -> tuple[int, dict, bytes]:
        r = client.request(method.upper(), url, headers=headers, content=body or b"")
        return r.status_code, dict(r.headers), r.content

    # Let callers shut the pool down cleanly (the MCP server does on exit).
    send.close = client.close  # type: ignore[attr-defined]
    return send