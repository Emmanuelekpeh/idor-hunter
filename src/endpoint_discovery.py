"""Pass 1/2 from the spec: turn raw captured requests (from Burp export,
Katana, OpenAPI, etc.) into normalized Endpoint + IdLocation records.

This module intentionally has no network access — it only parses already-
captured traffic/specs that the operator feeds in. Wiring to live Burp MCP
tools happens in mcp_tools.py.
"""
from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlparse, parse_qs

from .db import Database
from .models import Endpoint, IdLocation, now_iso

# Heuristics for recognizing object identifiers in a path segment.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INT_RE = re.compile(r"^\d+$")

# Resource keywords worth flagging as object_type_guess (expand as needed).
_HIGH_VALUE_RESOURCES = {
    "invoice", "invoices", "document", "documents", "profile", "profiles",
    "order", "orders", "project", "projects", "attachment", "attachments",
    "tenant", "tenants", "account", "accounts", "user", "users", "team", "teams",
}


def _classify_id(segment: str) -> str | None:
    if _UUID_RE.match(segment):
        return "uuid"
    if _INT_RE.match(segment):
        return "int"
    # Looks opaque (base64-ish, long alnum) but not clearly a UUID/int.
    if len(segment) >= 12 and re.match(r"^[A-Za-z0-9_\-=]+$", segment):
        return "opaque"
    return None


def path_template_from_raw(path: str) -> tuple[str, list[str], str | None]:
    """Collapse a raw path into a template, return (template, id-segment
    values, best-effort object_type_guess)."""
    parts = path.strip("/").split("/")
    templated = []
    id_values: list[str] = []
    object_type_guess = None

    for i, part in enumerate(parts):
        kind = _classify_id(part)
        if kind:
            templated.append("{id}")
            id_values.append(part)
            # the segment immediately before an id is usually the resource name
            if i > 0 and parts[i - 1].lower() in _HIGH_VALUE_RESOURCES:
                object_type_guess = parts[i - 1].lower().rstrip("s")
        else:
            templated.append(part)
            if part.lower() in _HIGH_VALUE_RESOURCES and object_type_guess is None:
                object_type_guess = part.lower().rstrip("s")

    return "/" + "/".join(templated), id_values, object_type_guess


def ingest_raw_request(
    db: Database,
    method: str,
    url: str,
    source: str,
    content_type: str | None = None,
    auth_scheme: str | None = None,
    json_body_keys: Iterable[str] = (),
    graphql_variables: Iterable[str] = (),
    headers_of_interest: Iterable[str] = (),
) -> str:
    """Normalize one captured request and upsert it. Returns endpoint_id.

    `json_body_keys` / `graphql_variables` / `headers_of_interest` are the
    caller's best guess at which fields carry object identifiers — wire a
    real JSON/GraphQL parser here rather than hand-listing keys in
    production use.
    """
    parsed = urlparse(url)
    path_template, id_values, object_type_guess = path_template_from_raw(parsed.path)
    query = parse_qs(parsed.query)

    endpoint = Endpoint(
        method=method.upper(),
        path_template=path_template,
        host=parsed.netloc,
        source=source,
        content_type=content_type,
        auth_scheme=auth_scheme,
        object_type_guess=object_type_guess,
        tags=["write"] if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} else ["read"],
        last_seen=now_iso(),
    )
    endpoint_id = db.upsert_endpoint(endpoint)

    # path-based id locations
    for idx, val in enumerate(id_values):
        db.add_id_location(IdLocation(
            endpoint_id=endpoint_id, in_part="path",
            name_or_path=f"segment_{idx}", value_type=_classify_id(val) or "opaque",
        ))

    # query-based id locations (anything with "id" in the key, as a default heuristic)
    for key in query:
        if "id" in key.lower():
            db.add_id_location(IdLocation(
                endpoint_id=endpoint_id, in_part="query",
                name_or_path=key, value_type="opaque",
            ))

    for key in json_body_keys:
        db.add_id_location(IdLocation(
            endpoint_id=endpoint_id, in_part="json_body",
            name_or_path=key, value_type="opaque",
        ))

    for key in graphql_variables:
        db.add_id_location(IdLocation(
            endpoint_id=endpoint_id, in_part="graphql_variable",
            name_or_path=key, value_type="graphql_global_id",
        ))

    for key in headers_of_interest:
        db.add_id_location(IdLocation(
            endpoint_id=endpoint_id, in_part="header",
            name_or_path=key, value_type="opaque",
        ))

    return endpoint_id
