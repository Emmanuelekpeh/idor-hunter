"""Dataclasses mirroring schema.sql. Kept intentionally plain (no ORM) so
the whole harness stays easy to read and port. See idor-hunter-spec.md
section 1 for field semantics.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def new_id() -> str:
    return str(uuid.uuid4())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class IdLocation:
    endpoint_id: str
    in_part: str            # path|query|json_body|graphql_variable|header
    name_or_path: str
    value_type: str         # int|uuid|opaque|graphql_global_id
    id_location_id: str = field(default_factory=new_id)


@dataclass
class Endpoint:
    method: str
    path_template: str
    host: str
    source: str              # burp_history|katana|openapi|graphql_introspection|js_route
    content_type: Optional[str] = None
    auth_scheme: Optional[str] = None
    observed_count: int = 1
    object_type_guess: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    endpoint_id: str = field(default_factory=new_id)
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)


@dataclass
class Subject:
    label: str
    role: str                 # standard_user|admin|anonymous|service
    session_ref: str          # harness looks this up at execute time; never put raw creds in a prompt
    tenant_id: Optional[str] = None
    created_for_test: bool = True
    subject_id: str = field(default_factory=new_id)


@dataclass
class HarnessObject:
    object_type: str
    owner_subject_id: Optional[str] = None
    tenant_id: Optional[str] = None
    created_by_harness: bool = False
    object_id: str = field(default_factory=new_id)


@dataclass
class NativeId:
    object_id: str
    endpoint_id: str
    value: str
    value_type: str
    native_id_id: str = field(default_factory=new_id)


@dataclass
class SharingGrant:
    object_id: str
    subject_id: str
    permission: str
    source: str                # observed|declared
    grant_id: str = field(default_factory=new_id)


@dataclass
class Relationship:
    from_id: str
    from_kind: str              # endpoint|object
    to_id: str
    to_kind: str
    relation: str                # creates|reads|updates|deletes|downloads|shares|belongs_to|references
    confidence: float = 0.5
    evidence_ref: Optional[str] = None
    relationship_id: str = field(default_factory=new_id)


@dataclass
class AuthFact:
    subject_id: str
    object_id: str
    action: str
    expected: str                 # allowed|denied|unknown
    basis: str                     # ownership|explicit_share|role|observed_test|declared_by_operator
    fact_id: str = field(default_factory=new_id)


@dataclass
class TestResult:
    hypothesis: str
    endpoint_id: str
    subject_id: str
    object_id: str
    action: str
    verdict: str = "pending"        # confirmed|rejected|inconclusive|needs_review|pending
    evidence_dir: Optional[str] = None
    response_status: Optional[int] = None
    response_fingerprint: Optional[str] = None
    diff_against: Optional[str] = None
    verdict_basis_fact_id: Optional[str] = None
    confidence: Optional[float] = None
    model_rationale: Optional[str] = None
    test_id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_iso)
    executed_at: Optional[str] = None
