-- IDOR/BOLA harness schema. See idor-hunter-spec.md for field semantics.

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id         TEXT PRIMARY KEY,
    method              TEXT NOT NULL,
    path_template       TEXT NOT NULL,
    host                TEXT NOT NULL,
    source              TEXT NOT NULL,
    content_type        TEXT,
    auth_scheme         TEXT,
    observed_count      INTEGER DEFAULT 1,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    object_type_guess   TEXT,
    tags                TEXT,              -- JSON array
    UNIQUE(method, path_template, host)
);

CREATE TABLE IF NOT EXISTS id_locations (
    id_location_id      TEXT PRIMARY KEY,
    endpoint_id         TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    in_part             TEXT NOT NULL,     -- path|query|json_body|graphql_variable|header
    name_or_path        TEXT NOT NULL,
    value_type          TEXT NOT NULL      -- int|uuid|opaque|graphql_global_id
);

CREATE TABLE IF NOT EXISTS subjects (
    subject_id          TEXT PRIMARY KEY,
    label               TEXT NOT NULL,
    role                TEXT NOT NULL,
    tenant_id           TEXT,
    session_ref         TEXT NOT NULL,
    created_for_test    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS objects (
    object_id           TEXT PRIMARY KEY,
    object_type         TEXT NOT NULL,
    owner_subject_id    TEXT REFERENCES subjects(subject_id),
    tenant_id           TEXT,
    created_by_harness  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS native_ids (
    native_id_id        TEXT PRIMARY KEY,
    object_id           TEXT NOT NULL REFERENCES objects(object_id),
    endpoint_id         TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    value               TEXT NOT NULL,
    value_type          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sharing_grants (
    grant_id            TEXT PRIMARY KEY,
    object_id           TEXT NOT NULL REFERENCES objects(object_id),
    subject_id          TEXT NOT NULL REFERENCES subjects(subject_id),
    permission           TEXT NOT NULL,
    source               TEXT NOT NULL      -- observed|declared
);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id      TEXT PRIMARY KEY,
    from_id               TEXT NOT NULL,
    from_kind             TEXT NOT NULL,     -- endpoint|object
    to_id                 TEXT NOT NULL,
    to_kind                TEXT NOT NULL,
    relation               TEXT NOT NULL,     -- creates|reads|updates|deletes|downloads|shares|belongs_to|references
    confidence              REAL DEFAULT 0.5,
    evidence_ref             TEXT
);

CREATE TABLE IF NOT EXISTS auth_facts (
    fact_id               TEXT PRIMARY KEY,
    subject_id             TEXT NOT NULL REFERENCES subjects(subject_id),
    object_id               TEXT NOT NULL REFERENCES objects(object_id),
    action                   TEXT NOT NULL,
    expected                 TEXT NOT NULL,    -- allowed|denied|unknown
    basis                     TEXT NOT NULL     -- ownership|explicit_share|role|observed_test|declared_by_operator
);

CREATE TABLE IF NOT EXISTS test_results (
    test_id                   TEXT PRIMARY KEY,
    hypothesis                 TEXT NOT NULL,
    endpoint_id                 TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    subject_id                   TEXT NOT NULL REFERENCES subjects(subject_id),
    object_id                     TEXT NOT NULL REFERENCES objects(object_id),
    action                         TEXT NOT NULL,
    evidence_dir                   TEXT,          -- path under /evidence/{test_id}/
    response_status                  INTEGER,
    response_fingerprint              TEXT,
    diff_against                       TEXT,
    verdict                             TEXT NOT NULL DEFAULT 'pending', -- confirmed|rejected|inconclusive|needs_review|pending
    verdict_basis_fact_id                TEXT REFERENCES auth_facts(fact_id),
    confidence                            REAL,
    model_rationale                        TEXT,
    created_at                              TEXT NOT NULL,
    executed_at                              TEXT
);

CREATE INDEX IF NOT EXISTS idx_endpoints_object_type ON endpoints(object_type_guess);
CREATE INDEX IF NOT EXISTS idx_test_results_verdict ON test_results(verdict);
CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_id, from_kind);
CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_id, to_kind);
