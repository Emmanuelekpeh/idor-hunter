"""CLI: feed captured traffic (JSONL) into the harness database.

Pairs with `scripts/ingest-burp-history.mjs`, which pulls Burp MCP proxy
history and writes `captures/*.jsonl` in exactly the shape read here:

    {"method": "GET", "url": "https://target/api/invoices/101",
     "source": "burp_history", "content_type": "application/json",
     "auth_scheme": "cookie", "json_body_keys": ["invoice_id"],
     "graphql_variables": [], "headers_of_interest": []}

Only `method` + `url` are required; the optional fields sharpen id-location
extraction. Endpoints are upserted, so re-ingesting the same history only
bumps `observed_count`.

Usage (from the repo root):
    python -m src.ingest --db harness.db captures/burp-history-2026-10-11.jsonl
    python -m src.ingest --db harness.db captures/            # every .jsonl in a dir
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .db import Database
from .endpoint_discovery import ingest_raw_request

KNOWN_KEYS = {
    "method", "url", "source", "content_type", "auth_scheme",
    "json_body_keys", "graphql_variables", "headers_of_interest",
}


def load_lines(paths: list[str]) -> list[dict]:
    """Expand dirs to *.jsonl, read every line, keep only parseable dicts."""
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("*.jsonl")))
        else:
            files.append(path)
    out = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"  !! {f.name}:{n}: bad JSON ({e}) — skipped", file=sys.stderr)
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    return out


def ingest_records(db: Database, records: list[dict], default_source: str) -> dict:
    stats = {"requests": 0, "skipped": 0, "endpoints": set(), "unknown_keys": set()}
    for rec in records:
        stats["unknown_keys"].update(set(rec) - KNOWN_KEYS)
        method = str(rec.get("method") or "").strip()
        url = str(rec.get("url") or "").strip()
        if not method or not url:
            stats["skipped"] += 1
            continue
        endpoint_id = ingest_raw_request(
            db,
            method=method,
            url=url,
            source=str(rec.get("source") or default_source),
            content_type=rec.get("content_type"),
            auth_scheme=rec.get("auth_scheme"),
            json_body_keys=rec.get("json_body_keys") or (),
            graphql_variables=rec.get("graphql_variables") or (),
            headers_of_interest=rec.get("headers_of_interest") or (),
        )
        stats["endpoints"].add(endpoint_id)
        stats["requests"] += 1
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Ingest captured traffic (JSONL) into the harness DB.")
    ap.add_argument("paths", nargs="+", help="JSONL file(s) or a directory containing them")
    ap.add_argument("--db", default="harness.db", help="SQLite path (default: harness.db)")
    ap.add_argument("--source", default="burp_history", help="default source tag if a record has none")
    args = ap.parse_args(argv)

    records = load_lines(args.paths)
    print(f"loaded {len(records)} record(s) from {len(args.paths)} path(s)")
    db = Database(args.db)
    stats = ingest_records(db, records, args.source)
    if stats["unknown_keys"]:
        print(f"  (ignored unknown keys: {', '.join(sorted(stats['unknown_keys']))})")
    print(f"ingested {stats['requests']} request(s) -> {len(stats['endpoints'])} endpoint(s), "
          f"{stats['skipped']} skipped (missing method/url)")
    print(f"next: python -c \"from src.db import Database; from src.ranker import rank_candidates; "
          f"db = Database('{args.db}'); [print(s.score, s.reasons, db.get_endpoint(s.endpoint_id)['path_template']) "
          f"for s in rank_candidates(db)]\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())