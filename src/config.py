"""Operator-set configuration. Fill in per-engagement; nothing here should
be inferred by the model."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HarnessConfig:
    allowed_hosts: set[str]                  # in-scope hosts only
    db_path: str = "harness.db"
    evidence_root: Path = field(default_factory=lambda: Path("./evidence"))
    max_requests_per_minute: int = 30
    require_approval_for_writes: bool = True
    # Model tiers per the research conversation (ChatGPT-Choosing IDOR Model
    # Locally, section 7 of that memo) and the spec section 5.4 ablation plan:
    # a 3B/4B Q4 model does routine analysis; the 8B is loaded selectively for
    # hard cases and must earn its memory cost in benchmark results.
    local_model: str = "qwen3:4b-instruct-q4_K_M"
    deep_model: str | None = "qwen3:8b-instruct-q4_K_M"
