"""Writes the /evidence/{test_id}/ layout from spec section 4."""
from __future__ import annotations

from pathlib import Path

_REDACT_HEADERS = {"authorization", "cookie", "x-api-key"}


def redact(text: str) -> str:
    lines = []
    for line in text.splitlines():
        header = line.split(":", 1)[0].strip().lower()
        if header in _REDACT_HEADERS:
            key, _, _ = line.partition(":")
            lines.append(f"{key}: [REDACTED]")
        else:
            lines.append(line)
    return "\n".join(lines)


def write_evidence(root: Path, test_id: str, request_text: str, response_text: str) -> Path:
    test_dir = root / test_id
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "request.txt").write_text(redact(request_text))
    (test_dir / "response.txt").write_text(response_text)
    return test_dir
