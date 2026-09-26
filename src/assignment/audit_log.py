"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.

IMPORTANT: Audit logs must NEVER contain plaintext secrets.
Any PII, password, API key must be [REDACTED] before storing.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


# Patterns for redacting secrets in audit logs
_AUDIT_REDACT_PATTERNS = [
    r"sk-[a-zA-Z0-9_-]{8,}",                          # API keys
    r"(?:password|passwd|pwd)\s*[:=]\s*\S+",            # password assignments
    r"\badmin123\b",                                    # known demo admin password
    r"(?:[a-z0-9-]+\.)+internal(?::\d+)?",             # internal DB hosts
    r"(?:\+84|0)(?:3[2-9]|5[6-9]|7[0-9]|8[0-9]|9[0-9])\d{7}",  # VN phone
    r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}",                  # email
    r"\b\d{12}\b",                                      # CCCD
]


def _redact_for_audit(text: str) -> str:
    """Remove secrets from text before storing in audit log."""
    if not text:
        return text
    result = text
    for pattern in _AUDIT_REDACT_PATTERNS:
        result = re.sub(pattern, "[REDACTED]", result, flags=re.IGNORECASE)
    return result


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._input_cache: dict[str, str] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        import time
        key = request_id or user_id
        self._open[key] = time.time()
        # Redact secrets before storing
        self._input_cache[key] = _redact_for_audit(text)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time
        key = request_id or user_id
        start = self._open.pop(key, None)
        latency_ms = round((time.time() - start) * 1000, 1) if start else None

        # Redact secrets before storing
        safe_input = self._input_cache.pop(key, "")
        safe_output = _redact_for_audit(text)

        entry = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": request_id,
            "input": safe_input,
            "output": safe_output,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = filepath or default_audit_log_path()
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(out)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
