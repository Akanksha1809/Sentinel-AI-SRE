"""Sanitise untrusted log text before it is stored, shown, or placed in an LLM prompt.

1. Strip control/format characters (ANSI escapes, NUL, bidi overrides) and truncate.
2. Redact secrets and PII (threat model T13).
3. Flag prompt-injection-like phrasing (threat model T1).

Flagging is a *signal for reviewers*, not the defence. The defence is structural:
the model has no tools, can only cite allowlisted runbooks, and every action needs
human approval. Matching text is kept (redacted, delimited) so reviewers can see it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.ingestion.alertmanager import clean_text

MAX_LINE = 512

_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("sentinel_token", re.compile(r"\bsnt_[A-Za-z0-9_-]{16,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "secret_kv",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization)"
            r"(\"?\s*[:=]\s*\"?)([^\s\"',;}&]{4,})"
        ),
    ),
    ("conn_string", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+):([^\s@/]+)@")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

_INJECTION = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)"
    r"|disregard\s+(all\s+|the\s+)?(previous|prior|above|system)"
    r"|you\s+are\s+now\s+(a|an|the)\b"
    r"|new\s+instructions\s*:"
    r"|system\s*prompt"
    r"|<\|?(im_start|im_end|system|assistant)\|?>"
    r"|\[/?(INST|SYS)\]"
    r"|###\s*(instruction|system)"
    r"|(approve|authori[sz]e|execute|run)\s+(the\s+|this\s+)?"
    r"(rollback|restart|scale|action|runbook|command|following)"
    r"|(sudo|rm\s+-rf|curl\s+[^|]*\|\s*(ba)?sh)"
    r")"
)


@dataclass(frozen=True)
class Sanitized:
    text: str
    redacted: bool
    suspicious: bool
    truncated: bool


def _redact(text: str) -> tuple[str, bool]:
    changed = False
    for name, pattern in _REDACTIONS:
        if name == "secret_kv":
            new = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
        elif name == "conn_string":
            new = pattern.sub(lambda m: f"{m.group(1)}:[REDACTED]@", text)
        else:
            new = pattern.sub(f"[REDACTED:{name}]", text)
        changed |= new != text
        text = new
    return text, changed


def sanitize_line(raw: str, limit: int = MAX_LINE) -> Sanitized:
    text = clean_text(raw, 10 * limit)  # strip control chars first (bounded work)
    text, redacted = _redact(text)
    suspicious = bool(_INJECTION.search(text))
    truncated = len(text) > limit
    if truncated:
        text = text[: limit - 1] + "…"
    return Sanitized(text, redacted, suspicious, truncated)
