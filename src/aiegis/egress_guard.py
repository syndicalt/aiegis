from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aiegis.models import Finding, FindingSeverity
from aiegis.policy import DecisionStatus

_REDACTED = "[REDACTED]"
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]+\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "api_key_assignment",
        re.compile(
            r"\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s,;]+)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class OutputInspection:
    status: DecisionStatus
    redacted_text: str
    findings: tuple[Finding, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "redacted_text": self.redacted_text,
            "findings": [finding.to_dict() for finding in self.findings],
            "reasons": list(self.reasons),
        }


def inspect_output(text: str) -> OutputInspection:
    redacted_text = text
    matched_patterns: list[str] = []
    for pattern_name, pattern in _SECRET_PATTERNS:
        redacted_text, replacements = _redact_pattern(
            redacted_text,
            pattern_name=pattern_name,
            pattern=pattern,
        )
        if replacements:
            matched_patterns.append(pattern_name)

    if not matched_patterns:
        return OutputInspection(
            status=DecisionStatus.ALLOW,
            redacted_text=text,
            findings=(),
            reasons=("No egress rule matched.",),
        )

    findings = tuple(
        Finding(
            code="secret_like_output",
            severity=FindingSeverity.HIGH,
            message="Secret-like material was detected in outbound content.",
            evidence=pattern_name,
        )
        for pattern_name in tuple(dict.fromkeys(matched_patterns))
    )
    return OutputInspection(
        status=DecisionStatus.BLOCK,
        redacted_text=redacted_text,
        findings=findings,
        reasons=tuple(
            f"Secret-like output matched egress pattern '{finding.evidence}'."
            for finding in findings
        ),
    )


def _redact_pattern(
    text: str,
    *,
    pattern_name: str,
    pattern: re.Pattern[str],
) -> tuple[str, int]:
    if pattern_name == "api_key_assignment":
        return pattern.subn(lambda match: f"{match.group(1)} = {_REDACTED}", text)
    return pattern.subn(_REDACTED, text)
