from __future__ import annotations

import re

from aiegis.input_limits import DEFAULT_MAX_INPUT_CHARS, apply_input_limit
from aiegis.models import Finding, FindingSeverity, GuardedContent, SourceType, TrustLevel
from aiegis.prompt_signals import prompt_injection_findings

_MEMORY_POISONING_PATTERNS = (
    re.compile(
        r"\bremember\s+this\s+as\s+(a\s+)?(permanent\s+)?(system\s+)?(rule|instruction)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bstore\s+this\s+(rule|instruction)\s+in\s+memory\b", re.IGNORECASE),
    re.compile(r"\bwrite\s+this\s+to\s+(long[- ]term\s+)?memory\b", re.IGNORECASE),
)

_EXFILTRATION_PATTERN = re.compile(
    r"\b(credentials?|secrets?|api\s+keys?|tokens?|passwords?)\b"
    r".{0,100}\b(forward|send|post|upload|exfiltrate)\b"
    r"|\b(forward|send|post|upload|exfiltrate)\b"
    r".{0,100}\b(credentials?|secrets?|api\s+keys?|tokens?|passwords?)\b",
    re.IGNORECASE | re.DOTALL,
)


def inspect_memory(
    text: str,
    *,
    max_input_chars: int | None = DEFAULT_MAX_INPUT_CHARS,
) -> GuardedContent:
    limited_text, limit_findings = apply_input_limit(text, max_input_chars=max_input_chars)
    findings = list(limit_findings)
    findings.extend(prompt_injection_findings(limited_text))
    findings.extend(_memory_poisoning_findings(limited_text))
    findings.extend(_exfiltration_findings(limited_text))

    return GuardedContent(
        text=limited_text,
        source_type=SourceType.MEMORY,
        trust_level=TrustLevel.UNTRUSTED,
        findings=tuple(findings),
    )


def _memory_poisoning_findings(text: str) -> tuple[Finding, ...]:
    matches: list[str] = []
    for pattern in _MEMORY_POISONING_PATTERNS:
        match = pattern.search(text)
        if match:
            matches.append(match.group(0))
            break
    return tuple(
        Finding(
            code="memory_poisoning_instruction",
            severity=FindingSeverity.CRITICAL,
            message="Memory content attempts to persist a new agent instruction.",
            evidence=match,
        )
        for match in matches
    )


def _exfiltration_findings(text: str) -> tuple[Finding, ...]:
    match = _EXFILTRATION_PATTERN.search(text)
    if match is None:
        return ()
    return (
        Finding(
            code="memory_exfiltration_instruction",
            severity=FindingSeverity.CRITICAL,
            message="Memory content appears to instruct credential or secret exfiltration.",
            evidence=_normalize_evidence(match.group(0)),
        ),
    )


def _normalize_evidence(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
