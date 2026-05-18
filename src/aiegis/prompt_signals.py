from __future__ import annotations

import re

from aiegis.models import Finding, FindingSeverity

_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?previous\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\breveal\s+(credentials|secrets|api\s+keys?)\b", re.IGNORECASE),
    re.compile(r"\bemail\s+secrets\b", re.IGNORECASE),
    re.compile(r"\bsend\s+(your\s+)?(api\s+key|secrets?)\b", re.IGNORECASE),
)


def prompt_injection_findings(text: str) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            code="prompt_injection_phrase",
            severity=FindingSeverity.HIGH,
            message="Prompt-like instruction was found in untrusted content.",
            evidence=match,
        )
        for match in matching_prompt_patterns(text)
    )


def matching_prompt_patterns(text: str) -> tuple[str, ...]:
    for pattern in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return (match.group(0),)
    return ()
