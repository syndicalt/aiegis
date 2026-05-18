from __future__ import annotations

from aiegis.models import Finding, FindingSeverity

DEFAULT_MAX_INPUT_CHARS = 1_000_000


def apply_input_limit(
    content: str,
    *,
    max_input_chars: int | None = DEFAULT_MAX_INPUT_CHARS,
) -> tuple[str, tuple[Finding, ...]]:
    if max_input_chars is None or len(content) <= max_input_chars:
        return content, ()
    if max_input_chars < 1:
        raise ValueError("max_input_chars must be a positive integer or None.")

    return (
        content[:max_input_chars],
        (
            Finding(
                code="input_truncated",
                severity=FindingSeverity.MEDIUM,
                message="Untrusted input exceeded the configured maximum and was truncated.",
                evidence=f"original_length={len(content)} limit={max_input_chars}",
            ),
        ),
    )
