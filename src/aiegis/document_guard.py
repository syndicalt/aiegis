from __future__ import annotations

from pathlib import PurePath

from aiegis.input_limits import DEFAULT_MAX_INPUT_CHARS, apply_input_limit
from aiegis.models import Finding, FindingSeverity, GuardedContent, SourceType, TrustLevel
from aiegis.prompt_signals import prompt_injection_findings

_TEXT_MEDIA_PREFIX = "text/"
_TEXT_EXTENSIONS = frozenset(
    {
        ".csv",
        ".json",
        ".log",
        ".md",
        ".text",
        ".txt",
        ".yaml",
        ".yml",
    }
)


def inspect_document(
    data: bytes,
    *,
    filename: str | None = None,
    media_type: str | None = None,
    max_input_chars: int | None = DEFAULT_MAX_INPUT_CHARS,
) -> GuardedContent:
    if _is_pdf(data, filename=filename, media_type=media_type):
        return _quarantined_document(
            source_type=SourceType.PDF,
            filename=filename,
            finding=Finding(
                code="unsupported_document_type",
                severity=FindingSeverity.MEDIUM,
                message="PDF extraction requires a configured PDF parser.",
                evidence=_document_evidence(filename=filename, media_type=media_type),
            ),
        )

    if _is_binary(data):
        return _quarantined_document(
            source_type=SourceType.DOCUMENT,
            filename=filename,
            finding=Finding(
                code="binary_document",
                severity=FindingSeverity.HIGH,
                message="Binary document content was quarantined before agent ingestion.",
                evidence=_document_evidence(filename=filename, media_type=media_type),
            ),
        )

    if not _is_text_like(filename=filename, media_type=media_type):
        return _quarantined_document(
            source_type=SourceType.DOCUMENT,
            filename=filename,
            finding=Finding(
                code="unsupported_document_type",
                severity=FindingSeverity.MEDIUM,
                message="Unsupported document type was quarantined before agent ingestion.",
                evidence=_document_evidence(filename=filename, media_type=media_type),
            ),
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _quarantined_document(
            source_type=SourceType.DOCUMENT,
            filename=filename,
            finding=Finding(
                code="document_decode_error",
                severity=FindingSeverity.HIGH,
                message="Document could not be decoded as UTF-8 text.",
                evidence=_document_evidence(filename=filename, media_type=media_type),
            ),
        )

    limited_text, limit_findings = apply_input_limit(text, max_input_chars=max_input_chars)
    findings = list(limit_findings)
    findings.extend(prompt_injection_findings(limited_text))
    return GuardedContent(
        text=limited_text,
        source_type=SourceType.DOCUMENT,
        trust_level=TrustLevel.UNTRUSTED,
        findings=tuple(findings),
    )


def _is_pdf(data: bytes, *, filename: str | None, media_type: str | None) -> bool:
    if media_type == "application/pdf":
        return True
    if filename and PurePath(filename).suffix.lower() == ".pdf":
        return True
    return data.startswith(b"%PDF-")


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:1024]


def _is_text_like(*, filename: str | None, media_type: str | None) -> bool:
    if media_type is not None:
        return media_type.startswith(_TEXT_MEDIA_PREFIX) or media_type in {
            "application/json",
            "application/x-yaml",
            "application/yaml",
        }
    if filename is None:
        return True
    return PurePath(filename).suffix.lower() in _TEXT_EXTENSIONS


def _quarantined_document(
    *,
    source_type: SourceType,
    filename: str | None,
    finding: Finding,
) -> GuardedContent:
    quarantined_segments = (filename,) if filename else ()
    return GuardedContent(
        text="",
        source_type=source_type,
        trust_level=TrustLevel.QUARANTINED,
        findings=(finding,),
        quarantined_segments=quarantined_segments,
    )


def _document_evidence(*, filename: str | None, media_type: str | None) -> str:
    parts: list[str] = []
    if filename:
        parts.append(f"filename={filename}")
    if media_type:
        parts.append(f"media_type={media_type}")
    return " ".join(parts) if parts else "unknown_document_type"
