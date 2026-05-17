from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import Parser
from email.utils import getaddresses

from aiegis.html_guard import inspect_html
from aiegis.models import Finding, FindingSeverity, GuardedContent, SourceType, TrustLevel

_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?previous\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bsend\s+your\s+api\s+key\b", re.IGNORECASE),
    re.compile(r"\breveal\s+(credentials|secrets|api\s+keys?)\b", re.IGNORECASE),
)


def inspect_email(raw_email: str) -> GuardedContent:
    message = Parser(policy=policy.default).parsestr(raw_email)
    findings: list[Finding] = []
    quarantined_segments: list[str] = []
    links: list[str] = []

    findings.extend(_header_findings(message))

    plain_parts: list[str] = []
    html_parts: list[GuardedContent] = []

    for part in _iter_leaf_parts(message):
        if _is_attachment(part):
            _quarantine_attachment(part, findings, quarantined_segments)
            continue

        content_type = part.get_content_type()
        if content_type == "text/plain":
            text = _part_text(part)
            if text:
                plain_parts.append(text)
                findings.extend(_prompt_findings(text))
        elif content_type == "text/html":
            guarded_html = inspect_html(_part_text(part))
            html_parts.append(guarded_html)
            findings.extend(guarded_html.findings)
            quarantined_segments.extend(guarded_html.quarantined_segments)
            links.extend(guarded_html.links)

    body_parts = [*plain_parts, *(html.text for html in html_parts if html.text)]
    text = _join_sections([_header_summary(message), *body_parts])

    return GuardedContent(
        text=text,
        source_type=SourceType.EMAIL,
        trust_level=TrustLevel.UNTRUSTED,
        findings=tuple(findings),
        quarantined_segments=tuple(quarantined_segments),
        links=tuple(dict.fromkeys(links)),
    )


def _iter_leaf_parts(message: EmailMessage) -> tuple[EmailMessage, ...]:
    if not message.is_multipart():
        return (message,)
    return tuple(
        part
        for part in message.walk()
        if isinstance(part, EmailMessage) and not part.is_multipart()
    )


def _is_attachment(part: EmailMessage) -> bool:
    return part.get_content_disposition() == "attachment"


def _quarantine_attachment(
    part: EmailMessage, findings: list[Finding], quarantined_segments: list[str]
) -> None:
    filename = part.get_filename() or "unnamed"
    content_type = part.get_content_type()
    quarantined_segments.append(f"attachment: {filename} ({content_type})")
    findings.append(
        Finding(
            code="attachment_quarantined",
            severity=FindingSeverity.MEDIUM,
            message="Email attachment was quarantined before agent ingestion.",
            evidence=filename,
        )
    )


def _part_text(part: EmailMessage) -> str:
    content = part.get_content()
    return _normalize_text(content if isinstance(content, str) else "")


def _header_summary(message: EmailMessage) -> str:
    lines = []
    for name in ("Subject", "From", "To"):
        value = _normalize_text(message.get(name, ""))
        if value:
            lines.append(f"{name}: {value}")
    return "\n".join(lines)


def _header_findings(message: EmailMessage) -> tuple[Finding, ...]:
    from_addresses = _addresses(message.get("From", ""))
    reply_to_addresses = _addresses(message.get("Reply-To", ""))
    if not from_addresses or not reply_to_addresses:
        return ()

    from_address = from_addresses[0]
    reply_to_address = reply_to_addresses[0]
    if from_address == reply_to_address:
        return ()

    return (
        Finding(
            code="reply_to_mismatch",
            severity=FindingSeverity.MEDIUM,
            message="Reply-To address does not match From address.",
            evidence=f"{from_address} -> {reply_to_address}",
        ),
    )


def _addresses(value: str) -> tuple[str, ...]:
    addresses = [address.lower() for _, address in getaddresses([value]) if address]
    return tuple(addresses)


def _prompt_findings(text: str) -> tuple[Finding, ...]:
    for pattern in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return (
                Finding(
                    code="prompt_injection_phrase",
                    severity=FindingSeverity.HIGH,
                    message="Prompt-like instruction was found in untrusted email content.",
                    evidence=match.group(0),
                ),
            )
    return ()


def _join_sections(sections: list[str]) -> str:
    return "\n\n".join(section for section in sections if section)


def _normalize_text(text: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", text).strip()
