from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from aiegis.input_limits import DEFAULT_MAX_INPUT_CHARS, apply_input_limit
from aiegis.models import Finding, FindingSeverity, GuardedContent, SourceType, TrustLevel

_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(all\s+)?previous\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\breveal\s+(credentials|secrets|api\s+keys?)\b", re.IGNORECASE),
    re.compile(r"\bemail\s+secrets\b", re.IGNORECASE),
    re.compile(r"\bsend\s+your\s+api\s+key\b", re.IGNORECASE),
)

_BLOCK_TAGS = {"address", "article", "aside", "blockquote", "div", "footer", "h1", "h2", "h3"}
_BLOCK_TAGS.update({"h4", "h5", "h6", "header", "li", "main", "nav", "ol", "p", "section", "ul"})


def inspect_html(
    html: str,
    *,
    max_input_chars: int | None = DEFAULT_MAX_INPUT_CHARS,
) -> GuardedContent:
    limited_html, limit_findings = apply_input_limit(html, max_input_chars=max_input_chars)
    soup = BeautifulSoup(limited_html, "html5lib")
    findings: list[Finding] = list(limit_findings)
    quarantined: list[str] = []
    links = _extract_safe_links(soup)

    _remove_unsafe_links(soup, findings, quarantined)
    _quarantine_metadata(soup, findings, quarantined)
    _quarantine_active_content(soup, findings, quarantined)

    for tag in list(soup.find_all(True)):
        if not isinstance(tag, Tag):
            continue
        if _is_hidden(tag):
            text = _normalized_text(tag.get_text(" ", strip=True))
            if text:
                quarantined.append(text)
                findings.append(
                    Finding(
                        code="hidden_text",
                        severity=FindingSeverity.HIGH,
                        message="Hidden text was quarantined before agent ingestion.",
                        evidence=_hidden_evidence(tag),
                    )
                )
                findings.extend(_prompt_findings(text))
            tag.decompose()

    visible_text = _visible_text(soup)
    findings.extend(_prompt_findings(visible_text))

    return GuardedContent(
        text=visible_text,
        source_type=SourceType.HTML,
        trust_level=TrustLevel.UNTRUSTED,
        findings=tuple(findings),
        quarantined_segments=tuple(quarantined),
        links=links,
    )


def _quarantine_metadata(
    soup: BeautifulSoup, findings: list[Finding], quarantined: list[str]
) -> None:
    title = soup.find("title")
    if isinstance(title, Tag):
        _add_metadata(title.get_text(" ", strip=True), findings, quarantined)
        title.decompose()

    for meta in list(soup.find_all("meta")):
        if not isinstance(meta, Tag):
            continue
        content = meta.get("content")
        if isinstance(content, str):
            _add_metadata(content, findings, quarantined)
        meta.decompose()


def _add_metadata(text: str, findings: list[Finding], quarantined: list[str]) -> None:
    normalized = _normalized_text(text)
    if not normalized:
        return
    quarantined.append(normalized)
    findings.append(
        Finding(
            code="metadata_text",
            severity=FindingSeverity.MEDIUM,
            message="HTML metadata was quarantined before agent ingestion.",
            evidence=normalized,
        )
    )
    findings.extend(_prompt_findings(normalized))


def _quarantine_active_content(
    soup: BeautifulSoup, findings: list[Finding], quarantined: list[str]
) -> None:
    for tag in list(soup.find_all(["script", "iframe", "object", "embed"])):
        if not isinstance(tag, Tag):
            continue
        text = _normalized_text(tag.string or tag.get_text(" ", strip=True))
        if text:
            quarantined.append(text)
        findings.append(
            Finding(
                code="active_content",
                severity=FindingSeverity.HIGH,
                message="Active HTML content was removed before agent ingestion.",
                evidence=tag.name,
            )
        )
        tag.decompose()


def _remove_unsafe_links(
    soup: BeautifulSoup, findings: list[Finding], quarantined: list[str]
) -> None:
    for tag in list(soup.find_all("a")):
        if not isinstance(tag, Tag):
            continue
        href = tag.get("href")
        if not isinstance(href, str):
            continue
        parsed = urlparse(href)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            text = _normalized_text(tag.get_text(" ", strip=True))
            if text:
                quarantined.append(text)
            findings.append(
                Finding(
                    code="unsafe_link",
                    severity=FindingSeverity.MEDIUM,
                    message="Unsafe link was removed before agent ingestion.",
                    evidence=href,
                )
            )
            tag.decompose()


def _extract_safe_links(soup: BeautifulSoup) -> tuple[str, ...]:
    links: list[str] = []
    for tag in soup.find_all("a"):
        if not isinstance(tag, Tag):
            continue
        href = tag.get("href")
        if not isinstance(href, str):
            continue
        parsed = urlparse(href)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            links.append(href)
    return tuple(dict.fromkeys(links))


def _is_hidden(tag: Tag) -> bool:
    if tag.has_attr("hidden") or tag.get("aria-hidden") == "true":
        return True
    style = tag.get("style")
    return isinstance(style, str) and _style_hides_content(style)


def _style_hides_content(style: str) -> bool:
    compact = re.sub(r"\s+", "", style).lower()
    return any(
        pattern in compact
        for pattern in (
            "display:none",
            "visibility:hidden",
            "font-size:0",
            "font-size:0px",
            "left:-9999px",
            "left:-10000px",
            "opacity:0",
        )
    )


def _hidden_evidence(tag: Tag) -> str:
    if tag.has_attr("hidden"):
        return "hidden"
    if tag.get("aria-hidden") == "true":
        return "aria-hidden=true"
    style = tag.get("style")
    return style if isinstance(style, str) else tag.name or "hidden"


def _prompt_findings(text: str) -> list[Finding]:
    matches = _matching_prompt_patterns(text)
    return [
        Finding(
            code="prompt_injection_phrase",
            severity=FindingSeverity.HIGH,
            message="Prompt-like instruction was found in untrusted content.",
            evidence=match,
        )
        for match in matches
    ]


def _matching_prompt_patterns(text: str) -> tuple[str, ...]:
    for pattern in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return (match.group(0),)
    return ()


def _visible_text(soup: BeautifulSoup) -> str:
    body = soup.body or soup
    lines: list[str] = []
    for node in body.descendants:
        if isinstance(node, Tag) and node.name in _BLOCK_TAGS and lines and lines[-1] != "\n":
            lines.append("\n")
        if isinstance(node, str):
            text = _normalized_text(node)
            if text:
                lines.append(text)
        parent = getattr(node, "parent", None)
        if isinstance(parent, Tag) and parent.name in _BLOCK_TAGS and lines and lines[-1] != "\n":
            lines.append("\n")
    return _join_lines(lines)


def _join_lines(parts: Iterable[str]) -> str:
    text = " ".join(parts)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
