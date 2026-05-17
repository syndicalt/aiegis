from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class FindingSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(Enum):
    PLAIN_TEXT = "plain_text"
    HTML = "html"
    EMAIL = "email"
    PDF = "pdf"
    MCP = "mcp"


class TrustLevel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"


_SEVERITY_RANK = {
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: FindingSeverity
    message: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class GuardedContent:
    text: str
    source_type: SourceType
    trust_level: TrustLevel
    findings: tuple[Finding, ...] = ()
    quarantined_segments: tuple[str, ...] = ()
    links: tuple[str, ...] = ()

    @property
    def highest_severity(self) -> FindingSeverity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda finding: _SEVERITY_RANK[finding.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        highest = self.highest_severity
        return {
            "text": self.text,
            "source_type": self.source_type.value,
            "trust_level": self.trust_level.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "quarantined_segments": list(self.quarantined_segments),
            "links": list(self.links),
            "highest_severity": highest.value if highest else None,
        }
