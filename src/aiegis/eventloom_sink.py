from __future__ import annotations

import hashlib
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from aiegis.audit import AuditRecord

AIEGIS_POLICY_DECIDED_EVENT = "aiegis.policy.decided"


class EventloomUnavailableError(RuntimeError):
    """Raised when the optional Zaxy Eventloom dependency is unavailable."""


class EventLogProtocol(Protocol):
    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, object],
        thread: str = "default",
    ) -> object: ...


EventLogFactory = Callable[[Path], EventLogProtocol]


class _UseDefault:
    pass


_USE_DEFAULT = _UseDefault()


def build_eventloom_payload(
    record: AuditRecord,
    *,
    content_hash: str,
    policy_profile: str,
) -> dict[str, object]:
    highest = record.content.highest_severity
    return {
        "audit_event_id": record.event_id,
        "content_hash": content_hash,
        "source_type": record.content.source_type.value,
        "trust_level": record.content.trust_level.value,
        "highest_severity": highest.value if highest else None,
        "findings": [
            {"code": finding.code, "severity": finding.severity.value}
            for finding in record.content.findings
        ],
        "finding_count": len(record.content.findings),
        "quarantined_segment_count": len(record.content.quarantined_segments),
        "link_count": len(record.content.links),
        "decision": record.decision.to_dict(),
        "policy_profile": policy_profile,
    }


class EventloomSink:
    def __init__(
        self,
        eventlog_factory: EventLogFactory | None | _UseDefault = _USE_DEFAULT,
    ) -> None:
        if eventlog_factory is _USE_DEFAULT:
            self._eventlog_factory = _load_zaxy_eventlog_factory()
        else:
            self._eventlog_factory = cast(EventLogFactory | None, eventlog_factory)

    def append(
        self,
        record: AuditRecord,
        *,
        log_path: Path,
        thread: str,
        policy_profile: str,
    ) -> None:
        if self._eventlog_factory is None:
            raise EventloomUnavailableError(
                "Install zaxy to use --eventloom-log, or run without Eventloom auditing."
            )
        eventlog = self._eventlog_factory(log_path)
        eventlog.append(
            AIEGIS_POLICY_DECIDED_EVENT,
            actor="aiegis",
            payload=build_eventloom_payload(
                record,
                content_hash=_content_hash(record),
                policy_profile=policy_profile,
            ),
            thread=thread,
        )


def _load_zaxy_eventlog_factory() -> EventLogFactory | None:
    try:
        module = import_module("zaxy.event")
    except ImportError:
        return None
    return cast(EventLogFactory, cast(Any, module).EventLog)


def _content_hash(record: AuditRecord) -> str:
    return "sha256:" + hashlib.sha256(record.content.text.encode("utf-8")).hexdigest()
