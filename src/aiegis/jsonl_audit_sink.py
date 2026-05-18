from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aiegis.audit import AuditRecord
from aiegis.tool_firewall import ToolCallDecision

CONTENT_DECIDED_EVENT = "aiegis.content.decided"
TOOL_CALL_DECIDED_EVENT = "aiegis.tool_call.decided"
_SENSITIVE_ARGUMENT_KEY_PARTS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
_REDACTED = "[REDACTED]"


class JsonlAuditSink:
    def __init__(
        self,
        clock: Callable[[], str] | None = None,
        *,
        include_raw: bool = False,
    ) -> None:
        self._clock = clock or _utc_now
        self._include_raw = include_raw

    def append_content_record(
        self,
        record: AuditRecord,
        *,
        log_path: Path,
        policy_profile: str,
    ) -> None:
        self._append_event(
            log_path=log_path,
            event_type=CONTENT_DECIDED_EVENT,
            policy_profile=policy_profile,
            payload=record.to_dict() if self._include_raw else _minimized_content_payload(record),
        )

    def append_tool_call_decision(
        self,
        decision: ToolCallDecision,
        *,
        log_path: Path,
        policy_profile: str,
    ) -> None:
        self._append_event(
            log_path=log_path,
            event_type=TOOL_CALL_DECIDED_EVENT,
            policy_profile=policy_profile,
            payload=(
                decision.to_dict()
                if self._include_raw
                else _redacted_tool_call_payload(decision)
            ),
        )

    def _append_event(
        self,
        *,
        log_path: Path,
        event_type: str,
        policy_profile: str,
        payload: dict[str, Any],
    ) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "schema_version": 1,
            "event_type": event_type,
            "timestamp": self._clock(),
            "policy_profile": policy_profile,
            "payload": payload,
        }
        with log_path.open("a", encoding="utf-8") as audit_log:
            audit_log.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _minimized_content_payload(record: AuditRecord) -> dict[str, Any]:
    highest = record.content.highest_severity
    return {
        "event_id": record.event_id,
        "content": {
            "source_type": record.content.source_type.value,
            "trust_level": record.content.trust_level.value,
            "findings": [finding.to_dict() for finding in record.content.findings],
            "quarantined_segment_count": len(record.content.quarantined_segments),
            "link_count": len(record.content.links),
            "highest_severity": highest.value if highest else None,
        },
        "decision": record.decision.to_dict(),
    }


def _redacted_tool_call_payload(decision: ToolCallDecision) -> dict[str, Any]:
    payload = decision.to_dict()
    tool = payload["tool"]
    if isinstance(tool, dict):
        arguments = tool.get("arguments")
        if isinstance(arguments, dict):
            tool["arguments"] = _redact_arguments(arguments)
    return payload


def _redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _REDACTED if _is_sensitive_argument_key(key) else value
        for key, value in arguments.items()
    }


def _is_sensitive_argument_key(key: str) -> bool:
    key_lower = key.lower()
    return any(part in key_lower for part in _SENSITIVE_ARGUMENT_KEY_PARTS)
