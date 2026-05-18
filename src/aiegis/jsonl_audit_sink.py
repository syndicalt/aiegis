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


class JsonlAuditSink:
    def __init__(self, clock: Callable[[], str] | None = None) -> None:
        self._clock = clock or _utc_now

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
            payload=record.to_dict(),
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
            payload=decision.to_dict(),
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
