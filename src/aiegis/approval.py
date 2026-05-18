from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from aiegis.tool_firewall import ToolCallDecision

_SENSITIVE_ARGUMENT_KEY_PARTS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
_REDACTED = "[REDACTED]"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    decision: ToolCallDecision
    status: str = "pending"

    @classmethod
    def from_decision(cls, approval_id: str, decision: ToolCallDecision) -> ApprovalRequest:
        return cls(approval_id=approval_id, decision=decision)

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "status": self.status,
            "decision": _redacted_decision(self.decision),
        }


class JsonlApprovalStore:
    def __init__(self, id_factory: Callable[[], str] | None = None) -> None:
        self._id_factory = id_factory or _approval_id

    def append_pending(
        self,
        decision: ToolCallDecision,
        *,
        log_path: Path,
    ) -> ApprovalRequest:
        request = ApprovalRequest.from_decision(self._id_factory(), decision)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as approval_log:
            approval_log.write(
                json.dumps(request.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
            )
        return request


def _approval_id() -> str:
    return f"approval_{uuid4().hex}"


def _redacted_decision(decision: ToolCallDecision) -> dict[str, Any]:
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
