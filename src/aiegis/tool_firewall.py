from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from aiegis.policy import DecisionStatus

_DEFAULT_APPROVAL_REQUIRED_TOOLS = ("send_email", "post_web", "file_upload", "shell")
_DEFAULT_BLOCKED_TOOLS = ("filesystem.delete", "memory.write_sensitive")
_DEFAULT_SENSITIVE_ARGUMENT_KEYS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    name: str
    target: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target,
            "arguments": self.arguments,
        }


@dataclass(frozen=True, slots=True)
class ToolCallPolicy:
    approval_required_tools: tuple[str, ...] = _DEFAULT_APPROVAL_REQUIRED_TOOLS
    blocked_tools: tuple[str, ...] = _DEFAULT_BLOCKED_TOOLS
    sensitive_argument_keys: tuple[str, ...] = _DEFAULT_SENSITIVE_ARGUMENT_KEYS


@dataclass(frozen=True, slots=True)
class ToolCallDecision:
    status: DecisionStatus
    tool: ToolCallRequest
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "tool": self.tool.to_dict(),
            "reasons": list(self.reasons),
        }


def evaluate_tool_call(
    tool: ToolCallRequest,
    policy: ToolCallPolicy,
) -> ToolCallDecision:
    if tool.name in policy.blocked_tools:
        return ToolCallDecision(
            status=DecisionStatus.BLOCK,
            tool=tool,
            reasons=(f"Tool '{tool.name}' is blocked by policy.",),
        )

    sensitive_key = _first_sensitive_argument_key(tool.arguments, policy.sensitive_argument_keys)
    if sensitive_key and _is_external_target(tool.target):
        return ToolCallDecision(
            status=DecisionStatus.BLOCK,
            tool=tool,
            reasons=(
                "Tool call targets an external destination while carrying sensitive "
                f"argument '{sensitive_key}'.",
            ),
        )

    if tool.name in policy.approval_required_tools:
        return ToolCallDecision(
            status=DecisionStatus.REQUIRE_APPROVAL,
            tool=tool,
            reasons=(f"Tool '{tool.name}' requires approval by policy.",),
        )

    if _is_external_target(tool.target):
        return ToolCallDecision(
            status=DecisionStatus.REQUIRE_APPROVAL,
            tool=tool,
            reasons=(f"External target '{tool.target}' requires approval.",),
        )

    return ToolCallDecision(
        status=DecisionStatus.ALLOW,
        tool=tool,
        reasons=("No tool firewall rule matched.",),
    )


def _first_sensitive_argument_key(
    arguments: dict[str, Any],
    sensitive_argument_keys: tuple[str, ...],
) -> str | None:
    normalized_sensitive_keys = tuple(key.lower() for key in sensitive_argument_keys)
    for key in arguments:
        key_lower = key.lower()
        if any(sensitive_key in key_lower for sensitive_key in normalized_sensitive_keys):
            return key
    return None


def _is_external_target(target: str) -> bool:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return True
    if "@" in target and not target.startswith("@"):
        return True
    return target == "external"
