from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, overload

import yaml

from aiegis.egress_guard import KNOWN_EGRESS_PATTERNS, EgressPolicy
from aiegis.policy import Policy
from aiegis.tool_firewall import ToolCallPolicy

_ALLOWED_POLICY_KEYS = {
    "approval_required_actions",
    "blocked_actions_on_prompt_injection",
    "approval_required_tools",
    "blocked_tools",
    "sensitive_argument_keys",
    "blocked_egress_patterns",
}


class PolicyProfileError(ValueError):
    """Raised when a policy profile file is invalid."""


@dataclass(frozen=True, slots=True)
class LoadedPolicyProfile:
    content_policy: Policy
    tool_call_policy: ToolCallPolicy
    egress_policy: EgressPolicy = EgressPolicy()


@overload
def load_policy_profile(
    path: Path,
    profile_name: str,
    *,
    include_tool_call_policy: Literal[False] = False,
) -> Policy: ...


@overload
def load_policy_profile(
    path: Path,
    profile_name: str,
    *,
    include_tool_call_policy: Literal[True],
) -> LoadedPolicyProfile: ...


def load_policy_profile(
    path: Path,
    profile_name: str,
    *,
    include_tool_call_policy: bool = False,
) -> Policy | LoadedPolicyProfile:
    raw_config = yaml.safe_load(path.read_text(encoding="utf-8"))
    config = _require_mapping(raw_config, "policy file")
    profiles = _require_mapping(config.get("profiles"), "profiles")
    if profile_name not in profiles:
        raise PolicyProfileError(f"Unknown policy profile '{profile_name}'")
    profile = _require_mapping(profiles[profile_name], f"profiles.{profile_name}")

    for key in profile:
        if key not in _ALLOWED_POLICY_KEYS:
            raise PolicyProfileError(f"Unknown policy key '{key}' in profile '{profile_name}'")

    content_policy = Policy(
        approval_required_actions=_string_tuple(
            profile.get("approval_required_actions", ()),
            f"profiles.{profile_name}.approval_required_actions",
        ),
        blocked_actions_on_prompt_injection=_string_tuple(
            profile.get("blocked_actions_on_prompt_injection", ()),
            f"profiles.{profile_name}.blocked_actions_on_prompt_injection",
        ),
    )
    if not include_tool_call_policy:
        return content_policy

    return LoadedPolicyProfile(
        content_policy=content_policy,
        tool_call_policy=ToolCallPolicy(
            approval_required_tools=_string_tuple(
                profile.get("approval_required_tools", ()),
                f"profiles.{profile_name}.approval_required_tools",
            ),
            blocked_tools=_string_tuple(
                profile.get("blocked_tools", ()),
                f"profiles.{profile_name}.blocked_tools",
            ),
            sensitive_argument_keys=_string_tuple(
                profile.get("sensitive_argument_keys", ()),
                f"profiles.{profile_name}.sensitive_argument_keys",
            ),
        ),
        egress_policy=EgressPolicy(
            blocked_patterns=_egress_pattern_tuple(
                profile.get("blocked_egress_patterns", None),
                f"profiles.{profile_name}.blocked_egress_patterns",
            )
        ),
    )


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        if label.startswith("profiles."):
            profile_name = label.removeprefix("profiles.")
            raise PolicyProfileError(f"Unknown policy profile '{profile_name}'")
        raise PolicyProfileError(f"{label} must be a mapping")
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise PolicyProfileError(f"{label} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise PolicyProfileError(f"{label} must contain only strings")
    return tuple(value)


def _egress_pattern_tuple(value: Any, label: str) -> tuple[str, ...]:
    patterns = _string_tuple(value, label)
    if value is None:
        return EgressPolicy().blocked_patterns
    for pattern in patterns:
        if pattern not in KNOWN_EGRESS_PATTERNS:
            raise PolicyProfileError(f"{label} contains unknown pattern '{pattern}'")
    return patterns
