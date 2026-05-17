from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aiegis.policy import Policy

_ALLOWED_POLICY_KEYS = {
    "approval_required_actions",
    "blocked_actions_on_prompt_injection",
}


class PolicyProfileError(ValueError):
    """Raised when a policy profile file is invalid."""


def load_policy_profile(path: Path, profile_name: str) -> Policy:
    raw_config = yaml.safe_load(path.read_text(encoding="utf-8"))
    config = _require_mapping(raw_config, "policy file")
    profiles = _require_mapping(config.get("profiles"), "profiles")
    if profile_name not in profiles:
        raise PolicyProfileError(f"Unknown policy profile '{profile_name}'")
    profile = _require_mapping(profiles[profile_name], f"profiles.{profile_name}")

    for key in profile:
        if key not in _ALLOWED_POLICY_KEYS:
            raise PolicyProfileError(f"Unknown policy key '{key}' in profile '{profile_name}'")

    return Policy(
        approval_required_actions=_string_tuple(
            profile.get("approval_required_actions", ()),
            f"profiles.{profile_name}.approval_required_actions",
        ),
        blocked_actions_on_prompt_injection=_string_tuple(
            profile.get("blocked_actions_on_prompt_injection", ()),
            f"profiles.{profile_name}.blocked_actions_on_prompt_injection",
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
