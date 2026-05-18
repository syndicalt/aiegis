from pathlib import Path

import pytest

from aiegis.egress_guard import EgressPolicy
from aiegis.policy import Policy
from aiegis.policy_profiles import (
    LoadedPolicyProfile,
    PolicyProfileError,
    load_policy_profile,
)
from aiegis.tool_firewall import ToolCallPolicy


def test_load_policy_profile_reads_named_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  strict_email:
    approval_required_actions:
      - send_email
      - file_upload
    blocked_actions_on_prompt_injection:
      - send_email
      - post_web
""",
        encoding="utf-8",
    )

    policy = load_policy_profile(config_path, "strict_email")

    assert policy == Policy(
        approval_required_actions=("send_email", "file_upload"),
        blocked_actions_on_prompt_injection=("send_email", "post_web"),
    )


def test_load_policy_profile_reads_tool_firewall_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  strict_tools:
    approval_required_actions:
      - send_email
    blocked_actions_on_prompt_injection: []
    approval_required_tools:
      - http.post
      - send_email
    blocked_tools:
      - shell
      - filesystem.delete
    sensitive_argument_keys:
      - bearer_token
      - session_cookie
""",
        encoding="utf-8",
    )

    loaded = load_policy_profile(config_path, "strict_tools", include_tool_call_policy=True)

    assert loaded == LoadedPolicyProfile(
        content_policy=Policy(
            approval_required_actions=("send_email",),
            blocked_actions_on_prompt_injection=(),
        ),
        tool_call_policy=ToolCallPolicy(
            approval_required_tools=("http.post", "send_email"),
            blocked_tools=("shell", "filesystem.delete"),
            sensitive_argument_keys=("bearer_token", "session_cookie"),
        ),
    )


def test_load_policy_profile_reads_egress_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  review_output:
    approval_required_actions: []
    blocked_actions_on_prompt_injection: []
    approval_required_tools: []
    blocked_tools: []
    sensitive_argument_keys: []
    blocked_egress_patterns:
      - private_key_block
      - github_token
""",
        encoding="utf-8",
    )

    loaded = load_policy_profile(config_path, "review_output", include_tool_call_policy=True)

    assert loaded.egress_policy == EgressPolicy(
        blocked_patterns=("private_key_block", "github_token"),
    )


def test_load_policy_profile_rejects_missing_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text("profiles:\n  default: {}\n", encoding="utf-8")

    with pytest.raises(PolicyProfileError, match="Unknown policy profile 'strict_email'"):
        load_policy_profile(config_path, "strict_email")


def test_load_policy_profile_rejects_non_string_actions(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  bad:
    approval_required_actions:
      - send_email
      - 42
""",
        encoding="utf-8",
    )

    with pytest.raises(
        PolicyProfileError,
        match="profiles.bad.approval_required_actions must contain only strings",
    ):
        load_policy_profile(config_path, "bad")


def test_load_policy_profile_rejects_unknown_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  bad:
    approval_required_actions: []
    allow_everything: true
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyProfileError, match="Unknown policy key 'allow_everything'"):
        load_policy_profile(config_path, "bad")


def test_load_policy_profile_rejects_non_string_tool_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  bad:
    approval_required_actions: []
    blocked_actions_on_prompt_injection: []
    blocked_tools:
      - shell
      - false
""",
        encoding="utf-8",
    )

    with pytest.raises(
        PolicyProfileError,
        match="profiles.bad.blocked_tools must contain only strings",
    ):
        load_policy_profile(config_path, "bad", include_tool_call_policy=True)


def test_load_policy_profile_rejects_unknown_egress_patterns(tmp_path: Path) -> None:
    config_path = tmp_path / "policies.yaml"
    config_path.write_text(
        """
profiles:
  bad:
    approval_required_actions: []
    blocked_actions_on_prompt_injection: []
    blocked_egress_patterns:
      - imaginary_pattern
""",
        encoding="utf-8",
    )

    with pytest.raises(
        PolicyProfileError,
        match="profiles.bad.blocked_egress_patterns contains unknown pattern 'imaginary_pattern'",
    ):
        load_policy_profile(config_path, "bad", include_tool_call_policy=True)
