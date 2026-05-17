from pathlib import Path

import pytest

from aiegis.policy import Policy
from aiegis.policy_profiles import PolicyProfileError, load_policy_profile


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
