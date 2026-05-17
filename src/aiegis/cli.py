from __future__ import annotations

import argparse
import sys
from pathlib import Path
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.email_guard import inspect_email
from aiegis.html_guard import inspect_html
from aiegis.models import GuardedContent
from aiegis.policy import ActionRequest, Policy, evaluate_policy
from aiegis.policy_profiles import load_policy_profile

_DEFAULT_POLICY = Policy(
    approval_required_actions=("send_email", "post_web", "file_upload", "shell"),
    blocked_actions_on_prompt_injection=("send_email", "post_web", "file_upload", "shell"),
)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "inspect-html":
        content = inspect_html(_read_input(args.path))
        _print_inspection(content, args.action, args.target, _policy_from_args(args))
        return 0

    if args.command == "inspect-email":
        content = inspect_email(_read_input(args.path))
        _print_inspection(content, args.action, args.target, _policy_from_args(args))
        return 0

    parser.print_help(sys.stderr)
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aiegis")
    subcommands = parser.add_subparsers(dest="command")

    inspect = subcommands.add_parser("inspect-html", help="Inspect untrusted HTML.")
    inspect.add_argument("path", nargs="?", help="HTML file path. Reads stdin when omitted.")
    inspect.add_argument("--action", default="summarize", help="Proposed agent action name.")
    inspect.add_argument("--target", default="local", help="Proposed action target.")
    _add_policy_arguments(inspect)

    inspect_email_parser = subcommands.add_parser("inspect-email", help="Inspect untrusted email.")
    inspect_email_parser.add_argument(
        "path", nargs="?", help="Email file path. Reads stdin when omitted."
    )
    inspect_email_parser.add_argument("--action", default="summarize", help="Proposed action name.")
    inspect_email_parser.add_argument("--target", default="local", help="Proposed action target.")
    _add_policy_arguments(inspect_email_parser)

    return parser


def _add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-file", help="YAML policy profile file.")
    parser.add_argument("--policy-profile", default="default", help="Policy profile name.")


def _policy_from_args(args: argparse.Namespace) -> Policy:
    if args.policy_file is None:
        return _DEFAULT_POLICY
    return load_policy_profile(Path(args.policy_file), args.policy_profile)


def _print_inspection(content: GuardedContent, action: str, target: str, policy: Policy) -> None:
    decision = evaluate_policy(
        content,
        ActionRequest(name=action, target=target),
        policy,
    )
    record = AuditRecord(event_id=f"evt_{uuid4().hex}", content=content, decision=decision)
    print(record.to_json())


def _read_input(path: str | None) -> str:
    if path is None:
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
