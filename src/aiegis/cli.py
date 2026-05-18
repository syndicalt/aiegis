from __future__ import annotations

import argparse
import sys
from pathlib import Path
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.email_guard import inspect_email
from aiegis.eventloom_sink import EventloomSink
from aiegis.html_guard import inspect_html
from aiegis.jsonl_audit_sink import JsonlAuditSink
from aiegis.mcp_server import McpServerConfig, run_stdio_server
from aiegis.models import GuardedContent
from aiegis.policy import ActionRequest, Policy, evaluate_policy
from aiegis.policy_profiles import LoadedPolicyProfile, load_policy_profile

_DEFAULT_POLICY = Policy(
    approval_required_actions=("send_email", "post_web", "file_upload", "shell"),
    blocked_actions_on_prompt_injection=("send_email", "post_web", "file_upload", "shell"),
)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "inspect-html":
        content = inspect_html(_read_input(args.path))
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
        return 0

    if args.command == "inspect-email":
        content = inspect_email(_read_input(args.path))
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
        return 0

    if args.command == "mcp-stdio":
        run_stdio_server(config=_mcp_config_from_args(args))
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

    mcp_stdio_parser = subcommands.add_parser(
        "mcp-stdio", help="Run the AIegis MCP server over stdio."
    )
    _add_policy_arguments(mcp_stdio_parser)

    return parser


def _add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-file", help="YAML policy profile file.")
    parser.add_argument("--policy-profile", default="default", help="Policy profile name.")
    parser.add_argument(
        "--audit-log",
        help="Append minimized JSONL audit events to a local file.",
    )
    parser.add_argument(
        "--audit-include-raw",
        action="store_true",
        help="Include raw content and unredacted tool arguments in local JSONL audit logs.",
    )
    parser.add_argument(
        "--eventloom-log",
        help="Append metadata audit event to a Zaxy Eventloom log.",
    )
    parser.add_argument(
        "--eventloom-thread",
        default="default",
        help="Eventloom thread/session ID.",
    )


def _policy_from_args(args: argparse.Namespace) -> Policy:
    if args.policy_file is None:
        return _DEFAULT_POLICY
    return load_policy_profile(Path(args.policy_file), args.policy_profile)


def _print_inspection(
    content: GuardedContent,
    action: str,
    target: str,
    policy: Policy,
    args: argparse.Namespace,
) -> None:
    decision = evaluate_policy(
        content,
        ActionRequest(name=action, target=target),
        policy,
    )
    record = AuditRecord(event_id=f"evt_{uuid4().hex}", content=content, decision=decision)
    if args.audit_log is not None:
        JsonlAuditSink(include_raw=args.audit_include_raw).append_content_record(
            record,
            log_path=Path(args.audit_log),
            policy_profile=args.policy_profile,
        )
    if args.eventloom_log is not None:
        EventloomSink().append(
            record,
            log_path=Path(args.eventloom_log),
            thread=args.eventloom_thread,
            policy_profile=args.policy_profile,
        )
    print(record.to_json())


def _mcp_config_from_args(args: argparse.Namespace) -> McpServerConfig:
    loaded_profile = _loaded_profile_from_args(args)
    return McpServerConfig(
        policy=loaded_profile.content_policy,
        tool_call_policy=loaded_profile.tool_call_policy,
        policy_profile=args.policy_profile,
        audit_log=Path(args.audit_log) if args.audit_log is not None else None,
        audit_include_raw=args.audit_include_raw,
        eventloom_log=Path(args.eventloom_log) if args.eventloom_log is not None else None,
        eventloom_thread=args.eventloom_thread,
    )


def _loaded_profile_from_args(args: argparse.Namespace) -> LoadedPolicyProfile:
    if args.policy_file is None:
        return LoadedPolicyProfile(
            content_policy=_DEFAULT_POLICY,
            tool_call_policy=McpServerConfig().tool_call_policy,
        )
    return load_policy_profile(
        Path(args.policy_file),
        args.policy_profile,
        include_tool_call_policy=True,
    )


def _read_input(path: str | None) -> str:
    if path is None:
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
