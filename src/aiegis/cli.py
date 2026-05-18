from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.audit_integrity import verify_audit_log
from aiegis.document_guard import inspect_document
from aiegis.egress_guard import EgressPolicy, inspect_output
from aiegis.email_guard import inspect_email
from aiegis.eventloom_sink import EventloomSink
from aiegis.html_guard import inspect_html
from aiegis.input_limits import DEFAULT_MAX_INPUT_CHARS
from aiegis.jsonl_audit_sink import JsonlAuditSink
from aiegis.mcp_proxy import McpProxyConfig
from aiegis.mcp_server import McpServerConfig, run_stdio_server
from aiegis.mcp_stdio_proxy import SubprocessMcpBackend, run_stdio_proxy
from aiegis.memory_guard import inspect_memory
from aiegis.models import GuardedContent
from aiegis.policy import ActionRequest, DecisionStatus, Policy, evaluate_policy
from aiegis.policy_profiles import LoadedPolicyProfile, load_policy_profile

_DEFAULT_POLICY = Policy(
    approval_required_actions=("send_email", "post_web", "file_upload", "shell"),
    blocked_actions_on_prompt_injection=("send_email", "post_web", "file_upload", "shell"),
)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    exit_code = 0

    if args.command == "inspect-html":
        content = inspect_html(_read_input(args.path), max_input_chars=args.max_input_chars)
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
    elif args.command == "inspect-email":
        content = inspect_email(_read_input(args.path), max_input_chars=args.max_input_chars)
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
    elif args.command == "inspect-memory":
        content = inspect_memory(_read_input(args.path), max_input_chars=args.max_input_chars)
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
    elif args.command == "inspect-document":
        content = inspect_document(
            _read_input_bytes(args.path),
            filename=Path(args.path).name if args.path is not None else None,
            media_type=args.media_type,
            max_input_chars=args.max_input_chars,
        )
        _print_inspection(content, args.action, args.target, _policy_from_args(args), args)
    elif args.command == "inspect-output":
        inspection = inspect_output(_read_input(args.path), policy=_egress_policy_from_args(args))
        print(json.dumps(inspection.to_dict(), sort_keys=True))
        exit_code = 0 if inspection.status is DecisionStatus.ALLOW else 1
    elif args.command == "mcp-stdio":
        run_stdio_server(config=_mcp_config_from_args(args))
    elif args.command == "mcp-proxy-stdio":
        with SubprocessMcpBackend(args.backend_command) as backend:
            run_stdio_proxy(config=_mcp_proxy_config_from_args(args, backend=backend))
    elif args.command == "verify-audit-log":
        verification = verify_audit_log(Path(args.path))
        print(json.dumps(verification.to_dict(), sort_keys=True))
        exit_code = 0 if verification.valid else 1
    else:
        parser.print_help(sys.stderr)
        exit_code = 2
    return exit_code


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

    inspect_memory_parser = subcommands.add_parser(
        "inspect-memory",
        help="Inspect untrusted persisted memory text.",
    )
    inspect_memory_parser.add_argument(
        "path", nargs="?", help="Memory text file path. Reads stdin when omitted."
    )
    inspect_memory_parser.add_argument(
        "--action", default="memory_retrieve", help="Proposed action name."
    )
    inspect_memory_parser.add_argument("--target", default="local", help="Proposed action target.")
    _add_policy_arguments(inspect_memory_parser)

    inspect_document_parser = subcommands.add_parser(
        "inspect-document",
        help="Inspect an untrusted attachment or document.",
    )
    inspect_document_parser.add_argument(
        "path", nargs="?", help="Document path. Reads stdin bytes when omitted."
    )
    inspect_document_parser.add_argument(
        "--media-type",
        help="Declared document media type, such as text/plain or application/pdf.",
    )
    inspect_document_parser.add_argument("--action", default="summarize", help="Proposed action.")
    inspect_document_parser.add_argument("--target", default="local", help="Proposed target.")
    _add_policy_arguments(inspect_document_parser)

    inspect_output_parser = subcommands.add_parser(
        "inspect-output",
        help="Inspect outbound text before returning or sending it.",
    )
    inspect_output_parser.add_argument(
        "path", nargs="?", help="Output text file path. Reads stdin when omitted."
    )
    _add_policy_arguments(inspect_output_parser)

    mcp_stdio_parser = subcommands.add_parser(
        "mcp-stdio", help="Run the AIegis MCP server over stdio."
    )
    _add_policy_arguments(mcp_stdio_parser)

    mcp_proxy_stdio_parser = subcommands.add_parser(
        "mcp-proxy-stdio",
        help="Run an AIegis MCP stdio proxy in front of a backend MCP command.",
    )
    _add_policy_arguments(mcp_proxy_stdio_parser)
    mcp_proxy_stdio_parser.add_argument(
        "backend_command",
        nargs="+",
        help="Backend MCP command and arguments, passed without a shell.",
    )

    verify_audit_log_parser = subcommands.add_parser(
        "verify-audit-log",
        help="Verify a local JSONL audit log hash chain.",
    )
    verify_audit_log_parser.add_argument("path", help="JSONL audit log path.")

    return parser


def _add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-file", help="YAML policy profile file.")
    parser.add_argument("--policy-profile", default="default", help="Policy profile name.")
    parser.add_argument(
        "--max-input-chars",
        default=DEFAULT_MAX_INPUT_CHARS,
        type=_positive_int,
        help="Maximum untrusted input characters to parse before truncation.",
    )
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
    return _mcp_config_from_loaded_profile(args, loaded_profile)


def _mcp_config_from_loaded_profile(
    args: argparse.Namespace,
    loaded_profile: LoadedPolicyProfile,
) -> McpServerConfig:
    return McpServerConfig(
        policy=loaded_profile.content_policy,
        tool_call_policy=loaded_profile.tool_call_policy,
        egress_policy=loaded_profile.egress_policy,
        policy_profile=args.policy_profile,
        audit_log=Path(args.audit_log) if args.audit_log is not None else None,
        audit_include_raw=args.audit_include_raw,
        max_input_chars=args.max_input_chars,
        eventloom_log=Path(args.eventloom_log) if args.eventloom_log is not None else None,
        eventloom_thread=args.eventloom_thread,
    )


def _loaded_profile_from_args(args: argparse.Namespace) -> LoadedPolicyProfile:
    if args.policy_file is None:
        return LoadedPolicyProfile(
            content_policy=_DEFAULT_POLICY,
            tool_call_policy=McpServerConfig().tool_call_policy,
            egress_policy=McpServerConfig().egress_policy,
        )
    return load_policy_profile(
        Path(args.policy_file),
        args.policy_profile,
        include_tool_call_policy=True,
    )


def _egress_policy_from_args(args: argparse.Namespace) -> EgressPolicy:
    return _loaded_profile_from_args(args).egress_policy


def _mcp_proxy_config_from_args(
    args: argparse.Namespace,
    *,
    backend: SubprocessMcpBackend,
) -> McpProxyConfig:
    loaded_profile = _loaded_profile_from_args(args)
    return McpProxyConfig(
        backend=backend,
        tool_call_policy=loaded_profile.tool_call_policy,
        egress_policy=loaded_profile.egress_policy,
        guard_config=_mcp_config_from_loaded_profile(args, loaded_profile),
    )


def _read_input(path: str | None) -> str:
    if path is None:
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _read_input_bytes(path: str | None) -> bytes:
    if path is None:
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
