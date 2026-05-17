from __future__ import annotations

import argparse
import sys
from pathlib import Path
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.html_guard import inspect_html
from aiegis.policy import ActionRequest, Policy, evaluate_policy

_DEFAULT_POLICY = Policy(
    approval_required_actions=("send_email", "post_web", "file_upload", "shell"),
    blocked_actions_on_prompt_injection=("send_email", "post_web", "file_upload", "shell"),
)


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "inspect-html":
        html = _read_input(args.path)
        content = inspect_html(html)
        decision = evaluate_policy(
            content,
            ActionRequest(name=args.action, target=args.target),
            _DEFAULT_POLICY,
        )
        record = AuditRecord(event_id=f"evt_{uuid4().hex}", content=content, decision=decision)
        print(record.to_json())
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

    return parser


def _read_input(path: str | None) -> str:
    if path is None:
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
