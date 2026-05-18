from __future__ import annotations

import json
import sys
from typing import Any, TextIO
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.email_guard import inspect_email
from aiegis.html_guard import inspect_html
from aiegis.models import GuardedContent
from aiegis.policy import ActionRequest, Policy, evaluate_policy

MCP_PROTOCOL_VERSION = "2025-11-25"
JSONRPC_VERSION = "2.0"

_DEFAULT_POLICY = Policy(
    approval_required_actions=("send_email", "post_web", "file_upload", "shell"),
    blocked_actions_on_prompt_injection=("send_email", "post_web", "file_upload", "shell"),
)

_INSPECTION_INPUT_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["content"],
    "properties": {
        "content": {"type": "string"},
        "action": {"type": "string", "default": "summarize"},
        "target": {"type": "string", "default": "local"},
    },
}


def handle_jsonrpc_message(message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None

    try:
        if method == "initialize":
            return _response(request_id, _initialize_result())
        if method == "tools/list":
            return _response(request_id, {"tools": _tool_definitions()})
        if method == "tools/call":
            return _response(request_id, _call_tool(message.get("params")))
        return _error(request_id, -32601, f"Method not found: {method}")
    except ValueError as exc:
        return _error(request_id, -32602, str(exc))


def run_stdio_server(
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> None:
    for line in stdin:
        stripped = line.strip()
        if not stripped:
            continue
        response: dict[str, object] | None
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            response = _error(None, -32700, "Parse error")
        else:
            response = handle_jsonrpc_message(message)
        if response is None:
            continue
        stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        stdout.flush()


def _initialize_result() -> dict[str, object]:
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "aiegis", "version": "0.1.0"},
    }


def _tool_definitions() -> list[dict[str, object]]:
    return [
        {
            "name": "aiegis.inspect_html",
            "description": (
                "Inspect untrusted HTML and return sanitized content, findings, "
                "and a policy decision."
            ),
            "inputSchema": _INSPECTION_INPUT_SCHEMA,
        },
        {
            "name": "aiegis.inspect_email",
            "description": (
                "Inspect untrusted email and return sanitized content, findings, "
                "and a policy decision."
            ),
            "inputSchema": _INSPECTION_INPUT_SCHEMA,
        },
    ]


def _call_tool(params: object) -> dict[str, object]:
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object.")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise ValueError("Tool name is required.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object.")

    content = arguments.get("content")
    if not isinstance(content, str):
        raise ValueError("Tool argument 'content' must be a string.")
    action = _optional_string(arguments, "action", default="summarize")
    target = _optional_string(arguments, "target", default="local")

    if name == "aiegis.inspect_html":
        guarded = inspect_html(content)
    elif name == "aiegis.inspect_email":
        guarded = inspect_email(content)
    else:
        raise ValueError(f"Unknown tool: {name}")

    audit = _audit_guarded_content(guarded, action=action, target=target).to_dict()
    return {
        "content": [{"type": "text", "text": json.dumps(audit, sort_keys=True)}],
        "structuredContent": audit,
        "isError": False,
    }


def _audit_guarded_content(content: GuardedContent, *, action: str, target: str) -> AuditRecord:
    decision = evaluate_policy(
        content,
        ActionRequest(name=action, target=target),
        _DEFAULT_POLICY,
    )
    return AuditRecord(event_id=f"evt_{uuid4().hex}", content=content, decision=decision)


def _optional_string(arguments: dict[object, object], key: str, *, default: str) -> str:
    value = arguments.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"Tool argument '{key}' must be a string.")
    return value


def _response(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }
