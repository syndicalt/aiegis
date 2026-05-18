from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO
from uuid import uuid4

from aiegis.audit import AuditRecord
from aiegis.email_guard import inspect_email
from aiegis.eventloom_sink import EventloomSink
from aiegis.html_guard import inspect_html
from aiegis.jsonl_audit_sink import JsonlAuditSink
from aiegis.models import GuardedContent
from aiegis.policy import ActionRequest, Policy, evaluate_policy
from aiegis.tool_firewall import (
    ToolCallDecision,
    ToolCallPolicy,
    ToolCallRequest,
    evaluate_tool_call,
)

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

_TOOL_CALL_INPUT_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["tool_name"],
    "properties": {
        "tool_name": {"type": "string"},
        "target": {"type": "string", "default": "local"},
        "arguments": {"type": "object", "default": {}},
    },
}


class EventloomSinkProtocol(Protocol):
    def append(
        self,
        record: AuditRecord,
        *,
        log_path: Path,
        thread: str,
        policy_profile: str,
    ) -> None: ...


class JsonlAuditSinkProtocol(Protocol):
    def append_content_record(
        self,
        record: AuditRecord,
        *,
        log_path: Path,
        policy_profile: str,
    ) -> None: ...

    def append_tool_call_decision(
        self,
        decision: ToolCallDecision,
        *,
        log_path: Path,
        policy_profile: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class McpServerConfig:
    policy: Policy = _DEFAULT_POLICY
    tool_call_policy: ToolCallPolicy = ToolCallPolicy()
    policy_profile: str = "default"
    audit_log: Path | None = None
    audit_sink: JsonlAuditSinkProtocol | None = None
    eventloom_log: Path | None = None
    eventloom_thread: str = "default"
    eventloom_sink: EventloomSinkProtocol | None = None


_DEFAULT_MCP_CONFIG = McpServerConfig()


def handle_jsonrpc_message(
    message: dict[str, Any],
    *,
    config: McpServerConfig = _DEFAULT_MCP_CONFIG,
) -> dict[str, Any] | None:
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
            return _response(request_id, _call_tool(message.get("params"), config=config))
        return _error(request_id, -32601, f"Method not found: {method}")
    except ValueError as exc:
        return _error(request_id, -32602, str(exc))


def run_stdio_server(
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    config: McpServerConfig = _DEFAULT_MCP_CONFIG,
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
            response = handle_jsonrpc_message(message, config=config)
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
        {
            "name": "aiegis.evaluate_tool_call",
            "description": (
                "Evaluate a proposed agent tool invocation before execution and return "
                "an allow, approval, or block decision."
            ),
            "inputSchema": _TOOL_CALL_INPUT_SCHEMA,
        },
    ]


def _call_tool(params: object, *, config: McpServerConfig) -> dict[str, object]:
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object.")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise ValueError("Tool name is required.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object.")

    if name == "aiegis.evaluate_tool_call":
        return _evaluate_tool_call(arguments, config=config)

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

    record = _audit_guarded_content(guarded, action=action, target=target, policy=config.policy)
    if config.audit_log is not None:
        audit_sink = config.audit_sink if config.audit_sink is not None else JsonlAuditSink()
        audit_sink.append_content_record(
            record,
            log_path=config.audit_log,
            policy_profile=config.policy_profile,
        )
    if config.eventloom_log is not None:
        sink = config.eventloom_sink if config.eventloom_sink is not None else EventloomSink()
        sink.append(
            record,
            log_path=config.eventloom_log,
            thread=config.eventloom_thread,
            policy_profile=config.policy_profile,
        )

    audit = record.to_dict()
    return {
        "content": [{"type": "text", "text": json.dumps(audit, sort_keys=True)}],
        "structuredContent": audit,
        "isError": False,
    }


def _evaluate_tool_call(
    arguments: dict[object, object],
    *,
    config: McpServerConfig,
) -> dict[str, object]:
    tool_name = _required_string(arguments, "tool_name")
    target = _optional_string(arguments, "target", default="local")
    tool_arguments = arguments.get("arguments", {})
    if not isinstance(tool_arguments, dict):
        raise ValueError("Tool argument 'arguments' must be an object.")

    decision = evaluate_tool_call(
        ToolCallRequest(name=tool_name, target=target, arguments=dict(tool_arguments)),
        config.tool_call_policy,
    )
    if config.audit_log is not None:
        audit_sink = config.audit_sink if config.audit_sink is not None else JsonlAuditSink()
        audit_sink.append_tool_call_decision(
            decision,
            log_path=config.audit_log,
            policy_profile=config.policy_profile,
        )
    decision_dict = decision.to_dict()
    return {
        "content": [{"type": "text", "text": json.dumps(decision_dict, sort_keys=True)}],
        "structuredContent": decision_dict,
        "isError": False,
    }


def _audit_guarded_content(
    content: GuardedContent,
    *,
    action: str,
    target: str,
    policy: Policy,
) -> AuditRecord:
    decision = evaluate_policy(
        content,
        ActionRequest(name=action, target=target),
        policy,
    )
    return AuditRecord(event_id=f"evt_{uuid4().hex}", content=content, decision=decision)


def _optional_string(arguments: dict[object, object], key: str, *, default: str) -> str:
    value = arguments.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"Tool argument '{key}' must be a string.")
    return value


def _required_string(arguments: dict[object, object], key: str) -> str:
    value = arguments.get(key)
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
