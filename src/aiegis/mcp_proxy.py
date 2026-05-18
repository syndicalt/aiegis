from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aiegis.approval import ApprovalRequest, JsonlApprovalStore
from aiegis.egress_guard import DEFAULT_EGRESS_POLICY, EgressPolicy, inspect_output
from aiegis.jsonl_audit_sink import JsonlAuditSink
from aiegis.mcp_server import JSONRPC_VERSION, McpServerConfig, handle_jsonrpc_message
from aiegis.policy import DecisionStatus
from aiegis.tool_firewall import (
    ToolCallDecision,
    ToolCallPolicy,
    ToolCallRequest,
    evaluate_tool_call,
)


class McpBackend(Protocol):
    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any] | None: ...


class ToolCallAuditSink(Protocol):
    def append_tool_call_decision(
        self,
        decision: ToolCallDecision,
        *,
        log_path: Path,
        policy_profile: str,
    ) -> None: ...


class ApprovalStore(Protocol):
    def append_pending(
        self,
        decision: ToolCallDecision,
        *,
        log_path: Path,
    ) -> ApprovalRequest: ...


@dataclass(frozen=True, slots=True)
class McpProxyConfig:
    backend: McpBackend
    tool_call_policy: ToolCallPolicy = ToolCallPolicy()
    egress_policy: EgressPolicy = DEFAULT_EGRESS_POLICY
    tool_targets: Mapping[str, str] = field(default_factory=dict)
    guard_config: McpServerConfig = McpServerConfig()
    policy_profile: str = "default"
    audit_log: Path | None = None
    audit_include_raw: bool = False
    audit_sink: ToolCallAuditSink | None = None
    approval_log: Path | None = None
    approval_store: ApprovalStore | None = None


def handle_proxy_jsonrpc_message(
    message: dict[str, Any],
    *,
    config: McpProxyConfig,
) -> dict[str, Any] | None:
    request_id = message.get("id")
    if request_id is None:
        return config.backend.handle_jsonrpc_message(message)

    method = message.get("method")
    if method != "tools/call":
        return config.backend.handle_jsonrpc_message(message)

    return _handle_tools_call(message, request_id=request_id, config=config)


def _handle_tools_call(
    message: dict[str, Any],
    *,
    request_id: object,
    config: McpProxyConfig,
) -> dict[str, Any] | None:
    response: dict[str, Any] | None

    try:
        tool_name, arguments = _tool_call_params(message.get("params"))
    except ValueError as exc:
        return _error(request_id, -32602, str(exc))

    if tool_name.startswith("aiegis."):
        return handle_jsonrpc_message(message, config=config.guard_config)

    decision = evaluate_tool_call(
        ToolCallRequest(
            name=tool_name,
            target=config.tool_targets.get(tool_name, "local"),
            arguments=arguments,
        ),
        config.tool_call_policy,
    )
    if decision.status is not DecisionStatus.ALLOW:
        _audit_tool_decision(decision, config=config)
        approval = _append_approval(decision, config=config)
        return _response(request_id, _tool_decision_result(decision.to_dict(), approval=approval))

    backend_response = config.backend.handle_jsonrpc_message(message)
    if backend_response is None:
        response = None
    else:
        response = _inspect_backend_response(backend_response, policy=config.egress_policy)
    return response


def _tool_call_params(params: object) -> tuple[str, dict[str, Any]]:
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object.")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise ValueError("Tool name is required.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object.")
    return name, dict(arguments)


def _inspect_backend_response(
    response: dict[str, Any],
    *,
    policy: EgressPolicy,
) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        return response

    text = _text_content(result)
    if text == "":
        return response

    inspection = inspect_output(text, policy=policy)
    if inspection.status is DecisionStatus.ALLOW:
        return response

    redacted_response = copy.deepcopy(response)
    redacted_response["result"] = {
        "content": [{"type": "text", "text": inspection.redacted_text}],
        "structuredContent": inspection.to_dict(),
        "isError": True,
    }
    return redacted_response


def _text_content(result: dict[str, Any]) -> str:
    content = result.get("content")
    if not isinstance(content, list):
        return ""

    text_parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "text":
            continue
        text = item.get("text")
        if isinstance(text, str):
            text_parts.append(text)
    return "\n".join(text_parts)


def _tool_decision_result(
    decision: dict[str, Any],
    *,
    approval: ApprovalRequest | None = None,
) -> dict[str, object]:
    structured_content = decision
    if approval is not None:
        structured_content = {**decision, "approval_id": approval.approval_id}
    return {
        "content": [{"type": "text", "text": json.dumps(structured_content, sort_keys=True)}],
        "structuredContent": structured_content,
        "isError": True,
    }


def _audit_tool_decision(decision: ToolCallDecision, *, config: McpProxyConfig) -> None:
    if config.audit_log is None:
        return
    sink = (
        config.audit_sink
        if config.audit_sink is not None
        else JsonlAuditSink(include_raw=config.audit_include_raw)
    )
    sink.append_tool_call_decision(
        decision,
        log_path=config.audit_log,
        policy_profile=config.policy_profile,
    )


def _append_approval(
    decision: ToolCallDecision,
    *,
    config: McpProxyConfig,
) -> ApprovalRequest | None:
    if decision.status is not DecisionStatus.REQUIRE_APPROVAL:
        return None
    if config.approval_log is None:
        return None
    store = config.approval_store if config.approval_store is not None else JsonlApprovalStore()
    return store.append_pending(decision, log_path=config.approval_log)


def _response(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }
