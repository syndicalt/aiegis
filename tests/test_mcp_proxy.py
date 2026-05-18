import json
from pathlib import Path
from typing import Any

from aiegis.egress_guard import EgressPolicy
from aiegis.mcp_proxy import McpProxyConfig, handle_proxy_jsonrpc_message
from aiegis.tool_firewall import ToolCallPolicy


class RecordingBackend:
    def __init__(self, response: dict[str, Any] | None) -> None:
        self.response = response
        self.messages: list[dict[str, Any]] = []

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        self.messages.append(message)
        return self.response


def test_proxy_forwards_tools_list_to_backend() -> None:
    backend_response = {
        "jsonrpc": "2.0",
        "id": "tools",
        "result": {
            "tools": [
                {
                    "name": "search.web",
                    "description": "Search the web.",
                    "inputSchema": {"type": "object"},
                }
            ]
        },
    }
    backend = RecordingBackend(backend_response)
    message = {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"}

    response = handle_proxy_jsonrpc_message(message, config=McpProxyConfig(backend=backend))

    assert response == backend_response
    assert backend.messages == [message]


def test_proxy_blocks_backend_tool_call_before_forwarding() -> None:
    backend = RecordingBackend(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "result": {"content": [{"type": "text", "text": "deleted"}]},
        }
    )

    response = handle_proxy_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": {
                "name": "filesystem.delete",
                "arguments": {"path": "/tmp/important"},
            },
        },
        config=McpProxyConfig(
            backend=backend,
            tool_call_policy=ToolCallPolicy(
                blocked_tools=("filesystem.delete",),
                approval_required_tools=(),
                sensitive_argument_keys=(),
            ),
        ),
    )

    assert backend.messages == []
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "call"
    result = response["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["status"] == "block"
    assert result["structuredContent"]["tool"]["name"] == "filesystem.delete"
    assert result["content"] == [
        {"type": "text", "text": json.dumps(result["structuredContent"], sort_keys=True)}
    ]


def test_proxy_audits_blocked_backend_tool_call() -> None:
    calls: list[dict[str, object]] = []

    class FakeAuditSink:
        def append_tool_call_decision(self, decision, *, log_path, policy_profile) -> None:
            calls.append(
                {
                    "status": decision.status.value,
                    "tool_name": decision.tool.name,
                    "log_path": log_path,
                    "policy_profile": policy_profile,
                }
            )

    response = handle_proxy_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": {
                "name": "filesystem.delete",
                "arguments": {"path": "/tmp/important"},
            },
        },
        config=McpProxyConfig(
            backend=RecordingBackend(None),
            tool_call_policy=ToolCallPolicy(
                blocked_tools=("filesystem.delete",),
                approval_required_tools=(),
                sensitive_argument_keys=(),
            ),
            audit_log=Path(".aiegis/proxy-audit.jsonl"),
            audit_sink=FakeAuditSink(),
            policy_profile="strict",
        ),
    )

    assert response["result"]["structuredContent"]["status"] == "block"
    assert calls == [
        {
            "status": "block",
            "tool_name": "filesystem.delete",
            "log_path": Path(".aiegis/proxy-audit.jsonl"),
            "policy_profile": "strict",
        }
    ]


def test_proxy_forwards_allowed_backend_tool_call() -> None:
    backend_response = {
        "jsonrpc": "2.0",
        "id": "call",
        "result": {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"ok": True},
            "isError": False,
        },
    }
    backend = RecordingBackend(backend_response)
    message = {
        "jsonrpc": "2.0",
        "id": "call",
        "method": "tools/call",
        "params": {
            "name": "search.web",
            "arguments": {"query": "AIegis"},
        },
    }

    response = handle_proxy_jsonrpc_message(
        message,
        config=McpProxyConfig(
            backend=backend,
            tool_call_policy=ToolCallPolicy(
                blocked_tools=(),
                approval_required_tools=(),
                sensitive_argument_keys=(),
            ),
        ),
    )

    assert response == backend_response
    assert backend.messages == [message]


def test_proxy_blocks_secret_like_backend_text_response() -> None:
    backend = RecordingBackend(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "result": {
                "content": [{"type": "text", "text": "api_key = sk-test-secret"}],
                "isError": False,
            },
        }
    )

    response = handle_proxy_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": {
                "name": "search.web",
                "arguments": {"query": "AIegis"},
            },
        },
        config=McpProxyConfig(
            backend=backend,
            tool_call_policy=ToolCallPolicy(
                blocked_tools=(),
                approval_required_tools=(),
                sensitive_argument_keys=(),
            ),
            egress_policy=EgressPolicy(blocked_patterns=("api_key_assignment",)),
        ),
    )

    result = response["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["status"] == "block"
    assert result["structuredContent"]["redacted_text"] == "api_key = [REDACTED]"
    assert "sk-test-secret" not in repr(response)


def test_proxy_delegates_aiegis_guard_tool_calls_without_backend_forwarding() -> None:
    backend = RecordingBackend(None)

    response = handle_proxy_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": "guard",
            "method": "tools/call",
            "params": {
                "name": "aiegis.inspect_output",
                "arguments": {"content": "safe summary"},
            },
        },
        config=McpProxyConfig(backend=backend),
    )

    assert backend.messages == []
    assert response["result"]["structuredContent"]["status"] == "allow"
