import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from aiegis.egress_guard import EgressPolicy
from aiegis.mcp_proxy import McpProxyConfig
from aiegis.mcp_stdio_proxy import SubprocessMcpBackend, run_stdio_proxy
from aiegis.tool_firewall import ToolCallPolicy


class StaticBackend:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.messages: list[dict[str, Any]] = []

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        self.messages.append(message)
        if message.get("id") is None:
            return None
        return self.response


def test_subprocess_backend_exchanges_jsonrpc_lines(tmp_path: Path) -> None:
    backend_script = tmp_path / "backend.py"
    backend_script.write_text(
        """
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    sys.stdout.write(json.dumps({
        "jsonrpc": "2.0",
        "id": message["id"],
        "result": {"content": [{"type": "text", "text": "backend-ok"}]},
    }) + "\\n")
    sys.stdout.flush()
""".lstrip(),
        encoding="utf-8",
    )

    with SubprocessMcpBackend((sys.executable, str(backend_script))) as backend:
        response = backend.handle_jsonrpc_message(
            {"jsonrpc": "2.0", "id": "call", "method": "tools/list"}
        )

    assert response == {
        "jsonrpc": "2.0",
        "id": "call",
        "result": {"content": [{"type": "text", "text": "backend-ok"}]},
    }


def test_subprocess_backend_rejects_empty_command() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        SubprocessMcpBackend(())


def test_subprocess_backend_requires_start_before_use() -> None:
    backend = SubprocessMcpBackend((sys.executable, "-c", ""))

    with pytest.raises(RuntimeError, match="has not been started"):
        backend.handle_jsonrpc_message({"jsonrpc": "2.0", "id": "call", "method": "tools/list"})


def test_subprocess_backend_close_is_idempotent_before_start() -> None:
    backend = SubprocessMcpBackend((sys.executable, "-c", ""))

    backend.close()


def test_subprocess_backend_start_is_idempotent(tmp_path: Path) -> None:
    backend_script = tmp_path / "backend.py"
    backend_script.write_text(
        """
import time
time.sleep(30)
""".lstrip(),
        encoding="utf-8",
    )
    backend = SubprocessMcpBackend((sys.executable, str(backend_script)))

    try:
        backend.start()
        backend.start()
    finally:
        backend.close()


def test_subprocess_backend_returns_none_for_notifications(tmp_path: Path) -> None:
    backend_script = tmp_path / "backend.py"
    backend_script.write_text(
        """
import sys

for line in sys.stdin:
    if line:
        break
""".lstrip(),
        encoding="utf-8",
    )

    with SubprocessMcpBackend((sys.executable, str(backend_script))) as backend:
        response = backend.handle_jsonrpc_message(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )

    assert response is None


def test_subprocess_backend_rejects_non_object_response(tmp_path: Path) -> None:
    backend_script = tmp_path / "backend.py"
    backend_script.write_text(
        """
import sys

sys.stdin.readline()
sys.stdout.write("[]\\n")
sys.stdout.flush()
""".lstrip(),
        encoding="utf-8",
    )

    with (
        SubprocessMcpBackend((sys.executable, str(backend_script))) as backend,
        pytest.raises(RuntimeError, match="non-object"),
    ):
        backend.handle_jsonrpc_message({"jsonrpc": "2.0", "id": "call", "method": "tools/list"})


def test_stdio_proxy_filters_backend_tool_call_response() -> None:
    backend = StaticBackend(
        {
            "jsonrpc": "2.0",
            "id": "call",
            "result": {
                "content": [{"type": "text", "text": "api_key = sk-test-secret"}],
                "isError": False,
            },
        }
    )
    stdin = StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "call",
                "method": "tools/call",
                "params": {"name": "search.web", "arguments": {"query": "AIegis"}},
            }
        )
        + "\n"
    )
    stdout = StringIO()

    run_stdio_proxy(
        stdin=stdin,
        stdout=stdout,
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

    output = json.loads(stdout.getvalue())
    assert output["result"]["isError"] is True
    assert output["result"]["structuredContent"]["redacted_text"] == "api_key = [REDACTED]"
    assert "sk-test-secret" not in stdout.getvalue()


def test_stdio_proxy_writes_parse_errors() -> None:
    backend = StaticBackend({"jsonrpc": "2.0", "id": "unused", "result": {}})
    stdout = StringIO()

    run_stdio_proxy(
        stdin=StringIO("{bad json}\n"),
        stdout=stdout,
        config=McpProxyConfig(backend=backend),
    )

    output = json.loads(stdout.getvalue())
    assert output == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "Parse error"},
    }
    assert backend.messages == []


def test_stdio_proxy_writes_invalid_request_errors() -> None:
    backend = StaticBackend({"jsonrpc": "2.0", "id": "unused", "result": {}})
    stdout = StringIO()

    run_stdio_proxy(
        stdin=StringIO("[]\n"),
        stdout=stdout,
        config=McpProxyConfig(backend=backend),
    )

    output = json.loads(stdout.getvalue())
    assert output == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    assert backend.messages == []


def test_stdio_proxy_skips_blank_lines_and_notifications() -> None:
    backend = StaticBackend({"jsonrpc": "2.0", "id": "unused", "result": {}})
    stdout = StringIO()

    run_stdio_proxy(
        stdin=StringIO('\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n'),
        stdout=stdout,
        config=McpProxyConfig(backend=backend),
    )

    assert stdout.getvalue() == ""
    assert backend.messages == [{"jsonrpc": "2.0", "method": "notifications/initialized"}]
