from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Sequence
from types import TracebackType
from typing import Any, TextIO

from aiegis.mcp_proxy import McpProxyConfig, handle_proxy_jsonrpc_message
from aiegis.mcp_server import JSONRPC_VERSION


class SubprocessMcpBackend:
    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("Backend command must not be empty.")
        self._command = tuple(command)
        self._process: subprocess.Popen[str] | None = None

    def __enter__(self) -> SubprocessMcpBackend:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def start(self) -> None:
        if self._process is not None:
            return
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            encoding="utf-8",
        )

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        process = self._require_process()
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("Backend process stdio pipes are unavailable.")

        process.stdin.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
        process.stdin.flush()

        if message.get("id") is None:
            return None

        response_line = process.stdout.readline()
        if response_line == "":
            raise RuntimeError("Backend process closed stdout before returning a response.")
        response = json.loads(response_line)
        if not isinstance(response, dict):
            raise RuntimeError("Backend process returned a non-object JSON-RPC response.")
        return response

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None:
            raise RuntimeError("Backend process has not been started.")
        return self._process


def run_stdio_proxy(
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    config: McpProxyConfig,
) -> None:
    for line in stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            response: dict[str, object] | None = _error(None, -32700, "Parse error")
        else:
            if not isinstance(message, dict):
                response = _error(None, -32600, "Invalid Request")
            else:
                response = handle_proxy_jsonrpc_message(message, config=config)
        if response is None:
            continue
        stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        stdout.flush()


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }
