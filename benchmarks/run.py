#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from time import perf_counter_ns
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from aiegis.audit import AuditRecord  # noqa: E402
from aiegis.audit_integrity import verify_audit_log  # noqa: E402
from aiegis.document_guard import inspect_document  # noqa: E402
from aiegis.egress_guard import inspect_output  # noqa: E402
from aiegis.email_guard import inspect_email  # noqa: E402
from aiegis.html_guard import inspect_html  # noqa: E402
from aiegis.jsonl_audit_sink import JsonlAuditSink  # noqa: E402
from aiegis.mcp_proxy import McpProxyConfig, handle_proxy_jsonrpc_message  # noqa: E402
from aiegis.memory_guard import inspect_memory  # noqa: E402
from aiegis.policy import ActionRequest, Policy, evaluate_policy  # noqa: E402
from aiegis.tool_firewall import (  # noqa: E402
    ToolCallPolicy,
    ToolCallRequest,
    evaluate_tool_call,
)

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


@dataclass(frozen=True, slots=True)
class Benchmark:
    name: str
    surface: str
    func: Callable[[], None]


class StaticBackend:
    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any]:
        return self._response


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AIegis local benchmark suite.")
    parser.add_argument("--iterations", type=_positive_int, default=100)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    report = {
        "schema_version": 1,
        "iterations": args.iterations,
        "benchmarks": [
            _run_benchmark(benchmark, iterations=args.iterations)
            for benchmark in _benchmarks()
        ],
    }

    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        _print_text_report(report)
    return 0


def _benchmarks() -> tuple[Benchmark, ...]:
    corpus = _load_corpus()
    prompt_html = inspect_html(corpus["html-large.html"])
    action = ActionRequest(name="send_email", target="external")
    policy = Policy(
        approval_required_actions=("send_email",),
        blocked_actions_on_prompt_injection=("send_email",),
    )
    tool_policy = ToolCallPolicy(
        blocked_tools=("filesystem.delete",),
        approval_required_tools=("send_email",),
        sensitive_argument_keys=("token", "api_key", "secret"),
    )
    audit_record = AuditRecord(
        event_id="benchmark_content",
        content=prompt_html,
        decision=evaluate_policy(prompt_html, action, policy),
    )
    tool_decision = evaluate_tool_call(
        ToolCallRequest(
            name="send_email",
            target="external",
            arguments={"to": "ops@example.test", "token": "secret-token"},
        ),
        tool_policy,
    )

    return (
        Benchmark(
            name="inspect_html_small",
            surface="core_guard",
            func=lambda: _consume(inspect_html(corpus["html-small.html"])),
        ),
        Benchmark(
            name="inspect_html_large_hidden_content",
            surface="core_guard",
            func=lambda: _consume(inspect_html(corpus["html-large.html"])),
        ),
        Benchmark(
            name="inspect_email_multipart",
            surface="core_guard",
            func=lambda: _consume(inspect_email(corpus["email-multipart.eml"])),
        ),
        Benchmark(
            name="inspect_memory_poisoning",
            surface="core_guard",
            func=lambda: _consume(inspect_memory(corpus["memory-poisoning.txt"])),
        ),
        Benchmark(
            name="inspect_document_text",
            surface="core_guard",
            func=lambda: _consume(
                inspect_document(
                    corpus["document-text.txt"].encode("utf-8"),
                    filename="document-text.txt",
                    media_type="text/plain",
                )
            ),
        ),
        Benchmark(
            name="inspect_output_secret",
            surface="core_guard",
            func=lambda: _consume(inspect_output(corpus["output-secret.txt"])),
        ),
        Benchmark(
            name="evaluate_policy_prompt_block",
            surface="boundary_decision",
            func=lambda: _consume(evaluate_policy(prompt_html, action, policy)),
        ),
        Benchmark(
            name="evaluate_tool_call_sensitive_external",
            surface="boundary_decision",
            func=lambda: _consume(
                evaluate_tool_call(
                    ToolCallRequest(
                        name="send_email",
                        target="external",
                        arguments={"to": "ops@example.test", "token": "secret-token"},
                    ),
                    tool_policy,
                )
            ),
        ),
        Benchmark(
            name="mcp_proxy_allowed_tool_call",
            surface="boundary_decision",
            func=lambda: _consume(
                handle_proxy_jsonrpc_message(
                    _tool_call_message("search.web", {"query": "aiegis"}),
                    config=McpProxyConfig(
                        backend=StaticBackend(_backend_text_response("clean result")),
                        tool_call_policy=tool_policy,
                    ),
                )
            ),
        ),
        Benchmark(
            name="mcp_proxy_blocked_tool_call",
            surface="boundary_decision",
            func=lambda: _consume(
                handle_proxy_jsonrpc_message(
                    _tool_call_message("filesystem.delete", {"path": "/tmp/important"}),
                    config=McpProxyConfig(
                        backend=StaticBackend(_backend_text_response("deleted")),
                        tool_call_policy=tool_policy,
                    ),
                )
            ),
        ),
        Benchmark(
            name="mcp_proxy_blocked_backend_text_response",
            surface="boundary_decision",
            func=lambda: _consume(
                handle_proxy_jsonrpc_message(
                    _tool_call_message("search.web", {"query": "token"}),
                    config=McpProxyConfig(
                        backend=StaticBackend(_backend_text_response(corpus["output-secret.txt"])),
                        tool_call_policy=tool_policy,
                    ),
                )
            ),
        ),
        Benchmark(
            name="jsonl_audit_append_content_record",
            surface="audit_overhead",
            func=lambda: _benchmark_content_audit_append(audit_record),
        ),
        Benchmark(
            name="jsonl_audit_append_tool_decision",
            surface="audit_overhead",
            func=lambda: _benchmark_tool_audit_append(tool_decision),
        ),
        Benchmark(
            name="verify_audit_log_100_events",
            surface="audit_overhead",
            func=lambda: _benchmark_audit_verify(audit_record, event_count=100),
        ),
        Benchmark(
            name="cli_inspect_html",
            surface="cli_smoke",
            func=lambda: _run_cli("inspect-html", corpus["html-small.html"]),
        ),
        Benchmark(
            name="cli_inspect_email",
            surface="cli_smoke",
            func=lambda: _run_cli("inspect-email", corpus["email-multipart.eml"]),
        ),
        Benchmark(
            name="cli_inspect_output",
            surface="cli_smoke",
            func=lambda: _run_cli(
                "inspect-output",
                corpus["output-secret.txt"],
                expected_returncodes=(1,),
            ),
        ),
    )


def _run_benchmark(benchmark: Benchmark, *, iterations: int) -> dict[str, Any]:
    durations_ms: list[float] = []
    for _ in range(iterations):
        started = perf_counter_ns()
        benchmark.func()
        elapsed_ns = perf_counter_ns() - started
        durations_ms.append(elapsed_ns / 1_000_000)

    median_ms = median(durations_ms)
    return {
        "name": benchmark.name,
        "surface": benchmark.surface,
        "iterations": iterations,
        "min_ms": min(durations_ms),
        "median_ms": median_ms,
        "p95_ms": _percentile(durations_ms, 0.95),
        "max_ms": max(durations_ms),
        "ops_per_sec": 1000 / median_ms if median_ms > 0 else 0,
    }


def _load_corpus() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(CORPUS_DIR.iterdir())
        if path.is_file()
    }


def _consume(value: object) -> None:
    if value is None:
        return


def _benchmark_content_audit_append(record: AuditRecord) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        JsonlAuditSink(clock=lambda: "2026-05-18T00:00:00+00:00").append_content_record(
            record,
            log_path=Path(tmpdir) / "audit.jsonl",
            policy_profile="benchmark",
        )


def _benchmark_tool_audit_append(tool_decision: Any) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        JsonlAuditSink(clock=lambda: "2026-05-18T00:00:00+00:00").append_tool_call_decision(
            tool_decision,
            log_path=Path(tmpdir) / "audit.jsonl",
            policy_profile="benchmark",
        )


def _benchmark_audit_verify(record: AuditRecord, *, event_count: int) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        sink = JsonlAuditSink(clock=lambda: "2026-05-18T00:00:00+00:00")
        for _ in range(event_count):
            sink.append_content_record(record, log_path=log_path, policy_profile="benchmark")
        _consume(verify_audit_log(log_path))


def _run_cli(
    command: str,
    input_text: str,
    *,
    expected_returncodes: tuple[int, ...] = (0,),
) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "aiegis.cli", command],
        input=input_text,
        text=True,
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode not in expected_returncodes:
        raise RuntimeError(f"{command} exited with {result.returncode}")


def _tool_call_message(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "benchmark",
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _backend_text_response(text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "benchmark",
        "result": {"content": [{"type": "text", "text": text}]},
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _print_text_report(report: dict[str, Any]) -> None:
    print(f"AIegis benchmarks ({report['iterations']} iterations)")
    for benchmark in report["benchmarks"]:
        print(
            f"{benchmark['surface']:<18} {benchmark['name']:<40} "
            f"median={benchmark['median_ms']:.3f}ms "
            f"p95={benchmark['p95_ms']:.3f}ms "
            f"ops/s={benchmark['ops_per_sec']:.1f}"
        )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
