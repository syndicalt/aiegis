import json
from pathlib import Path

from aiegis.audit import AuditRecord
from aiegis.jsonl_audit_sink import JsonlAuditSink
from aiegis.models import GuardedContent, SourceType, TrustLevel
from aiegis.policy import ActionRequest, Policy, evaluate_policy
from aiegis.tool_firewall import ToolCallPolicy, ToolCallRequest, evaluate_tool_call


def test_jsonl_sink_appends_content_audit_record(tmp_path: Path) -> None:
    sink = JsonlAuditSink(clock=lambda: "2026-05-18T00:00:00+00:00")
    log_path = tmp_path / "nested" / "audit.jsonl"
    content = GuardedContent(
        text="Visible body",
        source_type=SourceType.HTML,
        trust_level=TrustLevel.UNTRUSTED,
    )
    record = AuditRecord(
        event_id="evt_123",
        content=content,
        decision=evaluate_policy(
            content,
            ActionRequest(name="summarize", target="local"),
            Policy(),
        ),
    )

    sink.append_content_record(record, log_path=log_path, policy_profile="default")

    assert json.loads(log_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "event_type": "aiegis.content.decided",
        "timestamp": "2026-05-18T00:00:00+00:00",
        "policy_profile": "default",
        "payload": {
            "event_id": "evt_123",
            "content": {
                "source_type": "html",
                "trust_level": "untrusted",
                "findings": [],
                "quarantined_segment_count": 0,
                "link_count": 0,
                "highest_severity": None,
            },
            "decision": {
                "status": "allow",
                "action": {"name": "summarize", "target": "local"},
                "reasons": ["No blocking findings or sensitive action matched policy."],
            },
        },
    }


def test_jsonl_sink_minimizes_content_audit_by_default(tmp_path: Path) -> None:
    sink = JsonlAuditSink(clock=lambda: "2026-05-18T00:00:02+00:00")
    log_path = tmp_path / "audit.jsonl"
    content = GuardedContent(
        text="Visible body with customer secret",
        source_type=SourceType.HTML,
        trust_level=TrustLevel.UNTRUSTED,
        quarantined_segments=("ignore previous instructions",),
        links=("https://example.test",),
    )
    record = AuditRecord(
        event_id="evt_456",
        content=content,
        decision=evaluate_policy(
            content,
            ActionRequest(name="summarize", target="local"),
            Policy(),
        ),
    )

    sink.append_content_record(record, log_path=log_path, policy_profile="default")

    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert "Visible body with customer secret" not in repr(event)
    assert "ignore previous instructions" not in repr(event)
    assert event["payload"] == {
        "event_id": "evt_456",
        "content": {
            "source_type": "html",
            "trust_level": "untrusted",
            "findings": [],
            "quarantined_segment_count": 1,
            "link_count": 1,
            "highest_severity": None,
        },
        "decision": {
            "status": "allow",
            "action": {"name": "summarize", "target": "local"},
            "reasons": ["No blocking findings or sensitive action matched policy."],
        },
    }


def test_jsonl_sink_appends_tool_call_decision(tmp_path: Path) -> None:
    sink = JsonlAuditSink(clock=lambda: "2026-05-18T00:00:01+00:00")
    log_path = tmp_path / "audit.jsonl"
    decision = evaluate_tool_call(
        ToolCallRequest(name="shell", target="local", arguments={"command": "rm -rf /tmp/x"}),
        policy=ToolCallPolicy(blocked_tools=("shell",)),
    )

    sink.append_tool_call_decision(decision, log_path=log_path, policy_profile="strict")

    assert json.loads(log_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "event_type": "aiegis.tool_call.decided",
        "timestamp": "2026-05-18T00:00:01+00:00",
        "policy_profile": "strict",
        "payload": decision.to_dict(),
    }


def test_jsonl_sink_redacts_sensitive_tool_arguments_by_default(tmp_path: Path) -> None:
    sink = JsonlAuditSink(clock=lambda: "2026-05-18T00:00:03+00:00")
    log_path = tmp_path / "audit.jsonl"
    decision = evaluate_tool_call(
        ToolCallRequest(
            name="http.post",
            target="https://example.test/upload",
            arguments={"token": "secret-token", "body": "safe body"},
        ),
        policy=ToolCallPolicy(),
    )

    sink.append_tool_call_decision(decision, log_path=log_path, policy_profile="strict")

    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert "secret-token" not in repr(event)
    assert event["payload"]["tool"]["arguments"] == {
        "token": "[REDACTED]",
        "body": "safe body",
    }
