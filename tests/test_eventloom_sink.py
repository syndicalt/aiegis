from pathlib import Path

import pytest

from aiegis.audit import AuditRecord
from aiegis.eventloom_sink import (
    EventloomSink,
    EventloomUnavailableError,
    build_eventloom_payload,
)
from aiegis.models import Finding, FindingSeverity, GuardedContent, SourceType, TrustLevel
from aiegis.policy import ActionRequest, Policy, evaluate_policy

VISIBLE_SHA256 = "sha256:8411f5abb4c710b176d8f28c735f55a5f1e1ac648a8a48432ce4c10014a9bb91"


def test_build_eventloom_payload_excludes_raw_content() -> None:
    record = _audit_record(
        GuardedContent(
            text="secret body text",
            source_type=SourceType.EMAIL,
            trust_level=TrustLevel.UNTRUSTED,
            findings=(
                Finding(
                    code="prompt_injection_phrase",
                    severity=FindingSeverity.HIGH,
                    message="Prompt-like instruction was found.",
                    evidence="ignore previous instructions",
                ),
            ),
            quarantined_segments=("hidden malicious text",),
            links=("https://example.test",),
        )
    )

    payload = build_eventloom_payload(
        record,
        content_hash="sha256:abc123",
        policy_profile="strict_email",
    )

    assert payload == {
        "audit_event_id": "audit_1",
        "content_hash": "sha256:abc123",
        "source_type": "email",
        "trust_level": "untrusted",
        "highest_severity": "high",
        "findings": [{"code": "prompt_injection_phrase", "severity": "high"}],
        "finding_count": 1,
        "quarantined_segment_count": 1,
        "link_count": 1,
        "decision": {
            "status": "allow",
            "action": {"name": "summarize", "target": "local"},
            "reasons": ["No blocking findings or sensitive action matched policy."],
        },
        "policy_profile": "strict_email",
    }
    assert "secret body text" not in repr(payload)
    assert "hidden malicious text" not in repr(payload)
    assert "ignore previous instructions" not in repr(payload)


def test_eventloom_sink_appends_metadata_event() -> None:
    eventlog = _FakeEventLog()
    sink = EventloomSink(eventlog_factory=lambda path: eventlog)
    record = _audit_record(
        GuardedContent(
            text="Visible",
            source_type=SourceType.HTML,
            trust_level=TrustLevel.UNTRUSTED,
        )
    )

    sink.append(
        record,
        log_path=Path(".eventloom/aiegis.jsonl"),
        thread="aiegis-default",
        policy_profile="default",
    )

    assert eventlog.appended == [
        {
            "event_type": "aiegis.policy.decided",
            "actor": "aiegis",
            "thread": "aiegis-default",
            "payload": {
                "audit_event_id": "audit_1",
                "content_hash": VISIBLE_SHA256,
                "source_type": "html",
                "trust_level": "untrusted",
                "highest_severity": None,
                "findings": [],
                "finding_count": 0,
                "quarantined_segment_count": 0,
                "link_count": 0,
                "decision": {
                    "status": "allow",
                    "action": {"name": "summarize", "target": "local"},
                    "reasons": ["No blocking findings or sensitive action matched policy."],
                },
                "policy_profile": "default",
            },
        }
    ]


def test_eventloom_sink_reports_missing_zaxy_dependency() -> None:
    sink = EventloomSink(eventlog_factory=None)

    with pytest.raises(EventloomUnavailableError, match="Install zaxy"):
        sink.append(
            _audit_record(
                GuardedContent(
                    text="Visible",
                    source_type=SourceType.HTML,
                    trust_level=TrustLevel.UNTRUSTED,
                )
            ),
            log_path=Path(".eventloom/aiegis.jsonl"),
            thread="aiegis-default",
            policy_profile="default",
        )


class _FakeEventLog:
    def __init__(self) -> None:
        self.appended: list[dict[str, object]] = []

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, object],
        thread: str,
    ) -> None:
        self.appended.append(
            {
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "thread": thread,
            }
        )


def _audit_record(content: GuardedContent) -> AuditRecord:
    decision = evaluate_policy(content, ActionRequest(name="summarize", target="local"), Policy())
    return AuditRecord(event_id="audit_1", content=content, decision=decision)
