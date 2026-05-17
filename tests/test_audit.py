import json

from aiegis.audit import AuditRecord
from aiegis.models import GuardedContent, SourceType, TrustLevel
from aiegis.policy import ActionRequest, Policy, evaluate_policy


def test_audit_record_serializes_content_and_decision_as_json() -> None:
    content = GuardedContent(
        text="Visible body",
        source_type=SourceType.HTML,
        trust_level=TrustLevel.UNTRUSTED,
        links=("https://example.test",),
    )
    decision = evaluate_policy(content, ActionRequest(name="summarize", target="local"), Policy())
    record = AuditRecord(
        event_id="evt_123",
        content=content,
        decision=decision,
    )

    assert json.loads(record.to_json()) == {
        "event_id": "evt_123",
        "content": {
            "text": "Visible body",
            "source_type": "html",
            "trust_level": "untrusted",
            "findings": [],
            "quarantined_segments": [],
            "links": ["https://example.test"],
            "highest_severity": None,
        },
        "decision": {
            "status": "allow",
            "action": {"name": "summarize", "target": "local"},
            "reasons": ["No blocking findings or sensitive action matched policy."],
        },
    }
