import json
from pathlib import Path

from aiegis.approval import ApprovalRequest, JsonlApprovalStore
from aiegis.policy import DecisionStatus
from aiegis.tool_firewall import ToolCallDecision, ToolCallRequest


def test_approval_request_redacts_sensitive_arguments() -> None:
    decision = ToolCallDecision(
        status=DecisionStatus.REQUIRE_APPROVAL,
        tool=ToolCallRequest(
            name="send_email",
            target="external",
            arguments={"to": "ops@example.test", "api_token": "secret-token"},
        ),
        reasons=("Tool 'send_email' requires approval by policy.",),
    )

    request = ApprovalRequest.from_decision("approval-1", decision)

    assert request.to_dict() == {
        "approval_id": "approval-1",
        "status": "pending",
        "decision": {
            "status": "require_approval",
            "tool": {
                "name": "send_email",
                "target": "external",
                "arguments": {"to": "ops@example.test", "api_token": "[REDACTED]"},
            },
            "reasons": ["Tool 'send_email' requires approval by policy."],
        },
    }


def test_jsonl_approval_store_appends_pending_request(tmp_path: Path) -> None:
    decision = ToolCallDecision(
        status=DecisionStatus.REQUIRE_APPROVAL,
        tool=ToolCallRequest(name="send_email", target="external", arguments={}),
        reasons=("Tool 'send_email' requires approval by policy.",),
    )
    approval_log = tmp_path / "approvals.jsonl"
    store = JsonlApprovalStore(id_factory=lambda: "approval-1")

    request = store.append_pending(decision, log_path=approval_log)

    assert request.approval_id == "approval-1"
    assert [json.loads(line) for line in approval_log.read_text(encoding="utf-8").splitlines()] == [
        request.to_dict()
    ]
