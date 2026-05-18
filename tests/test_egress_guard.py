from aiegis.egress_guard import inspect_output
from aiegis.models import FindingSeverity
from aiegis.policy import DecisionStatus


def test_inspect_output_allows_text_without_secret_like_material() -> None:
    inspection = inspect_output("Invoice summary is ready.")

    assert inspection.status is DecisionStatus.ALLOW
    assert inspection.redacted_text == "Invoice summary is ready."
    assert inspection.findings == ()
    assert inspection.reasons == ("No egress rule matched.",)


def test_inspect_output_blocks_and_redacts_api_key_assignment() -> None:
    inspection = inspect_output("Use api_key = sk-test-1234567890abcdef for the upload.")

    assert inspection.status is DecisionStatus.BLOCK
    assert inspection.redacted_text == "Use api_key = [REDACTED] for the upload."
    assert [
        (finding.code, finding.severity, finding.evidence)
        for finding in inspection.findings
    ] == [("secret_like_output", FindingSeverity.HIGH, "api_key_assignment")]
    assert inspection.reasons == (
        "Secret-like output matched egress pattern 'api_key_assignment'.",
    )


def test_inspect_output_blocks_and_redacts_private_key_block() -> None:
    inspection = inspect_output(
        "-----BEGIN PRIVATE KEY-----\nsecret body\n-----END PRIVATE KEY-----"
    )

    assert inspection.status is DecisionStatus.BLOCK
    assert inspection.redacted_text == "[REDACTED]"
    assert inspection.findings[0].evidence == "private_key_block"


def test_output_inspection_serializes_without_original_secret() -> None:
    inspection = inspect_output("github_pat_secretvalue")

    serialized = inspection.to_dict()

    assert "github_pat_secretvalue" not in repr(serialized)
    assert serialized == {
        "status": "block",
        "redacted_text": "[REDACTED]",
        "findings": [
            {
                "code": "secret_like_output",
                "severity": "high",
                "message": "Secret-like material was detected in outbound content.",
                "evidence": "github_token",
            }
        ],
        "reasons": ["Secret-like output matched egress pattern 'github_token'."],
    }
