from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from aiegis.models import FindingSeverity, GuardedContent, TrustLevel


class DecisionStatus(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class ActionRequest:
    name: str
    target: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "target": self.target}


@dataclass(frozen=True, slots=True)
class Policy:
    approval_required_actions: tuple[str, ...] = ()
    blocked_actions_on_prompt_injection: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: DecisionStatus
    action: ActionRequest
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "action": self.action.to_dict(),
            "reasons": list(self.reasons),
        }


def evaluate_policy(
    content: GuardedContent, action: ActionRequest, policy: Policy
) -> PolicyDecision:
    critical = next(
        (finding for finding in content.findings if finding.severity is FindingSeverity.CRITICAL),
        None,
    )
    if critical:
        return PolicyDecision(
            status=DecisionStatus.QUARANTINE,
            action=action,
            reasons=(f"Critical finding '{critical.code}' requires quarantine.",),
        )

    has_prompt_injection = any(
        finding.code == "prompt_injection_phrase" for finding in content.findings
    )
    if has_prompt_injection and action.name in policy.blocked_actions_on_prompt_injection:
        return PolicyDecision(
            status=DecisionStatus.BLOCK,
            action=action,
            reasons=(f"Action '{action.name}' is blocked when prompt injection is present.",),
        )

    if (
        content.trust_level is TrustLevel.UNTRUSTED
        and action.name in policy.approval_required_actions
    ):
        return PolicyDecision(
            status=DecisionStatus.REQUIRE_APPROVAL,
            action=action,
            reasons=(f"Action '{action.name}' requires approval for untrusted content.",),
        )

    return PolicyDecision(
        status=DecisionStatus.ALLOW,
        action=action,
        reasons=("No blocking findings or sensitive action matched policy.",),
    )
