from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from aiegis.models import GuardedContent
from aiegis.policy import PolicyDecision


@dataclass(frozen=True, slots=True)
class AuditRecord:
    event_id: str
    content: GuardedContent
    decision: PolicyDecision

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "content": self.content.to_dict(),
            "decision": self.decision.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
