from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HASH_ALGORITHM = "sha256"
HASH_PREFIX = f"{HASH_ALGORITHM}:"


@dataclass(frozen=True, slots=True)
class AuditLogVerification:
    valid: bool
    checked_records: int
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "checked_records": self.checked_records,
            "errors": list(self.errors),
        }


def seal_audit_event(
    event: dict[str, Any],
    *,
    previous_event_hash: str | None,
) -> dict[str, Any]:
    sealed = dict(event)
    sealed["previous_event_hash"] = previous_event_hash
    sealed["event_hash"] = _event_hash(sealed)
    return sealed


def verify_audit_log(log_path: Path) -> AuditLogVerification:
    if not log_path.exists():
        return AuditLogVerification(
            valid=False,
            checked_records=0,
            errors=(f"audit log does not exist: {log_path}",),
        )

    expected_previous_hash: str | None = None
    errors: list[str] = []
    checked_records = 0
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        checked_records += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {line_number}: invalid JSON")
            expected_previous_hash = None
            continue
        if not isinstance(event, dict):
            errors.append(f"line {line_number}: event must be a JSON object")
            expected_previous_hash = None
            continue

        event_hash = event.get("event_hash")
        previous_hash = event.get("previous_event_hash")
        if previous_hash != expected_previous_hash:
            errors.append(f"line {line_number}: previous_event_hash does not match chain")
        if not isinstance(event_hash, str) or not event_hash.startswith(HASH_PREFIX):
            errors.append(f"line {line_number}: event_hash is missing or malformed")
            expected_previous_hash = None
            continue
        if event_hash != _event_hash(event):
            errors.append(f"line {line_number}: event_hash does not match event contents")
        expected_previous_hash = event_hash

    return AuditLogVerification(
        valid=not errors,
        checked_records=checked_records,
        errors=tuple(errors),
    )


def previous_event_hash(log_path: Path) -> str | None:
    if not log_path.exists():
        return None

    previous_hash: str | None = None
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            message = f"Cannot append to audit log with invalid JSON at line {line_number}."
            raise ValueError(message) from exc
        if not isinstance(event, dict):
            message = f"Cannot append to audit log with non-object event at line {line_number}."
            raise ValueError(message)
        event_hash = event.get("event_hash")
        if not isinstance(event_hash, str) or not event_hash.startswith(HASH_PREFIX):
            message = f"Cannot append to audit log with missing event_hash at line {line_number}."
            raise ValueError(message)
        previous_hash = event_hash
    return previous_hash


def _event_hash(event: dict[str, Any]) -> str:
    event_without_hash = dict(event)
    event_without_hash.pop("event_hash", None)
    canonical = json.dumps(
        event_without_hash,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return HASH_PREFIX + hashlib.sha256(canonical).hexdigest()
