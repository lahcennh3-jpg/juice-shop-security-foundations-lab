#!/usr/bin/env python3
"""Fail-closed authorization gate for the Juice Shop learning laboratory."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "lahcennh3-jpg/juice-shop-security-foundations-lab"
EXPECTED_TARGET = {
    "name": "OWASP Juice Shop",
    "release": "v20.1.1",
    "source_commit": "f915bddd82790d0f3018902d36ae9b4241a5f51f",
    "container_image": "bkimminich/juice-shop:v20.1.1",
}
PLACEHOLDERS = {"", "REPLACE_ME", "TODO", "TBD", "UNKNOWN"}
REQUIRED_ATTESTATIONS = (
    "record_complete",
    "ownership_verified",
    "authorization_verified",
    "rules_of_engagement_approved",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _is_complete_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() not in PLACEHOLDERS


def _parse_utc(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not _is_complete_string(value):
        errors.append(f"{field} is incomplete")
        return None

    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        errors.append(f"{field} must be an ISO-8601 timestamp")
        return None

    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        errors.append(f"{field} must use UTC")
        return None

    return parsed.astimezone(timezone.utc)


def validate(record: Any, now: datetime | None = None) -> list[str]:
    """Return validation failures; an empty list means authorization is allowed."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["authorization record must be a JSON object"]

    if record.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")

    if record.get("status") != "AUTHORIZED":
        errors.append("status is not AUTHORIZED")

    authorization = _mapping(record.get("authorization"))
    if not _is_complete_string(authorization.get("authorization_id")):
        errors.append("authorization.authorization_id is incomplete")

    for party_name in ("target_owner", "authorized_by"):
        party = _mapping(authorization.get(party_name))
        required = (
            ("name", "relationship", "verification_method")
            if party_name == "target_owner"
            else ("name", "role", "verification_method")
        )
        if any(not _is_complete_string(party.get(field)) for field in required):
            errors.append(f"authorization.{party_name} is incomplete")

    valid_from = _parse_utc(
        authorization.get("valid_from_utc"),
        "authorization.valid_from_utc",
        errors,
    )
    valid_until = _parse_utc(
        authorization.get("valid_until_utc"),
        "authorization.valid_until_utc",
        errors,
    )

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if valid_from and valid_until:
        if valid_from >= valid_until:
            errors.append("authorization period is not chronological")
        elif current < valid_from:
            errors.append("authorization period has not started")
        elif current > valid_until:
            errors.append("authorization has expired")

    scope = _mapping(record.get("scope"))
    if scope.get("repository") != EXPECTED_REPOSITORY:
        errors.append("scope.repository does not match the authorized repository")

    target = _mapping(scope.get("target"))
    for field, expected in EXPECTED_TARGET.items():
        if target.get(field) != expected:
            errors.append(f"scope.target.{field} does not match the pinned target")
    if not _is_complete_string(target.get("instance_id")):
        errors.append("scope.target.instance_id is incomplete")

    environment = _mapping(scope.get("environment"))
    if environment.get("type") != "private-github-codespace":
        errors.append("scope.environment.type must be private-github-codespace")
    if environment.get("host") != "127.0.0.1":
        errors.append("scope.environment.host must be 127.0.0.1")
    if environment.get("port") != 3000:
        errors.append("scope.environment.port must be 3000")
    if environment.get("public_exposure_allowed") is not False:
        errors.append("public exposure must be explicitly prohibited")

    for field in ("allowed_activities", "prohibited_activities", "excluded_assets"):
        value = scope.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"scope.{field} must be a non-empty list")

    limits = _mapping(record.get("limits"))
    requests_per_second = limits.get("requests_per_second")
    if (
        not isinstance(requests_per_second, (int, float))
        or isinstance(requests_per_second, bool)
        or requests_per_second <= 0
        or requests_per_second > 2
    ):
        errors.append("limits.requests_per_second must be greater than 0 and at most 2")
    if limits.get("concurrency") != 1:
        errors.append("limits.concurrency must be 1")

    data = _mapping(record.get("data"))
    if data.get("classification") != "synthetic-only":
        errors.append("data.classification must be synthetic-only")
    if data.get("real_personal_data_allowed") is not False:
        errors.append("real personal data must be explicitly prohibited")

    evidence = _mapping(record.get("evidence"))
    for field in ("redact_secrets", "redact_private_urls", "record_timestamps_and_hashes"):
        if evidence.get(field) is not True:
            errors.append(f"evidence.{field} must be true")

    for field in ("stop_conditions", "cleanup"):
        value = record.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"{field} must be a non-empty list")

    attestations = _mapping(record.get("attestations"))
    for field in REQUIRED_ATTESTATIONS:
        if attestations.get(field) is not True:
            errors.append(f"attestations.{field} must be true")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path, help="path to the local authorization JSON")
    args = parser.parse_args(argv)

    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print("AUTHORIZATION_INVALID")
        print(f"- {exc}")
        return 1

    errors = validate(record)
    if errors:
        print("AUTHORIZATION_BLOCKED")
        for error in errors:
            print(f"- {error}")
        return 2

    print("AUTHORIZATION_ALLOWED")
    print("- authorization record is complete, current, and within declared scope")
    return 0


if __name__ == "__main__":
    sys.exit(main())

