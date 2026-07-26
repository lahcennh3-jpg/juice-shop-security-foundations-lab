from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.authorization_gate import validate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = json.loads(
    (ROOT / "scope" / "authorization.example.json").read_text(encoding="utf-8")
)
NOW = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)


def authorized_record() -> dict:
    record = copy.deepcopy(EXAMPLE)
    record["status"] = "AUTHORIZED"
    record["authorization"].update(
        {
            "authorization_id": "AUTH-TEST-001",
            "target_owner": {
                "name": "Synthetic Owner",
                "relationship": "owner of isolated lab instance",
                "verification_method": "synthetic unit-test fixture",
            },
            "authorized_by": {
                "name": "Synthetic Authorizer",
                "role": "lab owner",
                "verification_method": "synthetic unit-test fixture",
            },
            "valid_from_utc": "2026-07-26T00:00:00Z",
            "valid_until_utc": "2026-08-25T00:00:00Z",
        }
    )
    record["scope"]["target"]["instance_id"] = "synthetic-private-lab-001"
    record["attestations"] = {
        "record_complete": True,
        "ownership_verified": True,
        "authorization_verified": True,
        "rules_of_engagement_approved": True,
    }
    return record


class AuthorizationGateTests(unittest.TestCase):
    def test_public_example_is_blocked(self) -> None:
        errors = validate(EXAMPLE, now=NOW)
        self.assertIn("status is not AUTHORIZED", errors)
        self.assertTrue(any("incomplete" in error for error in errors))

    def test_complete_current_record_is_allowed(self) -> None:
        self.assertEqual(validate(authorized_record(), now=NOW), [])

    def test_expired_authorization_is_blocked(self) -> None:
        record = authorized_record()
        record["authorization"]["valid_from_utc"] = "2026-07-24T00:00:00Z"
        record["authorization"]["valid_until_utc"] = "2026-07-25T00:00:00Z"
        self.assertIn("authorization has expired", validate(record, now=NOW))

    def test_public_binding_is_blocked(self) -> None:
        record = authorized_record()
        record["scope"]["environment"]["host"] = "0.0.0.0"
        self.assertIn(
            "scope.environment.host must be 127.0.0.1",
            validate(record, now=NOW),
        )

    def test_target_version_drift_is_blocked(self) -> None:
        record = authorized_record()
        record["scope"]["target"]["release"] = "latest"
        self.assertIn(
            "scope.target.release does not match the pinned target",
            validate(record, now=NOW),
        )

    def test_missing_attestation_is_blocked(self) -> None:
        record = authorized_record()
        record["attestations"]["ownership_verified"] = False
        self.assertIn(
            "attestations.ownership_verified must be true",
            validate(record, now=NOW),
        )

    def test_real_data_is_blocked(self) -> None:
        record = authorized_record()
        record["data"]["classification"] = "internal"
        self.assertIn(
            "data.classification must be synthetic-only",
            validate(record, now=NOW),
        )


if __name__ == "__main__":
    unittest.main()
