# Step 0.1 — Establish ownership and authorization

## Objective

Create a truthful, current, and bounded authorization record for one isolated
OWASP Juice Shop instance before any active security testing.

## Human-only checklist

The laboratory owner and authorizer must personally complete these items.
Automation must not invent, infer, or approve them.

- [ ] Confirm control of the repository.
- [ ] Confirm control of the private Codespace or loopback runtime.
- [ ] Confirm that the deployed Juice Shop instance belongs to the operator.
- [ ] Record how target ownership was verified.
- [ ] Identify the person granting authorization and record their authority.
- [ ] Set a UTC start and end time.
- [ ] Review every allowed activity.
- [ ] Review every prohibited activity.
- [ ] Review excluded assets and stop conditions.
- [ ] Confirm synthetic-data-only operation.
- [ ] Approve the rules of engagement.
- [ ] Set each attestation to `true` only after it has been verified.

## Procedure

```bash
cp scope/authorization.example.json scope/authorization.local.json
code scope/authorization.local.json
python3 scripts/authorization_gate.py scope/authorization.local.json
```

The local authorization file is intentionally ignored by Git. Do not paste
private Codespace URLs, tokens, credentials, signatures, or unnecessary
personal information into committed files or evidence.

## Completion criteria

- The gate prints `AUTHORIZATION_ALLOWED`.
- The authorization period is current.
- The target version and runtime match the record.
- Port 3000 is loopback-bound and remains private.
- Synthetic data, evidence rules, stop conditions, and cleanup are confirmed.

Until every criterion is satisfied, the lab status remains
`AUTHORIZATION_BLOCKED`.

