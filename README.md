# OWASP Juice Shop Security Foundations Lab

An authorization-first learning laboratory for building professional web, API,
and later AI-security engineering skills with a private OWASP Juice Shop
instance.

## Current status

`BLOCKED BY DEFAULT`

The repository contains planning, validation, and deployment scaffolding. It
does not grant permission to test any system. Active testing is allowed only
after the local authorization record passes the fail-closed gate.

## Pinned training target

| Item | Value |
| --- | --- |
| Application | OWASP Juice Shop |
| Release | `v20.1.1` |
| Source commit | `f915bddd82790d0f3018902d36ae9b4241a5f51f` |
| Container image | `bkimminich/juice-shop:v20.1.1` |
| Expected binding | `127.0.0.1:3000` |
| Permitted data | Synthetic data only |

The target is intentionally vulnerable. Never expose it publicly.

## Phase 0 workflow

1. Create the private authorization record:

   ```bash
   cp scope/authorization.example.json scope/authorization.local.json
   ```

2. Personally verify and complete the ownership, authorization period, scope,
   rules of engagement, and attestations. Never commit the local record.

3. Run the authorization gate:

   ```bash
   python3 scripts/authorization_gate.py scope/authorization.local.json
   ```

4. Continue only when the command prints `AUTHORIZATION_ALLOWED` and exits
   successfully.

5. Start the isolated target:

   ```bash
   docker compose up -d
   ```

6. Confirm that the forwarded port remains private before opening the
   application or performing any testing.

## Learning method

Complete one authentication or authorization finding before adding another
target:

`Authorize → deploy → understand → threat-model → test safely → collect
evidence → remediate → regression-test → detect → investigate → publish`

## Repository map

- `scope/authorization.example.json` — public-safe authorization template
- `scripts/authorization_gate.py` — fail-closed authorization validator
- `docs/phase-0/step-0.1-authorization.md` — human completion checklist
- `docs/rules-of-engagement.md` — allowed and prohibited activity baseline
- `evidence/README.md` — safe evidence-handling rules
- `compose.yaml` — loopback-only Juice Shop deployment
- `tests/` — authorization-gate regression tests

## Safety boundary

GitHub, GitHub Codespaces infrastructure, public Juice Shop demonstrations,
third-party services, external IP addresses, and every system not explicitly
listed in the completed local authorization record are out of scope.

