# Rules of Engagement

## Authorized target

Only the operator-owned OWASP Juice Shop `v20.1.1` instance identified in the
completed `scope/authorization.local.json` record.

## Permitted environment

- Private GitHub Codespace or an operator-controlled loopback environment
- Host binding `127.0.0.1`
- Application port `3000`
- Synthetic identities, credentials, files, and business records only

## Allowed activity

- Planning and documentation
- Local source and architecture review
- Manual application and HTTP inspection after authorization
- Authentication and authorization learning exercises after authorization
- Sanitized evidence collection
- Remediation and regression testing
- Detection and reporting practice

## Prohibited activity

- Testing GitHub, Codespaces infrastructure, public demonstrations, third
  parties, external addresses, or production systems
- Publicly exposing the intentionally vulnerable target
- Credential stuffing, brute force, denial of service, or resource exhaustion
- Malware, persistence, destructive modification, or social engineering
- Real credentials, personal data, or production data
- Outbound callbacks or SSRF to real services
- Publishing secrets, private URLs, personal data, or unredacted sensitive
  evidence

## Rate and concurrency limits

- Maximum: 2 requests per second
- Maximum concurrency: 1

## Stop immediately when

- The observed target, version, instance, or environment differs from scope.
- Port 3000 becomes public.
- Real data or a third-party interaction is encountered.
- Authorization expires, is revoked, or cannot be verified.
- The application or environment becomes unstable.

## Cleanup

Stop and remove the container, close port forwarding, delete synthetic runtime
data when appropriate, and sanitize or delete sensitive evidence.

