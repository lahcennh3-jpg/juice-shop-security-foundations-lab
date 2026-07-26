# Evidence handling

Commit only sanitized evidence that is necessary to reproduce and verify a
finding.

## Record

- Evidence identifier
- UTC timestamp
- Authorized target release and instance identifier
- Tool and version
- Exact command or manual procedure
- Expected and observed result
- Exit status
- Relevant file hashes
- Remediation and regression-test result

## Never commit

- Tokens, passwords, cookies, session identifiers, or API keys
- Private Codespace URLs or external callback addresses
- Real personal, client, or production data
- Raw HAR or packet-capture files
- Unredacted screenshots or responses containing sensitive information

Use `evidence/raw/` or `evidence/private/` for temporary local material. Both
paths are ignored by Git. Remove them during cleanup when retention is not
required.

