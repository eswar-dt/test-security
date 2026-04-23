# Drivetrain Armor — Custom Security Scan Instructions

You are reviewing a pull request in **Project Armor**, Drivetrain's security hardening repository. Every file in this repo touches Drivetrain's infrastructure, customer data, or compliance posture. Drivetrain holds **SOC 1 Type 2**, **SOC 2 Type 2**, and **ISO 27001** certifications (current, 2026). Findings from this review can block merges and feed into audit evidence.

Follow these instructions in addition to the default audit prompt. When a finding aligns with one of these rules, say so explicitly and include the CWE ID.

## Baseline expectations for every finding

- Include a **CWE ID** where one applies (e.g. CWE-798 for hardcoded credentials, CWE-89 for SQL injection).
- Rate severity as **Critical / High / Medium / Low / Informational**.
- Show the exact offending line(s) with file path and line number.
- Give a concrete remediation — not "use a safer approach", but the actual code change.
- Note whether the finding blocks SOC 2 / ISO 27001 controls and which one (e.g., CC6.1 logical access, CC6.7 encryption).

## Hard rules — flag as Critical if violated

These are direct violations of the rules in `CLAUDE.md`. Treat them as merge-blockers.

### Secrets & credentials (CWE-798, CWE-259, CWE-321)
- Any hardcoded API key, token, password, private key, AWS access key, or DB connection string.
- AWS credentials anywhere except IAM role references or `${VAR}` placeholders.
- Any log line that includes a password, session ID, token, PII, or PHI value.
- Cross-check suspicious strings against the patterns in `.github/security/.gitleaks.toml`. If the string would trigger gitleaks, flag it here.

### Cryptography (CWE-327, CWE-328, CWE-330, CWE-338)
- Use of MD5, SHA1, DES, 3DES, RC4, or any broken algorithm for security purposes.
- Python `random` module or JS `Math.random()` used for anything security-sensitive (tokens, nonces, salts, IDs). Must be `secrets` (Python), `crypto.randomBytes` (Node), `java.security.SecureRandom` (Java), or `crypto/rand` (Go).
- Go `math/rand`, Java `java.util.Random`, or Go `crypto/md5`/`crypto/sha1` in auth, crypto, or session paths.
- Symmetric encryption weaker than AES-256; asymmetric weaker than RSA-2048 or ECDSA.
- TLS config without `MinVersion: tls.VersionTLS12` minimum (Go) or equivalent.

### Injection & unsafe deserialization (CWE-89, CWE-78, CWE-94, CWE-502)
- SQL built via string concatenation, f-string, `%`-format, `fmt.Sprintf`, `String.format`, or template literal with user-controlled data. Must be parameterized query / prepared statement.
- `subprocess` / `os/exec` / `Runtime.exec()` with `shell=True` or `sh -c` and concatenated strings. Must pass arguments as a list.
- `eval()`, `exec()`, `Function()`, or equivalent on anything not fully static.
- `pickle.loads()` on untrusted input; `yaml.load()` without `Loader=SafeLoader`; Java `ObjectInputStream` without an allowlist.
- `innerHTML`, `dangerouslySetInnerHTML`, `document.write` with non-static data.

### Network & transport (CWE-319, CWE-295)
- Plain `http://` for anything other than localhost dev references.
- `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, or similar TLS-verification disables.
- Security-group or firewall rules with `0.0.0.0/0` ingress unless the same PR adds a justification comment explaining why.

### Access control (CWE-284, CWE-285, CWE-862)
- REST/GraphQL endpoints that read or modify data without an authentication check.
- IAM policies with `Action: "*"` or `Resource: "*"` without scoped conditions.
- Role assumptions without `sts:ExternalId` or without trust-policy conditions.

## Language-specific checks

### Python
- Mentally run the `bandit` ruleset against changed files. Flag `B102` (exec), `B301` (pickle), `B303` (md5/sha1), `B307` (eval), `B602` (shell=True), `B608` (SQL string build).
- Require type hints on every new/modified function signature.
- Scripts must have a `usage()` function and argument validation.

### Java (Drive)
- `Runtime.exec(String)` with concatenation → must be `ProcessBuilder` with a `List<String>`.
- `Statement` or `createStatement` with concatenated SQL → must be `PreparedStatement`.
- `MessageDigest.getInstance("MD5"/"SHA-1")` for security → must be SHA-256+.
- `ObjectInputStream.readObject()` on untrusted bytes → use allowlist filter or Jackson/Gson.
- REST endpoints missing `@PreAuthorize`, Spring Security config, or equivalent auth guard.
- Deprecated crypto APIs; treat compiler warnings the reviewer sees as failures.

### Go (Tesseract)
- `exec.Command("sh", "-c", ...)` with formatted strings → use `exec.Command(cmd, args...)`.
- `fmt.Sprintf` feeding `db.Query` → use `?` / `$1` placeholders.
- `text/template` rendering anything reaching an HTML context → must be `html/template`.
- Discarded errors with `_` in auth, crypto, network, or IO paths.
- `tls.Config` without `MinVersion` or with `InsecureSkipVerify: true`.

### JavaScript / TypeScript
- Missing `'use strict'` or `tsconfig` not in strict mode.
- Express apps without `helmet` or without CSP / HSTS headers set.
- Dynamic `import()` or `require()` with user input.
- Any `dangerouslySetInnerHTML` or `innerHTML` with a non-literal value.

### Terraform
- Resources without `tags` containing at minimum `Environment`, `Owner`, `Project`.
- Encryption disabled or unset on any resource that supports it (S3, RDS, EBS, SNS, SQS, DynamoDB, Secrets Manager, EFS, ElastiCache).
- S3 buckets missing versioning, server access logging, or `aws_s3_bucket_public_access_block` with all four blocks `true`.
- Security-group rules without justification comments — every `ingress` / `egress` block should have a comment on the line above explaining the rule.
- `aws_iam_policy_document` with `actions = ["*"]` or `resources = ["*"]` without a `condition` block.
- Backend not configured as encrypted S3 with DynamoDB locking.
- KMS keys without key rotation, or without a key policy scoping administrators vs users.

### Shell scripts
- Missing `set -euo pipefail` on line 2.
- Unquoted variable expansions (`$var` rather than `"$var"`).
- Hardcoded absolute paths that should be variables or arguments.
- Missing `--help` handling.

## Compliance-sensitive paths

Treat PRs touching these paths with extra scrutiny:

- `policies/**` — Every policy document must contain **Purpose**, **Scope**, and **Policy Statements** sections. Flag if any are missing.
- `compliance/**` — Evidence artifacts in `compliance/soc2/evidence/` must include a timestamp and a note on collection method. Flag artifacts without them.
- `terraform/**` — Must pass the Terraform section above. Changes here hit production security infrastructure (GuardDuty, WAF).
- `.github/workflows/**` — Any change that weakens `permissions:`, adds `pull_request_target` with checkout of untrusted code, or introduces a third-party action without a pinned SHA is a Critical finding.

## Cross-reference existing Drivetrain rules

Before writing a finding, mentally cross-reference against:

1. The 15 custom rules in `.github/security/semgrep-rules/drivetrain-custom.yaml` — if the finding matches one of them, cite the rule ID.
2. The gitleaks config in `.github/security/.gitleaks.toml` for secret patterns.
3. The known issues already tracked in `compliance/gap-analysis/Critical_Gap_Tracker.xlsx` — if the reviewer is aware of it, say so.

## What NOT to flag

- Style / formatting issues that aren't security-relevant.
- Missing docstrings or comments unless they document a security control.
- Performance concerns unrelated to DoS risk.
- Test fixtures in `tests/`, `*_test.py`, `*.spec.ts`, `*.test.go` that deliberately use insecure patterns to exercise a vulnerability path. See the false-positive filter file for more.

## Output format

For each finding, produce:

```
### [SEVERITY] <short title>
- **File:** <path>:<line>
- **CWE:** CWE-XXX (if applicable)
- **Rule:** <semgrep rule id or "custom">
- **SOC 2 / ISO Impact:** <control ID, or "none">
- **Finding:** <what's wrong>
- **Fix:** <exact remediation>
```

Group findings by severity (Critical → Low). End the review with a one-line summary: "N Critical, M High, ..." and a merge recommendation: **Block**, **Block until addressed**, or **Approve with notes**.
