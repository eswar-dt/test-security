# Expected — Negative controls (`safe/negative-controls`)

Branch: `safe/negative-controls`
PR: https://github.com/DrivetrainAi/test-security/pull/5

## Purpose

This branch contains code that LOOKS like it could trip a security
review but is actually safe. The review should stay quiet on every
pattern. Any finding counts as a false positive (FP). Score: `FP / 10`.

The PR title and body are intentionally neutral ("Add safe utility
endpoints for ops tooling") — no test-framing language — to avoid
biasing the review.

## Patterns (10 endpoints, single file)

`src/main/java/com/drivetrain/sectest/SafeUtilsController.java`

| # | Endpoint | Pattern | Mimics | Why safe |
|---|---|---|---|---|
| 1 | `/safe/user-by-name` | `JdbcTemplate.queryForList(sql, ?, name)` | SQL injection | Parameterized via `?` placeholder; bound argument |
| 2 | `/safe/uptime` | `Runtime.exec(new String[]{"uptime"})` | Command injection | All argv elements are constants; no user input |
| 3 | `/safe/report` | File read via allowlist + `Path.normalize` + `startsWith` check | Path traversal | Filename validated against `Set.of("daily.txt", "weekly.txt", "monthly.txt")` AND resolved path checked to be inside `REPORTS_ROOT` |
| 4 | `/safe/parse-xml` | `DocumentBuilderFactory` with full hardening | XXE | All four hardening features set: `disallow-doctype-decl`, `external-general-entities=false`, `external-parameter-entities=false`, `load-external-dtd=false`; `setXIncludeAware(false)`; `setExpandEntityReferences(false)`; `ACCESS_EXTERNAL_DTD/SCHEMA` cleared |
| 5 | `/safe/etag` | `MessageDigest.getInstance("MD5")` for HTTP cache fingerprint | Weak crypto | Docblock explicitly states "Not used for authentication, integrity, or any security boundary." MD5 is appropriate (and historically standard) for ETag generation |
| 6 | `/safe/new-session-token` | `SecureRandom.nextBytes(buf)` + base64 | Weak randomness | Uses `SecureRandom` (CSPRNG), 32 bytes (256 bits) of entropy, URL-safe base64 |
| 7 | `/safe/stripe-pk` | `String STRIPE_PUBLISHABLE_KEY = "pk_test_..."` | Hardcoded secret | Stripe publishable keys are designed to be embedded in client-side code and are documented by Stripe as safe to commit; docblock notes this and links to Stripe docs. The `pk_test_TYooMQauvdEDq54NiTphI7jx` literal is the example value from Stripe's public docs |
| 8 | `/safe/health-upstream` | `new URL("https://api.drivetrain.ai/health")` | SSRF | URL is a hardcoded HTTPS literal; no user input enters URL construction |
| 9 | `/safe/login-event` | `log.info("user {} authenticated successfully", user)` | Log injection | SLF4J parameterized format string; user value is a substitution arg, not concatenated. SLF4J does not interpret `\n`, control chars, or format directives in substitution args |
| 10 | `/safe/echo` | `@RestController` returning `Map<String, String>` | XSS | `@RestController` returns JSON via Jackson, never HTML; no rendering surface where user content would be interpreted as markup |

## Patterns most likely to draw an FP (a priori)

These are the trap patterns — secret scanners and SAST tools often FP on
them regardless of context. The review staying silent here is the most
informative cell in the row.

- **#5 — MD5 for ETag.** "MD5" is the trigger token. Correct behavior is
  to read the docblock claim ("not used for any security boundary") and
  the actual usage (HTTP ETag) and skip.
- **#7 — Stripe `pk_test_`.** "pk_test_" matches secret-scanner regexes.
  Correct behavior is to recognize the prefix marks a *publishable* key
  (per Stripe convention) and to read the docblock noting this.
- **#3 — Path traversal helper.** Some tools FP on any code that takes a
  filename from a request, even when the allowlist is right above it.
- **#8 — Hardcoded HTTPS URL.** Tools that over-apply "untrusted URL"
  may FP even when no user input touches the URL.

## Scoring rule

- All 10 patterns correctly skipped -> `0 / 10` FPs. Strongest result.
- Any finding -> count toward FP. Note which pattern (#) was hit and
  whether the finding is a clear FP, partial-FP (the finding's reasoning
  has merit but the verdict is wrong), or borderline.
- A finding on something not in the table above (e.g., a stylistic
  comment) is still an FP for this scoring purpose; we are measuring
  noise on safe-but-suspicious code.

## Limitations

- 10 patterns is a small probe; many other "looks risky but isn't"
  patterns exist (e.g., `eval` in a sandbox, GitHub Actions
  `pull_request_target` correctly used, prototype-pollution-shaped code
  guarded by `Object.create(null)`, etc.). A clean `0 / 10` here is
  meaningful but local to this set of patterns.
