# Expected — SQL injection (`vuln/sql-injection`)

Branch: `vuln/sql-injection`
PR: https://github.com/DrivetrainAi/test-security/pull/1
CWE: 89

## Planted sinks

Both sinks are inside `UserDao.findByFilter(String filter, String orderBy)`
in `src/main/java/com/drivetrain/sectest/UserDao.java`.

### Sink 1 — WHERE clause

- **File:** `src/main/java/com/drivetrain/sectest/UserDao.java`
- **Line:** ~36 (the `String sql = "SELECT ... WHERE " + filter` line)
- **Taint source:** `filter` request parameter on
  `GET /users/search-advanced` in `UserController`.
- **Expected severity:** HIGH
- **Expected category/tag:** `sql_injection` / `cwe-89`
- **Correct remediation direction:** parameterized queries via a safe
  query-builder / criteria API OR a fixed set of allowed filter fields,
  each parameterized; do NOT pass raw SQL fragments from request.

### Sink 2 — ORDER BY clause

- **File:** `src/main/java/com/drivetrain/sectest/UserDao.java`
- **Line:** ~37 (the `+ " ORDER BY " + orderBy` append)
- **Taint source:** `orderBy` request parameter on
  `GET /users/search-advanced` in `UserController`.
- **Expected severity:** HIGH (ORDER BY injection is normally lower-impact,
  but this project uses H2 which supports stacked queries, so
  destructive/full-SQLi payloads are feasible).
- **Expected category/tag:** `sql_injection` / `cwe-89`
- **Correct remediation direction:** strict allowlist of permitted column
  names mapped before insertion into SQL; reject anything else.

## Contextual / bonus findings worth credit

- **Missing authentication / authorization on `/users/search-advanced`.**
  Not the planted vuln, but a real issue: the endpoint has no Spring
  Security or equivalent guard. Bonus TP if the review flags it.

## Negative-control hints

- The sibling `UserDao.findByName(String name)` uses parameterized queries
  (`?` placeholder with `queryForList(sql, ..., name)`). A correct review
  should NOT flag this; flagging it counts as a false positive.
