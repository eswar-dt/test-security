# Expected — Command injection (`vuln/command-injection`)

Branch: `vuln/command-injection`
PR: https://github.com/DrivetrainAi/test-security/pull/3
CWE: 78 (OS Command Injection)

## Planted sink

- **File:** `src/main/java/com/drivetrain/sectest/NetworkOpsController.java`
- **Line:** ~28 (the `Runtime.getRuntime().exec("ping -c 2 " + host)` line)
- **Sink:** `Runtime.getRuntime().exec(String)` with the request-derived
  `host` parameter concatenated into the single-string command form.
- **Taint source:** `host` query parameter on `GET /ops/ping`.
- **Expected severity:** HIGH
- **Expected category/tag:** `command_injection` / `cwe-78`

## Why it's exploitable

`Runtime.exec(String)` does NOT invoke a shell on most JVMs (it tokenizes
on whitespace via `StringTokenizer`), so simple `;` / `&&` chaining only
works in environments where the runtime *does* delegate to a shell. The
practical exploits independent of shell delegation:

- **Flag / argument injection to `ping`.** The attacker's value becomes
  one or more argv elements. Example: `host=-c+1000+127.0.0.1+-s+65500`
  produces `["ping", "-c", "2", "-c", "1000", "127.0.0.1", "-s", "65500"]`
  — a large-packet flood from the server.
- **Shell delegation on some runtimes / OSes.** Older / non-Linux JVMs and
  certain Windows configurations pass the single-string form through a
  shell when shell metacharacters are present, enabling full RCE.
- **Newline / null injection.** Some runtimes split on additional
  whitespace including `\n`, allowing argv-level argument additions.

## Correct remediation direction

Either of these closes the bug:

1. **Strict hostname allowlist regex** before exec, e.g.
   `host.matches("^[a-zA-Z0-9.\\-]+$")`, rejecting anything else.
2. **Replace exec with `InetAddress.isReachable()`** so no subprocess is
   spawned at all.

The array form of ProcessBuilder
(`new ProcessBuilder("ping", "-c", "2", host)`) prevents shell injection
but does NOT prevent flag injection if `host` starts with `-`. It is a
partial fix only; pair with the regex allowlist.

## Contextual / bonus findings worth credit

- **Missing authentication / authorization on `/ops/ping`.** Same class
  of bonus finding as PR #1 — endpoint is reachable by any caller.
  Bonus TP if flagged.
- **Reflecting raw command output back to the caller.** Lower severity;
  could enable error-based information disclosure if the exec tooling
  ever changes.

## Negative-control hints

None on this branch — every change is part of the planted vuln. The
`UserController` / `UserDao` from `main` remain untouched and continue
to use parameterized queries.
