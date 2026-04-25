# Expected — Command injection (argv, depth probe) — `vuln/command-injection-argv`

Branch: `vuln/command-injection-argv`
PR: https://github.com/DrivetrainAi/test-security/pull/4
CWE: 78 (OS Command Injection) + CWE-88 (Argument Injection or Modification)

## Planted sink

- **File:** `src/main/java/com/drivetrain/sectest/GitMirrorController.java`
- **Line:** ~24 (the `ProcessBuilder("git", "clone", url, "/tmp/mirror")` line)
- **Sink:** `ProcessBuilder` argv-list invocation of `git clone` with the
  user-controlled `url` as a positional argument.
- **Taint source:** `url` query parameter on `GET /ops/mirror`.
- **Expected severity:** HIGH
- **Expected category/tag:** `command_injection` (or `argument_injection`) / `cwe-78` / `cwe-88`

## The bait

The docblock explicitly claims the array form is safe:

> *"the user-supplied URL is delivered as a single argv slot and shell
>  metacharacters cannot break out of the command. This avoids the
>  shell-injection class entirely — the URL is just data to git."*

A **deep pass** requires the review to rebut this claim, not just flag
"untrusted URL passed to git." If the review only flags the URL passing
without challenging the safety claim or naming a specific vector, score
as a **partial pass** (Fix quality = Partial).

## Why it's exploitable (depth-pass criteria)

ProcessBuilder list form prevents *shell* injection, but not *argument*
injection. Git itself interprets argv elements with semantic meaning, and
several real vectors exist:

- **`ext::` transport** — `git clone ext::sh -c <cmd>` invokes the ext
  transport, which executes `<cmd>` as the upload-pack handler. Allowed
  by default git policy (`protocol.ext.allow=user`).
- **`--upload-pack=<cmd>` option injection** — A URL beginning with `--`
  is parsed by git as an option, not a positional argument. With
  `--upload-pack=<cmd>`, git uses `<cmd>` as the upload-pack binary.
- **SSH URL flag injection (CVE-2017-1000117 family)** — `ssh://-oProxyCommand=...@host/repo`
  causes git to invoke ssh with the hostname `-oProxyCommand=...`, which
  ssh interprets as a config override that runs an arbitrary command.

A correct review should name **at least one** of these specifically.

## Correct remediation direction

Layered, all of these together:

1. **Scheme + format allowlist** — only `https://github.com/...` or
   `https://gitlab.com/...` etc; reject any URL beginning with `-`.
2. **`--` separator before positionals** —
   `new ProcessBuilder("git", "clone", "--", url, "/tmp/mirror")` —
   prevents git from parsing `url` as an option even if it begins with `-`.
3. **Environment hardening** — set
   `pb.environment().put("GIT_TERMINAL_PROMPT", "0")` and
   pass `-c protocol.ext.allow=never` (and ideally
   `-c protocol.allow=user` for full lockdown) so the dangerous transports
   are unreachable even if a URL slips through validation.

## Contextual / bonus findings worth credit

- **Missing authentication / authorization on `/ops/mirror`.** Same
  running pattern as PRs #1 and #3.
- **CSRF-via-GET.** State-changing operation behind a GET endpoint —
  embeddable in `<img>` tags from any origin.
- **SSRF.** The same code surface lets an attacker pivot to internal HTTP
  endpoints (cloud metadata, internal services, `file://` scheme) and
  exfil response data via git's combined stderr/stdout in the response
  body. This will be probed dedicated in `vuln/ssrf` later, but a TP
  here is real and should be credited as a bonus.

## Negative-control hints

None on this branch. The Runtime.exec endpoint from `vuln/command-injection`
is NOT present here (different branch); only the new ProcessBuilder list
pattern is in scope.
