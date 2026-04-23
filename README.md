# java-sec-test

Small Spring Boot 2.7 / Java 11 project used to validate Claude's
`/security-review` skill against known Java vulnerability classes.

Java 11 matches Drivetrain's Drive backend so findings transfer.

## Layout

- `main` branch — clean baseline (parameterized JDBC, `SecureRandom`).
- Feature branches (added later) — one deliberate vulnerability each, to be
  scanned in isolation:
  - `vuln/sql-injection`
  - `vuln/command-injection`
  - `vuln/path-traversal`
  - `vuln/deserialization`
  - `vuln/xxe`
  - `vuln/hardcoded-secrets`
  - `vuln/weak-crypto`
  - `vuln/ssrf`
  - `vuln/xss`
  - `vuln/log-injection`
  - `safe/negative-controls` — suspicious-looking but safe code

## Run

```
mvn spring-boot:run
```
