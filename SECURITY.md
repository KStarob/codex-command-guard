# Security Policy

## Supported Versions

Until a stable major release, only the latest `0.1.x` release is supported with
security fixes.

## Reporting A Vulnerability

Please use GitHub's **Report a vulnerability** private security-advisory flow
for this repository. Do not open a public issue with a working bypass before a
fix is available.

Include:

- the Codex Command Guard version or commit;
- macOS, Codex Desktop/CLI, and Swift versions;
- the exact hook request or command spelling;
- expected and observed allow/deny behavior;
- whether the issue requires a same-user malicious process or occurs during
  ordinary Codex command generation.

## Intended Boundary

This project is an emergency brake for accidental or attacker-influenced
catastrophic command generation. It is not a sandbox and does not claim to
resist a malicious process already running with the same user's unrestricted
filesystem access.

The one-time authorization store prevents casual replay with exact command
hashing, expiration, private file modes, and atomic single consumption. Version
`0.1.x` does not cryptographically bind that record to Touch ID against another
same-user process.

Hook coverage is also controlled by Codex. Commands executed through a path
that does not invoke the configured `PreToolUse` hook cannot be inspected by
this project. Treat new Codex releases and `unified_exec` changes as requiring
fresh canary validation.
