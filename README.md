# Codex Command Guard

Codex Command Guard is a small macOS-native `PreToolUse` hook that acts as an
emergency brake for catastrophic shell commands while Codex operates with full
filesystem access. Ordinary commands stay silent and autonomous. A recognized
catastrophic or structurally ambiguous command is denied until the user grants
one exact, short-lived authorization with Touch ID or the macOS password.

It is intentionally narrow: this is a last line of defense against accidental
or attacker-influenced command generation, not a sandbox.

## What It Protects

The policy covers high-impact forms of:

- broad recursive filesystem deletion;
- destructive Git worktree/history operations and protected force-pushes;
- raw-device writes, disk erase, filesystem creation, and system power actions;
- Docker volume pruning and Terraform/OpenTofu destruction;
- mass Kubernetes deletion and destructive database statements;
- recursive cloud deletion and broad delete-sync operations.

The scanner recognizes ordinary shell command boundaries and nested
`sh`/`bash`/`zsh -c` calls. Execution-bearing syntax it cannot safely reduce,
such as command substitution and backticks, fails closed and requires one-time
authorization. Forced recursive deletion also fails closed when its target
contains an unresolved shell variable. Simple unconditional assignments in the
same command are resolved first, so cleanup such as
`workdir=/tmp/codex-preview; rm -rf "$workdir"` remains autonomous.

Ordinary file deletion and explicit narrow recursive targets are unaffected.
For example, `rm -f generated.json`, `rm -rf ./build`, and
`rm -rf /tmp/codex-preview` remain allowed.

## Security Boundary

Codex Command Guard does not:

- replace macOS permissions, backups, Git commits, or remote branch protection;
- understand the complete Bash/zsh grammar;
- guarantee interception of shell execution paths that Codex does not send
  through the configured hook;
- resist a malicious process already running as the same macOS user with
  unrestricted filesystem access;
- cryptographically prove that an on-disk one-time authorization record came
  from Touch ID.

The last point matters when threat-modeling full access: the current
authorization store is designed to prevent accidents and replay, not a
deliberate same-user bypass. Records are still exact-command, short-lived,
single-use, private (`0600`), and consumed atomically.

See [SECURITY.md](SECURITY.md) for supported versions and vulnerability
reporting.

## Requirements And Compatibility

- macOS 13 or newer;
- Swift 6 toolchain (Apple Command Line Tools are sufficient; full Xcode is not
  required);
- a Codex build that supports global `PreToolUse` command hooks with the `Bash`
  matcher.

This release was verified locally with Codex CLI `0.144.0-alpha.4`, Codex
Desktop `26.707.51957`, and Apple Swift `6.3.3`. Hook APIs can evolve, so a new
Codex release should be canary-tested before relying on interception. At the
time of verification, some newer/current-task `unified_exec` paths were not
intercepted; direct hook and Codex CLI paths were intercepted. A newly started
task is required after installing or changing hooks.

## Build And Test

```bash
swift run command-guard-tests
swift build -c release
swift scripts/run-canaries.swift --binary .build/release/codex-command-guard
swift scripts/benchmark.swift --binary .build/release/codex-command-guard
```

The canary script never executes the command text it tests. It submits JSON to
the guard binary and verifies the allow/deny response against a disposable
sentinel directory.

## Install

Clone the repository, review the source, and run:

```bash
swift run command-guard-tests
swift build -c release
install -d -m 700 "$HOME/.codex/local-hooks/bin"
install -m 755 .build/release/codex-command-guard \
  "$HOME/.codex/local-hooks/bin/codex-command-guard"
"$HOME/.codex/local-hooks/bin/codex-command-guard" install-hook \
  --binary "$HOME/.codex/local-hooks/bin/codex-command-guard" \
  --hooks "$HOME/.codex/hooks.json"
```

Restart Codex, open **Settings → Hooks**, review the `PreToolUse` entry, press
**Trust**, and ensure it is enabled. Codex intentionally requires review because
hooks execute outside its normal sandbox.

The installer preserves unrelated hooks, creates a private backup of
`hooks.json`, and installs only an exact `^Bash$` matcher.

## One-Time Authorization

When a command is blocked, the denial contains a short code. Review the exact
command shown by the guard, then run this manually in a terminal:

```bash
"$HOME/.codex/local-hooks/bin/codex-command-guard" allow-once ABCD-12
```

macOS displays a Touch ID/password prompt. Approval applies to the exact command
bytes, expires after five minutes, and is consumed once.

## Update

```bash
git pull --ff-only
swift run command-guard-tests
swift build -c release
install -m 755 .build/release/codex-command-guard \
  "$HOME/.codex/local-hooks/bin/codex-command-guard"
```

Restart Codex and review the hook again if the application marks the changed
binary or configuration as needing trust.

## Uninstall

```bash
"$HOME/.codex/local-hooks/bin/codex-command-guard" uninstall-hook \
  --binary "$HOME/.codex/local-hooks/bin/codex-command-guard" \
  --hooks "$HOME/.codex/hooks.json"
```

After verifying that Codex no longer lists the hook, the installed binary and
its state directory may be removed manually. Uninstalling the hook does not
change Codex approval or sandbox settings and does not modify unrelated hooks.

## Performance

The last local release benchmark measured roughly 8–9 ms median/p95 per full
subprocess invocation. GitHub Actions checks the behavior, but does not enforce
machine-specific latency thresholds.

## Provenance

This is an independent Swift implementation with no third-party package
dependencies. It does not include source code or license text from
`Dicklesworthstone/destructive_command_guard` (DCG). DCG and public reports of
accidental destructive agent commands were evaluated as prior art and
motivation; this repository uses its own architecture, parser, policy, tests,
installer, and authorization flow.

## License

Apache License 2.0. See [LICENSE](LICENSE).
