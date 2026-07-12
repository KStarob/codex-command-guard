# Codex Command Guard

A narrow, macOS-native `PreToolUse` emergency brake for catastrophic Codex
commands. It preserves autonomous `danger-full-access` operation and is not a
sandbox or complete enforcement boundary.

## Behavior

Ordinary commands exit silently. Recognized catastrophic commands return the
minimal Codex `permissionDecision: deny` response and a short authorization
code. Rules cover broad recursive deletion, destructive Git workspace/history
operations, raw-device writes, system power, selected mass infrastructure and
database operations, and broad cloud sync/delete operations.

Repository files cannot configure or weaken the guard. It performs no network
access and writes no persistent command history.

## One-Time Authorization

After reviewing the exact blocked command, run manually:

```bash
~/.codex/local-hooks/bin/codex-command-guard allow-once ABCD-12
```

macOS requires Touch ID or the account password. Approval is bound to the exact
command bytes, expires after five minutes, and is consumed once.

## Build And Verify

```bash
swift run command-guard-tests
swift build -c release
swift scripts/run-canaries.swift --binary .build/release/codex-command-guard
swift scripts/benchmark.swift --binary .build/release/codex-command-guard
```

This repository uses a standalone Swift test executable because the installed
Command Line Tools include `swiftc` but not the XCTest/Swift Testing runtime.

## Install

The verified binary is installed at:

```text
~/.codex/local-hooks/bin/codex-command-guard
```

The binary's `install-hook` command merges one global `PreToolUse` handler into
`~/.codex/hooks.json`, preserving unrelated hooks and writing a private backup.
Codex must then review and trust the hook definition in Settings → Hooks or
`/hooks`.

## Rollback

```bash
~/.codex/local-hooks/bin/codex-command-guard uninstall-hook \
  --binary ~/.codex/local-hooks/bin/codex-command-guard \
  --hooks ~/.codex/hooks.json
```

This removes only the matching guard handler. It does not change
`approval_policy`, `sandbox_mode`, other hooks, the source checkout, or state.

## Limitations And Canary Matrix

OpenAI documents that `PreToolUse` does not yet intercept every newer
`unified_exec` shell path. Direct binary canaries prove the policy and transport;
host canaries after trust must record actual coverage here:

| Host path | Result |
| --- | --- |
| Direct hook protocol | intercepted; canaries pass |
| Codex Desktop current-task `unified_exec` | not intercepted; task predates hook reload |
| Codex Desktop new-task simple shell | pending after app restart and hook trust |
| Codex Desktop continuing terminal | pending |
| Codex Desktop nested `bash -c` | pending |
| Codex CLI simple shell | intercepted; deny and exact one-time allow verified |

The one-time override was host-tested with macOS LocalAuthentication: the first
exact command ran after Touch ID, its authorization was consumed atomically,
and an identical second command was denied while the disposable repository's
`HEAD` remained unchanged.

`not_intercepted` is an expected documented limitation, not permission to claim
complete protection.

Release benchmark on this Mac (1,000 full subprocess invocations, alternating
safe and denied commands): median 8.35 ms, p95 9.06 ms, max 38.91 ms.
