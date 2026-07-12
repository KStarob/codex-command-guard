import CommandGuardCore
import Foundation

private var failures = 0

@MainActor
private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        failures += 1
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
    }
}

@MainActor
private func testHookProtocol() {
    let bash = #"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#.data(using: .utf8)!
    if case .valid(let request) = HookRequest.decode(bash) {
        expect(request.command == "git status", "decode Bash command")
    } else {
        expect(false, "decode valid Bash request")
    }

    let patch = #"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"rm -rf /"}}"#.data(using: .utf8)!
    if case .invalid = HookRequest.decode(patch) { expect(true, "reject non-Bash tool") }
    else { expect(false, "reject non-Bash tool") }
    if case .invalid = HookRequest.decode(Data("{".utf8)) { expect(true, "reject malformed JSON") }
    else { expect(false, "reject malformed JSON") }

    do {
        let raw = try JSONSerialization.jsonObject(with: HookResponse.denied(reason: "blocked"))
        guard let object = raw as? [String: Any],
              let output = object["hookSpecificOutput"] as? [String: String]
        else {
            expect(false, "decode denial output")
            return
        }
        expect(Set(object.keys) == ["hookSpecificOutput"], "minimal denial root")
        expect(Set(output.keys) == ["hookEventName", "permissionDecision", "permissionDecisionReason"], "minimal denial fields")
        expect(output["hookEventName"] == "PreToolUse", "denial event")
        expect(output["permissionDecision"] == "deny", "denial decision")
        expect(output["permissionDecisionReason"] == "blocked", "denial reason")
    } catch {
        expect(false, "serialize denial: \(error)")
    }
}

@MainActor
private func testShellScanner() {
    let nested = ShellScanner.scan(#"sudo env X=1 bash -c 'git reset --hard && echo done'"#)
    expect(nested.map(\.executable) == ["git", "echo"], "scan nested wrapper executables")
    expect(nested.first?.arguments == ["reset", "--hard"], "scan nested wrapper arguments")

    let quoted = ShellScanner.scan(#"printf '%s' 'a;b'"#)
    expect(quoted.count == 1, "do not split quoted semicolon")
    expect(quoted.first?.arguments.last == "a;b", "preserve quoted semicolon")
    expect(quoted.first?.ambiguous == false, "quoted command is unambiguous")

    let chained = ShellScanner.scan("git status; command nohup rm -rf /tmp/build || echo failed")
    expect(chained.map(\.executable) == ["git", "rm", "echo"], "split top-level shell operators")

    let pipe = ShellScanner.scan("printf safe | git reset --hard")
    expect(pipe.map(\.executable) == ["printf", "git"], "split single pipe")

    let background = ShellScanner.scan("printf safe & git reset --hard")
    expect(background.map(\.executable) == ["printf", "git"], "split background operator")

    let multiline = ShellScanner.scan("printf safe\ngit reset --hard")
    expect(multiline.map(\.executable) == ["printf", "git"], "split unquoted newline")

    let substitution = ShellScanner.scan(#"printf "$(whoami)""#)
    expect(substitution.count == 1 && substitution[0].ambiguous, "mark command substitution ambiguous")

    let backticks = ShellScanner.scan(#"printf "`whoami`""#)
    expect(backticks.count == 1 && backticks[0].ambiguous, "mark backticks ambiguous")

    let quotedSubstitution = ShellScanner.scan(#"printf '%s' '$(whoami)'"#)
    expect(quotedSubstitution.first?.ambiguous == false, "single-quoted substitution is literal")

    let malformed = ShellScanner.scan("rm -rf '/Users")
    expect(malformed.count == 1 && malformed[0].ambiguous, "mark unterminated quote ambiguous")

    let oversized = ShellScanner.scan(String(repeating: "x", count: 64), maxBytes: 32)
    expect(oversized.count == 1 && oversized[0].ambiguous, "mark oversized command ambiguous")

    let deep = ShellScanner.scan(#"bash -c "bash -c 'bash -c \\"rm -rf /\\"'""#, maxDepth: 1)
    expect(deep.contains(where: \.ambiguous), "mark recursion depth overflow ambiguous")
}

@MainActor
private func testAmbiguousPolicy() {
    let cwd = URL(fileURLWithPath: "/tmp/project", isDirectory: true)
    let decisions = [
        CatastrophicPolicy.evaluate(command: #"printf "$(whoami)""#, cwd: cwd),
        CatastrophicPolicy.evaluate(command: #"printf "`whoami`""#, cwd: cwd),
    ]
    for decision in decisions {
        guard case .denied(let ruleID, _) = decision else {
            expect(false, "deny executable shell ambiguity")
            continue
        }
        expect(ruleID == "parser.ambiguous-shell", "ambiguity rule id")
    }
    expect(
        CatastrophicPolicy.evaluate(command: #"printf '%s' '$(whoami)'"#, cwd: cwd) == .allowed,
        "allow literal single-quoted substitution"
    )
}

private struct PolicyFixture: Decodable {
    let command: String
    let cwd: String
    let expected: String
    let ruleID: String?
}

private final class LockedResults: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Bool] = []

    func append(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        values.append(value)
    }

    var successCount: Int {
        lock.lock(); defer { lock.unlock() }
        return values.filter { $0 }.count
    }
}

private struct FakeAuthenticator: Authenticating {
    let result: Bool
    func authenticate(reason: String) throws -> Bool { result }
}

@MainActor
private func testCatastrophicPolicy() {
    do {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/commands.json")
        let fixtures = try JSONDecoder().decode([PolicyFixture].self, from: Data(contentsOf: source))
        expect(fixtures.count >= 40, "load complete policy fixture corpus")

        for fixture in fixtures {
            let decision = CatastrophicPolicy.evaluate(
                command: fixture.command,
                cwd: URL(fileURLWithPath: fixture.cwd, isDirectory: true)
            )
            switch (fixture.expected, decision) {
            case ("allow", .allowed):
                break
            case ("deny", .denied(let ruleID, _)):
                expect(ruleID == fixture.ruleID, "rule for: \(fixture.command)")
            default:
                expect(false, "decision \(decision) for: \(fixture.command)")
            }
        }
    } catch {
        expect(false, "load policy fixtures: \(error)")
    }
}

@MainActor
private func testAuthorizationStore() {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("command-guard-state-\(UUID().uuidString)", isDirectory: true)
    defer { try? fm.removeItem(at: root) }
    let store = AuthorizationStore(root: root)
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    do {
        let pending = try store.recordPending(command: "git reset --hard", now: t0)
        expect(pending.code.count == 7, "pending display code length")
        let loaded = try store.pending(code: pending.code, now: t0)
        expect(loaded?.command == "git reset --hard", "load pending exact command")

        try store.authorize(code: pending.code, now: t0)
        let changed = try store.consume(command: "git reset --hard HEAD~1", now: t0)
        let exact = try store.consume(command: "git reset --hard", now: t0)
        let reused = try store.consume(command: "git reset --hard", now: t0)
        expect(!changed, "reject changed command")
        expect(exact, "consume exact authorization")
        expect(!reused, "authorization is single-use")

        let expired = try store.recordPending(command: "rm -rf /", now: t0)
        try store.authorize(code: expired.code, now: t0)
        let expiredResult = try store.consume(command: "rm -rf /", now: t0.addingTimeInterval(301))
        expect(!expiredResult, "authorization expires after five minutes")

        let rootMode = (try fm.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber)?.intValue
        expect(rootMode == 0o700, "state directory mode 0700")
        let files = try fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        for file in files {
            let mode = (try fm.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue
            expect(mode == 0o600, "state file mode 0600: \(file.lastPathComponent)")
        }

        let concurrent = try store.recordPending(command: "git clean -fdx", now: t0)
        try store.authorize(code: concurrent.code, now: t0)
        let start = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        let results = LockedResults()
        for _ in 0..<64 {
            group.enter()
            DispatchQueue.global().async {
                start.wait()
                results.append((try? store.consume(command: "git clean -fdx", now: t0)) == true)
                group.leave()
            }
        }
        for _ in 0..<64 { start.signal() }
        group.wait()
        expect(results.successCount == 1, "exactly one concurrent authorization consumer")
    } catch {
        expect(false, "authorization store operations: \(error)")
    }

    do {
        let badRoot = fm.temporaryDirectory.appendingPathComponent("command-guard-link-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: badRoot) }
        try fm.createSymbolicLink(at: badRoot, withDestinationURL: root)
        let linked = AuthorizationStore(root: badRoot)
        do {
            _ = try linked.recordPending(command: "git reset --hard", now: t0)
            expect(false, "reject symlink state root")
        } catch {
            expect(true, "symlink rejection")
        }
    } catch {
        expect(false, "create symlink fixture: \(error)")
    }
}

@MainActor
private func testGuardEngine() {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("command-guard-engine-\(UUID().uuidString)", isDirectory: true)
    defer { try? fm.removeItem(at: root) }
    let store = AuthorizationStore(root: root)
    let engine = GuardEngine(store: store)
    let now = Date(timeIntervalSince1970: 1_700_000_000)

    func input(_ command: String) -> Data {
        try! JSONSerialization.data(withJSONObject: [
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": "/tmp/project",
            "tool_input": ["command": command],
        ])
    }

    expect(engine.process(input: input("git status"), fallbackCWD: URL(fileURLWithPath: "/tmp/project"), now: now) == nil, "safe command is silent")
    let invalidInputs: [Data] = [
        Data("{".utf8),
        Data(#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#.utf8),
        Data(#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}"#.utf8),
        Data(#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"git status"}}"#.utf8),
        Data(#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":7}}"#.utf8),
    ]
    for invalid in invalidInputs {
        guard let denial = engine.process(input: invalid, fallbackCWD: URL(fileURLWithPath: "/tmp/project"), now: now),
              let object = try? JSONSerialization.jsonObject(with: denial) as? [String: Any],
              let output = object["hookSpecificOutput"] as? [String: String]
        else {
            expect(false, "invalid hook input emits denial")
            continue
        }
        expect(output["permissionDecision"] == "deny", "invalid hook input decision")
        expect(output["permissionDecisionReason"]?.contains("protocol.invalid-request") == true, "invalid hook input rule id")
    }

    guard let denial = engine.process(input: input("git reset --hard"), fallbackCWD: URL(fileURLWithPath: "/tmp/project"), now: now),
          let object = try? JSONSerialization.jsonObject(with: denial) as? [String: Any],
          let output = object["hookSpecificOutput"] as? [String: String],
          let reason = output["permissionDecisionReason"],
          let match = reason.range(of: #"[0-9A-F]{4}-[0-9A-F]{2}"#, options: .regularExpression)
    else {
        expect(false, "dangerous command emits denial with code")
        return
    }
    let code = String(reason[match])
    expect(reason.contains("git.reset-hard"), "denial includes rule id")

    do {
        try store.authorize(code: code, now: now)
        expect(engine.process(input: input("git reset --hard"), fallbackCWD: URL(fileURLWithPath: "/tmp/project"), now: now) == nil, "authorized exact command runs once")
        expect(engine.process(input: input("git reset --hard"), fallbackCWD: URL(fileURLWithPath: "/tmp/project"), now: now) != nil, "authorization is consumed")
    } catch {
        expect(false, "authorize engine command: \(error)")
    }
}

@MainActor
private func testManualAuthorizer() {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("command-guard-auth-\(UUID().uuidString)", isDirectory: true)
    defer { try? fm.removeItem(at: root) }
    let store = AuthorizationStore(root: root)
    let now = Date(timeIntervalSince1970: 1_700_000_000)

    do {
        let approved = try store.recordPending(command: "git reset --hard", now: now)
        let command = try ManualAuthorizer.authorize(
            code: approved.code,
            store: store,
            authenticator: FakeAuthenticator(result: true),
            now: now
        )
        expect(command == "git reset --hard", "manual authorization returns reviewed command")
        let consumed = try store.consume(command: command, now: now)
        expect(consumed, "successful authentication creates authorization")

        let rejected = try store.recordPending(command: "rm -rf /", now: now)
        do {
            _ = try ManualAuthorizer.authorize(
                code: rejected.code,
                store: store,
                authenticator: FakeAuthenticator(result: false),
                now: now
            )
            expect(false, "rejected authentication must throw")
        } catch {
            let unauthorized = try store.consume(command: "rm -rf /", now: now)
            expect(!unauthorized, "rejected authentication creates no authorization")
        }
    } catch {
        expect(false, "manual authorizer: \(error)")
    }
}

@MainActor
private func testHookInstaller() {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("command-guard-installer-\(UUID().uuidString)", isDirectory: true)
    defer { try? fm.removeItem(at: root) }
    do { try fm.createDirectory(at: root, withIntermediateDirectories: true) }
    catch { expect(false, "create installer fixture root: \(error)"); return }
    let hooks = root.appendingPathComponent("hooks.json")
    let binary = URL(fileURLWithPath: "/Users/test/.codex/local-hooks/bin/codex-command-guard")

    do {
        try HookInstaller.install(hooksURL: hooks, binaryURL: binary)
        let installed = try JSONSerialization.jsonObject(with: Data(contentsOf: hooks)) as! [String: Any]
        let rootHooks = installed["hooks"] as! [String: Any]
        let groups = rootHooks["PreToolUse"] as! [[String: Any]]
        expect(groups.count == 1, "install one PreToolUse group")
        expect(groups[0]["matcher"] as? String == "^Bash$", "install Bash matcher")

        let unrelated: [String: Any] = [
            "hooks": [
                "SessionStart": [["matcher": "startup", "hooks": [["type": "command", "command": "/tmp/existing"]]]],
                "PreToolUse": groups,
            ],
            "custom": "preserve-me",
        ]
        try JSONSerialization.data(withJSONObject: unrelated, options: [.prettyPrinted, .sortedKeys]).write(to: hooks)
        try HookInstaller.install(hooksURL: hooks, binaryURL: binary)
        let merged = try JSONSerialization.jsonObject(with: Data(contentsOf: hooks)) as! [String: Any]
        expect(merged["custom"] as? String == "preserve-me", "preserve unknown root fields")
        let mergedHooks = merged["hooks"] as! [String: Any]
        expect(mergedHooks["SessionStart"] != nil, "preserve unrelated hook events")
        expect((mergedHooks["PreToolUse"] as! [[String: Any]]).count == 1, "installation is idempotent")

        try HookInstaller.uninstall(hooksURL: hooks, binaryURL: binary)
        let removed = try JSONSerialization.jsonObject(with: Data(contentsOf: hooks)) as! [String: Any]
        let removedHooks = removed["hooks"] as! [String: Any]
        expect(removedHooks["SessionStart"] != nil, "rollback preserves unrelated hook")
        expect((removedHooks["PreToolUse"] as? [[String: Any]])?.isEmpty != false, "rollback removes guard only")
        let backups = try fm.contentsOfDirectory(atPath: root.path)
        expect(backups.contains(where: { $0.hasPrefix("hooks.json.backup-") }), "installer creates backup")
    } catch {
        expect(false, "hook installer lifecycle: \(error)")
    }

    do {
        let target = root.appendingPathComponent("real.json")
        let link = root.appendingPathComponent("linked.json")
        try Data("{}".utf8).write(to: target)
        try fm.createSymbolicLink(at: link, withDestinationURL: target)
        do {
            try HookInstaller.install(hooksURL: link, binaryURL: binary)
            expect(false, "installer rejects symlink hooks file")
        } catch {
            expect(true, "symlink hooks rejection")
        }
    } catch {
        expect(false, "symlink installer fixture: \(error)")
    }
}

testHookProtocol()
testShellScanner()
testAmbiguousPolicy()
testCatastrophicPolicy()
testAuthorizationStore()
testGuardEngine()
testManualAuthorizer()
testHookInstaller()

if failures == 0 {
    print("PASS: command-guard-tests")
} else {
    exit(1)
}
