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
    expect(HookRequest.decode(bash)?.command == "git status", "decode Bash command")

    let patch = #"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"rm -rf /"}}"#.data(using: .utf8)!
    expect(HookRequest.decode(patch)?.command == nil, "ignore non-Bash tool")
    expect(HookRequest.decode(Data("{".utf8)) == nil, "reject malformed JSON")

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

    let malformed = ShellScanner.scan("rm -rf '/Users")
    expect(malformed.count == 1 && malformed[0].ambiguous, "mark unterminated quote ambiguous")

    let oversized = ShellScanner.scan(String(repeating: "x", count: 64), maxBytes: 32)
    expect(oversized.count == 1 && oversized[0].ambiguous, "mark oversized command ambiguous")

    let deep = ShellScanner.scan(#"bash -c "bash -c 'bash -c \\"rm -rf /\\"'""#, maxDepth: 1)
    expect(deep.contains(where: \.ambiguous), "mark recursion depth overflow ambiguous")
}

private struct PolicyFixture: Decodable {
    let command: String
    let cwd: String
    let expected: String
    let ruleID: String?
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

testHookProtocol()
testShellScanner()
testCatastrophicPolicy()

if failures == 0 {
    print("PASS: command-guard-tests")
} else {
    exit(1)
}
