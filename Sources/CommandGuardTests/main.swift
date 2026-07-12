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

testHookProtocol()

if failures == 0 {
    print("PASS: command-guard-tests")
} else {
    exit(1)
}
