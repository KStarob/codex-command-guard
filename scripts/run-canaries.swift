#!/usr/bin/env swift
import Foundation

struct CanaryError: Error, CustomStringConvertible {
    let description: String
}

func argument(_ name: String) -> String? {
    guard let index = CommandLine.arguments.firstIndex(of: name), CommandLine.arguments.indices.contains(index + 1) else { return nil }
    return CommandLine.arguments[index + 1]
}

guard let binaryPath = argument("--binary") else {
    throw CanaryError(description: "usage: swift scripts/run-canaries.swift --binary <path>")
}

let fm = FileManager.default
let binary = URL(fileURLWithPath: binaryPath).standardizedFileURL
guard fm.isExecutableFile(atPath: binary.path) else {
    throw CanaryError(description: "binary is not executable: \(binary.path)")
}

let root = fm.temporaryDirectory.appendingPathComponent("codex-command-guard-canary-\(UUID().uuidString)", isDirectory: true)
try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
defer { try? fm.removeItem(at: root) }
let sentinel = root.appendingPathComponent("sentinel.txt")
try Data("must survive\n".utf8).write(to: sentinel)

let stateRoot = fm.homeDirectoryForCurrentUser.appendingPathComponent(".codex/local-hooks/state/codex-command-guard", isDirectory: true)
let beforeState = Set((try? fm.contentsOfDirectory(atPath: stateRoot.path)) ?? [])
defer {
    let after = Set((try? fm.contentsOfDirectory(atPath: stateRoot.path)) ?? [])
    for name in after.subtracting(beforeState) where name.hasPrefix("pending-") {
        try? fm.removeItem(at: stateRoot.appendingPathComponent(name))
    }
}

func invoke(_ command: String, cwd: URL = root) throws -> Data {
    let request: [String: Any] = [
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": cwd.path,
        "tool_input": ["command": command],
    ]
    let process = Process()
    let input = Pipe(); let output = Pipe(); let errors = Pipe()
    process.executableURL = binary
    process.standardInput = input
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: request))
    try input.fileHandleForWriting.close()
    process.waitUntilExit()
    let stderr = errors.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0 else {
        throw CanaryError(description: "guard exited \(process.terminationStatus): \(String(decoding: stderr, as: UTF8.self))")
    }
    return output.fileHandleForReading.readDataToEndOfFile()
}

func expectAllowed(_ command: String) throws {
    let output = try invoke(command)
    guard output.isEmpty else { throw CanaryError(description: "expected allow: \(command)") }
}

func expectDenied(_ command: String, rule: String) throws {
    let output = try invoke(command)
    guard !output.isEmpty,
          let root = try JSONSerialization.jsonObject(with: output) as? [String: Any],
          let details = root["hookSpecificOutput"] as? [String: String],
          details["permissionDecision"] == "deny",
          details["permissionDecisionReason"]?.contains(rule) == true
    else { throw CanaryError(description: "expected denial \(rule): \(command)") }
}

try expectAllowed("git status")
try expectAllowed("rm -rf node_modules .next dist")
try expectDenied("git reset --hard", rule: "git.reset-hard")
try expectDenied("sudo env X=1 bash -c 'echo start && rm -rf /'", rule: "filesystem.rm-broad")
try expectDenied("dd if=/dev/zero of=/dev/disk99", rule: "device.raw-write")
guard fm.fileExists(atPath: sentinel.path), try String(contentsOf: sentinel, encoding: .utf8) == "must survive\n" else {
    throw CanaryError(description: "sentinel changed during direct canaries")
}

print("PASS: direct canaries (fixture root: \(root.path))")
