#!/usr/bin/env swift
import Foundation

func argument(_ name: String) -> String? {
    guard let index = CommandLine.arguments.firstIndex(of: name), CommandLine.arguments.indices.contains(index + 1) else { return nil }
    return CommandLine.arguments[index + 1]
}

guard let binaryPath = argument("--binary") else {
    fatalError("usage: swift scripts/benchmark.swift --binary <path>")
}
let binary = URL(fileURLWithPath: binaryPath).standardizedFileURL
let fm = FileManager.default
let stateRoot = fm.homeDirectoryForCurrentUser.appendingPathComponent(".codex/local-hooks/state/codex-command-guard", isDirectory: true)
let beforeState = Set((try? fm.contentsOfDirectory(atPath: stateRoot.path)) ?? [])
func cleanBenchmarkState() {
    let after = Set((try? fm.contentsOfDirectory(atPath: stateRoot.path)) ?? [])
    for name in after.subtracting(beforeState) where name.hasPrefix("pending-") {
        try? fm.removeItem(at: stateRoot.appendingPathComponent(name))
    }
}
defer { cleanBenchmarkState() }

func payload(_ command: String) -> Data {
    try! JSONSerialization.data(withJSONObject: [
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/tmp/project",
        "tool_input": ["command": command],
    ])
}

func measure(_ input: Data) throws -> Double {
    let process = Process(); let stdin = Pipe(); let stdout = Pipe(); let stderr = Pipe()
    let completed = DispatchSemaphore(value: 0)
    process.executableURL = binary
    process.standardInput = stdin; process.standardOutput = stdout; process.standardError = stderr
    process.terminationHandler = { _ in completed.signal() }
    let start = ContinuousClock.now
    try process.run(); stdin.fileHandleForWriting.write(input); try stdin.fileHandleForWriting.close()
    completed.wait(); _ = stdout.fileHandleForReading.readDataToEndOfFile(); _ = stderr.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0 else { fatalError("benchmark subprocess failed") }
    return Double(start.duration(to: .now).components.attoseconds) / 1e15
}

let safe = payload("rg --files && git status --short")
let dangerous = payload("git reset --hard")
let count = Int(argument("--count") ?? "1000") ?? 1_000
for _ in 0..<20 { _ = try measure(safe) }
var values: [Double] = []
for index in 0..<count {
    let isDangerous = !index.isMultiple(of: 2)
    values.append(try measure(isDangerous ? dangerous : safe))
    if isDangerous { cleanBenchmarkState() }
}
values.sort()
func percentile(_ fraction: Double) -> Double { values[min(values.count - 1, Int(Double(values.count - 1) * fraction))] }
let median = percentile(0.5), p95 = percentile(0.95), maximum = values.last!
let report = String(format: "subprocess latency: median=%.2fms p95=%.2fms max=%.2fms n=%d", median, p95, maximum, values.count)
print(report)
if let outputPath = argument("--output") {
    try Data((report + "\n").utf8).write(to: URL(fileURLWithPath: outputPath), options: .atomic)
}
guard median < 10, p95 < 20 else { exit(1) }
