// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "codex-command-guard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CommandGuardCore", targets: ["CommandGuardCore"]),
        .executable(name: "codex-command-guard", targets: ["CodexCommandGuard"]),
        .executable(name: "command-guard-tests", targets: ["CommandGuardTests"]),
    ],
    targets: [
        .target(name: "CommandGuardCore"),
        .executableTarget(name: "CodexCommandGuard", dependencies: ["CommandGuardCore"]),
        .executableTarget(name: "CommandGuardTests", dependencies: ["CommandGuardCore"]),
    ]
)
