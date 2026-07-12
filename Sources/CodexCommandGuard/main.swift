import CommandGuardCore
import Foundation

private let stateRoot = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".codex/local-hooks/state/codex-command-guard", isDirectory: true)
private let store = AuthorizationStore(root: stateRoot)

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("codex-command-guard: \(message)\n".utf8))
    exit(2)
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.first == "allow-once" {
    guard arguments.count == 2 else { fail("usage: codex-command-guard allow-once <code>") }
    let code = arguments[1]
    do {
        guard let pending = try store.pending(code: code) else { fail("unknown or expired authorization code") }
        print("The following exact command will be authorized once for five minutes:\n")
        print(pending.command)
        print("\nConfirm with Touch ID or your macOS password.")
        let command = try ManualAuthorizer.authorize(
            code: code,
            store: store,
            authenticator: MacUserAuthenticator()
        )
        print("Authorized once: \(AuthorizationStore.commandHash(command).prefix(12))")
        exit(0)
    } catch {
        fail(String(describing: error))
    }
}

if !arguments.isEmpty {
    fail("unknown command: \(arguments.joined(separator: " "))")
}

let input = FileHandle.standardInput.readDataToEndOfFile()
let engine = GuardEngine(store: store)
let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
if let response = engine.process(input: input, fallbackCWD: cwd) {
    FileHandle.standardOutput.write(response)
    FileHandle.standardOutput.write(Data("\n".utf8))
}
