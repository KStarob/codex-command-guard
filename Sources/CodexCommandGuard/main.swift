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

func option(_ name: String, in arguments: [String]) -> String? {
    guard let index = arguments.firstIndex(of: name), arguments.indices.contains(index + 1) else { return nil }
    return arguments[index + 1]
}

if arguments.first == "install-hook" || arguments.first == "uninstall-hook" {
    guard let binaryPath = option("--binary", in: arguments),
          let hooksPath = option("--hooks", in: arguments)
    else {
        fail("usage: codex-command-guard \(arguments.first!) --binary <absolute-path> --hooks <path>")
    }
    let binary = URL(fileURLWithPath: binaryPath).standardizedFileURL
    let hooks = URL(fileURLWithPath: hooksPath).standardizedFileURL
    guard binary.path.hasPrefix("/") else { fail("binary path must be absolute") }
    do {
        if arguments.first == "install-hook" {
            try HookInstaller.install(hooksURL: hooks, binaryURL: binary)
            print("Installed Codex hook in \(hooks.path)")
        } else {
            try HookInstaller.uninstall(hooksURL: hooks, binaryURL: binary)
            print("Removed Codex hook from \(hooks.path)")
        }
        exit(0)
    } catch {
        fail(String(describing: error))
    }
}

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
