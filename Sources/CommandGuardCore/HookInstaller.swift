import Darwin
import Foundation

public enum HookInstallerError: Error, CustomStringConvertible {
    case unsafePath(String)
    case malformedConfiguration(String)
    case io(String)

    public var description: String {
        switch self {
        case .unsafePath(let value): "Unsafe hooks path: \(value)"
        case .malformedConfiguration(let value): "Malformed hooks configuration: \(value)"
        case .io(let value): "Hook configuration I/O error: \(value)"
        }
    }
}

public enum HookInstaller {
    public static func install(hooksURL: URL, binaryURL: URL) throws {
        var root = try loadRoot(hooksURL)
        var hooks = root["hooks"] as? [String: Any] ?? [:]
        var groups = hooks["PreToolUse"] as? [[String: Any]] ?? []
        groups = removingGuard(binaryPath: binaryURL.path, from: groups)
        groups.append([
            "matcher": "^Bash$",
            "hooks": [[
                "type": "command",
                "command": binaryURL.path,
                "timeout": 5,
                "statusMessage": "Checking catastrophic command safety",
            ]],
        ])
        hooks["PreToolUse"] = groups
        root["hooks"] = hooks
        try save(root, to: hooksURL)
    }

    public static func uninstall(hooksURL: URL, binaryURL: URL) throws {
        var root = try loadRoot(hooksURL)
        guard var hooks = root["hooks"] as? [String: Any] else { return }
        let groups = hooks["PreToolUse"] as? [[String: Any]] ?? []
        hooks["PreToolUse"] = removingGuard(binaryPath: binaryURL.path, from: groups)
        root["hooks"] = hooks
        try save(root, to: hooksURL)
    }

    private static func removingGuard(binaryPath: String, from groups: [[String: Any]]) -> [[String: Any]] {
        groups.compactMap { group in
            guard let handlers = group["hooks"] as? [[String: Any]] else { return group }
            let remaining = handlers.filter { ($0["command"] as? String) != binaryPath }
            guard !remaining.isEmpty else { return nil }
            var copy = group
            copy["hooks"] = remaining
            return copy
        }
    }

    private static func loadRoot(_ url: URL) throws -> [String: Any] {
        try validateExistingPath(url)
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        do {
            let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
            guard let root = object as? [String: Any] else {
                throw HookInstallerError.malformedConfiguration("root must be an object")
            }
            if let hooks = root["hooks"], !(hooks is [String: Any]) {
                throw HookInstallerError.malformedConfiguration("hooks must be an object")
            }
            return root
        } catch let error as HookInstallerError { throw error }
        catch { throw HookInstallerError.malformedConfiguration(error.localizedDescription) }
    }

    private static func validateExistingPath(_ url: URL) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return }
            throw HookInstallerError.io(String(cString: strerror(errno)))
        }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
            throw HookInstallerError.unsafePath(url.path)
        }
    }

    private static func save(_ root: [String: Any], to url: URL) throws {
        guard JSONSerialization.isValidJSONObject(root) else {
            throw HookInstallerError.malformedConfiguration("contains unsupported JSON values")
        }
        let fm = FileManager.default
        let parent = url.deletingLastPathComponent()
        do {
            try fm.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            if fm.fileExists(atPath: url.path) {
                let formatter = ISO8601DateFormatter()
                let stamp = formatter.string(from: Date()).replacingOccurrences(of: ":", with: "-")
                let backup = parent.appendingPathComponent("\(url.lastPathComponent).backup-\(stamp)-\(UUID().uuidString)")
                try fm.copyItem(at: url, to: backup)
                try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
            }
            let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) + Data("\n".utf8)
            let temp = parent.appendingPathComponent(".\(url.lastPathComponent).tmp-\(UUID().uuidString)")
            try data.write(to: temp, options: .withoutOverwriting)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temp.path)
            if rename(temp.path, url.path) != 0 {
                let message = String(cString: strerror(errno)); try? fm.removeItem(at: temp)
                throw HookInstallerError.io(message)
            }
        } catch let error as HookInstallerError { throw error }
        catch { throw HookInstallerError.io(error.localizedDescription) }
    }
}
