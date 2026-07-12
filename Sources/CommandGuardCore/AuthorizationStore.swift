import CryptoKit
import Darwin
import Foundation
import Security

public struct PendingCommand: Codable, Equatable, Sendable {
    public let code: String
    public let command: String
    public let commandHash: String
    public let createdAt: Date
    public let expiresAt: Date
}

private struct CommandAuthorization: Codable, Sendable {
    let commandHash: String
    let createdAt: Date
    let expiresAt: Date
    let nonce: String
}

public enum AuthorizationStoreError: Error, CustomStringConvertible {
    case unsafeRoot(String)
    case invalidCode
    case expired
    case io(String)

    public var description: String {
        switch self {
        case .unsafeRoot(let value): "Unsafe state root: \(value)"
        case .invalidCode: "Unknown authorization code"
        case .expired: "Pending authorization expired"
        case .io(let value): "State I/O error: \(value)"
        }
    }
}

public struct AuthorizationStore: Sendable {
    public let root: URL
    private var fileManager: FileManager { .default }
    private let pendingLifetime: TimeInterval = 600
    private let authorizationLifetime: TimeInterval = 300

    public init(root: URL) {
        self.root = root.standardizedFileURL
    }

    public static func commandHash(_ command: String) -> String {
        SHA256.hash(data: Data(command.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public func recordPending(command: String, now: Date = Date()) throws -> PendingCommand {
        try ensureSecureRoot()
        try cleanup(now: now)
        let code = try randomCode()
        let record = PendingCommand(
            code: code,
            command: command,
            commandHash: Self.commandHash(command),
            createdAt: now,
            expiresAt: now.addingTimeInterval(pendingLifetime)
        )
        try writeSecure(record, to: pendingURL(code: code))
        return record
    }

    public func pending(code: String, now: Date = Date()) throws -> PendingCommand? {
        try ensureSecureRoot()
        let url = pendingURL(code: normalize(code))
        guard let record: PendingCommand = try readRegular(url) else { return nil }
        guard record.expiresAt >= now else {
            try? fileManager.removeItem(at: url)
            return nil
        }
        return record
    }

    public func authorize(code: String, now: Date = Date()) throws {
        guard let pending = try pending(code: code, now: now) else {
            throw AuthorizationStoreError.invalidCode
        }
        guard pending.expiresAt >= now else { throw AuthorizationStoreError.expired }
        let authorization = CommandAuthorization(
            commandHash: pending.commandHash,
            createdAt: now,
            expiresAt: now.addingTimeInterval(authorizationLifetime),
            nonce: try randomHex(byteCount: 16)
        )
        try writeSecure(authorization, to: authorizationURL(hash: pending.commandHash))
        try? fileManager.removeItem(at: pendingURL(code: pending.code))
    }

    public func consume(command: String, now: Date = Date()) throws -> Bool {
        try ensureSecureRoot()
        let hash = Self.commandHash(command)
        let source = authorizationURL(hash: hash)
        let claimed = root.appendingPathComponent("claimed-\(UUID().uuidString).json")
        guard rename(source.path, claimed.path) == 0 else {
            if errno == ENOENT { return false }
            throw AuthorizationStoreError.io(String(cString: strerror(errno)))
        }
        defer { try? fileManager.removeItem(at: claimed) }
        guard let authorization: CommandAuthorization = try readRegular(claimed) else { return false }
        return authorization.commandHash == hash && authorization.expiresAt >= now
    }

    private func ensureSecureRoot() throws {
        var info = stat()
        if lstat(root.path, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFDIR else {
                throw AuthorizationStoreError.unsafeRoot(root.path)
            }
            guard chmod(root.path, 0o700) == 0 else {
                throw AuthorizationStoreError.io(String(cString: strerror(errno)))
            }
            return
        }
        guard errno == ENOENT else { throw AuthorizationStoreError.io(String(cString: strerror(errno))) }
        do {
            try fileManager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        } catch {
            throw AuthorizationStoreError.io(error.localizedDescription)
        }
    }

    private func cleanup(now: Date) throws {
        let urls = try fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
        for url in urls where url.lastPathComponent.hasPrefix("pending-") || url.lastPathComponent.hasPrefix("auth-") {
            if let pending: PendingCommand = try? readRegular(url), pending.expiresAt < now {
                try? fileManager.removeItem(at: url)
            } else if let authorization: CommandAuthorization = try? readRegular(url), authorization.expiresAt < now {
                try? fileManager.removeItem(at: url)
            }
        }
    }

    private func pendingURL(code: String) -> URL {
        root.appendingPathComponent("pending-\(normalize(code)).json")
    }

    private func authorizationURL(hash: String) -> URL {
        root.appendingPathComponent("auth-\(hash).json")
    }

    private func normalize(_ code: String) -> String {
        code.uppercased().filter { $0.isHexDigit || $0 == "-" }
    }

    private func randomCode() throws -> String {
        let value = try randomHex(byteCount: 3).uppercased()
        return "\(value.prefix(4))-\(value.suffix(2))"
    }

    private func randomHex(byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw AuthorizationStoreError.io("secure random generation failed")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func writeSecure<T: Encodable>(_ value: T, to destination: URL) throws {
        let data = try JSONEncoder.guardEncoder.encode(value)
        let temp = root.appendingPathComponent(".tmp-\(UUID().uuidString)")
        let descriptor = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw AuthorizationStoreError.io(String(cString: strerror(errno))) }
        var writeError: AuthorizationStoreError?
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                if count < 0 { writeError = .io(String(cString: strerror(errno))); break }
                offset += count
            }
        }
        if fsync(descriptor) != 0 && writeError == nil { writeError = .io(String(cString: strerror(errno))) }
        _ = close(descriptor)
        if let writeError { try? fileManager.removeItem(at: temp); throw writeError }
        guard rename(temp.path, destination.path) == 0 else {
            let message = String(cString: strerror(errno)); try? fileManager.removeItem(at: temp)
            throw AuthorizationStoreError.io(message)
        }
    }

    private func readRegular<T: Decodable>(_ url: URL) throws -> T? {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw AuthorizationStoreError.io(String(cString: strerror(errno)))
        }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
            throw AuthorizationStoreError.unsafeRoot(url.path)
        }
        do { return try JSONDecoder.guardDecoder.decode(T.self, from: Data(contentsOf: url)) }
        catch { throw AuthorizationStoreError.io(error.localizedDescription) }
    }
}

private extension JSONEncoder {
    static var guardEncoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

private extension JSONDecoder {
    static var guardDecoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}
