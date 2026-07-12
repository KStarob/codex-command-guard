import Foundation

public protocol Authenticating {
    func authenticate(reason: String) throws -> Bool
}

public enum ManualAuthorizationError: Error, CustomStringConvertible {
    case unknownCode
    case authenticationRejected

    public var description: String {
        switch self {
        case .unknownCode: "Unknown or expired authorization code"
        case .authenticationRejected: "macOS authentication was not approved"
        }
    }
}

public enum ManualAuthorizer {
    @discardableResult
    public static func authorize(
        code: String,
        store: AuthorizationStore,
        authenticator: Authenticating,
        now: Date = Date()
    ) throws -> String {
        guard let pending = try store.pending(code: code, now: now) else {
            throw ManualAuthorizationError.unknownCode
        }
        let reason = "Authorize one exact Codex command: \(pending.command)"
        guard try authenticator.authenticate(reason: reason) else {
            throw ManualAuthorizationError.authenticationRejected
        }
        try store.authorize(code: code, now: now)
        return pending.command
    }
}
