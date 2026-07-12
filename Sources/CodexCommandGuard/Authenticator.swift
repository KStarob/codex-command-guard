import CommandGuardCore
import Foundation
import LocalAuthentication

private final class AuthenticationResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Bool, Error>?

    func store(_ result: Result<Bool, Error>) {
        lock.lock(); defer { lock.unlock() }
        value = result
    }

    func load() -> Result<Bool, Error>? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

struct MacUserAuthenticator: Authenticating {
    func authenticate(reason: String) throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var authorizationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authorizationError) else {
            throw authorizationError ?? ManualAuthorizationError.authenticationRejected
        }

        let semaphore = DispatchSemaphore(value: 0)
        let box = AuthenticationResultBox()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            if let error { box.store(.failure(error)) }
            else { box.store(.success(success)) }
            semaphore.signal()
        }
        semaphore.wait()
        return try box.load()?.get() ?? false
    }
}
