import Foundation

public struct GuardEngine {
    public let store: AuthorizationStore

    public init(store: AuthorizationStore) {
        self.store = store
    }

    public func process(input: Data, fallbackCWD: URL, now: Date = Date()) -> Data? {
        let request: HookRequest
        switch HookRequest.decode(input) {
        case .valid(let decoded):
            request = decoded
        case .invalid(let reason):
            return HookResponse.denied(
                reason: "BLOCKED by codex-command-guard [protocol.invalid-request]: \(reason)."
            )
        }
        let command = request.command
        let cwd = request.cwd.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? fallbackCWD
        guard case .denied(let ruleID, let reason) = CatastrophicPolicy.evaluate(command: command, cwd: cwd) else {
            return nil
        }

        do {
            if try store.consume(command: command, now: now) { return nil }
            let pending = try store.recordPending(command: command, now: now)
            let message = """
            BLOCKED by codex-command-guard [\(ruleID)]: \(reason).
            To authorize this exact command once within 5 minutes, run manually:
            codex-command-guard allow-once \(pending.code)
            """
            return HookResponse.denied(reason: message)
        } catch {
            return HookResponse.denied(
                reason: "BLOCKED by codex-command-guard [\(ruleID)]: authorization state unavailable (\(error))."
            )
        }
    }
}
