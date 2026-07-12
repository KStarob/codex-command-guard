import Foundation

public struct HookRequest: Sendable {
    public let command: String?
    public let cwd: String?

    private struct WireRequest: Decodable {
        let hookEventName: String
        let toolName: String?
        let toolInput: ToolInput?
        let cwd: String?

        enum CodingKeys: String, CodingKey {
            case hookEventName = "hook_event_name"
            case toolName = "tool_name"
            case toolInput = "tool_input"
            case cwd
        }
    }

    private struct ToolInput: Decodable {
        let command: String?
    }

    public static func decode(_ data: Data) -> HookRequest? {
        guard let wire = try? JSONDecoder().decode(WireRequest.self, from: data) else {
            return nil
        }
        let command = wire.hookEventName == "PreToolUse" && wire.toolName == "Bash"
            ? wire.toolInput?.command
            : nil
        return HookRequest(command: command, cwd: wire.cwd)
    }
}

public enum HookResponse {
    public static func denied(reason: String) -> Data {
        let object: [String: Any] = [
            "hookSpecificOutput": [
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            ],
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }
}
