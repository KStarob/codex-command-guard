import Foundation

public struct ScannedCommand: Equatable, Sendable {
    public let original: String
    public let executable: String
    public let arguments: [String]
    public let ambiguous: Bool
    public let variableBindings: [String: String]

    public init(
        original: String,
        executable: String,
        arguments: [String],
        ambiguous: Bool,
        variableBindings: [String: String] = [:]
    ) {
        self.original = original
        self.executable = executable
        self.arguments = arguments
        self.ambiguous = ambiguous
        self.variableBindings = variableBindings
    }
}

public enum ShellScanner {
    public static func scan(
        _ command: String,
        maxDepth: Int = 3,
        maxBytes: Int = 131_072
    ) -> [ScannedCommand] {
        guard command.utf8.count <= maxBytes else {
            return [ambiguous(command)]
        }
        return scanLevel(command, depth: 0, maxDepth: maxDepth, variableBindings: [:])
    }

    private static func scanLevel(
        _ command: String,
        depth: Int,
        maxDepth: Int,
        variableBindings initialBindings: [String: String]
    ) -> [ScannedCommand] {
        let split = splitSegments(command)
        if split.ambiguous {
            return [ambiguous(command)]
        }

        var scanned: [ScannedCommand] = []
        var variableBindings = initialBindings
        var bindingsReliable = true
        for segment in split.segments {
            if !segment.hasUnconditionalPredecessor {
                bindingsReliable = false
                variableBindings.removeAll()
            }
            let tokenized = tokenize(segment.text)
            guard !tokenized.ambiguous else {
                scanned.append(ambiguous(segment.text))
                continue
            }
            if let assignments = standaloneAssignments(tokenized.tokens) {
                if bindingsReliable {
                    variableBindings.merge(assignments) { _, new in new }
                }
                continue
            }
            var tokens = tokenized.tokens
            stripTransparentPrefixes(&tokens)
            guard let executable = tokens.first else { continue }
            let args = Array(tokens.dropFirst())

            if ["sh", "bash", "zsh"].contains(baseName(executable)),
               let cIndex = args.firstIndex(of: "-c"),
               args.indices.contains(cIndex + 1)
            {
                let nested = args[cIndex + 1]
                guard depth < maxDepth else {
                    scanned.append(ambiguous(nested))
                    continue
                }
                scanned.append(contentsOf: scanLevel(
                    nested,
                    depth: depth + 1,
                    maxDepth: maxDepth,
                    variableBindings: variableBindings
                ))
                continue
            }

            scanned.append(ScannedCommand(
                original: segment.text.trimmingCharacters(in: .whitespacesAndNewlines),
                executable: baseName(executable),
                arguments: args,
                ambiguous: false,
                variableBindings: variableBindings
            ))
        }
        return scanned
    }

    private static func ambiguous(_ original: String) -> ScannedCommand {
        ScannedCommand(original: original, executable: "", arguments: [], ambiguous: true)
    }

    private static func baseName(_ executable: String) -> String {
        URL(fileURLWithPath: executable).lastPathComponent.lowercased()
    }

    private static func standaloneAssignments(_ tokens: [String]) -> [String: String]? {
        guard !tokens.isEmpty else { return nil }
        var assignments: [String: String] = [:]
        for token in tokens {
            guard let assignment = assignment(token) else { return nil }
            assignments[assignment.name] = assignment.value
        }
        return assignments
    }

    private static func assignment(_ token: String) -> (name: String, value: String)? {
        guard let equals = token.firstIndex(of: "=") else { return nil }
        let name = String(token[..<equals])
        guard let first = name.first,
              first == "_" || first.isLetter,
              name.dropFirst().allSatisfy({ $0 == "_" || $0.isLetter || $0.isNumber })
        else { return nil }
        return (name, String(token[token.index(after: equals)...]))
    }

    private static func stripTransparentPrefixes(_ tokens: inout [String]) {
        var changed = true
        while changed, let first = tokens.first {
            changed = false
            switch baseName(first) {
            case "sudo":
                tokens.removeFirst()
                while let next = tokens.first, next.hasPrefix("-") {
                    tokens.removeFirst()
                    if ["-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D"].contains(next), !tokens.isEmpty {
                        tokens.removeFirst()
                    }
                }
                changed = true
            case "env":
                tokens.removeFirst()
                while let next = tokens.first,
                      next.contains("=") || next.hasPrefix("-")
                {
                    tokens.removeFirst()
                }
                changed = true
            case "command", "nohup":
                tokens.removeFirst()
                changed = true
            default:
                while let first = tokens.first,
                      !first.hasPrefix("-") && first.contains("=")
                {
                    tokens.removeFirst()
                    changed = true
                }
            }
        }
    }

    private static func splitSegments(
        _ text: String
    ) -> (segments: [(text: String, hasUnconditionalPredecessor: Bool)], ambiguous: Bool) {
        var segments: [(text: String, hasUnconditionalPredecessor: Bool)] = []
        var current = ""
        var hasUnconditionalPredecessor = true
        var single = false
        var double = false
        var escaped = false
        var executableAmbiguity = false
        let characters = Array(text)
        var index = 0

        while index < characters.count {
            let char = characters[index]
            if escaped {
                current.append(char)
                escaped = false
                index += 1
                continue
            }
            if char == "\\" && !single {
                current.append(char)
                escaped = true
                index += 1
                continue
            }
            if char == "'" && !double {
                single.toggle(); current.append(char); index += 1; continue
            }
            if char == "\"" && !single {
                double.toggle(); current.append(char); index += 1; continue
            }
            if !single && !double {
                let next = index + 1 < characters.count ? characters[index + 1] : "\0"
                if char == ";" || char == "\n" || char == "&" || char == "|" {
                    if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        segments.append((current, hasUnconditionalPredecessor))
                    }
                    current = ""
                    hasUnconditionalPredecessor = char == ";" || char == "\n"
                    index += ((char == "&" || char == "|") && next == char ? 2 : 1)
                    continue
                }
            }
            if !single {
                let next = index + 1 < characters.count ? characters[index + 1] : "\0"
                if char == "`" || (char == "$" && next == "(") {
                    executableAmbiguity = true
                }
            }
            current.append(char)
            index += 1
        }
        if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            segments.append((current, hasUnconditionalPredecessor))
        }
        return (segments, single || double || escaped || executableAmbiguity)
    }

    private static func tokenize(_ text: String) -> (tokens: [String], ambiguous: Bool) {
        var tokens: [String] = []
        var current = ""
        var single = false
        var double = false
        var escaped = false

        for char in text {
            if escaped {
                current.append(char)
                escaped = false
                continue
            }
            if char == "\\" && !single {
                escaped = true
                continue
            }
            if char == "'" && !double { single.toggle(); continue }
            if char == "\"" && !single { double.toggle(); continue }
            if char.isWhitespace && !single && !double {
                if !current.isEmpty { tokens.append(current); current = "" }
                continue
            }
            current.append(char)
        }
        if !current.isEmpty { tokens.append(current) }
        return (tokens, single || double || escaped)
    }
}
