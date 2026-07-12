import Foundation

public struct ScannedCommand: Equatable, Sendable {
    public let original: String
    public let executable: String
    public let arguments: [String]
    public let ambiguous: Bool

    public init(original: String, executable: String, arguments: [String], ambiguous: Bool) {
        self.original = original
        self.executable = executable
        self.arguments = arguments
        self.ambiguous = ambiguous
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
        return scanLevel(command, depth: 0, maxDepth: maxDepth)
    }

    private static func scanLevel(_ command: String, depth: Int, maxDepth: Int) -> [ScannedCommand] {
        let split = splitSegments(command)
        if split.ambiguous {
            return [ambiguous(command)]
        }

        return split.segments.flatMap { segment -> [ScannedCommand] in
            let tokenized = tokenize(segment)
            guard !tokenized.ambiguous else { return [ambiguous(segment)] }
            var tokens = tokenized.tokens
            stripTransparentPrefixes(&tokens)
            guard let executable = tokens.first else { return [] }
            let args = Array(tokens.dropFirst())

            if ["sh", "bash", "zsh"].contains(baseName(executable)),
               let cIndex = args.firstIndex(of: "-c"),
               args.indices.contains(cIndex + 1)
            {
                let nested = args[cIndex + 1]
                guard depth < maxDepth else { return [ambiguous(nested)] }
                return scanLevel(nested, depth: depth + 1, maxDepth: maxDepth)
            }

            return [ScannedCommand(
                original: segment.trimmingCharacters(in: .whitespacesAndNewlines),
                executable: baseName(executable),
                arguments: args,
                ambiguous: false
            )]
        }
    }

    private static func ambiguous(_ original: String) -> ScannedCommand {
        ScannedCommand(original: original, executable: "", arguments: [], ambiguous: true)
    }

    private static func baseName(_ executable: String) -> String {
        URL(fileURLWithPath: executable).lastPathComponent.lowercased()
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

    private static func splitSegments(_ text: String) -> (segments: [String], ambiguous: Bool) {
        var segments: [String] = []
        var current = ""
        var single = false
        var double = false
        var escaped = false
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
                if char == ";" || (char == "&" && next == "&") || (char == "|" && next == "|") {
                    if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        segments.append(current)
                    }
                    current = ""
                    index += (char == ";" ? 1 : 2)
                    continue
                }
            }
            current.append(char)
            index += 1
        }
        if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            segments.append(current)
        }
        return (segments, single || double || escaped)
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
