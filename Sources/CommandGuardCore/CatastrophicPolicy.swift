import Foundation

public enum PolicyDecision: Equatable, CustomStringConvertible, Sendable {
    case allowed
    case denied(ruleID: String, reason: String)

    public var description: String {
        switch self {
        case .allowed: "allowed"
        case .denied(let ruleID, _): "denied(\(ruleID))"
        }
    }
}

public enum CatastrophicPolicy {
    private static let catastrophicMarkers = [
        "rm", "reset", "clean", "destroy", "drop", "truncate", "erase",
        "mkfs", "shred", "/dev/", "--force", "--mirror", "shutdown",
        "reboot", "halt", "poweroff", "prune", "--delete",
    ]

    public static func evaluate(command: String, cwd: URL) -> PolicyDecision {
        let scanned = ShellScanner.scan(command)
        for item in scanned {
            if item.ambiguous {
                let lower = item.original.lowercased()
                if catastrophicMarkers.contains(where: lower.contains) {
                    return deny("parser.ambiguous-catastrophic", "Ambiguous command contains a catastrophic marker")
                }
                continue
            }
            if let decision = evaluate(item, cwd: cwd) { return decision }
        }
        return .allowed
    }

    private static func evaluate(_ item: ScannedCommand, cwd: URL) -> PolicyDecision? {
        switch item.executable {
        case "rm": return evaluateRM(item.arguments, cwd: cwd)
        case "git": return evaluateGit(item.arguments)
        case "dd": return item.arguments.contains(where: { $0.lowercased().hasPrefix("of=/dev/") })
            ? deny("device.raw-write", "Raw-device output is destructive") : nil
        case "diskutil": return item.arguments.first.map { ["erasedisk", "erasevolume", "partitiondisk", "secureerase"].contains($0.lowercased()) } == true
            ? deny("device.diskutil-erase", "Disk erase or partition operation") : nil
        case let executable where executable.hasPrefix("mkfs"):
            return item.arguments.contains(where: isDevicePath) ? deny("device.mkfs", "Filesystem creation on a device") : nil
        case "shred": return item.arguments.contains(where: isDevicePath)
            ? deny("device.shred", "Device shredding operation") : nil
        case "shutdown", "reboot", "halt", "poweroff":
            return deny("system.power", "System power operation")
        case "docker": return evaluateDocker(item.arguments)
        case "terraform", "tofu": return evaluateTerraform(item.arguments)
        case "kubectl": return evaluateKubectl(item.arguments)
        case "psql", "mysql", "mariadb", "sqlite3": return evaluateDatabase(item.arguments)
        case "aws": return evaluateAWS(item.arguments)
        case "gsutil": return evaluateGSUtil(item.arguments)
        case "rclone": return evaluateRclone(item.arguments)
        case "rsync": return evaluateRsync(item.arguments)
        default: return nil
        }
    }

    private static func evaluateRM(_ args: [String], cwd: URL) -> PolicyDecision? {
        let flags = args.filter { $0.hasPrefix("-") }.joined().lowercased()
        guard flags.contains("r") && flags.contains("f") else { return nil }
        let targets = args.filter { !$0.hasPrefix("-") }
        for target in targets where isBroadDeletionTarget(target, cwd: cwd) {
            return deny("filesystem.rm-broad", "Broad recursive deletion target: \(target)")
        }
        return nil
    }

    private static func isBroadDeletionTarget(_ target: String, cwd: URL) -> Bool {
        let expanded = target == "~" || target.hasPrefix("~/")
            ? NSHomeDirectory() + String(target.dropFirst())
            : target
        let literal = expanded.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if ["", ".", "..", "*", "Users"].contains(literal) { return true }
        if expanded == NSHomeDirectory() || expanded == NSHomeDirectory() + "/" { return true }
        if expanded == cwd.path || expanded == cwd.path + "/" { return true }
        if expanded.contains("/*") || expanded.contains("/.*") { return true }
        return false
    }

    private static func evaluateGit(_ original: [String]) -> PolicyDecision? {
        let args = stripGitGlobalOptions(original)
        guard let subcommand = args.first else { return nil }
        let rest = Array(args.dropFirst())
        switch subcommand.lowercased() {
        case "reset":
            return rest.contains("--hard") ? deny("git.reset-hard", "Hard reset discards working-tree changes") : nil
        case "clean":
            let flags = rest.filter { $0.hasPrefix("-") }.joined().lowercased()
            let dryRun = flags.contains("n") || rest.contains("--dry-run")
            let forced = flags.contains("f") || rest.contains("--force")
            let broad = flags.contains("d") || flags.contains("x") || flags.contains("X")
            return forced && broad && !dryRun ? deny("git.clean-force", "Forced broad Git clean") : nil
        case "checkout":
            return rest.contains("--") && rest.last == "." ? deny("git.restore-worktree", "Whole-worktree checkout discards changes") : nil
        case "restore":
            return rest.last == "." ? deny("git.restore-worktree", "Whole-worktree restore discards changes") : nil
        case "push": return evaluateGitPush(rest)
        default: return nil
        }
    }

    private static func stripGitGlobalOptions(_ args: [String]) -> [String] {
        var result = args
        while let first = result.first, first.hasPrefix("-") {
            result.removeFirst()
            if ["-C", "-c", "--git-dir", "--work-tree", "--namespace"].contains(first), !result.isEmpty {
                result.removeFirst()
            }
        }
        return result
    }

    private static func evaluateGitPush(_ args: [String]) -> PolicyDecision? {
        if args.contains("--mirror") || args.contains("--all") {
            return deny("git.force-protected", "Mirror or all-ref push has broad impact")
        }
        let forced = args.contains("--force") || args.contains("-f") || args.contains("--force-with-lease")
        guard forced else { return nil }
        let protected = args.contains { arg in
            let lower = arg.lowercased()
            return ["main", "master", "dev", "develop"].contains(lower)
                || lower.hasPrefix("release/") || lower.hasPrefix("refs/heads/release/")
        }
        return protected ? deny("git.force-protected", "Force push targets a protected branch") : nil
    }

    private static func evaluateDocker(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        return lower.starts(with: ["system", "prune"]) && lower.contains(where: { $0 == "--volumes" })
            ? deny("docker.prune-volumes", "Docker system prune includes volumes") : nil
    }

    private static func evaluateTerraform(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        if lower.first == "destroy" { return deny("terraform.destroy", "Terraform destroy") }
        if lower.first == "plan" && lower.contains("-destroy") {
            return deny("terraform.destroy-plan", "Terraform destroy plan creation")
        }
        return nil
    }

    private static func evaluateKubectl(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        guard let deleteIndex = lower.firstIndex(of: "delete") else { return nil }
        let tail = Array(lower.dropFirst(deleteIndex + 1))
        let clusterKinds = ["namespace", "namespaces", "ns", "crd", "crds", "customresourcedefinition", "customresourcedefinitions", "clusterrole", "clusterroles", "clusterrolebinding", "clusterrolebindings"]
        if tail.contains(where: clusterKinds.contains) || tail.contains("--all") || tail.contains("-a") {
            return deny("kubernetes.mass-delete", "Mass or cluster-scoped Kubernetes deletion")
        }
        return nil
    }

    private static func evaluateDatabase(_ args: [String]) -> PolicyDecision? {
        let sql = args.joined(separator: " ").uppercased()
        if sql.contains("DROP DATABASE") || sql.contains("DROP SCHEMA") {
            return deny("database.drop", "Database or schema drop")
        }
        if sql.contains("TRUNCATE ") {
            return deny("database.truncate", "Table truncation")
        }
        return nil
    }

    private static func evaluateAWS(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        return lower.starts(with: ["s3", "rm"]) && lower.contains("--recursive")
            ? deny("cloud.recursive-delete", "Recursive cloud object deletion") : nil
    }

    private static func evaluateGSUtil(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        return lower.contains("rm") && (lower.contains("-r") || lower.contains("-R".lowercased()))
            ? deny("cloud.recursive-delete", "Recursive cloud object deletion") : nil
    }

    private static func evaluateRclone(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        return lower.first == "sync" && lower.contains(where: { $0.hasPrefix("--delete-") })
            ? deny("cloud.sync-delete", "Cloud sync deletes destination objects") : nil
    }

    private static func evaluateRsync(_ args: [String]) -> PolicyDecision? {
        let lower = args.map { $0.lowercased() }
        guard lower.contains("--delete") || lower.contains(where: { $0.hasPrefix("--delete-") }) else { return nil }
        guard let destination = args.last else { return nil }
        let broad = destination == "/" || destination == NSHomeDirectory() || destination.hasPrefix("/Users/")
        return broad ? deny("filesystem.sync-delete", "Delete-sync targets a broad local path") : nil
    }

    private static func isDevicePath(_ value: String) -> Bool {
        value.lowercased().hasPrefix("/dev/")
    }

    private static func deny(_ ruleID: String, _ reason: String) -> PolicyDecision {
        .denied(ruleID: ruleID, reason: reason)
    }
}
