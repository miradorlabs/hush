import Darwin
import Foundation

/// Resolves `hush run`'s target to an absolute executable, refusing the setups
/// a middleman uses to interpose itself between hush and your app: a relative
/// or cwd-local command, a binary reached through a group/world-writable PATH
/// directory, or a binary another user can overwrite. Without this, a malicious
/// `./npm` or a shim in a writable PATH dir would receive the secrets right
/// after your legitimate approval.
enum CommandResolver {
    struct Resolution {
        var path: String
        var warnings: [String]
    }

    private static func writableByOthers(_ path: String) -> Bool {
        guard let perms = try? FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int else { return false }
        return perms & 0o022 != 0 // group-write or other-write
    }

    /// Returns the absolute path or a fatal reason. `allowUnsafe` downgrades the
    /// fatal cases to warnings.
    static func resolve(_ command: String, allowUnsafe: Bool) -> (resolution: Resolution?, fatal: String?) {
        let fm = FileManager.default
        var warnings: [String] = []

        func finish(_ path: String) -> (Resolution?, String?) {
            let dir = (path as NSString).deletingLastPathComponent
            if writableByOthers(path) { warnings.append("\(path) is group/world-writable — another user could replace it") }
            if writableByOthers(dir) { warnings.append("\(dir) is group/world-writable — a binary there can be swapped") }
            return (Resolution(path: path, warnings: warnings), nil)
        }

        // Explicit path (has a slash)
        if command.contains("/") {
            if !command.hasPrefix("/") && !allowUnsafe {
                return (nil, "refusing a relative command path '\(command)' — it can resolve into an attacker-writable location. use an absolute path, a bare name, or --allow-unsafe-path")
            }
            let abs = command.hasPrefix("/") ? command
                : (fm.currentDirectoryPath as NSString).appendingPathComponent(command)
            guard fm.isExecutableFile(atPath: abs) else { return (nil, "not an executable: \(command)") }
            return finish(abs)
        }

        // Bare name → walk PATH, skipping unsafe entries
        let dirs = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        for dir in dirs {
            if dir.isEmpty || dir == "." || !dir.hasPrefix("/") {
                warnings.append("PATH entry '\(dir.isEmpty ? "(empty = cwd)" : dir)' is unsafe — skipped")
                continue
            }
            let candidate = (dir as NSString).appendingPathComponent(command)
            guard fm.isExecutableFile(atPath: candidate) else { continue }
            if writableByOthers(dir) && !allowUnsafe {
                return (nil, "'\(command)' resolves via '\(dir)', which is group/world-writable — a classic interposition setup. fix its permissions, use an absolute path, or --allow-unsafe-path")
            }
            return finish(candidate)
        }
        return (nil, "command not found in a safe PATH directory: \(command)")
    }
}

/// Best-effort description of the process that invoked hush, surfaced in the
/// auth prompt and the log. A decrypt triggered by something other than your
/// shell (an editor, an agent, a stray script) is then visible *before* you
/// approve — the only userland defense against an approval-riding deputy.
func parentContext() -> String {
    let ppid = getppid()
    var buf = [CChar](repeating: 0, count: 4096)
    let n = proc_pidpath(ppid, &buf, UInt32(buf.count))
    if n > 0 {
        let name = (String(cString: buf) as NSString).lastPathComponent
        return "\(name) [pid \(ppid)]"
    }
    return "pid \(ppid)"
}
