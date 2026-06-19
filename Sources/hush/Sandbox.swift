import Foundation

/// Containment for `hush run --sandbox`: wrap the launched command in a macOS
/// Seatbelt profile (via `/usr/bin/sandbox-exec`) so a prompt-injected agent or a
/// malicious dependency can't write a persistent backdoor (`~/.ssh`), rewrite
/// credentials for lateral movement (`~/.aws`, `~/.kube`), drop a LaunchAgent, or
/// edit your shell rc — even after it has whatever secrets you injected.
///
/// Honest scope: this is write-containment (plus optional network gating), not an
/// unescapable jail. `sandbox-exec` is officially deprecated by Apple (still
/// present and widely used) and a kernel-level escape would defeat it; it does
/// not stop the process from *reading* what it can reach or exfiltrating over an
/// allowed network. It raises the cost of the persistence/lateral-movement half
/// of an attack, which is the half the other hush layers don't cover.
enum Sandbox {
    static let sandboxExec = "/usr/bin/sandbox-exec"
    static func available() -> Bool { FileManager.default.isExecutableFile(atPath: sandboxExec) }

    enum Level: String { case guarded = "guard", strict = "strict" }

    /// Directories whose WRITE is the persistence / lateral-movement target.
    /// Denied in `guard`, and (being outside the project) already denied in `strict`.
    static func sensitiveWriteDirs(home: String) -> [String] {
        ["\(home)/.ssh", "\(home)/.aws", "\(home)/.kube", "\(home)/.gnupg",
         "\(home)/.docker", "\(home)/.config/gcloud", "\(home)/.config/systemd",
         "\(home)/.hush", "\(home)/Library/LaunchAgents",
         "/Library/LaunchAgents", "/Library/LaunchDaemons", "/etc", "/private/etc"]
    }
    static func sensitiveWriteFiles(home: String) -> [String] {
        ["\(home)/.netrc", "\(home)/.npmrc", "\(home)/.pypirc", "\(home)/.gitconfig",
         "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv",
         "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile"]
    }

    /// Writable roots a deny-default (`strict`) profile must still permit so common
    /// agent tooling functions: the project, system temp, and tool caches/state.
    static func defaultWritableDirs(projectDir: String, home: String) -> [String] {
        [projectDir, "/private/tmp", "/private/var/folders",
         "\(home)/Library/Caches", "\(home)/.npm", "\(home)/.cache",
         "\(home)/.claude", "\(home)/.cursor", "\(home)/.config"]
    }

    /// SBPL string literal: double-quoted, with backslash and quote escaped.
    static func quote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func profile(projectDir: String, home: String, level: Level,
                        extraWritable: [String], allowNetwork: Bool) -> String {
        func dirs(_ ps: [String]) -> String { ps.map { "(subpath \(quote($0)))" }.joined(separator: " ") }
        func files(_ ps: [String]) -> String { ps.map { "(literal \(quote($0)))" }.joined(separator: " ") }
        var lines = ["(version 1)"]
        switch level {
        case .guarded:
            // Allow by default (so the tool just works), deny writes to the
            // sensitive set. Matches the stated goal: no backdoor to ~/.ssh, no
            // rewrite of ~/.aws/credentials, no LaunchAgent persistence.
            lines.append("(allow default)")
            lines.append("(deny file-write* \(dirs(sensitiveWriteDirs(home: home))) \(files(sensitiveWriteFiles(home: home))))")
            if !allowNetwork { lines.append("(deny network*)") }
        case .strict:
            // Deny by default; permit reads + exec, and writes only under the
            // project, temp, and tool caches (plus any --sandbox-allow paths).
            lines.append("(deny default)")
            lines.append("(allow process-exec*)")
            lines.append("(allow process-fork)")
            lines.append("(allow signal (target self))")
            lines.append("(allow sysctl-read)")
            lines.append("(allow mach-lookup)")
            lines.append("(allow iokit-open)")
            lines.append("(allow file-read*)")
            let writable = defaultWritableDirs(projectDir: projectDir, home: home) + extraWritable
            let devs = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
                        "/dev/tty", "/dev/dtracehelper", "/dev/stdout", "/dev/stderr"]
            lines.append("(allow file-write* \(dirs(writable)) \(files(devs)))")
            if allowNetwork { lines.append("(allow network*)") }
        }
        return lines.joined(separator: "\n")
    }

    /// argv that runs `exePath args...` under `sandbox-exec` with `profile` passed
    /// inline (`-p`), so there's no temp profile file to race on or clean up.
    static func wrap(exePath: String, args: [String], profile: String) -> (exe: String, argv: [String]) {
        (sandboxExec, ["sandbox-exec", "-p", profile, exePath] + args)
    }
}
