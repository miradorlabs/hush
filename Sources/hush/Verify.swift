import CryptoKit
import Foundation

/// `hush verify-assistant` — a supply-chain check for the AI tools you let read
/// your project (Claude Code, Cursor, VS Code/Copilot, …) before you trust them
/// with secrets.
///
/// What it checks, and what it can't: for signed apps it runs codesign + Gatekeeper
/// and pins the signer identity (Team ID + leaf authority) trust-on-first-use, so a
/// later swap to a different signer or to an unsigned build is caught — tamper-
/// evident, like hush's identity-key pin. For JS-based CLIs (Claude Code, Copilot)
/// there is no binary signature, so it pins a content hash of the resolved
/// entrypoint instead (a legit update changes it; re-pin with `--repin`). It also
/// scans your shell and AI-tool config for injection red flags. There is no
/// authoritative remote manifest to diff against, so "known-good" means "what you
/// pinned on a machine you trust the first time"; a root attacker who rewrites both
/// the tool and the pin defeats it.
enum AssistantVerify {
    static let pinFile = identityDir.appendingPathComponent("assistants.json")
    static let knownNames = ["claude", "cursor", "code", "claude-desktop", "copilot", "windsurf"]

    struct Report {
        let target: String
        var checks: [(name: String, ok: Bool, detail: String)]
        var ok: Bool { checks.allSatisfy { $0.ok } }
    }

    // MARK: - resolution

    static func candidatePaths(for name: String) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        switch name.lowercased() {
        case "cursor": return ["/Applications/Cursor.app"]
        case "code", "vscode": return ["/Applications/Visual Studio Code.app", "\(home)/Applications/Visual Studio Code.app"]
        case "claude-desktop": return ["/Applications/Claude.app"]
        case "windsurf": return ["/Applications/Windsurf.app"]
        case "claude", "claude-code": return [which("claude")].compactMap { $0 }
        case "copilot": return [which("copilot")].compactMap { $0 }
        default: return []
        }
    }

    static func which(_ cmd: String) -> String? {
        let r = Doctor.runTool("/usr/bin/which", [cmd])
        guard r.status == 0 else { return nil }
        let p = r.out.split(separator: "\n").first.map(String.init)
        return (p != nil && FileManager.default.fileExists(atPath: p!)) ? p : nil
    }

    // MARK: - signature

    struct Signature { var valid: Bool; var teamID: String?; var authority: String? }

    /// codesign run directly (never via a shell), so a path with metacharacters
    /// can't inject. `-dvvv` writes the identity to stderr, which runTool captures.
    static func codesign(_ path: String) -> Signature {
        let valid = Doctor.runTool("/usr/bin/codesign", ["--verify", "--strict", "--deep", path]).status == 0
        let info = Doctor.runTool("/usr/bin/codesign", ["-dvvv", path]).out
        var team: String?, authority: String?
        for line in info.split(separator: "\n") {
            if line.hasPrefix("TeamIdentifier=") { team = String(line.dropFirst("TeamIdentifier=".count)) }
            // The first Authority line is the leaf (signing) certificate.
            if authority == nil, line.hasPrefix("Authority=") { authority = String(line.dropFirst("Authority=".count)) }
        }
        if team == "not set" { team = nil }
        return Signature(valid: valid, teamID: team, authority: authority)
    }

    static func gatekeeperAccepts(_ path: String) -> Bool {
        Doctor.runTool("/usr/sbin/spctl", ["--assess", "--type", "execute", path]).status == 0
    }

    static func sha256OfEntrypoint(_ path: String) -> String? {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: resolved)) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - trust-on-first-use pin

    static func loadPins() -> [String: String] {
        guard let data = try? Data(contentsOf: pinFile),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return [:] }
        return obj
    }
    static func savePins(_ pins: [String: String]) {
        try? FileManager.default.createDirectory(at: identityDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        if let data = try? JSONSerialization.data(withJSONObject: pins, options: [.sortedKeys, .prettyPrinted]) {
            try? data.write(to: pinFile, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pinFile.path)
        }
    }

    enum PinResult: Equatable { case pinned, matches, changed(old: String) }

    /// Pure pin comparison (no IO) — the testable core.
    static func comparePin(stored: String?, current: String) -> PinResult {
        guard let stored else { return .pinned }
        return stored == current ? .matches : .changed(old: stored)
    }

    private static func pinCheck(path: String, fingerprint: String, repin: Bool) -> (String, Bool, String) {
        var pins = loadPins()
        let key = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if repin {
            pins[key] = fingerprint; savePins(pins)
            return ("trust-pin", true, "re-pinned")
        }
        switch comparePin(stored: pins[key], current: fingerprint) {
        case .pinned:
            pins[key] = fingerprint; savePins(pins)
            return ("trust-pin", true, "pinned (trust-on-first-use)")
        case .matches:
            return ("trust-pin", true, "matches the pinned identity")
        case .changed(let old):
            AuditLog.record(.denyForgery, action: "verify-assistant \(path)", detail: "identity changed since pinned")
            return ("trust-pin", false, "CHANGED since pinned (was \(old)) — re-run with --repin only if you updated it on purpose")
        }
    }

    // MARK: - config-injection scan

    struct Finding { let location: String; let issue: String }

    /// Pure red-flag scan of a config/rc file's text — the testable core. Heuristic
    /// by nature: it flags the common persistence/injection shapes, not every one.
    static func scanText(name: String, _ content: String) -> [Finding] {
        let envHooks: [(String, String)] = [
            ("PYTHONSTARTUP", "PYTHONSTARTUP set — runs code on every Python start"),
            ("BASH_ENV", "BASH_ENV set — runs a script on every non-interactive bash"),
            ("DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES — dylib injection"),
            ("LD_PRELOAD", "LD_PRELOAD — library injection"),
            ("PROMPT_COMMAND", "PROMPT_COMMAND hook — runs on every shell prompt"),
        ]
        var findings: [Finding] = []
        for (i, raw) in content.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("//") { continue }
            let loc = "\(name):\(i + 1)"
            for (needle, issue) in envHooks where line.contains(needle) {
                findings.append(Finding(location: loc, issue: issue))
            }
            if line.contains("NODE_OPTIONS"), line.contains("--require") || line.contains("-r ") {
                findings.append(Finding(location: loc, issue: "NODE_OPTIONS --require — code injected into every node process"))
            }
            let pipedToShell = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"].contains { line.contains($0) }
            if (line.contains("curl") || line.contains("wget")) && pipedToShell {
                findings.append(Finding(location: loc, issue: "remote script piped into a shell"))
            }
            if line.contains("eval") && (line.contains("curl") || line.contains("wget")) {
                findings.append(Finding(location: loc, issue: "eval of remotely-fetched content"))
            }
            if line.contains("base64") && pipedToShell {
                findings.append(Finding(location: loc, issue: "base64-decoded payload piped into a shell"))
            }
            // An AI-tool hook/MCP entry whose command spawns a raw shell.
            if line.contains("\"command\""), ["\"sh\"", "\"bash\"", "\"zsh\"", "/bin/sh", "/bin/bash"].contains(where: line.contains) {
                findings.append(Finding(location: loc, issue: "config command spawns a raw shell"))
            }
        }
        return findings
    }

    static func scanConfig(home: String, projectDir: String) -> [Finding] {
        let files = [
            "\(home)/.zshrc", "\(home)/.zprofile", "\(home)/.zshenv",
            "\(home)/.bashrc", "\(home)/.bash_profile", "\(home)/.profile",
            "\(home)/.claude.json", "\(home)/.claude/settings.json",
            "\(projectDir)/.claude/settings.json", "\(projectDir)/.mcp.json",
            "\(home)/.cursor/mcp.json",
        ]
        var findings: [Finding] = []
        for f in files {
            guard let text = try? String(contentsOfFile: f, encoding: .utf8) else { continue }
            findings += scanText(name: (f as NSString).abbreviatingWithTildeInPath, text)
        }
        return findings
    }

    // MARK: - orchestration

    static func verify(nameOrPath: String, repin: Bool) -> Report {
        let path = FileManager.default.fileExists(atPath: nameOrPath)
            ? nameOrPath
            : candidatePaths(for: nameOrPath).first(where: { FileManager.default.fileExists(atPath: $0) })
        guard let path else {
            return Report(target: nameOrPath, checks: [("install", false, "not found in known locations")])
        }
        var checks: [(String, Bool, String)] = [("install", true, path)]
        let sig = codesign(path)
        if sig.valid {
            checks.append(("codesign", true, "valid signature" + (sig.teamID.map { " (Team \($0))" } ?? "")))
            // Gatekeeper/notarization is only a meaningful pass/fail for .app
            // bundles; `spctl --assess --type execute` rejects validly-signed bare
            // CLI binaries (claude, /bin/ls), so reporting it for those is noise.
            if path.hasSuffix(".app") {
                let gk = gatekeeperAccepts(path)
                checks.append(("gatekeeper", gk, gk ? "accepted (notarized / allowed)" : "NOT accepted by Gatekeeper"))
            }
            checks.append(pinCheck(path: path, fingerprint: "sig:team=\(sig.teamID ?? "-")|auth=\(sig.authority ?? "-")", repin: repin))
        } else if let hash = sha256OfEntrypoint(path) {
            // No code signature is expected for a JS CLI; pin its content instead.
            checks.append(("codesign", true, "unsigned entrypoint (JS tool) — pinning content hash"))
            checks.append(pinCheck(path: path, fingerprint: "hash:\(hash)", repin: repin))
        } else {
            checks.append(("codesign", false, "no valid signature and the entrypoint couldn't be hashed"))
        }
        return Report(target: "\(nameOrPath) → \(path)", checks: checks)
    }
}
