import Foundation

/// `hush doctor` — hunts for the ways secrets leak *around* the encryption:
/// leftover plaintext, git history, backups, and a tamperable install.
enum Doctor {
    @discardableResult
    static func sh(_ command: String) -> (status: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", command]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (127, "") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Run an executable directly (never via `/bin/sh -c`) and capture
    /// stdout+stderr. Use this whenever an argument is a path/filename that
    /// could contain shell metacharacters — interpolating one into a shell
    /// command is a command-injection sink a secrets tool must not have.
    @discardableResult
    static func runTool(_ path: String, _ args: [String]) -> (status: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (127, "") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Whether the binary at `path` is signed with the hardened runtime. Runs
    /// codesign directly so a path with shell metacharacters can't inject.
    static func hardenedRuntimeEnabled(at path: String) -> Bool {
        runTool("/usr/bin/codesign", ["-dv", path]).out.contains("runtime")
    }

    static func run() -> Int32 {
        var problems = 0
        func ok(_ msg: String) { print("  ✓ \(msg)") }
        func bad(_ msg: String, fix: String) { problems += 1; print("  ✗ \(msg)\n    → \(fix)") }
        func warn(_ msg: String) { print("  ⚠ \(msg)") }

        let fm = FileManager.default
        let cwd = fm.currentDirectoryPath

        // 1. Plaintext dotenv files lying around (decoys are fine — they're bait)
        print("plaintext:")
        let entries = (try? fm.contentsOfDirectory(atPath: cwd)) ?? []
        let exampleSuffixes = [".example", ".sample", ".template", ".dist", ".defaults"]
        let plaintextEnvs = entries.filter { name in
            guard name == ".env" || name.hasPrefix(".env.") || name.hasSuffix(".env") else { return false }
            // committed templates aren't secrets — don't flag them
            if exampleSuffixes.contains(where: { name.hasSuffix($0) }) { return false }
            guard let head = fm.contents(atPath: name)?.prefix(7) else { return false }
            return String(decoding: head, as: UTF8.self) != "#!hush " // sealed files are fine
        }
        var realPlain: [String] = []
        for f in plaintextEnvs {
            let content = (try? String(contentsOfFile: f, encoding: .utf8)) ?? ""
            if Decoy.isDecoy(content) { ok("\(f) is a honeytoken decoy (no real secrets)") }
            else { realPlain.append(f) }
        }
        if realPlain.isEmpty {
            ok("no real plaintext .env files in this directory")
        } else {
            for f in realPlain {
                bad("plaintext secrets file: \(f)", fix: "hush lock \(f) --rm — and remember backups/snapshots may hold old copies; rotating the secrets is the only complete fix")
            }
            let snapshots = sh("tmutil listlocalsnapshots / 2>/dev/null | wc -l").out
            if let n = Int(snapshots), n > 0 {
                warn("\(n) local Time Machine snapshot(s) exist — deleted plaintext may persist in them")
            }
        }

        // 2. Location binding of sealed files in this directory
        let sealedHere = entries.filter { name in
            guard let head = fm.contents(atPath: name)?.prefix(7) else { return false }
            return String(decoding: head, as: UTF8.self) == "#!hush "
        }
        if !sealedHere.isEmpty {
            print("binding:")
            for f in sealedHere {
                guard let text = try? String(contentsOfFile: f, encoding: .utf8),
                      let sealed = try? SealedFile.parse(text) else {
                    bad("\(f) is not a parseable hush file", fix: "re-create it with `hush lock`")
                    continue
                }
                if let dir = sealed.directory {
                    if dir == resolvedDir(of: f) {
                        ok("\(f) is bound to this directory")
                    } else {
                        bad("\(f) is bound to \(dir), not here", fix: "if you moved the project, run `hush rebind -f \(f)`")
                    }
                } else {
                    bad("\(f) has no location binding (older format)", fix: "re-create it with `hush lock`")
                }
            }
        }

        // 3. Git exposure
        print("git:")
        if sh("git rev-parse --is-inside-work-tree 2>/dev/null").out == "true" {
            let history = sh("git log --all --format=%h -- .env '.env.*' '*.env' 2>/dev/null | head -1").out
            if history.isEmpty {
                ok("no .env files in git history")
            } else {
                bad("a .env file was committed to git history (first hit: \(history))",
                    fix: "those secrets are in every clone forever — rotate them; scrub history with `git filter-repo` if the repo is shared")
            }
            let tracked = sh("git ls-files -- .env '.env.*' '*.env'").out
            if !tracked.isEmpty {
                bad("plaintext env file is tracked by git right now: \(tracked.split(separator: "\n").joined(separator: ", "))",
                    fix: "git rm --cached <file> — then rotate those secrets")
            }
            // --no-index: ignore rules never apply to tracked files, so ask about the pattern itself
            if sh("git check-ignore -q --no-index .env").status == 0 {
                ok(".env matches an ignore rule (local or global gitignore)")
            } else {
                bad(".env is NOT covered by any gitignore", fix: "echo '.env*' >> .gitignore (keep .hush committable if you want)")
            }
        } else {
            warn("not a git repository — skipping git checks")
        }

        // 3. Identity health
        print("identity:")
        if fm.fileExists(atPath: identityFile.path) {
            let perms = (try? fm.attributesOfItem(atPath: identityFile.path)[.posixPermissions] as? Int) ?? 0
            if perms & 0o077 == 0 {
                ok("Secure Enclave identity present, permissions \(String(perms, radix: 8))")
            } else {
                bad("identity file is group/world readable (\(String(perms, radix: 8)))",
                    fix: "chmod 600 \(identityFile.path) — the blob is enclave-bound, but no reason to share it")
            }
        } else {
            bad("no identity — decryption will fail", fix: "run `hush init`")
        }

        // 4. Deploy-time exposure (the class behind mass .env scanners)
        print("deploy:")
        let publicDirs = ["public", "dist", "build", "static", "www", "htdocs", "out"]
        var exposedFound = false
        for d in publicDirs {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: d, isDirectory: &isDir), isDir.boolValue else { continue }
            let hits = sh("find '\(d)' -maxdepth 4 \\( -name '.env' -o -name '.env.*' -o -name '*.hush' \\) 2>/dev/null").out
            if !hits.isEmpty {
                exposedFound = true
                bad("secrets file inside web-served dir '\(d)/': \(hits.split(separator: "\n").joined(separator: ", "))",
                    fix: "move it out of \(d)/ — files there can be served publicly; this is exactly how mass .env scanners win")
            }
        }
        if !exposedFound { ok("no .env/.hush inside common web-served dirs") }

        if fm.fileExists(atPath: ".env"),
           let perms = try? fm.attributesOfItem(atPath: ".env")[.posixPermissions] as? Int {
            let content = (try? String(contentsOfFile: ".env", encoding: .utf8)) ?? ""
            if perms & 0o044 != 0 && !Decoy.isDecoy(content) {
                bad(".env is readable by group/other (\(String(perms, radix: 8)))", fix: "chmod 600 .env")
            } else {
                ok(".env permissions are \(String(perms, radix: 8))" + (Decoy.isDecoy(content) ? " (decoy — readable is fine)" : ""))
            }
        }

        if fm.fileExists(atPath: "Dockerfile") || fm.fileExists(atPath: "Containerfile") {
            let di = (try? String(contentsOfFile: ".dockerignore", encoding: .utf8)) ?? ""
            if di.split(separator: "\n").contains(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix(".env") }) {
                ok(".dockerignore excludes .env")
            } else {
                bad("Dockerfile present but .dockerignore doesn't exclude .env",
                    fix: "echo '.env*' >> .dockerignore so plaintext secrets don't bake into the image")
            }
        }

        // 5. Install tamper-resistance
        print("install:")
        let selfPath = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let resolved = sh("command -v hush").out
        if !resolved.isEmpty, (resolved as NSString).resolvingSymlinksInPath != (selfPath as NSString).resolvingSymlinksInPath {
            warn("`hush` on PATH (\(resolved)) is not this binary (\(selfPath)) — possible shim, or you're running a dev build")
        }
        if fm.isWritableFile(atPath: selfPath) {
            warn("binary is writable by your user — malware running as you could replace it; for max paranoia: sudo make install PREFIX=/usr/local && sudo chown root:wheel /usr/local/bin/hush")
        } else {
            ok("binary is not writable by your user")
        }
        if hardenedRuntimeEnabled(at: selfPath) {
            ok("hardened runtime enabled (DYLD injection blocked)")
        } else {
            bad("hardened runtime not enabled on this binary", fix: "rebuild with `make install` (signs with -o runtime)")
        }

        print(problems == 0 ? "\nall clear" : "\n\(problems) problem(s) found")
        return problems == 0 ? 0 : 1
    }
}
