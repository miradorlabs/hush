import Darwin
import Foundation

let defaultSecretsFile = ".hush"
let identityDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hush", isDirectory: true)
let identityFile = identityDir.appendingPathComponent("identity.json")

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("hush: \(message)\n".utf8))
    exit(1)
}

func note(_ message: String) {
    print("hush: \(message)")
}

// MARK: - Identity persistence

func loadIdentityRaw() -> HushCrypto.Identity {
    guard let data = try? Data(contentsOf: identityFile),
          let identity = try? JSONDecoder().decode(HushCrypto.Identity.self, from: data) else {
        fail("no identity found — run `hush init` first")
    }
    // Transparently add a signing key to pre-v2 identities (no auth needed).
    // try? flattens Identity?? → nil means either "no upgrade needed" or an
    // error; both correctly fall through to returning the identity as-is.
    if let upgraded = try? HushCrypto.upgraded(identity) {
        do {
            try saveIdentity(upgraded)
            note("upgraded identity with a Secure Enclave signing key (locking now requires Touch ID)")
        } catch { fail("could not upgrade identity: \(error)") }
        return upgraded
    }
    return identity
}

func loadIdentity() -> HushCrypto.Identity {
    let identity = loadIdentityRaw()
    // Pin the public-key fingerprint in the Keychain and verify it every load,
    // so a swapped key in identity.json (a MITM on your key material) is caught.
    let fp = Trust.fingerprint(identity)
    switch Trust.pinStatus(fp) {
    case .missing: Trust.writePin(fp) // trust on first use
    case .matches: break
    case .mismatch:
        AuditLog.record(.denyForgery, action: "identity check", detail: "fingerprint \(fp) ≠ pinned key")
        fail("""
        identity fingerprint changed — the public key in identity.json does not
        match the one pinned in your Keychain. if you did not re-init hush, this
        is tampering (a possible man-in-the-middle on your key).
          current: \(fp)
        to accept the new key on purpose: `hush fingerprint --repin`
        """)
    }
    return identity
}

func saveIdentity(_ identity: HushCrypto.Identity) throws {
    try FileManager.default.createDirectory(at: identityDir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let data = try JSONEncoder().encode(identity)
    try data.write(to: identityFile, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: identityFile.path)
}

// MARK: - Sealed file helpers

func loadSealed(_ path: String) -> SealedFile {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        fail("cannot read \(path)" + (path == defaultSecretsFile ? " — run `hush lock` to create it from .env" : ""))
    }
    do { return try SealedFile.parse(text) } catch { fail("\(path): \(error)") }
}

/// Overwrite every file in `dir` then remove it. The overwrite is best-effort:
/// on an SSD with wear-leveling / copy-on-write APFS it does NOT guarantee the
/// old bytes are gone — the real protection is the 0700 directory (other users
/// can't read it) and prompt removal. We rely on FileVault + secret rotation
/// for anything stronger.
func shredDirectory(_ dir: URL) {
    let fm = FileManager.default
    if let files = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey]) {
        for f in files {
            if let size = try? fm.attributesOfItem(atPath: f.path)[.size] as? Int, size > 0 {
                try? Data(count: size).write(to: f)
            }
        }
    }
    try? fm.removeItem(at: dir)
}

/// Absolute, fully-canonicalized directory containing `path`. Uses realpath(3)
/// so symlink firmlinks like /var → /private/var resolve consistently no matter
/// how the directory was reached — otherwise the same project bound two ways
/// could fail its own location check.
func resolvedDir(of path: String) -> String {
    let dir = URL(fileURLWithPath: path).standardizedFileURL.deletingLastPathComponent().path
    var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
    if realpath(dir, &buf) != nil { return String(cString: buf) }
    // Directory doesn't exist yet (e.g. locking to a new path) — best effort.
    return URL(fileURLWithPath: dir).resolvingSymlinksInPath().path
}

func decryptSecrets(_ path: String, action: String) -> Data {
    let sealed = loadSealed(path)
    guard let boundDir = sealed.directory else {
        fail("\(path) has no location binding (older format) — re-create it with `hush lock`")
    }
    let actualDir = resolvedDir(of: path)
    if actualDir != boundDir {
        AuditLog.record(.denyLocation, action: action, detail: "bound=\(boundDir) accessed=\(actualDir)")
        fail("""
        location check failed — refusing to decrypt
          bound to:    \(boundDir)
          accessed at: \(actualDir)
        if you moved this project on purpose, run `hush rebind` inside it
        """)
    }
    let identity = loadIdentity()
    // Reject forgeries before prompting: a file not signed by your enclave key
    // never gets to the decrypt step.
    guard HushCrypto.verify(sealed, identity: identity) else {
        AuditLog.record(.denyForgery, action: action, detail: boundDir)
        fail("""
        signature check failed — refusing to decrypt \(path)
        this file was not sealed by this Mac's hush key (possible forgery or tampering).
        if it's an older unsigned file, re-create it with `hush lock`.
        """)
    }
    let requester = parentContext()
    do {
        let plaintext = try HushCrypto.open(sealed, identity: identity,
                                            reason: "\(action) in \(boundDir) — requested by \(requester)")
        // Register values before logging so no secret can land in a log/alert.
        SecretScrub.register(DotEnv.parse(String(decoding: plaintext, as: UTF8.self)).map { $0.value })
        AuditLog.record(.ok, action: action, detail: "\(boundDir) (by \(requester))")
        return plaintext
    } catch {
        AuditLog.record(.denyAuth, action: action, detail: "\(boundDir) (by \(requester)): \(error)")
        fail("\(error)")
    }
}

// MARK: - Commands

func cmdInit(args: [String]) {
    let biometryOnly = args.contains("--biometry-only")
    guard HushCrypto.secureEnclaveAvailable() else {
        fail("Secure Enclave not available on this machine")
    }
    if FileManager.default.fileExists(atPath: identityFile.path) {
        fail("identity already exists at \(identityFile.path) — delete it to re-init (existing .hush files will become unreadable)")
    }
    var created: HushCrypto.Identity!
    do {
        created = try HushCrypto.createIdentity(biometryOnly: biometryOnly)
        try saveIdentity(created)
    } catch { fail("\(error)") }
    Trust.writePin(Trust.fingerprint(created)) // pin the new key (overwrites any stale pin)
    note("created Secure Enclave identity at \(identityFile.path)")
    note("fingerprint: \(Trust.fingerprint(created))")
    if biometryOnly {
        note("decryption requires a currently-enrolled fingerprint — the account password CANNOT approve")
        note("warning: changing fingerprint enrollment, or a broken sensor, permanently locks existing .hush files")
    } else {
        note("decryption now requires Touch ID or your account password on this Mac")
    }
    note("next: `hush lock` in a project with a .env file")
}

func cmdLock(args: [String]) {
    var input = ".env"
    var output: String?
    var removePlaintext = false
    var leaveDecoy = false
    var it = args.makeIterator()
    while let arg = it.next() {
        switch arg {
        case "-o", "--output": output = it.next()
        case "--rm": removePlaintext = true
        case "--decoy": leaveDecoy = true; removePlaintext = true
        default: input = arg
        }
    }
    let out = output ?? (input.hasSuffix(".env") || (input as NSString).lastPathComponent == ".env"
        ? (input as NSString).deletingLastPathComponent.isEmpty ? defaultSecretsFile
            : (input as NSString).deletingLastPathComponent + "/" + defaultSecretsFile
        : input + ".hush")

    guard let plaintext = FileManager.default.contents(atPath: input) else {
        fail("cannot read \(input)")
    }
    let identity = loadIdentity()
    let boundDir = resolvedDir(of: out)
    do {
        let sealed = try HushCrypto.seal(plaintext, identity: identity, directory: boundDir,
                                         reason: "seal secrets for \(boundDir)")
        try sealed.serialize().write(toFile: out, atomically: true, encoding: .utf8)
    } catch { fail("\(error)") }
    AuditLog.record(.sealed, action: "lock \(input) → \(out)", detail: boundDir)
    note("locked \(input) → \(out) (bound to \(boundDir))")
    if removePlaintext {
        // Best-effort overwrite before unlinking. NOT a guaranteed erase on SSD
        // (wear-leveling / APFS copy-on-write may keep the old blocks); if this
        // secret was ever exposed in plaintext, rotate it rather than trust this.
        if let size = try? FileManager.default.attributesOfItem(atPath: input)[.size] as? Int, size > 0 {
            try? Data(count: size).write(to: URL(fileURLWithPath: input))
        }
        try? FileManager.default.removeItem(atPath: input)
        note("removed plaintext \(input) (overwrite is best-effort on SSD — rotate the secret if it ever leaked)")
    } else {
        note("plaintext \(input) still exists — remove it with `rm \(input)` (or use `hush lock --rm`)")
    }
    if leaveDecoy {
        let content = Decoy.generate(id: UUID().uuidString)
        FileManager.default.createFile(atPath: input, contents: Data(content.utf8),
                                       attributes: [.posixPermissions: 0o644])
        note("left a honeytoken decoy at \(input) — an agent/scanner that reads it gets fake creds")
        note("wire the fake values to real canaries with `hush decoy --dns/--url/--aws` so exfiltration alerts you")
    }
}

/// Package-manager install invocations run untrusted post-install/build scripts
/// — exactly the supply-chain vector that scrapes `process.env`. Injecting
/// secrets into one hands them to every malicious postinstall. Guarded by
/// default; override with --allow-pkg.
func isPackageInstall(_ argv: [String]) -> Bool {
    guard let cmd = argv.first.map({ ($0 as NSString).lastPathComponent }) else { return false }
    let sub = argv.dropFirst().first(where: { !$0.hasPrefix("-") }) ?? ""
    switch cmd {
    case "npm", "pnpm", "yarn", "bun": return ["install", "i", "ci", "add", "update", "upgrade"].contains(sub)
    case "pip", "pip3", "uv": return sub == "install"
    case "bundle": return sub == "install"
    case "gem", "cargo", "composer", "poetry", "brew": return ["install", "add", "require", "update"].contains(sub)
    case "go": return ["install", "get"].contains(sub)
    default: return false
    }
}

func cmdRun(args: [String]) {
    var file = defaultSecretsFile
    var only: Set<String>?
    var allowPkg = false
    var allowUnsafePath = false
    var watch = false
    var redact = false
    var rest = args
    while let first = rest.first {
        if first == "-f" || first == "--file" {
            rest.removeFirst()
            guard !rest.isEmpty else { fail("\(first) needs a value") }
            file = rest.removeFirst()
        } else if first == "--only" {
            rest.removeFirst()
            guard !rest.isEmpty else { fail("--only needs a comma-separated list of keys") }
            only = Set(rest.removeFirst().split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) })
        } else if first == "--allow-pkg" {
            allowPkg = true
            rest.removeFirst()
        } else if first == "--allow-unsafe-path" {
            allowUnsafePath = true
            rest.removeFirst()
        } else if first == "--watch" {
            watch = true
            rest.removeFirst()
        } else if first == "--redact" {
            watch = true; redact = true
            rest.removeFirst()
        } else if first == "--" {
            rest.removeFirst()
            break
        } else {
            break
        }
    }
    guard !rest.isEmpty else { fail("usage: hush run [-f file] [--only K1,K2] [--watch] [--redact] [--allow-pkg] -- <command> [args...]") }

    if isPackageInstall(rest) && !allowPkg {
        AuditLog.record(.blocked, action: "run \(rest.joined(separator: " "))", detail: "package-manager guard")
        fail("""
        refusing to inject secrets into a package-manager install: \(rest.joined(separator: " "))
        install scripts run untrusted code that can scrape every injected env var.
        safer: run the install WITHOUT hush, or with --ignore-scripts. then `hush run` your app.
        to override anyway: hush run --allow-pkg -- \(rest.joined(separator: " "))
        """)
    }

    // Resolve to an absolute, non-interposable binary BEFORE decrypting, so a
    // PATH/wrapper middleman can't receive the secrets after your approval.
    let (resolution, fatal) = CommandResolver.resolve(rest[0], allowUnsafe: allowUnsafePath)
    if let fatal {
        AuditLog.record(.blocked, action: "run \(rest.joined(separator: " "))", detail: "unsafe command path")
        fail(fatal)
    }
    let exePath = resolution!.path
    for w in resolution!.warnings { note("warning: \(w)") }

    let label = "run \u{201C}\(rest.joined(separator: " "))\u{201D} with secrets"
    let plaintext = decryptSecrets(file, action: only.map { "\(label) (only \($0.sorted().joined(separator: ",")))" } ?? label)
    var injected = DotEnv.parse(String(decoding: plaintext, as: UTF8.self))
    if let only {
        let before = injected.count
        injected = injected.filter { only.contains($0.key) }
        let missing = only.subtracting(injected.map(\.key))
        if !missing.isEmpty { note("warning: --only names not in secrets: \(missing.sorted().joined(separator: ", "))") }
        note("injecting \(injected.count) of \(before) vars (least-privilege)")
    }
    for (key, value) in injected { setenv(key, value, 1) }

    if watch {
        // Supervise instead of exec: stream output through a leak scanner.
        note("watching output for leaked secret values\(redact ? " (redacting)" : "")")
        exit(Watch.supervise(rest, executablePath: exePath, secrets: injected, redact: redact))
    }

    // execv (not execvp): run the absolute path we vetted, no second PATH lookup.
    var argv: [UnsafeMutablePointer<CChar>?] = rest.map { strdup($0) }
    argv.append(nil)
    execv(exePath, &argv)
    fail("could not exec \(exePath): \(String(cString: strerror(errno)))")
}

func cmdShow(args: [String]) {
    var file = defaultSecretsFile
    var key: String?
    var it = args.makeIterator()
    while let arg = it.next() {
        switch arg {
        case "-f", "--file": if let v = it.next() { file = v }
        default: key = arg
        }
    }
    let plaintext = String(decoding: decryptSecrets(file, action: "reveal \(key.map { "the value of \($0)" } ?? "all secrets")"), as: UTF8.self)
    if let key {
        guard let match = DotEnv.parse(plaintext).last(where: { $0.key == key }) else {
            fail("no variable named \(key)")
        }
        print(match.value)
    } else {
        print(plaintext, terminator: plaintext.hasSuffix("\n") ? "" : "\n")
    }
}

func cmdEdit(args: [String]) {
    var file = defaultSecretsFile
    var it = args.makeIterator()
    while let arg = it.next() {
        if arg == "-f" || arg == "--file", let v = it.next() { file = v }
    }
    let plaintext = decryptSecrets(file, action: "edit secrets")

    // Edit inside a private 0700 directory we own, not loose in /tmp. Editors
    // drop their own swap/backup files (.swp, ~, #...#) next to the file being
    // edited — keeping that *inside* this directory means our cleanup catches
    // them too, instead of leaving plaintext fragments behind in shared /tmp.
    let tmpDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("hush-edit-\(UUID().uuidString)", isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    } catch { fail("could not create temp dir: \(error.localizedDescription)") }
    let tmp = tmpDir.appendingPathComponent("secrets.env")
    FileManager.default.createFile(atPath: tmp.path, contents: plaintext,
                                   attributes: [.posixPermissions: 0o600])
    defer { shredDirectory(tmpDir) }

    let editor = ProcessInfo.processInfo.environment["EDITOR"] ?? "vi"
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/bin/sh")
    proc.arguments = ["-c", "\(editor) \"$0\"", tmp.path]
    do {
        try proc.run()
        proc.waitUntilExit()
    } catch { fail("could not launch editor \(editor): \(error.localizedDescription)") }
    guard proc.terminationStatus == 0 else { fail("editor exited with status \(proc.terminationStatus); not saving") }

    guard let edited = FileManager.default.contents(atPath: tmp.path) else { fail("could not read edited file") }
    if edited == plaintext {
        note("no changes")
        return
    }
    let identity = loadIdentity()
    do {
        let sealed = try HushCrypto.seal(edited, identity: identity, directory: resolvedDir(of: file),
                                         reason: "re-seal edited secrets for \(resolvedDir(of: file))")
        try sealed.serialize().write(toFile: file, atomically: true, encoding: .utf8)
    } catch { fail("\(error)") }
    AuditLog.record(.sealed, action: "edit \(file)", detail: resolvedDir(of: file))
    note("updated \(file)")
}

func cmdUnlock(args: [String]) {
    var file = defaultSecretsFile
    var output = ".env"
    var it = args.makeIterator()
    while let arg = it.next() {
        switch arg {
        case "-f", "--file": if let v = it.next() { file = v }
        case "-o", "--output": if let v = it.next() { output = v }
        default: fail("unknown argument \(arg)")
        }
    }
    if FileManager.default.fileExists(atPath: output) {
        fail("\(output) already exists — refusing to overwrite")
    }
    let plaintext = decryptSecrets(file, action: "export plaintext secrets")
    FileManager.default.createFile(atPath: output, contents: plaintext,
                                   attributes: [.posixPermissions: 0o600])
    note("wrote plaintext to \(output) — this defeats the protection; re-lock when done")
}

func cmdRebind(args: [String]) {
    var file = defaultSecretsFile
    var it = args.makeIterator()
    while let arg = it.next() {
        if arg == "-f" || arg == "--file", let v = it.next() { file = v }
    }
    let sealed = loadSealed(file)
    guard let oldDir = sealed.directory else {
        fail("\(file) has no location binding — re-create it with `hush lock`")
    }
    let newDir = resolvedDir(of: file)
    if oldDir == newDir {
        note("already bound to \(newDir)")
        return
    }
    let identity = loadIdentity()
    guard HushCrypto.verify(sealed, identity: identity) else {
        fail("signature check failed — \(file) was not sealed by this Mac's hush key; re-create it with `hush lock`")
    }
    do {
        let plaintext = try HushCrypto.open(sealed, identity: identity,
                                            reason: "MOVE secrets bound to \(oldDir) → \(newDir)")
        let resealed = try HushCrypto.seal(plaintext, identity: identity, directory: newDir,
                                           reason: "re-seal secrets for \(newDir)")
        try resealed.serialize().write(toFile: file, atomically: true, encoding: .utf8)
    } catch { fail("\(error)") }
    AuditLog.record(.sealed, action: "rebind \(file)", detail: "\(oldDir) → \(newDir)")
    note("rebound \(file): \(oldDir) → \(newDir)")
}

func cmdDecoy(args: [String]) {
    var output = ".env"
    var canaries = Decoy.Canaries()
    var force = false
    var it = args.makeIterator()
    while let arg = it.next() {
        switch arg {
        case "-o", "--output": if let v = it.next() { output = v }
        case "--dns": canaries.dnsHost = it.next()
        case "--url": canaries.url = it.next()
        case "--aws":
            if let pair = it.next() {
                let parts = pair.split(separator: ":", maxSplits: 1).map(String.init)
                canaries.awsKey = parts.first
                canaries.awsSecret = parts.count > 1 ? parts[1] : nil
            }
        case "--force": force = true
        case "-h", "--help":
            print("""
            hush decoy — write a believable fake .env full of canary values.

            An injected agent or a malicious post-install script that reads .env
            gets these instead of your real secrets. Wire the fake values to real
            canary tokens so their use/resolution alerts you to an exfiltration:

              --dns HOST     DB/Redis host → use a canarytokens.org DNS token
                             (fires when an exfiltrator resolves or connects to it)
              --url URL      WEBHOOK_URL → a canarytokens.org HTTP token (fires on GET)
              --aws KEY:SEC  AWS_ACCESS_KEY_ID / SECRET → AWS canary keypair (fires on use)
              -o FILE        output path (default .env)
              --force        overwrite an existing non-decoy file

            Get free tokens at https://canarytokens.org. Without these flags the
            decoy still looks real but only helps if you monitor those fake creds.
            """)
            return
        default: fail("unknown argument \(arg)")
        }
    }
    if let existing = try? String(contentsOfFile: output, encoding: .utf8), !Decoy.isDecoy(existing), !force {
        fail("\(output) exists and isn't a decoy — refusing to overwrite real content (use --force)")
    }
    let content = Decoy.generate(id: UUID().uuidString, canaries: canaries)
    FileManager.default.createFile(atPath: output, contents: Data(content.utf8),
                                   attributes: [.posixPermissions: 0o644])
    note("wrote honeytoken decoy to \(output)")
    if canaries.dnsHost == nil && canaries.url == nil && canaries.awsKey == nil {
        note("no canaries wired — pass --dns/--url/--aws with tokens from canarytokens.org so exfiltration alerts you")
    } else {
        note("canaries embedded — you'll be alerted if these fake creds are used or resolved")
    }
}

func cmdLog(args: [String]) {
    var limit = 30
    var it = args.makeIterator()
    while let arg = it.next() {
        if arg == "-n", let v = it.next(), let n = Int(v) { limit = n }
    }
    AuditLog.show(limit: limit)
}

func cmdFingerprint(args: [String]) {
    let identity = loadIdentityRaw() // raw: we want to *report* a mismatch, not refuse
    let fp = Trust.fingerprint(identity)
    if args.contains("--repin") {
        Trust.writePin(fp)
        note("re-pinned identity fingerprint: \(fp)")
        return
    }
    print("fingerprint: \(fp)")
    if args.contains("--pubkey") { print("pubkey: \(Trust.publicKeyBase64(identity))") }
    switch Trust.pinStatus(fp) {
    case .matches: note("matches the key pinned in your Keychain ✓")
    case .missing: note("no pin recorded yet — run any command once to pin (trust-on-first-use)")
    case .mismatch: note("DOES NOT MATCH the pinned key — possible tampering. `hush fingerprint --repin` to accept")
    }
    note("teammates verify this fingerprint out-of-band before trusting your key (MITM defense for sharing)")
}

let help = """
hush — .env files sealed to your Mac's Secure Enclave

Secrets are encrypted into a .hush file. Reading them back — to run your
app, print, or edit — always triggers the macOS Touch ID / password prompt.

usage:
  hush init [--biometry-only]    one-time: create a Secure Enclave key
                                 (--biometry-only: fingerprint only, no password fallback)
  hush lock [.env] [--rm]        prompt → encrypt + sign .env → .hush
            [--decoy] [-o f]     (--decoy: leave a honeytoken .env behind)
  hush run [-f f] [--only K1,K2] prompt → inject secrets as env vars → exec cmd
           [--watch] [--redact]  (--only: subset; --watch: alert if a secret
           [--allow-pkg] -- cmd   leaks into output; --redact: mask it too.
                                  command is resolved to a vetted absolute path)
  hush show [-f f] [KEY]         prompt → print all secrets or one value
  hush edit [-f f]               prompt → edit in $EDITOR → re-encrypt
  hush unlock [-f f] [-o f]      prompt → write plaintext back out (escape hatch)
  hush rebind [-f f]             prompt → re-bind secrets after moving a project
  hush decoy [--dns/--url/--aws] write a fake .env wired to canary tokens
  hush fingerprint [--repin]     show/verify your identity fingerprint
  hush log [-n N]                show the access log (every decrypt attempt)
  hush doctor                    audit for leftover plaintext, git leaks, exposure

each .hush file is bound to the directory it was locked in; hush refuses to
decrypt it anywhere else, and the auth prompt always names the bound path
(and for `run`, the exact command).

alerts: a leaked secret (--watch), a forged .hush, or access from the wrong
directory raises a macOS notification. set HUSH_ALERT_WEBHOOK=<url> for remote
alerting, or HUSH_NOTIFY=off to silence popups.

examples:
  hush lock --decoy              lock .env, leave a canary decoy for exfil bait
  hush run --only DB_URL -- node server.js   inject just one secret
  hush show DATABASE_URL         print one secret
  hush log -n 20                 review recent access
"""

let argv = Array(CommandLine.arguments.dropFirst())
switch argv.first {
case "init": cmdInit(args: Array(argv.dropFirst()))
case "doctor": exit(Doctor.run())
case "lock": cmdLock(args: Array(argv.dropFirst()))
case "run": cmdRun(args: Array(argv.dropFirst()))
case "show": cmdShow(args: Array(argv.dropFirst()))
case "edit": cmdEdit(args: Array(argv.dropFirst()))
case "unlock": cmdUnlock(args: Array(argv.dropFirst()))
case "rebind": cmdRebind(args: Array(argv.dropFirst()))
case "decoy": cmdDecoy(args: Array(argv.dropFirst()))
case "log": cmdLog(args: Array(argv.dropFirst()))
case "fingerprint", "fp": cmdFingerprint(args: Array(argv.dropFirst()))
case "help", "-h", "--help", nil: print(help)
case .some(let other): fail("unknown command \(other)\n\n\(help)")
}
