import CryptoKit
import Foundation

/// Config File Integrity Binding (defensive layer).
///
/// AI coding tools are steered by in-repo config: `CLAUDE.md`, `.claude/agents`,
/// `.cursor` rules, `.vscode` tasks, Copilot instructions. A prompt-injection or
/// a malicious commit that rewrites one of these can turn your own assistant into
/// the exfiltrator — it reads `.env` (which it is allowed to) and ships it out.
/// The only twist is that the injected instruction lives in a file you trust
/// rather than in the data the agent is processing.
///
/// When you `hush lock --bind-config`, hush fingerprints that config surface and
/// binds the fingerprint into the sealed file (signed by the Secure Enclave, so
/// it cannot be edited to match a tampered config). Every later decrypt recomputes
/// the fingerprint over the *same* paths and refuses — before the Touch ID prompt
/// — if anything changed since the seal, raising an alert. Re-authorize a change
/// you made on purpose with `hush reconfig` (which prompts for Touch ID).
///
/// This is detection / defense-in-depth, not prevention: it cannot stop config
/// you approve, and a same-user attacker who also runs `hush reconfig` defeats it.
/// What it closes is the *silent* swap — a changed agent instruction that would
/// otherwise ride your next approved decrypt unnoticed.
enum ConfigBinding {
    /// The default AI-assistant config surface. Each entry is a path relative to
    /// the project directory (the directory the `.hush` is bound to). Directories
    /// are fingerprinted recursively. A missing path is bound as "absent", so a
    /// file appearing where none existed is itself a detected change.
    static let defaultPaths: [String] = [
        "CLAUDE.md",
        "AGENTS.md",
        ".claude/agents",
        ".claude/commands",
        ".claude/settings.json",
        ".cursor/rules",
        ".cursorrules",
        ".vscode/settings.json",
        ".vscode/tasks.json",
        ".github/copilot-instructions.md",
    ]

    /// A config path is stored comma-separated on one human-readable header line,
    /// so it must be a relative path with no comma, newline, or NUL, and must not
    /// escape the project directory.
    static func validate(_ paths: [String]) throws {
        guard !paths.isEmpty else { throw HushError("no config paths to bind") }
        for p in paths {
            if p.isEmpty || p.contains(",") || p.contains("\n") || p.contains("\u{0}") {
                throw HushError("invalid config path \(p.isEmpty ? "<empty>" : "“\(p)”") — must be non-empty with no comma or newline")
            }
            if p.hasPrefix("/") || p.split(separator: "/").contains("..") {
                throw HushError("config path “\(p)” must be relative to the project and stay inside it")
            }
        }
    }

    /// Deterministic SHA-256 over the contents of `paths` under `root`. It is
    /// order-independent (paths and directory entries are sorted), unambiguous
    /// (every field is length-prefixed), and total: a missing path hashes as
    /// "absent" and a symlink as its destination, so swapping a file for a link,
    /// or creating one that wasn't there, both change the fingerprint.
    static func fingerprint(root: String, paths: [String]) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data("hush-config-v1".utf8))
        func put(_ d: Data) {
            var len = UInt32(d.count).bigEndian
            withUnsafeBytes(of: &len) { hasher.update(data: Data($0)) }
            hasher.update(data: d)
        }
        let rootURL = URL(fileURLWithPath: root, isDirectory: true)
        for entry in manifest(root: rootURL, paths: paths) {
            put(Data(entry.name.utf8))
            put(Data([entry.kind.rawValue]))
            put(entry.payload)
        }
        return Data(hasher.finalize())
    }

    // MARK: - manifest

    enum Kind: UInt8 { case file = 0x46 /* F */, absent = 0x41 /* A */, symlink = 0x4C /* L */ }
    struct Entry { let name: String; let kind: Kind; let payload: Data }

    /// Canonical, sorted list of (relative-name, kind, payload) for every file
    /// reachable from `paths`. payload = SHA-256 of file contents, the symlink
    /// destination, or empty for an absent path.
    static func manifest(root: URL, paths: [String]) -> [Entry] {
        var entries: [Entry] = []
        for p in paths.sorted() {
            collect(relName: p, url: root.appendingPathComponent(p), into: &entries)
        }
        return entries.sorted { $0.name < $1.name }
    }

    /// lstat semantics (`attributesOfItem` does not follow symlinks), so a link
    /// is recorded as a link rather than followed out of the project tree.
    private static func collect(relName: String, url: URL, into entries: inout [Entry]) {
        let fm = FileManager.default
        let type = (try? fm.attributesOfItem(atPath: url.path)[.type]) as? FileAttributeType
        switch type {
        case .typeSymbolicLink:
            let dest = (try? fm.destinationOfSymbolicLink(atPath: url.path)) ?? ""
            entries.append(Entry(name: relName, kind: .symlink, payload: Data(dest.utf8)))
        case .typeDirectory:
            let children = (try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
            if children.isEmpty {
                // An empty directory still registers (distinct from absent), so
                // emptying a previously-populated `.claude/agents` is a change.
                entries.append(Entry(name: relName + "/", kind: .file, payload: Data()))
            }
            for child in children {
                collect(relName: relName + "/" + child.lastPathComponent, url: child, into: &entries)
            }
        case .typeRegular:
            let content = (try? Data(contentsOf: url)) ?? Data()
            entries.append(Entry(name: relName, kind: .file, payload: Data(SHA256.hash(data: content))))
        default:
            entries.append(Entry(name: relName, kind: .absent, payload: Data()))
        }
    }

    /// Human summary for failure messages: which watched paths currently exist
    /// (• present, · absent). Never prints file contents — only paths.
    static func describe(root: String, paths: [String]) -> String {
        let rootURL = URL(fileURLWithPath: root, isDirectory: true)
        let fm = FileManager.default
        return paths.sorted().map { p in
            let exists = fm.fileExists(atPath: rootURL.appendingPathComponent(p).path)
            return "    \(exists ? "•" : "·") \(p)"
        }.joined(separator: "\n")
    }
}
