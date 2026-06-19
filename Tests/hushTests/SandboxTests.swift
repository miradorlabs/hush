import XCTest
@testable import hush

/// The Seatbelt profile must encode the intended containment, and (when
/// sandbox-exec is present) actually enforce it.
final class SandboxProfileTests: XCTestCase {
    func testGuardAllowsByDefaultButDeniesSensitiveWrites() {
        let p = Sandbox.profile(projectDir: "/tmp/proj", home: "/Users/x", level: .guarded,
                                extraWritable: [], allowNetwork: true)
        XCTAssertTrue(p.contains("(allow default)"))
        XCTAssertTrue(p.contains("/Users/x/.ssh"))
        XCTAssertTrue(p.contains("/Users/x/.aws"))
        XCTAssertTrue(p.contains("/Users/x/.kube"))
        XCTAssertFalse(p.contains("(deny network*)"))
    }

    func testNoNetworkDeniesNetwork() {
        let p = Sandbox.profile(projectDir: "/tmp/proj", home: "/Users/x", level: .guarded,
                                extraWritable: [], allowNetwork: false)
        XCTAssertTrue(p.contains("(deny network*)"))
    }

    func testStrictDeniesByDefaultAndAllowsProjectPlusExtra() {
        let p = Sandbox.profile(projectDir: "/tmp/proj", home: "/Users/x", level: .strict,
                                extraWritable: ["/tmp/extra"], allowNetwork: true)
        XCTAssertTrue(p.contains("(deny default)"))
        XCTAssertTrue(p.contains("(allow file-read*)"))
        XCTAssertTrue(p.contains("(subpath \"/tmp/proj\")"))
        XCTAssertTrue(p.contains("(subpath \"/tmp/extra\")"))
        XCTAssertTrue(p.contains("(allow network*)"))
    }

    func testWrapBuildsSandboxExecArgv() {
        let w = Sandbox.wrap(exePath: "/usr/bin/node", args: ["server.js"], profile: "(version 1)")
        XCTAssertEqual(w.exe, "/usr/bin/sandbox-exec")
        XCTAssertEqual(w.argv, ["sandbox-exec", "-p", "(version 1)", "/usr/bin/node", "server.js"])
    }
}

/// Integration: drive `sandbox-exec` with a generated profile and confirm the
/// containment actually holds. Skipped if sandbox-exec is unavailable.
final class SandboxEnforcementTests: XCTestCase {
    // Canonicalize the way the app (and the sandbox kernel) does: realpath(3)
    // resolves the /var -> /private/var firmlink that Foundation's
    // resolvingSymlinksInPath leaves alone, so a temp-dir path used in a profile
    // matches what sandbox-exec sees when the write happens.
    private func canonical(_ path: String) -> String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        return realpath(path, &buf) != nil ? String(cString: buf) : path
    }

    private func sandboxRun(_ profile: String, _ script: String) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: Sandbox.sandboxExec)
        p.arguments = ["-p", profile, "/bin/sh", "-c", script]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    func testStrictConfinesWritesToProject() throws {
        try XCTSkipUnless(Sandbox.available())
        let proj = FileManager.default.temporaryDirectory.appendingPathComponent("hush-sbx-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: proj, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: proj) }
        let realProj = canonical(proj.path)
        let realHome = FileManager.default.homeDirectoryForCurrentUser.path
        let prof = Sandbox.profile(projectDir: realProj, home: realHome, level: .strict,
                                   extraWritable: [], allowNetwork: true)

        XCTAssertEqual(sandboxRun(prof, "echo ok > '\(realProj)/inside.txt'"), 0,
                       "a write inside the project must succeed under strict")
        // The home root is writable normally but is not in the strict allowlist.
        let denied = "\(realHome)/.hush_sbx_strict_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: denied) }
        XCTAssertNotEqual(sandboxRun(prof, "echo evil > '\(denied)'"), 0,
                          "a write outside the project must be denied under strict")
        XCTAssertFalse(FileManager.default.fileExists(atPath: denied),
                       "the denied write must not have created the file")
    }

    func testGuardBlocksSshButAllowsOtherWrites() throws {
        try XCTSkipUnless(Sandbox.available())
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("hush-home-\(UUID().uuidString)")
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let realHome = canonical(home.path)
        let prof = Sandbox.profile(projectDir: "/tmp", home: realHome, level: .guarded,
                                   extraWritable: [], allowNetwork: true)

        XCTAssertEqual(sandboxRun(prof, "echo ok > '\(realHome)/ok.txt'"), 0,
                       "guard allows writes outside the sensitive set")
        XCTAssertNotEqual(sandboxRun(prof, "echo evil > '\(realHome)/.ssh/authorized_keys'"), 0,
                          "guard must block a write into ~/.ssh (the backdoor-persistence target)")
    }
}

/// Compartmentalization ergonomics: `-f .env.backend` resolves to `.env.backend.hush`.
final class CompartmentTests: XCTestCase {
    func testResolveSealedPathPrefersSuffixedOnlyWhenLiteralAbsent() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hush-cmp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = dir.appendingPathComponent(".env.backend").path

        XCTAssertEqual(resolveSealedPath(base), base, "nothing exists → return input unchanged")
        try "sealed".write(toFile: base + ".hush", atomically: true, encoding: .utf8)
        XCTAssertEqual(resolveSealedPath(base), base + ".hush", "only the .hush exists → resolve to it")
        try "literal".write(toFile: base, atomically: true, encoding: .utf8)
        XCTAssertEqual(resolveSealedPath(base), base, "literal exists → never override it")
    }
}
