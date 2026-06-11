import XCTest
@testable import hush

final class PackageGuardTests: XCTestCase {
    func testInstallsAreDetected() {
        XCTAssertTrue(isPackageInstall(["npm", "install"]))
        XCTAssertTrue(isPackageInstall(["npm", "i"]))
        XCTAssertTrue(isPackageInstall(["yarn", "add", "lodash"]))
        XCTAssertTrue(isPackageInstall(["pnpm", "install"]))
        XCTAssertTrue(isPackageInstall(["pip3", "install", "requests"]))
        XCTAssertTrue(isPackageInstall(["go", "get", "./..."]))
        XCTAssertTrue(isPackageInstall(["brew", "install", "jq"]))
        XCTAssertTrue(isPackageInstall(["/usr/local/bin/npm", "ci"])) // absolute path still matched
    }

    func testNonInstallsAreAllowed() {
        XCTAssertFalse(isPackageInstall(["npm", "run", "dev"]))
        XCTAssertFalse(isPackageInstall(["node", "server.js"]))
        XCTAssertFalse(isPackageInstall(["cargo", "build"]))
        XCTAssertFalse(isPackageInstall(["python", "app.py"]))
        XCTAssertFalse(isPackageInstall([]))
    }
}

final class CommandResolverTests: XCTestCase {
    private var tmp: URL!

    override func setUpWithError() throws {
        tmp = FileManager.default.temporaryDirectory.appendingPathComponent("hushtest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: tmp) }

    private func makeExecutable(_ name: String, perms: Int = 0o755, dirPerms: Int = 0o755) throws -> String {
        let path = tmp.appendingPathComponent(name)
        FileManager.default.createFile(atPath: path.path, contents: Data("#!/bin/sh\n".utf8),
                                       attributes: [.posixPermissions: perms])
        try FileManager.default.setAttributes([.posixPermissions: dirPerms], ofItemAtPath: tmp.path)
        return path.path
    }

    func testRelativePathRefused() {
        let (res, fatal) = CommandResolver.resolve("./evil", allowUnsafe: false)
        XCTAssertNil(res)
        XCTAssertNotNil(fatal)
        XCTAssertTrue(fatal!.contains("relative"))
    }

    func testNonExecutableRefused() throws {
        let path = tmp.appendingPathComponent("data.txt")
        FileManager.default.createFile(atPath: path.path, contents: Data("x".utf8),
                                       attributes: [.posixPermissions: 0o644])
        let (res, fatal) = CommandResolver.resolve(path.path, allowUnsafe: false)
        XCTAssertNil(res)
        XCTAssertTrue(fatal!.contains("not an executable"))
    }

    func testAbsoluteExecutableInSafeDir() throws {
        let path = try makeExecutable("tool", dirPerms: 0o755)
        let (res, fatal) = CommandResolver.resolve(path, allowUnsafe: false)
        XCTAssertNil(fatal)
        XCTAssertEqual(res?.path, path)
        XCTAssertTrue(res?.warnings.isEmpty ?? false)
    }

    func testWorldWritableParentDirWarns() throws {
        let path = try makeExecutable("tool", dirPerms: 0o777)
        let (res, fatal) = CommandResolver.resolve(path, allowUnsafe: false)
        XCTAssertNil(fatal)
        XCTAssertFalse(res?.warnings.isEmpty ?? true) // flagged as swappable
    }
}

final class SecretScrubTests: XCTestCase {
    func testScrubsRegisteredValues() {
        SecretScrub.register(["supersecretvalue123"])
        XCTAssertEqual(SecretScrub.apply("token=supersecretvalue123 end"), "token=‹redacted› end")
    }

    func testSkipsShortValues() {
        SecretScrub.register(["abc"]) // too short to register
        XCTAssertEqual(SecretScrub.apply("x=abc"), "x=abc")
    }
}

final class PathTests: XCTestCase {
    func testResolvedDirIsAbsoluteParent() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hushpath-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent(".hush").path
        XCTAssertEqual(resolvedDir(of: file), dir.resolvingSymlinksInPath().path)
    }
}
