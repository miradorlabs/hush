import Foundation

/// Least-privilege policy for the MCP secrets gateway, loaded from a project-local
/// `.hushmcp.json`:
///
///     {
///       "allow": ["DATABASE_URL", "DB_*"],     // if present, only these keys are servable
///       "deny":  ["AWS_SECRET_ACCESS_KEY"],    // always removed; takes precedence
///       "http_allow_hosts": ["api.stripe.com"] // hosts a reference-handle may send a secret to
///     }
///
/// `allow`/`deny` support a single trailing `*` wildcard. This is the
/// least-privilege layer: an agent that only needs `DATABASE_URL` never gets
/// `AWS_SECRET_ACCESS_KEY`, so a compromised agent can't scrape the whole set.
struct GatewayPolicy {
    var allow: [String]
    var deny: [String]
    var httpAllowHosts: [String]
    /// Whether a policy file actually exists. Absent → all keys servable (with a
    /// warning); reference-handle HTTP still defaults to deny, since sending a
    /// secret onto the network is the dangerous direction.
    var present: Bool

    static let filename = ".hushmcp.json"

    static func load(projectDir: String) -> GatewayPolicy {
        let url = URL(fileURLWithPath: projectDir).appendingPathComponent(filename)
        guard let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return GatewayPolicy(allow: [], deny: [], httpAllowHosts: [], present: false)
        }
        func strings(_ key: String) -> [String] { (obj[key] as? [String]) ?? [] }
        return GatewayPolicy(allow: strings("allow"), deny: strings("deny"),
                             httpAllowHosts: strings("http_allow_hosts"), present: true)
    }

    private func matches(_ value: String, _ patterns: [String]) -> Bool {
        for p in patterns {
            if p.hasSuffix("*") {
                if value.hasPrefix(String(p.dropLast())) { return true }
            } else if value == p {
                return true
            }
        }
        return false
    }

    /// Whether a secret key may be served at all. Deny wins; an explicit non-empty
    /// allowlist makes everything else implicitly denied.
    func allowsKey(_ key: String) -> Bool {
        if matches(key, deny) { return false }
        if !allow.isEmpty { return matches(key, allow) }
        return true
    }

    /// Whether `http_request` may send a secret to `host`. Deny by default unless
    /// the host is explicitly allowlisted — so even a compromised agent that can
    /// call `http_request` with a `{{secret:…}}` placeholder can't redirect the
    /// secret to an attacker host. Supports an exact host or a `*.example.com`
    /// suffix wildcard (the host convention, distinct from the key `DB_*` form).
    func allowsHost(_ host: String) -> Bool {
        guard !host.isEmpty else { return false }
        for p in httpAllowHosts {
            if p == host { return true }
            if p.hasPrefix("*.") && host.hasSuffix(String(p.dropFirst(1))) { return true }
        }
        return false
    }
}

/// Server-side substitution for the reference-handle path: the model writes
/// `{{secret:NAME}}` in an `http_request`'s headers or body, and the gateway
/// replaces it with the real value *without the value ever entering the model's
/// context*. Pure and testable; the actual decryption/auth happens in the caller.
enum SecretTemplating {
    static let pattern = try! NSRegularExpression(pattern: "\\{\\{secret:([A-Za-z_][A-Za-z0-9_]*)\\}\\}")

    /// Names referenced by `{{secret:NAME}}` placeholders in `text`.
    static func referencedNames(in text: String) -> [String] {
        let ns = text as NSString
        var names: [String] = []
        for m in pattern.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            names.append(ns.substring(with: m.range(at: 1)))
        }
        return names
    }

    /// Replace every `{{secret:NAME}}` with `lookup(NAME)`. Returns the result and
    /// the set of names actually substituted; a name with no value is left intact
    /// and reported via `missing` so the caller can refuse rather than silently
    /// send an unresolved placeholder.
    static func substitute(in text: String, lookup: (String) -> String?) -> (result: String, used: [String], missing: [String]) {
        let ns = text as NSString
        let matches = pattern.matches(in: text, range: NSRange(location: 0, length: ns.length))
        var result = ""
        var used: [String] = []
        var missing: [String] = []
        var cursor = 0
        for m in matches {
            result += ns.substring(with: NSRange(location: cursor, length: m.range.location - cursor))
            let name = ns.substring(with: m.range(at: 1))
            if let value = lookup(name) {
                result += value
                used.append(name)
            } else {
                result += ns.substring(with: m.range) // leave the placeholder intact
                missing.append(name)
            }
            cursor = m.range.location + m.range.length
        }
        result += ns.substring(with: NSRange(location: cursor, length: ns.length - cursor))
        return (result, used, missing)
    }
}
