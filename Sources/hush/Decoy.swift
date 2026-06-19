import CryptoKit
import Foundation

/// Builds a believable-but-fake `.env` to leave in place of the real one.
///
/// The threat (prompt-injected agents and npm/MCP secret-scanners): an injected
/// agent or post-install script reads `.env` and exfiltrates it. A decoy turns
/// that read into a tripwire — if you wire the embedded values to canary
/// tokens (canarytokens.org, AWS canary keys), their *use* or even DNS
/// resolution alerts you that an exfiltration happened.
///
/// Every decoy carries a `# hush-decoy:` marker so `doctor`/`lock` recognize it
/// and never mistake it for real plaintext that needs locking.
enum Decoy {
    static let marker = "# hush-decoy:"

    static func isDecoy(_ content: String) -> Bool {
        content.contains(marker)
    }

    struct Canaries {
        var dnsHost: String?   // fires when an exfiltrator resolves/connects to the DB/Redis host
        var url: String?       // fires on HTTP GET (canarytokens.org URL token)
        var awsKey: String?    // fires on use against AWS
        var awsSecret: String?
    }

    /// Deterministic filler so a decoy is stable for a given id (no RNG needed).
    private static func filler(_ id: String, _ salt: String, _ count: Int) -> String {
        var out = ""
        var i = 0
        while out.count < count {
            let h = SHA256.hash(data: Data("\(id)|\(salt)|\(i)".utf8))
            out += Data(h).base64EncodedString()
                .replacingOccurrences(of: "/", with: "x")
                .replacingOccurrences(of: "+", with: "z")
                .replacingOccurrences(of: "=", with: "")
            i += 1
        }
        return String(out.prefix(count))
    }

    static func generate(id: String, canaries: Canaries = Canaries()) -> String {
        let shortId = String(id.replacingOccurrences(of: "-", with: "").prefix(12))
        let dbHost = canaries.dnsHost ?? "db-\(filler(id, "host", 8).lowercased()).internal.example.com"
        let awsKey = canaries.awsKey ?? "AKIA" + filler(id, "akia", 16).uppercased()
        let awsSecret = canaries.awsSecret ?? filler(id, "awssecret", 40)
        let urlLine = canaries.url.map { "WEBHOOK_URL=\($0)\n" } ?? ""
        return """
        # application configuration
        NODE_ENV=production
        PORT=3000
        DATABASE_URL=postgres://app:\(filler(id, "dbpw", 18))@\(dbHost):5432/appdb
        REDIS_URL=redis://default:\(filler(id, "redispw", 16))@\(dbHost):6379
        AWS_ACCESS_KEY_ID=\(awsKey)
        AWS_SECRET_ACCESS_KEY=\(awsSecret)
        AWS_REGION=us-east-1
        STRIPE_SECRET_KEY=sk_live_\(filler(id, "stripe", 24))
        JWT_SECRET=\(filler(id, "jwt", 44))
        SENTRY_DSN=https://\(filler(id, "sentry", 32).lowercased())@o0.ingest.sentry.io/0
        \(urlLine)\(marker)\(shortId)  # these credentials are FAKE canaries — see `hush decoy --help`
        """ + "\n"
    }
}
