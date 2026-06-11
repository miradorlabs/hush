import Foundation

/// Secret values that must never appear in a log line or an alert — otherwise
/// an alert sent to a webhook could itself exfiltrate the secret. `hush run`
/// registers the values it injects; everything written by AuditLog is scrubbed.
enum SecretScrub {
    private static var values: [String] = []
    static func register(_ vals: [String]) {
        values += vals.filter { $0.count >= 6 } // short values would over-redact
    }
    static func apply(_ s: String) -> String {
        var out = s
        for v in values where !v.isEmpty { out = out.replacingOccurrences(of: v, with: "‹redacted›") }
        return out
    }
}

/// Append-only access log. The Touch ID prompt *prevents* unauthorized
/// decryption; this log *detects* it — every attempt (approved, denied,
/// forged, blocked) leaves a timestamped line so a decrypt you didn't initiate
/// is visible after the fact.
enum AuditLog {
    static let file = identityDir.appendingPathComponent("access.log")

    static func record(_ result: Result, action: String, detail: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        // strip tabs/newlines so one event = one line, and scrub any secret
        // value so neither the log file nor an outbound alert leaks it
        func clean(_ s: String) -> String {
            SecretScrub.apply(s).replacingOccurrences(of: "\t", with: " ").replacingOccurrences(of: "\n", with: " ")
        }
        let line = "\(ts)\t\(result.rawValue)\t\(clean(action))\t\(clean(detail))\n"
        try? FileManager.default.createDirectory(at: identityDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        if let fh = try? FileHandle(forWritingTo: file) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: Data(line.utf8))
        } else {
            try? Data(line.utf8).write(to: file)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        // Surface the high-signal events immediately — the log is passive, this
        // makes a real anomaly reach you whether or not you go read the file.
        if result.alerts {
            Alert.raise(title: "hush: \(result.headline)", message: "\(clean(action)) — \(clean(detail))")
        }
    }

    enum Result: String {
        case ok = "OK"              // decrypt approved + succeeded
        case sealed = "SEAL"        // file locked/re-sealed (signed)
        case denyAuth = "DENY-AUTH" // user cancelled or auth failed
        case denyForgery = "DENY-FORGERY" // signature check failed
        case denyLocation = "DENY-LOCATION" // bound to a different directory
        case blocked = "BLOCK"      // a guard (e.g. package manager) stopped it
        case exposure = "EXPOSURE"  // a secret value leaked into a running app's output

        /// Only the genuine anomalies notify — not your own cancels or routine ops.
        var alerts: Bool {
            switch self {
            case .exposure, .denyForgery, .denyLocation: return true
            case .ok, .sealed, .denyAuth, .blocked: return false
            }
        }

        var headline: String {
            switch self {
            case .exposure: return "secret exposed in output"
            case .denyForgery: return "forged/tampered .hush blocked"
            case .denyLocation: return "secrets accessed from wrong location"
            default: return rawValue
            }
        }
    }

    static func show(limit: Int) {
        guard let text = try? String(contentsOf: file, encoding: .utf8), !text.isEmpty else {
            print("hush: no access log yet (\(file.path))")
            return
        }
        let lines = text.split(separator: "\n")
        print("when\tresult\taction\tdetail")
        for line in lines.suffix(limit) { print(line) }
    }
}
