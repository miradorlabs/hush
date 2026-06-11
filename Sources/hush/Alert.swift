import Foundation

/// Where alerts go. macOS Notification Center by default (always available via
/// osascript); plus an optional webhook for remote/Slack alerting so you find
/// out even when you're away from the machine.
///   HUSH_NOTIFY=off            disable Notification Center popups
///   HUSH_ALERT_WEBHOOK=<url>   POST {"text": "..."} to this URL on each alert
enum Alert {
    static var notifyEnabled: Bool { ProcessInfo.processInfo.environment["HUSH_NOTIFY"] != "off" }
    static var webhook: String? {
        let w = ProcessInfo.processInfo.environment["HUSH_ALERT_WEBHOOK"]
        return (w?.isEmpty == false) ? w : nil
    }

    static func raise(title: String, message: String) {
        if notifyEnabled { macNotify(title: title, message: message) }
        if let url = webhook { postWebhook(url, text: "\(title) — \(message)") }
        // Always echo to stderr so it's visible even with notifications off.
        FileHandle.standardError.write(Data("hush[alert]: \(title) — \(message)\n".utf8))
    }

    private static func macNotify(title: String, message: String) {
        func esc(_ s: String) -> String {
            s.replacingOccurrences(of: "\\", with: "")
             .replacingOccurrences(of: "\"", with: "'")
        }
        let script = "display notification \"\(esc(message))\" with title \"\(esc(title))\" sound name \"Funk\""
        run("/usr/bin/osascript", ["-e", script], timeout: 5)
    }

    private static func postWebhook(_ url: String, text: String) {
        let payload = (try? String(decoding: JSONEncoder().encode(["text": text]), as: UTF8.self)) ?? "{}"
        run("/usr/bin/curl", ["-s", "-m", "5", "-X", "POST",
                              "-H", "Content-Type: application/json", "-d", payload, url], timeout: 8)
    }

    private static func run(_ path: String, _ args: [String], timeout: Double) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return }
        p.waitUntilExit()
    }
}
