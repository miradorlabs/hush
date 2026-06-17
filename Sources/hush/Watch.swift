import Foundation

/// Supervised `hush run`: instead of exec-ing the app, hush stays the parent,
/// streams the child's stdout/stderr through, and scans each line for the
/// actual secret VALUES. When one appears in output — the everyday way a
/// running app leaks (logs, stack traces, console dumps, debug prints) — it
/// raises an alert, and with --redact masks the value in the stream.
///
/// Honest scope: this catches secrets that flow through the app's std streams.
/// It does NOT catch an attacker silently reading the process environment and
/// exfiltrating over the network — for that, the decoy/canary is the tripwire.
enum Watch {
    /// One scanner per stream; line-buffered so a secret split across read
    /// chunks is still caught (a value never spans a newline).
    final class LineScanner {
        let watched: [(key: String, value: String)]
        let redact: Bool
        let sink: FileHandle
        let onExposure: (String) -> Void
        private var buf = Data()
        // `feed` runs on the pipe's background readability queue, but after the
        // child exits we drain the remainder synchronously on the main thread —
        // setting readabilityHandler=nil doesn't wait for an in-flight handler,
        // so both could touch `buf` at once. Serialize all buffer access.
        private let lock = NSLock()

        init(watched: [(key: String, value: String)], redact: Bool, sink: FileHandle,
             onExposure: @escaping (String) -> Void) {
            self.watched = watched; self.redact = redact; self.sink = sink; self.onExposure = onExposure
        }

        func feed(_ data: Data) {
            lock.lock(); defer { lock.unlock() }
            buf.append(data)
            while let nl = buf.range(of: Data([0x0A])) {
                let line = buf.subdata(in: buf.startIndex..<nl.upperBound)
                buf.removeSubrange(buf.startIndex..<nl.upperBound)
                emit(line)
            }
        }

        func flush() {
            lock.lock(); defer { lock.unlock() }
            if !buf.isEmpty { emit(buf); buf.removeAll() }
        }

        private func emit(_ lineData: Data) {
            var line = String(decoding: lineData, as: UTF8.self)
            for s in watched where line.contains(s.value) {
                onExposure(s.key)
                if redact { line = line.replacingOccurrences(of: s.value, with: "‹\(s.key) redacted by hush›") }
            }
            try? sink.write(contentsOf: Data(line.utf8))
        }
    }

    static func supervise(_ argv: [String], executablePath: String, secrets: [(key: String, value: String)], redact: Bool) -> Int32 {
        // Only watch values long enough to be real secrets — short ones
        // (PORT=3000, DEBUG=true) would false-positive on ordinary output.
        let watched = secrets.filter { $0.value.count >= 8 }

        // Run the vetted absolute path directly — no /usr/bin/env PATH lookup
        // that a middleman could intercept.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executablePath)
        proc.arguments = Array(argv.dropFirst())
        proc.standardInput = FileHandle.standardInput
        let outPipe = Pipe(), errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        let alertedLock = NSLock()
        var alerted = Set<String>()
        let onExposure: (String) -> Void = { key in
            alertedLock.lock(); let firstTime = alerted.insert(key).inserted; alertedLock.unlock()
            if firstTime {
                AuditLog.record(.exposure, action: "run \(argv.joined(separator: " "))",
                                detail: "\(key) appeared in the app's output")
            }
        }

        let outScanner = LineScanner(watched: watched, redact: redact, sink: FileHandle.standardOutput, onExposure: onExposure)
        let errScanner = LineScanner(watched: watched, redact: redact, sink: FileHandle.standardError, onExposure: onExposure)
        outPipe.fileHandleForReading.readabilityHandler = { outScanner.feed($0.availableData) }
        errPipe.fileHandleForReading.readabilityHandler = { errScanner.feed($0.availableData) }

        do { try proc.run() } catch { fail("could not exec \(argv[0]): \(error.localizedDescription)") }
        proc.waitUntilExit()

        // Stop async handlers, then drain + scan whatever's left synchronously.
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        outScanner.feed(outPipe.fileHandleForReading.readDataToEndOfFile()); outScanner.flush()
        errScanner.feed(errPipe.fileHandleForReading.readDataToEndOfFile()); errScanner.flush()
        return proc.terminationStatus
    }
}
