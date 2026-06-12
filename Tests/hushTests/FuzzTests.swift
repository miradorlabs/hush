import XCTest
@testable import hush

/// Property/fuzz tests for the only code paths that ingest *untrusted* input —
/// the dotenv parser (reads decrypted content) and the `.hush` parser (reads a
/// file that may be attacker-controlled). They throw many randomized inputs at
/// the parsers and assert invariants hold and nothing crashes. The RNG is
/// seeded so any failure reproduces.
final class FuzzTests: XCTestCase {

    /// Deterministic SplitMix64 — reproducible fuzzing without Date/random deps.
    private struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        init(seed: UInt64) { state = seed }
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }

    private let nasty = Array("ABCabc012=#\n\r\t \"'._-/:@\\${}[]")

    private func randomString(_ rng: inout SplitMix64, maxLen: Int) -> String {
        let n = Int(rng.next() % UInt64(maxLen + 1))
        var s = ""
        s.reserveCapacity(n)
        for _ in 0..<n { s.append(nasty[Int(rng.next() % UInt64(nasty.count))]) }
        return s
    }

    private func randomData(_ rng: inout SplitMix64, minLen: Int, maxLen: Int) -> Data {
        let n = minLen + Int(rng.next() % UInt64(maxLen - minLen + 1))
        var bytes = [UInt8](); bytes.reserveCapacity(n)
        for _ in 0..<n { bytes.append(UInt8(rng.next() & 0xFF)) }
        return Data(bytes)
    }

    func testDotEnvNeverCrashesAndKeepsInvariants() {
        var rng = SplitMix64(seed: 0xDEAD_BEEF)
        for _ in 0..<5000 {
            let input = randomString(&rng, maxLen: 120)
            for (key, _) in DotEnv.parse(input) {
                // The parser must only ever emit non-empty, '='-free keys.
                XCTAssertFalse(key.isEmpty)
                XCTAssertFalse(key.contains("="))
            }
        }
    }

    func testSealedFileParseHandlesGarbage() {
        var rng = SplitMix64(seed: 0x0C0FFEE)
        for _ in 0..<5000 {
            let input = randomString(&rng, maxLen: 200)
            // Must either throw a clean error or return a value — never crash.
            if let parsed = try? SealedFile.parse(input) {
                XCTAssertFalse(parsed.ephemeralPublicKey.isEmpty || parsed.ciphertext.isEmpty,
                               "a parsed file must have non-empty eph and ct")
            }
        }
    }

    func testSealedFileRoundTripsArbitraryBinary() throws {
        var rng = SplitMix64(seed: 0xF00D_4242)
        for _ in 0..<2000 {
            // Directory is a raw header field, so keep it newline-free and
            // non-empty (an empty dir round-trips to nil by design).
            let dir = "/" + randomString(&rng, maxLen: 40).replacingOccurrences(of: "\n", with: "")
                                                          .replacingOccurrences(of: "\r", with: "")
            let eph = randomData(&rng, minLen: 1, maxLen: 80)
            let ct = randomData(&rng, minLen: 1, maxLen: 200)
            let sig = (rng.next() & 1 == 0) ? randomData(&rng, minLen: 1, maxLen: 70) : nil
            let original = SealedFile(directory: dir, ephemeralPublicKey: eph, ciphertext: ct, signature: sig)

            let parsed = try SealedFile.parse(original.serialize())
            XCTAssertEqual(parsed.directory, dir)
            XCTAssertEqual(parsed.ephemeralPublicKey, eph)
            XCTAssertEqual(parsed.ciphertext, ct)
            XCTAssertEqual(parsed.signature, sig)
        }
    }
}
