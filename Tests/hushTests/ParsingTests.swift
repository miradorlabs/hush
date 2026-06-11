import XCTest
@testable import hush

final class DotEnvTests: XCTestCase {
    func testBasicPairs() {
        let vars = DotEnv.parse("A=1\nB=two\n")
        XCTAssertEqual(vars.count, 2)
        XCTAssertEqual(vars[0].key, "A"); XCTAssertEqual(vars[0].value, "1")
        XCTAssertEqual(vars[1].key, "B"); XCTAssertEqual(vars[1].value, "two")
    }

    func testCommentsBlankAndExport() {
        let vars = DotEnv.parse("# comment\n\nexport TOKEN=abc\n   \nKEY = spaced \n")
        let dict = Dictionary(uniqueKeysWithValues: vars.map { ($0.key, $0.value) })
        XCTAssertEqual(dict["TOKEN"], "abc")
        XCTAssertEqual(dict["KEY"], "spaced")
        XCTAssertNil(dict["#"])
    }

    func testQuotesStripped() {
        let vars = DotEnv.parse(#"A="quoted"\#nB='single'\#nC="with=equals""#)
        let dict = Dictionary(uniqueKeysWithValues: vars.map { ($0.key, $0.value) })
        XCTAssertEqual(dict["A"], "quoted")
        XCTAssertEqual(dict["B"], "single")
        XCTAssertEqual(dict["C"], "with=equals")
    }

    func testEqualsInValuePreserved() {
        let vars = DotEnv.parse("URL=postgres://u:p@h/db?x=1\n")
        XCTAssertEqual(vars.first?.value, "postgres://u:p@h/db?x=1")
    }
}

final class SealedFileTests: XCTestCase {
    func testRoundTrip() throws {
        let original = SealedFile(directory: "/tmp/proj",
                                  ephemeralPublicKey: Data([1, 2, 3, 4]),
                                  ciphertext: Data([9, 8, 7]),
                                  signature: Data([5, 5, 5]))
        let parsed = try SealedFile.parse(original.serialize())
        XCTAssertEqual(parsed.directory, "/tmp/proj")
        XCTAssertEqual(parsed.ephemeralPublicKey, Data([1, 2, 3, 4]))
        XCTAssertEqual(parsed.ciphertext, Data([9, 8, 7]))
        XCTAssertEqual(parsed.signature, Data([5, 5, 5]))
    }

    func testSerializeIsHumanReadable() {
        let f = SealedFile(directory: "/x", ephemeralPublicKey: Data([1]), ciphertext: Data([2]), signature: nil)
        let text = f.serialize()
        XCTAssertTrue(text.hasPrefix("#!hush "))
        XCTAssertTrue(text.contains("dir: /x"))
        XCTAssertFalse(text.contains("sig:")) // no signature line when unsigned
    }

    func testParseRejectsGarbage() {
        XCTAssertThrowsError(try SealedFile.parse("not a hush file"))
    }

    func testSignedPayloadDependsOnDirectory() {
        let a = SealedFile(directory: "/one", ephemeralPublicKey: Data([1]), ciphertext: Data([2]), signature: nil)
        let b = SealedFile(directory: "/two", ephemeralPublicKey: Data([1]), ciphertext: Data([2]), signature: nil)
        XCTAssertNotEqual(a.signedPayload(), b.signedPayload())
    }
}

final class DecoyTests: XCTestCase {
    func testMarkerAndDetection() {
        let content = Decoy.generate(id: "abc-123")
        XCTAssertTrue(content.contains(Decoy.marker))
        XCTAssertTrue(Decoy.isDecoy(content))
        XCTAssertFalse(Decoy.isDecoy("API_KEY=real\n"))
    }

    func testDeterministicForSameId() {
        XCTAssertEqual(Decoy.generate(id: "same"), Decoy.generate(id: "same"))
        XCTAssertNotEqual(Decoy.generate(id: "one"), Decoy.generate(id: "two"))
    }

    func testCanariesEmbedded() {
        let c = Decoy.Canaries(dnsHost: "x7.canarytokens.com",
                               url: "https://canarytokens.org/t/abc",
                               awsKey: "AKIACANARY", awsSecret: "shh")
        let out = Decoy.generate(id: "z", canaries: c)
        XCTAssertTrue(out.contains("x7.canarytokens.com"))
        XCTAssertTrue(out.contains("https://canarytokens.org/t/abc"))
        XCTAssertTrue(out.contains("AKIACANARY"))
    }

    func testLooksLikeRealEnv() {
        let out = Decoy.generate(id: "z")
        XCTAssertTrue(out.contains("AWS_ACCESS_KEY_ID="))
        XCTAssertTrue(out.contains("DATABASE_URL="))
    }
}
