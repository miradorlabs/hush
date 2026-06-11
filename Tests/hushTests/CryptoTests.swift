import XCTest
import CryptoKit
@testable import hush

/// These exercise the real encryption/AAD/signature math. The Enclave key needs
/// Touch ID to *use*, so we stand in a software P-256 key for the recipient and
/// reproduce the open() steps — verifying the security-critical properties
/// (location binding, signature verification) without a prompt.
final class CryptoTests: XCTestCase {

    private func softwareDecrypt(_ file: SealedFile, recipient: P256.KeyAgreement.PrivateKey, directory: String) throws -> Data {
        let ephPub = try P256.KeyAgreement.PublicKey(rawRepresentation: file.ephemeralPublicKey)
        let shared = try recipient.sharedSecretFromKeyAgreement(with: ephPub)
        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: file.ephemeralPublicKey + recipient.publicKey.rawRepresentation,
            sharedInfo: HushCrypto.hkdfInfo,
            outputByteCount: 32
        )
        let box = try AES.GCM.SealedBox(combined: file.ciphertext)
        return try AES.GCM.open(box, using: symKey, authenticating: HushCrypto.locationAAD(directory))
    }

    private func identity(recipientPub: Data, signingPub: Data? = nil) -> HushCrypto.Identity {
        HushCrypto.Identity(version: 2, privateKey: Data(), publicKey: recipientPub,
                            signingPrivateKey: nil, signingPublicKey: signingPub, biometryOnly: false)
    }

    func testEncryptDecryptRoundTrip() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let id = identity(recipientPub: recipient.publicKey.rawRepresentation)
        let secret = Data("API_KEY=hunter2\n".utf8)
        let file = try HushCrypto.encrypt(secret, identity: id, directory: "/tmp/app")
        let opened = try softwareDecrypt(file, recipient: recipient, directory: "/tmp/app")
        XCTAssertEqual(opened, secret)
    }

    func testWrongDirectoryFailsToDecrypt() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let id = identity(recipientPub: recipient.publicKey.rawRepresentation)
        let file = try HushCrypto.encrypt(Data("x".utf8), identity: id, directory: "/tmp/app")
        // The directory is GCM additional-authenticated data, so a different
        // location must fail authentication — the location-binding guarantee.
        XCTAssertThrowsError(try softwareDecrypt(file, recipient: recipient, directory: "/tmp/evil"))
    }

    func testWrongKeyFailsToDecrypt() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let id = identity(recipientPub: recipient.publicKey.rawRepresentation)
        let file = try HushCrypto.encrypt(Data("x".utf8), identity: id, directory: "/tmp/app")
        XCTAssertThrowsError(try softwareDecrypt(file, recipient: P256.KeyAgreement.PrivateKey(), directory: "/tmp/app"))
    }

    func testSignatureVerifies() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let signing = P256.Signing.PrivateKey()
        var id = identity(recipientPub: recipient.publicKey.rawRepresentation,
                          signingPub: signing.publicKey.rawRepresentation)
        var file = try HushCrypto.encrypt(Data("x".utf8), identity: id, directory: "/tmp/app")
        file.signature = try signing.signature(for: file.signedPayload()).rawRepresentation
        XCTAssertTrue(HushCrypto.verify(file, identity: id))

        // Unsigned file is rejected (defeats the strip-the-signature downgrade)
        var unsigned = file; unsigned.signature = nil
        XCTAssertFalse(HushCrypto.verify(unsigned, identity: id))

        // Tampered ciphertext breaks the signature
        var tampered = file; tampered.ciphertext = Data(file.ciphertext.reversed())
        XCTAssertFalse(HushCrypto.verify(tampered, identity: id))

        // A different signing key (forgery) is rejected
        id.signingPublicKey = P256.Signing.PrivateKey().publicKey.rawRepresentation
        XCTAssertFalse(HushCrypto.verify(file, identity: id))
    }
}

final class FingerprintTests: XCTestCase {
    private func id(_ pub: Data, _ sign: Data?) -> HushCrypto.Identity {
        HushCrypto.Identity(version: 2, privateKey: Data(), publicKey: pub,
                            signingPrivateKey: nil, signingPublicKey: sign, biometryOnly: false)
    }

    func testDeterministicAndSensitive() {
        let a = id(Data([1, 2, 3]), Data([4, 5]))
        let b = id(Data([1, 2, 3]), Data([4, 5]))
        let c = id(Data([1, 2, 9]), Data([4, 5]))
        XCTAssertEqual(Trust.fingerprint(a), Trust.fingerprint(b))
        XCTAssertNotEqual(Trust.fingerprint(a), Trust.fingerprint(c))
    }

    func testFormat() {
        let fp = Trust.fingerprint(id(Data([1, 2, 3]), nil))
        // 128 bits as hex grouped in 4s => 8 groups separated by 7 dashes
        XCTAssertEqual(fp.split(separator: "-").count, 8)
        XCTAssertEqual(fp.count, 39)
        XCTAssertEqual(fp, fp.uppercased())
    }
}
