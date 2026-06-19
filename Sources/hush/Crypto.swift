import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Identity = two P-256 keys generated inside the Secure Enclave:
///   • a key-agreement key, used to *decrypt* sealed files
///   • a signing key, used to *authenticate* sealed files
/// Neither private key ever leaves the chip; the stored `dataRepresentation`
/// is an opaque blob only this machine's enclave can use, and using either
/// requires user presence (Touch ID or the account password) because the
/// access-control flags are baked into the key at creation time.
enum HushCrypto {
    static let hkdfInfo = Data("hush-v1".utf8)
    static let sigDomain = Data("hush-sig-v1".utf8)

    struct Identity: Codable {
        var version: Int
        var privateKey: Data            // Secure Enclave agreement key (opaque, machine-bound)
        var publicKey: Data             // P-256 agreement public key (raw)
        var signingPrivateKey: Data?    // Secure Enclave signing key (v2+)
        var signingPublicKey: Data?     // P-256 signing public key (raw)
        var biometryOnly: Bool?         // remembered so upgrades use the same policy
    }

    static func secureEnclaveAvailable() -> Bool {
        SecureEnclave.isAvailable
    }

    private static func accessControl(biometryOnly: Bool) throws -> SecAccessControl {
        var aclError: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = biometryOnly
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .userPresence]
        guard let acl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &aclError
        ) else {
            throw HushError("could not create access control: \(aclError?.takeRetainedValue().localizedDescription ?? "unknown")")
        }
        return acl
    }

    /// `biometryOnly` uses .biometryCurrentSet: the account password cannot
    /// approve use, and enrolling a new fingerprint invalidates the keys.
    static func createIdentity(biometryOnly: Bool = false) throws -> Identity {
        let acl = try accessControl(biometryOnly: biometryOnly)
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
        let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
        return Identity(
            version: 2,
            privateKey: agreement.dataRepresentation,
            publicKey: agreement.publicKey.rawRepresentation,
            signingPrivateKey: signing.dataRepresentation,
            signingPublicKey: signing.publicKey.rawRepresentation,
            biometryOnly: biometryOnly
        )
    }

    /// Add a signing key to a v1 identity that predates authentication support.
    /// Generating a key needs no auth; it leaves the agreement key untouched so
    /// existing sealed files still decrypt.
    static func upgraded(_ identity: Identity) throws -> Identity? {
        guard identity.signingPrivateKey == nil else { return nil }
        let acl = try accessControl(biometryOnly: identity.biometryOnly ?? false)
        let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
        var updated = identity
        updated.version = 2
        updated.signingPrivateKey = signing.dataRepresentation
        updated.signingPublicKey = signing.publicKey.rawRepresentation
        return updated
    }

    /// The bound directory is mixed into AES-GCM's additional authenticated
    /// data: editing the `dir:` header in the file breaks decryption.
    static func locationAAD(_ directory: String) -> Data {
        Data("hush-v1|dir=\(directory)".utf8)
    }

    /// Encrypt with the public key only — no auth needed for this step.
    static func encrypt(_ plaintext: Data, identity: Identity, directory: String) throws -> SealedFile {
        let recipient = try P256.KeyAgreement.PublicKey(rawRepresentation: identity.publicKey)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.publicKey.rawRepresentation + recipient.rawRepresentation,
            sharedInfo: hkdfInfo,
            outputByteCount: 32
        )
        let box = try AES.GCM.seal(plaintext, using: symKey, authenticating: locationAAD(directory))
        guard let combined = box.combined else { throw HushError("encryption failed") }
        return SealedFile(directory: directory, ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
                          ciphertext: combined, signature: nil)
    }

    /// Encrypt, then sign with the Secure Enclave signing key. Signing triggers
    /// the auth prompt — so *authoring* a file you'll later trust requires your
    /// fingerprint, which is what stops an attacker from forging one.
    static func seal(_ plaintext: Data, identity: Identity, directory: String,
                     config: (paths: [String], fingerprint: Data)? = nil, reason: String) throws -> SealedFile {
        guard let skData = identity.signingPrivateKey else {
            throw HushError("identity has no signing key — re-run `hush init`")
        }
        var file = try encrypt(plaintext, identity: identity, directory: directory)
        if let config {
            file.configPaths = config.paths.sorted()
            file.configFingerprint = config.fingerprint
        }
        let context = LAContext()
        context.localizedReason = reason
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: skData, authenticationContext: context)
        } catch {
            throw HushError("could not load Secure Enclave signing key: \(error.localizedDescription)")
        }
        do {
            file.signature = try key.signature(for: file.signedPayload()).rawRepresentation
        } catch let laError as LAError where laError.code == .userCancel {
            throw HushError("authentication cancelled")
        } catch {
            throw HushError("could not sign: \(error.localizedDescription)")
        }
        return file
    }

    /// Verify the signature with the public key — no auth, so a forged file is
    /// rejected *before* any decrypt prompt appears.
    static func verify(_ file: SealedFile, identity: Identity) -> Bool {
        guard let spkData = identity.signingPublicKey,
              let sig = file.signature,
              let pub = try? P256.Signing.PublicKey(rawRepresentation: spkData),
              let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else {
            return false
        }
        return pub.isValidSignature(ecdsa, for: file.signedPayload())
    }

    /// Decrypt. The key-agreement call runs inside the Secure Enclave and
    /// triggers the system Touch ID / password prompt. Call `verify` first.
    static func open(_ file: SealedFile, identity: Identity, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: identity.privateKey,
                authenticationContext: context
            )
        } catch {
            throw HushError("could not load Secure Enclave key (was it created on this Mac?): \(error.localizedDescription)")
        }
        let ephemeralPub = try P256.KeyAgreement.PublicKey(rawRepresentation: file.ephemeralPublicKey)
        let shared: SharedSecret
        do {
            shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPub)
        } catch let laError as LAError where laError.code == .userCancel {
            throw HushError("authentication cancelled")
        } catch {
            throw HushError("authentication failed: \(error.localizedDescription)")
        }
        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: file.ephemeralPublicKey + privateKey.publicKey.rawRepresentation,
            sharedInfo: hkdfInfo,
            outputByteCount: 32
        )
        guard let boundDir = file.directory else {
            throw HushError("file has no location binding — re-create it with `hush lock`")
        }
        do {
            let box = try AES.GCM.SealedBox(combined: file.ciphertext)
            return try AES.GCM.open(box, using: symKey, authenticating: locationAAD(boundDir))
        } catch {
            throw HushError("decryption failed — file corrupt, location header tampered with, or sealed for a different key")
        }
    }
}

/// On-disk format of a .hush file. Human-readable header so `cat` explains itself.
/// `dir:` is informational AND cryptographically bound (GCM AAD); `sig:` is a
/// Secure Enclave signature over directory + ephemeral key + ciphertext.
struct SealedFile {
    var directory: String?
    var ephemeralPublicKey: Data
    var ciphertext: Data
    var signature: Data?
    // Config File Integrity Binding (optional). `configPaths` is the AI-tool
    // config surface watched at seal time; `configFingerprint` is the SHA-256 of
    // its contents. Both are covered by the signature, so an attacker can't edit
    // the `cfg:` line to match a config they tampered with, nor strip the lines
    // to downgrade (the payload would no longer match the signature).
    var configPaths: [String]?
    var configFingerprint: Data?

    static let banner = "#!hush v1 — secrets sealed to this Mac's Secure Enclave; run `hush` to access (requires Touch ID / password)"

    /// Canonical config-path bytes the header and signature share: sorted, then
    /// comma-joined. One place so serialization and signing can never diverge.
    func canonicalConfigPaths() -> String { (configPaths ?? []).sorted().joined(separator: ",") }

    /// Canonical, length-prefixed bytes the signature covers. Length prefixes
    /// keep the boundary between fields unambiguous. The config fields are only
    /// appended when present, so files sealed without config binding produce the
    /// exact same payload as before — their existing signatures still verify.
    func signedPayload() -> Data {
        var out = HushCrypto.sigDomain
        func append(_ field: Data) {
            var len = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
            out.append(field)
        }
        append(Data((directory ?? "").utf8))
        append(ephemeralPublicKey)
        append(ciphertext)
        if let configFingerprint {
            append(Data(canonicalConfigPaths().utf8))
            append(configFingerprint)
        }
        return out
    }

    func serialize() -> String {
        var lines = [Self.banner, "dir: \(directory ?? "")",
                     "eph: \(ephemeralPublicKey.base64EncodedString())",
                     "ct: \(ciphertext.base64EncodedString())"]
        if let configFingerprint {
            lines.append("cfgpaths: \(canonicalConfigPaths())")
            lines.append("cfg: \(configFingerprint.base64EncodedString())")
        }
        if let signature { lines.append("sig: \(signature.base64EncodedString())") }
        return lines.joined(separator: "\n") + "\n"
    }

    static func parse(_ text: String) throws -> SealedFile {
        var dir: String?
        var eph: Data?
        var ct: Data?
        var sig: Data?
        var cfgPaths: [String]?
        var cfgFingerprint: Data?
        for line in text.split(separator: "\n") {
            if line.hasPrefix("dir: ") { dir = String(line.dropFirst(5)) }
            if line.hasPrefix("eph: ") { eph = Data(base64Encoded: String(line.dropFirst(5))) }
            if line.hasPrefix("ct: ") { ct = Data(base64Encoded: String(line.dropFirst(4))) }
            if line.hasPrefix("cfgpaths: ") { cfgPaths = String(line.dropFirst(10)).split(separator: ",").map(String.init) }
            else if line.hasPrefix("cfg: ") { cfgFingerprint = Data(base64Encoded: String(line.dropFirst(5))) }
            if line.hasPrefix("sig: ") { sig = Data(base64Encoded: String(line.dropFirst(5))) }
        }
        guard let eph, let ct else { throw HushError("not a valid .hush file") }
        return SealedFile(directory: dir?.isEmpty == true ? nil : dir,
                          ephemeralPublicKey: eph, ciphertext: ct, signature: sig,
                          configPaths: cfgPaths, configFingerprint: cfgFingerprint)
    }
}

struct HushError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}
