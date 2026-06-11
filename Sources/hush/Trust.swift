import CryptoKit
import Foundation
import Security

/// Identity fingerprinting + a tamper-evidence pin.
///
/// The MITM this targets: malware swaps the public key in identity.json so your
/// next `hush lock` encrypts to *its* key (a man-in-the-middle on your own key
/// material). We pin a fingerprint of the public keys in the macOS Keychain —
/// a separate store from the file an attacker edits — and verify it on every
/// load. A file-only swap changes the fingerprint and is caught.
///
/// The same fingerprint is the primitive a future team-sharing feature needs:
/// teammates compare it out-of-band (like an SSH key fingerprint or a Signal
/// safety number) before trusting each other's keys, which is what defeats a
/// MITM on a key *exchange*.
enum Trust {
    /// Human-comparable fingerprint of the identity's public keys.
    static func fingerprint(_ identity: HushCrypto.Identity) -> String {
        var material = identity.publicKey
        if let signing = identity.signingPublicKey { material += signing }
        let hex = SHA256.hash(data: material).map { String(format: "%02X", $0) }.joined()
        let short = String(hex.prefix(32)) // 128 bits is plenty for comparison
        return stride(from: 0, to: short.count, by: 4).map {
            let s = short.index(short.startIndex, offsetBy: $0)
            let e = short.index(s, offsetBy: 4)
            return String(short[s..<e])
        }.joined(separator: "-")
    }

    static func publicKeyBase64(_ identity: HushCrypto.Identity) -> String {
        identity.publicKey.base64EncodedString()
    }

    // MARK: - Keychain pin

    private static let service = "com.hush.identity-pin"
    private static let account = "default"

    enum PinStatus { case matches, missing, mismatch }

    static func pinStatus(_ fingerprint: String) -> PinStatus {
        guard let pinned = readPin() else { return .missing }
        return pinned == fingerprint ? .matches : .mismatch
    }

    static func readPin() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    static func writePin(_ fingerprint: String) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(fingerprint.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}
