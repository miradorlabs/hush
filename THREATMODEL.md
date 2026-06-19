# hush — Threat Model

This document states precisely what hush protects, how, and what it explicitly
does not protect. The goal is that a reviewer can judge the design without
reading the whole codebase, and that users aren't surprised by a gap. Every
guarantee below has a matching adversarial test (`make test` / `make exploit`).

## What hush is

A macOS CLI that encrypts a project's `.env` into a `.hush` file sealed to the
machine's Secure Enclave. Reading the secrets back — to run an app, print, or
edit — requires a per-access user-presence approval (Touch ID / account
password / Apple Watch). It is a **developer-machine, at-rest** secrets tool. It
is not a deployment secret manager.

## Assets

- The plaintext secrets (`.env` contents).
- The Secure Enclave private keys (one key-agreement, one signing). These never
  leave the chip; only opaque, machine-bound blobs are stored on disk.

## Actors / trust boundaries

- **You** — trusted; you approve prompts.
- **The Secure Enclave + macOS biometric subsystem** — trusted; the sensor↔SEP
  channel is encrypted and authenticated by Apple's hardware.
- **Other processes running as your user** — *untrusted*. This is the main
  adversary: a malicious dependency, an MCP server, a prompt-injected coding
  agent, a stray script.
- **Other users / the network / stolen disk** — untrusted.

## Cryptographic construction

- **Identity**: two P-256 keys generated inside the Secure Enclave at
  `hush init`, each with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
  access-control flags `privateKeyUsage` + `userPresence` (or
  `biometryCurrentSet` in `--biometry-only` mode):
  - a **key-agreement** key (decryption),
  - a **signing** key (authenticity).
- **Encryption (`lock`)** — ECIES-style:
  1. generate an ephemeral P-256 key,
  2. ECDH(ephemeral_priv, recipient_pub) → shared secret,
  3. HKDF-SHA256(shared, salt = ephemeral_pub ‖ recipient_pub, info = "hush-v1")
     → 256-bit key,
  4. AES-256-GCM seal, with the **bound directory** as additional authenticated
     data (AAD),
  5. sign (directory ‖ ephemeral_pub ‖ ciphertext, length-prefixed) with the
     Enclave signing key.
  Encryption uses only the public key, but signing requires user presence, so
  *authoring* a file you'll trust requires your fingerprint.
- **Decryption (`run`/`show`/`edit`)** — verify the signature (public, no auth),
  check the bound directory equals the file's location, then ECDH inside the
  Enclave (user-presence prompt) → HKDF → AES-GCM open with the same AAD.

All primitives are Apple CryptoKit. The bespoke parts — the ECIES composition,
the file format, the directory-as-AAD binding, the signature payload — are the
intended review surface.

## Guarantees and how they're enforced

| Guarantee | Mechanism | Test |
|---|---|---|
| At-rest file reveals only ciphertext | AES-256-GCM; no plaintext written | `test_atRestRead_yieldsNoPlaintext` |
| No silent decryption | Enclave key requires user presence | (manual; enclave-gated) |
| Can't forge a trusted file from the public key | Enclave signature; verified pre-prompt | `test_substitution_…` |
| Strip-signature downgrade fails | Unsigned file rejected | `test_signatureStripDowngrade_rejected` |
| Tampered ciphertext/header rejected | Signature covers dir‖eph‖ct; GCM tag | `test_ciphertextTamper_…`, `test_headerForge…` |
| Relocated/copied file won't decrypt | Directory is GCM AAD + signed | `test_exfilByRelocation_…` |
| Package installs don't get secrets | Install-command guard | `test_packageInstallScrape_blocked` |
| No wrapper interposition on delivery | Absolute-path resolution, writable-dir refusal | `test_wrapperInterposition_refused` |
| Key-material swap is detected | Keychain-pinned fingerprint | `test_keySwap_changesFingerprint` |
| Decoy carries no real secret | Generated fakes + marker | `test_decoy_containsNoRealSecret` |
| Alerts/logs can't leak the secret | Value scrubbing | `test_alertCannotLeakSecret` |
| Tampered AI-tool config is detected (opt-in) | Signed config fingerprint, re-checked pre-prompt | `test_configModification_detected`, `test_configFingerprintTamper_breaksSignature`, `test_configStripDowngrade_rejected` |

`tests/exploits.sh` re-runs the file-forgery, relocation, downgrade, guard, and
interposition attacks against the actual installed binary.

## Defense-in-depth (detection, not prevention)

- **Config File Integrity Binding** (opt-in, `hush lock --bind-config`) — binds a
  signed fingerprint of the AI-tool config (`CLAUDE.md`, `.claude/agents`,
  `.cursor` rules, `.vscode` tasks, Copilot instructions) into the sealed file.
  Decrypt recomputes it before the prompt and refuses, with an alert, on any
  change, so a prompt-injection that rewrites your own assistant's instructions
  to exfiltrate `.env` is caught instead of silently riding your next approval.
  `hush reconfig` re-authorizes a deliberate change. It cannot stop config you
  approve, and a same-user attacker who also runs `hush reconfig` defeats it; it
  closes the *silent* swap.
- **Honeytoken decoy** — bait `.env` wired to canary tokens; turns an
  exfiltration into an alert.
- **`--watch`/`--redact`** — supervises a running app and alerts/redacts if a
  secret value appears in its output.
- **Access log + alerts** — every decrypt attempt recorded; forgery, wrong-
  location, and exposure events raise a notification (macOS / webhook).

## Non-goals (explicit)

hush does **not** defend against:

1. **The running app.** Once you approve, secrets are in the process's memory
   and environment; same-user code can read them, and the app can leak them.
   `--only` and `--watch` narrow this; they don't close it.
2. **Silent in-memory / network exfiltration** by code running as you (no local
   signal — the canary decoy is the only tripwire).
3. **Approval-riding.** Malware can trigger a decrypt and hope you approve. hush
   shows the requesting process and command; the last line of defense is reading
   the prompt before you authenticate.
4. **Sophisticated same-user tampering** that rewrites both `identity.json` and
   the Keychain pin.
5. **Persistent root compromise.**
6. **Plaintext that already escaped** (git history, backups, APFS snapshots) —
   rotation is the only fix; `hush doctor` tells you when.

## Verifying these claims

```sh
make test       # unit + exploit suite (software-key crypto, guards, parsers)
make exploit    # attacks against the installed binary
```

A regression that weakens any guarantee above fails the corresponding test.
