# Security Policy

hush guards secrets, so its own integrity matters. This document explains how to
report a vulnerability and what is in and out of scope.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Preferred: use GitHub's private vulnerability reporting (the **Security** tab →
**Report a vulnerability**). This keeps the report confidential until a fix is
available.

Alternative: email the maintainers at `<security-contact@your-domain>` (replace
with a real address before publishing). PGP key, if any, goes here.

Please include: the version/commit, your platform (macOS version, Apple Silicon
or Intel/T2), a description of the issue, and a proof-of-concept if you have one.

### What to expect

- Acknowledgement within **3 business days**.
- An initial assessment (in scope / severity) within **7 business days**.
- Coordinated disclosure: we'll agree on a timeline and credit you (or stay
  anonymous, your choice). Please give us a reasonable window before public
  disclosure.

## Scope

**In scope** — report these:

- Any way to recover plaintext from a `.hush` file without the legitimate
  Secure Enclave key and a user-presence approval.
- Forging or substituting a `.hush` that hush accepts as authentic (signature
  bypass).
- Bypassing the directory binding (decrypting a relocated/edited file).
- Bypassing a guard: package-manager guard, command-path (MITM-on-delivery)
  resolver, or the identity fingerprint pin.
- A secret value leaking into a log line, an alert, or the access log.
- Memory-safety or parsing bugs in the dotenv or `.hush` parsers.
- Weaknesses in the cryptographic construction (key agreement, KDF, AEAD, AAD,
  signature).

**Out of scope** — these are documented non-goals (see `THREATMODEL.md`); they
are limitations of the approach, not bugs:

- Reading secrets from a *running* app's memory or environment after you have
  approved (the app legitimately holds them).
- A persistent root compromise, or malware that, running as your user, both
  swaps `identity.json` **and** rewrites the Keychain pin.
- Secrets that already escaped in plaintext (old commits, backups, snapshots).
- Tricking a user into approving a legitimate-looking prompt (we surface the
  requesting process and command; we cannot attest the caller).
- Physical "evil maid" attacks with the Mac unlocked and unattended.

## Safe harbor

We will not pursue or support legal action against researchers who:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption, and
- report promptly and give us a reasonable time to remediate before disclosure.

Testing must be against your own machine and your own data only.

## Supported versions

Until a `1.0` release, only the latest commit on the default branch is
supported. After `1.0`, this section will list supported version ranges.
