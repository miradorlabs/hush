# Changelog

All notable changes to hush are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release in preparation; everything below will ship as `0.1.0` once tagged.

### Added
- Core: encrypt a project's `.env` into a `.hush` file sealed to the Secure
  Enclave; `init`, `lock`, `run`, `show`, `edit`, `unlock`.
- Per-access user-presence approval (Touch ID / account password / Apple Watch)
  for every decryption; `init --biometry-only` removes the password fallback.
- Authenticity: a second Secure Enclave **signing** key; sealed files are signed
  and verified before any decrypt prompt, defeating forgery/substitution.
- Location binding: each `.hush` is bound to its directory via GCM AAD and the
  signature; `rebind` re-authorizes a moved project.
- `doctor`: audits leftover plaintext, git history/tracking, gitignore coverage,
  location binding, deploy-time exposure (web-served dirs, perms, `.dockerignore`),
  and install tamper-resistance.
- Honeytoken decoy (`lock --decoy`, `decoy`) wired to canary tokens.
- Least-privilege injection (`run --only`) and a package-manager guard.
- Exposure tripwire (`run --watch` / `--redact`) that scans a running app's
  output for secret values; macOS notification + optional `HUSH_ALERT_WEBHOOK`.
- Access log (`log`) with secret-value scrubbing.
- MITM hardening: command-path resolution before injection, parent-process
  context in the prompt/log, and a Keychain-pinned identity fingerprint
  (`fingerprint`).
- Tests: unit, exploit, and seeded fuzz suites (`make test`); a CLI exploit
  suite against the installed binary (`make exploit`).
- Project: Apache-2.0 license, `SECURITY.md`, `THREATMODEL.md`, `RELEASING.md`,
  GitHub Actions CI, a runnable `examples/web-app`, and a Homebrew formula.

### Fixed
- `resolvedDir` now canonicalizes via `realpath(3)`, so the same project reached
  via a `/var` ↔ `/private/var` symlink path binds consistently. (Found by the
  exploit suite.)
- `doctor` no longer flags committed `.env.example`/`.sample`/`.template` files
  as plaintext leaks.

### Security
- Secret values are scrubbed from every log line and alert, so telemetry can't
  itself leak a secret.

[Unreleased]: https://github.com/OWNER/REPO/commits/main
