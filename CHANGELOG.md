# Changelog

All notable changes to hush are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release in preparation; everything below will ship as `0.1.0` once tagged.

### Added
- **Sandboxed execution** (`hush run --sandbox[=strict]`, `--no-network`,
  `--sandbox-allow`): wrap the launched command in a macOS Seatbelt profile so a
  compromised tool can't write a backdoor to `~/.ssh`, rewrite `~/.aws`/`~/.kube`
  for lateral movement, drop a LaunchAgent, or edit your shell rc. `guard` denies
  the sensitive write set; `strict` denies writes by default (project + temp
  only). Write-containment, not an unescapable jail.
- **Assistant verification** (`hush verify-assistant`, `hush init
  --verify-assistants`): codesign + Gatekeeper checks with a trust-on-first-use
  signer pin (content-hash pin for JS CLIs like Claude Code/Copilot), plus a scan
  of shell and AI-tool config for injection red flags.
- **Compartmentalization ergonomics**: `hush run -f .env.backend` resolves to the
  `.env.backend.hush` produced by `hush lock .env.backend`, and the access log now
  names which secret set (and any sandbox) each run used.
- **Secrets gateway over MCP** (`hush mcp`): a stdio JSON-RPC MCP server so an AI
  tool requests secrets through tools (`list_secrets`, `get_secret`,
  `http_request`) instead of reading `.env` directly. Every request runs the full
  check path plus a Touch ID prompt naming the caller and key, is audited, and is
  scoped by a project-local `.hushmcp.json` least-privilege policy (key allow/deny
  + host allowlist). `http_request` substitutes `{{secret:NAME}}` placeholders
  server-side, so a secret can be used for a network call without ever entering
  the model context, and only to an allowlisted host. Hand-rolled on Foundation
  to keep the zero-dependency guarantee.
- **Config File Integrity Binding** (`hush lock --bind-config`, `hush reconfig`):
  optionally fingerprint the AI-tool config surface (`CLAUDE.md`, `AGENTS.md`,
  `.claude/agents`, `.claude/commands`, `.cursor` rules, `.vscode/settings.json`
  and `tasks.json`, Copilot instructions) and bind it into the sealed file,
  signed by the Secure Enclave. Every decrypt re-checks the config before the
  Touch ID prompt and refuses, with an alert, if it changed since the seal, the
  signal of a prompt-injection that turns your own assistant into the
  exfiltrator. `hush reconfig` re-authorizes a deliberate change (Touch ID), and
  `hush doctor` reports binding status. Opt-in, fully backward compatible.
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
  GitHub Actions CI, a tag-triggered release workflow (publishes a GitHub release
  and opens a PR pinning the Homebrew formula), a runnable `examples/web-app`, and
  a Homebrew formula.

### Fixed
- `resolvedDir` now canonicalizes via `realpath(3)`, so the same project reached
  via a `/var` ↔ `/private/var` symlink path binds consistently. (Found by the
  exploit suite.)
- `doctor` no longer flags committed `.env.example`/`.sample`/`.template` files
  as plaintext leaks.

### Security
- Secret values are scrubbed from every log line and alert, so telemetry can't
  itself leak a secret.

[Unreleased]: https://github.com/miradorlabs/hush/commits/main
