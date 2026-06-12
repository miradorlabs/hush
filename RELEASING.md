# Releasing hush

A tool that guards secrets must not itself be a supply-chain risk. This is how a
release is built so that users can trust the binary matches the source.

## Principles

- **Zero third-party dependencies.** hush links only Apple frameworks. CI
  enforces this. The dependency you don't have can't be compromised.
- **Reproducible.** The same source + toolchain should produce the same binary,
  so anyone can rebuild and compare.
- **Signed and notarized.** Released binaries are signed with a Developer ID and
  notarized by Apple, so Gatekeeper trusts them and the origin is verifiable.
- **Checksummed.** Every artifact ships with a SHA-256 a user can verify.

## 1. Build + checksum (no credentials needed)

```sh
make dist
# → dist/hush and dist/hush.sha256
```

`make dist` builds the release binary and writes its SHA-256. This is the
reproducible core; anyone can run it and compare `dist/hush.sha256`.

### Reproducibility notes

- Pin the Swift toolchain (record `swift --version` in the release notes; ideally
  build in a documented Xcode version).
- Build is `swift build -c release` with no codegen that embeds timestamps.
- There are no vendored dependencies, so there is no lockfile drift. If
  dependencies are ever added, commit `Package.resolved` and verify it in CI.

## 2. Sign with Developer ID (requires an Apple Developer account)

```sh
# Replace with your Developer ID Application identity:
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Your Name (TEAMID)" dist/hush
codesign --verify --strict --verbose=2 dist/hush
```

`--options runtime` keeps the hardened runtime (blocks DYLD injection into hush
itself, as the local `make build` already does with an ad-hoc signature).

## 3. Notarize

```sh
ditto -c -k --keepParent dist/hush dist/hush.zip
xcrun notarytool submit dist/hush.zip \
  --apple-id "you@example.com" --team-id TEAMID --password "<app-specific-password>" \
  --wait
# notarytool staples to archives; for a bare binary, verify with:
spctl --assess --type execute --verbose=2 dist/hush
```

Store credentials in a notarytool keychain profile rather than inline:
`xcrun notarytool store-credentials`.

## 4. Publish

- Attach `dist/hush`, `dist/hush.zip`, and `dist/hush.sha256` to a tagged
  GitHub release. Sign the tag (`git tag -s`).
- Prefer a **Homebrew formula** (auditable, pins a URL + SHA-256) over a
  `curl | bash` installer.
- Put the toolchain version and the SHA-256 in the release notes so users — and
  reproducible-build checkers — can verify.

## Verifying a release (for users)

```sh
shasum -a 256 hush                 # compare to the published checksum
codesign --verify --strict hush    # confirms the signature
spctl --assess --type execute hush # confirms notarization / Gatekeeper trust
```
