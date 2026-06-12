# Homebrew formula for hush. Builds from source (auditable; no prebuilt binary
# to trust). Until a release is tagged, the url/sha256 below are placeholders —
# fill them in per RELEASING.md when you publish:
#
#   1. tag and push v0.1.0 (the version is derived from the tag in the url)
#   2. curl -L https://github.com/OWNER/REPO/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
#   3. replace OWNER/REPO and the sha256 below
#
# Install before publishing (local test):
#   brew install --build-from-source ./Formula/hush.rb
# After publishing, host this file in a tap (e.g. OWNER/homebrew-tap) so users run:
#   brew install OWNER/tap/hush
class Hush < Formula
  desc ".env files sealed to your Mac's Secure Enclave (Touch ID gated)"
  homepage "https://github.com/OWNER/REPO"
  url "https://github.com/OWNER/REPO/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SOURCE_TARBALL_SHA256"
  license "Apache-2.0"

  depends_on xcode: ["14.0", :build]
  depends_on macos: :ventura # 13+, for the Secure Enclave APIs used

  def install
    system "swift", "build", "--disable-sandbox", "-c", "release"
    bin.install ".build/release/hush"
    # Re-assert the hardened runtime (blocks DYLD injection into hush itself).
    system "codesign", "--force", "--options", "runtime", "--sign", "-", bin/"hush"
  end

  test do
    # `help` needs no identity or prompt and prints the banner.
    assert_match "Secure Enclave", shell_output("#{bin}/hush help")
  end
end
