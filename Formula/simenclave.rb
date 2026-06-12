# typed: false
# frozen_string_literal: true

# Builds the helper and the CLI from source. The interposer dylib is never built or shipped here; it
# loads only through a debug simulator scheme (the fence), so an install ships the helper and the CLI.
#
# url and sha256 point at the release-attached source tarball (the one SHA256SUMS covers) and are
# bumped by .github/workflows/release.yml on each tagged release.
class Simenclave < Formula
  desc "Give the iOS Simulator a real hardware Secure Enclave"
  homepage "https://github.com/nirapod-labs/simenclave"
  url "https://github.com/nirapod-labs/simenclave/releases/download/v1.0.0/simenclave-1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on xcode: ["16.0", :build]
  depends_on :macos

  def install
    ENV["SIGN_ID"] = "-" # ad-hoc; the Secure Enclave works under it and Gatekeeper runs it locally
    system "bash", "scripts/build-menubar-app.sh"
    system "xcrun", "swift", "build", "-c", "release",
           "--package-path", "tools/simenclavectl", "--disable-sandbox"

    prefix.install "dist/SimEnclave.app"
    bin.install "tools/simenclavectl/.build/release/simenclavectl"
  end

  def caveats
    <<~EOS
      The SimEnclave helper is at:
        #{opt_prefix}/SimEnclave.app
      Open it (it runs in the menu bar), then drive it with the CLI:
        simenclavectl doctor
      To inject the Secure Enclave into a Simulator app, wire a debug scheme with:
        simenclavectl init --dylib <path-to-built-interposer>
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/simenclavectl version")
  end
end
