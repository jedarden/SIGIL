# Formula/sigil.rb
#
# Homebrew formula for SIGIL — Secret Injection, Guarding, and Isolation Layer.
#
# This formula builds SIGIL from the released source tarball and installs the
# full binary set the workspace produces: sigil, sigild, sigil-shell, sigil-tui,
# sigil-mcp, sigil-proxy, sigil-ssh-agent, git-credential-sigil, and
# docker-credential-sigil. (sigil-fuse is excluded from the workspace because it
# needs libfuse3; build that crate yourself if you want the FUSE filesystem.)
#
# Install from this repo directly:
#
#   brew tap jedarden/sigil https://github.com/jedarden/SIGIL
#   brew install sigil
#
# Or, per Homebrew convention, this file can be moved into a dedicated
# `jedarden/homebrew-sigil` tap repo, after which the install simplifies to:
#
#   brew tap jedarden/sigil
#   brew install sigil
#
# NOTE: SIGIL's binary release pipeline (per-platform tarballs / bottles) is
# tracked in bead bf-37jk. Until that lands, source build is the reliable
# install path and is what this formula uses. When versioned binary archives
# exist, swap the `install` block for the binary distribution — the snippet is
# in notes/bf-24w30.md.
class Sigil < Formula
  desc "Secret management system for AI coding agents — agents use secrets without ever seeing their values"
  homepage "https://github.com/jedarden/SIGIL"
  url "https://github.com/jedarden/SIGIL/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "27e916d32a2ef33d369617c25feeea78176be6797d47bfe6c4cec8bcad3da846"
  version "0.4.0"
  license "MIT OR Apache-2.0"

  # Track main between tagged releases.
  head "https://github.com/jedarden/SIGIL.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "rust" => :build

  # bubblewrap backs the Linux sandbox; recommended on Linux (unavailable on macOS,
  # where the sandbox feature is simply disabled).
  on_linux do
    depends_on "bubblewrap" => :recommended
  end

  # The workspace's Cargo.toml excludes sigil-fuse (needs libfuse3) and
  # sigil-sdk-nodejs (needs the napi toolchain), so a plain workspace build does
  # not require either. `cargo build` on a virtual manifest compiles every member
  # binary; we then install the known release binaries explicitly.
  def install
    system "cargo", "build", "--release", "--locked", "--bins"
    bin.install "target/release/sigil"
    bin.install "target/release/sigild"
    bin.install "target/release/sigil-shell"
    bin.install "target/release/sigil-tui"
    bin.install "target/release/sigil-mcp"
    bin.install "target/release/sigil-proxy"
    bin.install "target/release/sigil-ssh-agent"
    bin.install "target/release/git-credential-sigil"
    bin.install "target/release/docker-credential-sigil"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sigil --version")
  end
end
