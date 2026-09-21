# Homebrew formula — the source of truth lives in the main repo; after
# tagging a release, `sh scripts/release-brew.sh` pins the tag's tarball
# sha256 here and pushes the copy the tap (cschlick/homebrew-tap) serves.
#
# This installs the NATIVE macOS node: the real `gw`, running the mesh on this
# Mac via wireguard-go (userspace WireGuard — macOS has no kernel module) and
# a launchd daemon that `sudo gw create`/`gw join` installs. It replaces the
# Lima-VM appliance this formula used to ship (preserved at repo tag
# lima-era-archive) — see docs/macos.md for what changed and the migration.
class Greasewood < Formula
  desc "Minimal self-hosted WireGuard mesh overlay"
  homepage "https://github.com/cschlick/greasewood"
  url "https://github.com/cschlick/greasewood/archive/refs/tags/v0.6.0.tar.gz"
  sha256 "1b7b4a310285784ccaca5fba74f6539a6814712789781fb2e390a6ae73d83060" # pinned by release-brew.sh
  license "MIT"

  # Bottle hosted in the tap (bottles/ dir) — built by hand on macOS/arm64
  # per release and pinned here afterwards. It is what makes `brew install`
  # work on a Mac WITHOUT the Xcode CLT: the formula itself compiles nothing
  # (wheels), but Homebrew's source-build gate refuses any non-bottled
  # install without the CLT. (GitHub's macOS runners lag the OS a version, so
  # their bottles would carry the wrong tag for current Macs — hence by hand.)
  # The block is (re)added after the release's bottle is built; a stale
  # previous-version block would make brew chase a bottle that doesn't exist.
  bottle do
    root_url "https://raw.githubusercontent.com/cschlick/homebrew-tap/main/bottles"
    rebuild 1
    sha256 arm64_tahoe: "136729ad6ace0fcec76002fbbdda4037f003d07cba7da1ba56ad4d7d985ecd00"
  end
  head "https://github.com/cschlick/greasewood.git", branch: "main"

  depends_on "python@3.13"
  depends_on "wireguard-go"
  depends_on "wireguard-tools"

  def install
    # A PLAIN venv with a real pip — deliberately not Homebrew's
    # virtualenv_create, which builds a pip-less venv and drives its own
    # vendored pip with --no-binary. Wheels are the point here: cryptography
    # from source needs a rust toolchain (and the CLT), which is exactly the
    # install friction this project avoids; the wheel is the same artifact
    # the Linux pipx install uses. greasewood itself is pure Python.
    system Formula["python@3.13"].opt_bin/"python3.13", "-m", "venv", libexec
    system libexec/"bin/pip", "install", "--quiet", "cryptography>=42.0"
    system libexec/"bin/pip", "install", "--quiet", buildpath
    bin.install_symlink libexec/"bin/gw"
  end

  def caveats
    <<~EOS
      greasewood needs root for the data plane (utun, routes, /etc/hosts):

        sudo gw create <mesh>     # start a new mesh (this Mac is the anchor)
        sudo gw join <token>      # or join an existing one

      Both install a launchd daemon (com.greasewood.<mesh>) that starts at
      boot and restarts on failure. Logs: /var/log/greasewood/<mesh>.log

      Port enforcement (the grant table's port scopes) is not available on
      macOS yet — a pf backend is planned. Tunnel-level access control is
      fully enforced.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/gw --version")
  end
end
