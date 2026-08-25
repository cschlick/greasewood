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
  include Language::Python::Virtualenv

  desc "Minimal self-hosted WireGuard mesh overlay"
  homepage "https://github.com/cschlick/greasewood"
  url "https://github.com/cschlick/greasewood/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # pinned by release-brew.sh
  license "MIT"
  head "https://github.com/cschlick/greasewood.git", branch: "main"

  depends_on "python@3.13"
  depends_on "wireguard-go"
  depends_on "wireguard-tools"

  def install
    venv = virtualenv_create(libexec, "python3.13")
    # cryptography first, as a WHEEL: building it from source needs a rust
    # toolchain (and the CLT), which is exactly the install friction this
    # project avoids. The wheel is the same artifact the Linux pipx install
    # uses. greasewood itself is pure Python and builds from the tarball.
    system libexec/"bin/pip", "install", "cryptography>=42.0"
    venv.pip_install_and_link buildpath
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
