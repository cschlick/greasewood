# Homebrew formula — the source of truth lives in the main repo; after
# tagging a release, `sh scripts/release-brew.sh` pins the tag's tarball
# sha256 here and pushes the copy the tap (cschlick/homebrew-tap) serves.
#
# greasewood has no macOS build, on purpose (see docs/macos.md): the daemon is
# Linux-only, and a Mac joins a mesh via a minimal Lima VM. What brew installs
# is the Mac side of that story:
#   gw      run greasewood's CLI inside the node VM, from a Mac terminal
#   gw-mac  create/start the VM, route the whole Mac into the overlay
# plus the VM recipes and gateway files under <prefix>/share/greasewood.
class Greasewood < Formula
  desc "WireGuard mesh node on macOS — Lima VM appliance + Mac-side tooling"
  homepage "https://github.com/cschlick/greasewood"
  url "https://github.com/cschlick/greasewood/archive/refs/tags/v0.1.3.tar.gz"
  sha256 "d4c0330e9d0c60ab48353abeee6286b8c33e57ba313f9201533ba60255a9f2fc"
  license "MIT"
  head "https://github.com/cschlick/greasewood.git", branch: "main"

  depends_on "lima"

  def install
    ex = "docs/examples"
    bin.install "#{ex}/gw-shim.sh" => "gw"
    bin.install "#{ex}/gw-mac-net.sh" => "gw-mac"
    pkgshare.install "#{ex}/greasewood-node.yaml",
                     "#{ex}/greasewood-node-alpine.yaml",
                     "#{ex}/gw-mac-gateway.nft",
                     "#{ex}/gw-mac-gateway.sysctl.conf",
                     "#{ex}/gw-mac-gateway.service",
                     "#{ex}/gw-mac-gateway.initd",
                     "#{ex}/gw-mac-priv.sh"
    doc.install "docs/macos.md"
  end

  # `gw-mac up` is an idempotent reconciler: VM started if stopped, mesh route
  # reinstalled if gone (reboot kills it — macOS routes aren't files), hosts
  # block resynced if drifted. Headless root needs the one-time
  # `sudo gw-mac install-autostart` (see caveats).
  service do
    run [opt_bin/"gw-mac", "up"]
    run_type :interval
    interval 120
    log_path var/"log/gw-mac.log"
    error_log_path var/"log/gw-mac.log"
    environment_variables PATH: std_service_path_env
  end

  def caveats
    <<~EOS
      The node runs in a Lima VM; these commands drive it from the Mac:
        gw-mac         first run creates the VM; afterwards it starts the VM,
                       routes this Mac into the overlay, and syncs mesh names
        gw <command>   greasewood's CLI, run inside the VM (gw watch, gw join …)

      To join a mesh:
        gw-mac                                        # creates the VM
        # on your anchor:  sudo gw invite --hostname greasewood-node
        gw join <token>
        gw-mac                                        # routes the Mac in

      The mesh route is not persistent — rerun `gw-mac` after a reboot, or let
      it run itself:
        sudo gw-mac install-autostart   # once: root helper + scoped sudoers rule
        brew services start greasewood  # 'gw-mac up' every 2 min at login
    EOS
  end

  test do
    assert_match "usage: gw-mac", shell_output("#{bin}/gw-mac help 2>&1", 2)
  end
end
