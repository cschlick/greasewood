"""
A mesh of NO-nftables hosts — end to end.

The restart-loop bug lived exactly here: a daemon on a host without nftables that
still tried to enforce ports would sys.exit and crash-loop under systemd. Now:
create/join must detect no nft and write enforce_ports=false, the daemon must
RUN (unenforced, not crash-loop), the mesh must still form (grants gate tunnels;
only per-port scopes are skipped), and gw watch must render with the firewall
surface degraded (host-firewall block omitted, gw-table honest about no table).

nft is present in the test image, so we move it off PATH to make a genuine no-nft
host BEFORE create/join, so detection sees its absence.
"""
import time

from .helpers import (podman, pexec, container_addr, wait_for_control_plane,
                      wait_for_ping)
from .conftest import (_ep, _extract_token, _wait_iface_gone,
                       overlay_addr_from_id_pub, _ENROLL_LOCK)


def _start(gw_network):
    cid = podman("run", "-d", "--privileged", "--network", gw_network,
                 "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                 "greasewood-test:latest", "sleep", "infinity").stdout.strip()
    time.sleep(1)
    return cid


def _disable_nft(cid):
    """Move nft off PATH → a genuine no-nftables host (shutil.which returns None)."""
    pexec(cid, "sh", "-c", 'mv "$(command -v nft)" /root/nft.disabled')
    assert pexec(cid, "sh", "-c", "command -v nft || true").stdout.strip() == "", \
        "nft still on PATH"


def _tail(cid):
    return pexec(cid, "sh", "-c", "tail -20 /tmp/gw.log", check=False).stdout


def test_no_nft_mesh_forms_unenforced(gw_image, gw_network):
    anchor = node = None
    try:
        # --- anchor with no nftables ---
        anchor = _start(gw_network)
        a_ipv6 = container_addr(anchor, gw_network)
        _disable_nft(anchor)
        pexec(anchor, "gw", "create", "nonftmesh", "--hostname", "anchor",
              "--endpoint", _ep(a_ipv6, 51900))
        assert "enforce_ports = false" in \
            pexec(anchor, "sh", "-c", "cat /etc/greasewood_*.toml").stdout, \
            "create should detect no nft and write enforce_ports=false"
        podman("exec", "-d", anchor, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")
        assert wait_for_control_plane(anchor, timeout=20), \
            "no-nft anchor daemon did not come up (restart loop?):\n" + _tail(anchor)

        # --- node with no nftables ---
        node = _start(gw_network)
        n_ipv6 = container_addr(node, gw_network)
        _disable_nft(node)
        with _ENROLL_LOCK:
            tok = _extract_token(pexec(anchor, "gw", "invite", "--endpoint", a_ipv6).stdout)
            j = pexec(node, "gw", "join", tok, "--endpoint", _ep(n_ipv6, 51900), check=False)
            assert j.returncode == 0, f"join failed:\n{j.stdout}\n{j.stderr}"
            _wait_iface_gone(anchor, "gw-door")
        assert "enforce_ports = false" in \
            pexec(node, "sh", "-c", "cat /etc/greasewood_*.toml").stdout
        podman("exec", "-d", node, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

        # --- the mesh forms without port enforcement ---
        a_overlay = overlay_addr_from_id_pub(
            pexec(anchor, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip())
        assert wait_for_ping(node, a_overlay, timeout=40), \
            "no-nft node never reached the anchor overlay:\n" + _tail(node)

        # --- gw watch renders with the firewall surface degraded ---
        out = pexec(anchor, "sh", "-c", "gw watch --snapshot").stdout
        assert "main firewall" not in out            # host-firewall check omitted (no nft)
        assert "port enforcement off" in out          # gw-table block honest
        assert "anchor" in out                        # roster still renders
    finally:
        for cid in (node, anchor):
            if cid:
                podman("rm", "-f", cid, check=False)
