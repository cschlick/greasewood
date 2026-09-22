"""
A mesh of NO-nftables hosts — end to end.

greasewood installs no packet filter and needs no nftables anywhere: on a host
without nft, create/join must succeed, the daemon must RUN (the restart-loop
bug of the old port-enforcement era lived exactly here), the mesh must form
(grants gate tunnels — pure software), and gw watch must render with the
host-firewall block simply omitted.

nft is present in the test image, so we move it off PATH to make a genuine no-nft
host BEFORE create/join.
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


def test_no_nft_mesh_forms(gw_image, gw_network):
    anchor = node = None
    try:
        # --- anchor with no nftables ---
        anchor = _start(gw_network)
        a_ipv6 = container_addr(anchor, gw_network)
        _disable_nft(anchor)
        pexec(anchor, "gw", "create", "nonftmesh", "--hostname", "anchor",
              "--endpoint", _ep(a_ipv6, 51900))
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
        podman("exec", "-d", node, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

        # --- the mesh forms; no packet filter needed anywhere ---
        a_overlay = overlay_addr_from_id_pub(
            pexec(anchor, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip())
        assert wait_for_ping(node, a_overlay, timeout=40), \
            "no-nft node never reached the anchor overlay:\n" + _tail(node)

        # --- gw watch renders; the host-firewall block is simply omitted ---
        out = pexec(anchor, "sh", "-c", "gw watch --snapshot").stdout
        assert "main firewall" not in out            # host-firewall check omitted (no nft)
        assert "anchor" in out                        # roster still renders
    finally:
        for cid in (node, anchor):
            if cid:
                podman("rm", "-f", cid, check=False)
