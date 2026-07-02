"""
Integration test for the managed /etc/hosts block (name resolution, on by default).

A hub should, once its daemon is up, write a marked block mapping its overlay
address to "<hostname>.gw.internal" — validating the config-write → reconcile →
/etc/hosts path end to end. hosts_sync is on by default (no flag needed).
"""
import time

import pytest

from .helpers import container_ipv6, pexec, podman, wait_for_control_plane

pytestmark = pytest.mark.integration


def test_hub_writes_managed_hosts_block(gw_image, gw_network):
    cid = None
    try:
        cid = podman(
            "run", "-d", "--privileged", "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        ).stdout.strip()
        time.sleep(1)
        ipv6 = container_ipv6(cid, gw_network)

        pexec(cid, "gw", "create", "--hostname", "hubby",
              "--endpoint", f"[{ipv6}]:51900")   # hosts_sync on by default
        cfg = pexec(cid, "cat", "/etc/greasewood.toml").stdout
        assert "hosts_sync = true" in cfg, cfg

        podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")
        assert wait_for_control_plane(cid, timeout=20)

        block = ""
        for _ in range(15):
            block = pexec(cid, "cat", "/etc/hosts").stdout
            if "BEGIN greasewood" in block and "hubby.gw.internal" in block:
                break
            time.sleep(2)
        assert "BEGIN greasewood" in block, f"no managed block:\n{block}"
        # the overlay address maps to the mesh name
        assert any("hubby.gw.internal" in ln and "fd8d:" in ln
                   for ln in block.splitlines()), block
        # user lines preserved
        assert "localhost" in block
    finally:
        if cid:
            podman("rm", "-f", cid, check=False)
