"""
Menu invite, end to end: ONE standing invite with --self-roles, joiners
self-select DIFFERENT classes off it, and an out-of-menu pick is refused — the
auto-provisioning use case on real containers.
"""
import time

import pytest

from .conftest import make_anchor, _ENROLL_LOCK, _extract_token, container_addr
from .helpers import pexec, podman, wait_for_hostname

pytestmark = pytest.mark.integration


def _fresh(gw_image, gw_network):
    cid = podman("run", "-d", "--privileged", "--network", gw_network,
                 "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                 gw_image, "sleep", "infinity").stdout.strip()
    time.sleep(1)
    return cid, container_addr(cid, gw_network)


def _cfg(cid):
    return pexec(cid, "sh", "-c", "cat /etc/greasewood_*.toml").stdout


def test_menu_invite_self_select_roles(gw_image, gw_network):
    anchor = make_anchor(gw_image, gw_network)
    cids = []
    try:
        with _ENROLL_LOCK:
            # ONE standing menu invite for all classes.
            res = pexec(anchor["cid"], "gw", "invite", "--standing",
                        "--self-roles", "web,db,cache",
                        "--endpoint", anchor["ipv6"], "-q")
            token = _extract_token(res.stdout + "\n" + res.stderr)

            # A joiner self-selects 'web'.
            w_cid, w_ip = _fresh(gw_image, gw_network); cids.append(w_cid)
            j = pexec(w_cid, "gw", "join", token, "--endpoint", f"[{w_ip}]:51900",
                      "--hostname", "web1", "--roles", "web", check=False)
            assert j.returncode == 0, f"web join failed:\n{j.stdout}\n{j.stderr}"
            assert wait_for_hostname(anchor["cid"], "web1", timeout=20)
            assert "role:web" in _cfg(w_cid) and "role:db" not in _cfg(w_cid)

            # A DIFFERENT joiner self-selects 'db' on the SAME standing token.
            d_cid, d_ip = _fresh(gw_image, gw_network); cids.append(d_cid)
            j = pexec(d_cid, "gw", "join", token, "--endpoint", f"[{d_ip}]:51900",
                      "--hostname", "db1", "--roles", "db", check=False)
            assert j.returncode == 0, f"db join failed:\n{j.stdout}\n{j.stderr}"
            assert wait_for_hostname(anchor["cid"], "db1", timeout=20)
            assert "role:db" in _cfg(d_cid) and "role:web" not in _cfg(d_cid)

            # An out-of-menu pick is REFUSED, and the menu is named.
            x_cid, x_ip = _fresh(gw_image, gw_network); cids.append(x_cid)
            j = pexec(x_cid, "gw", "join", token, "--endpoint", f"[{x_ip}]:51900",
                      "--hostname", "admin1", "--roles", "admin", check=False)
            assert j.returncode != 0, "out-of-menu role was NOT refused"
            out = j.stdout + j.stderr
            assert "not offered" in out and "web, db, cache" in out
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
        podman("rm", "-f", anchor["cid"], check=False)
