"""
Integration: --enforce-ports actually filters on kernel nftables.

The claim the unit tests can't make: on a real mesh with a real grant table and
a real nftables ruleset, a GRANTED port passes and an UNGRANTED port on the SAME
(granted) tunnel is dropped. Also the fail-closed posture — the table persists
across a daemon stop, and the roleless/anchor-hardwired paths hold.
"""
import time

import pytest

from .conftest import bring_up_node, make_anchor
from .helpers import podman, pexec, wait_for_ping

pytestmark = pytest.mark.integration


def _apply(anchor_cid: str, toml: str) -> str:
    podman("exec", anchor_cid, "sh", "-c",
           f'cat > "$(ls -d /var/lib/greasewood_*)"/grants.toml <<\'EOF\'\n{toml}\nEOF')
    return pexec(anchor_cid, "gw", "policy", "apply", "-y").stdout


# a tiny TCP listener on two ports, so we can probe granted vs ungranted
_LISTENER = r'''
import socket, sys, threading
def serve(p):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", p)); s.listen(8)
    while True:
        c,_ = s.accept(); c.sendall(b"OK"); c.close()
for p in (8000, 9999):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
import time; time.sleep(100000)
'''

_PROBE = r'''
import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((addr, port), timeout=3)
    print("REACH" if s.recv(2) == b"OK" else "NODATA")
except Exception as e:
    print("BLOCKED")
'''


def test_ports_are_filtered_within_a_granted_tunnel(gw_image, gw_network):
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="pfanchor")
        cids.append(anchor["cid"])
        # web is a client; api is the server. Enforce on the api node.
        web = bring_up_node(gw_image, gw_network, anchor, hostname="web1", roles="web")
        cids.append(web["cid"])
        api = bring_up_node(gw_image, gw_network, anchor, hostname="api1",
                            roles="api", run_args=["--enforce-ports"])
        cids.append(api["cid"])

        # grant web -> api : tcp/8000 ONLY (9999 is deliberately ungranted)
        out = _apply(anchor["cid"],
                     '[[grant]]\nfrom = ["web"]\nto = ["api"]\nports = ["tcp/8000"]')
        assert "web1 ↔ api1" not in out or "api1" in out  # applied (no crash)

        # the tunnel must exist (web→api is granted)
        assert wait_for_ping(web["cid"], api["overlay"], timeout=60), \
            "granted web→api tunnel never formed"

        # give reconcile a couple of cycles to install the nftables table
        deadline = time.time() + 40
        got = False
        while time.time() < deadline:
            r = pexec(api["cid"], "nft", "list", "table", "inet", "greasewood",
                      check=False)
            if r.returncode == 0 and "p_tcp_8000" in r.stdout:
                got = True
                break
            time.sleep(3)
        assert got, "the greasewood nftables table never appeared on the api node"

        # start the two-port listener on the api node
        podman("exec", "-d", api["cid"], "python3", "-c", _LISTENER)
        time.sleep(2)

        # from web: the GRANTED port passes, the UNGRANTED port on the same
        # tunnel is dropped.
        granted = pexec(web["cid"], "python3", "-c", _PROBE,
                        api["overlay"], "8000").stdout.strip()
        ungranted = pexec(web["cid"], "python3", "-c", _PROBE,
                          api["overlay"], "9999").stdout.strip()
        assert granted == "REACH", f"granted tcp/8000 should pass, got {granted!r}"
        assert ungranted == "BLOCKED", \
            f"ungranted tcp/9999 must be dropped, got {ungranted!r}"

        # fail-closed: stop the daemon; the table (and its drop) persists.
        pexec(api["cid"], "pkill", "-f", "[g]w.*run", check=False)
        time.sleep(3)
        r = pexec(api["cid"], "nft", "list", "table", "inet", "greasewood",
                  check=False)
        assert r.returncode == 0 and "drop" in r.stdout, \
            "enforcement table must persist across daemon stop (fail closed)"
        still = pexec(web["cid"], "python3", "-c", _PROBE,
                      api["overlay"], "9999").stdout.strip()
        assert still == "BLOCKED", "ungranted port must stay blocked with no daemon"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
