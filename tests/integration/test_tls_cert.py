"""
Integration test for TLS service certs (§12).

A node with the `tls` capability requests an x509 cert from the hub and uses it
for a real TLS handshake validated against the returned mesh CA cert — the
Postgres-style use case end to end. Also checks the capability gate.
"""
import pytest

from .conftest import bring_up_node
from .helpers import pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


# An in-process TLS handshake: server uses the issued leaf cert+key, client
# trusts only the returned ca.crt and validates the SAN. Prints HANDSHAKE_OK.
_TLS_HANDSHAKE = r"""
import ssl, socket, threading, sys
d = "/tmp/tls"
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
sctx.load_cert_chain(d + "/postgres.crt", d + "/postgres.key")
cctx = ssl.create_default_context(cafile=d + "/ca.crt")
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.bind(("127.0.0.1", 0)); ls.listen(1)
port = ls.getsockname()[1]
err = {}
def serve():
    try:
        c, _ = ls.accept()
        with sctx.wrap_socket(c, server_side=True) as ss:
            ss.recv(16)
    except Exception as e:
        err["server"] = repr(e)
t = threading.Thread(target=serve); t.start()
try:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with cctx.wrap_socket(raw, server_hostname="postgres.mesh") as cs:
            cs.send(b"hi")
    print("HANDSHAKE_OK")
except Exception as e:
    print("HANDSHAKE_FAIL", repr(e), err)
t.join(timeout=5)
"""


def test_node_requests_and_uses_tls_cert(gw_hub, gw_image, gw_network):
    nodes = []
    try:
        # Node enrolled WITH the tls capability.
        node = bring_up_node(gw_image, gw_network, gw_hub,
                             hostname="dbnode", caps="mesh,tls")
        nodes.append(node["cid"])

        # Wait for the node↔hub overlay tunnel before talking to the control plane.
        assert wait_for_ping(node["cid"], gw_hub["overlay"], timeout=30), \
            "node never reached the hub overlay"

        # Request a cert for a service name.
        r = pexec(node["cid"], "gw", "cert-request",
                  "--san", "postgres.mesh", "--name", "postgres",
                  "--out-dir", "/tmp/tls", check=False)
        assert r.returncode == 0, f"cert-request failed:\n{r.stdout}\n{r.stderr}"

        # Files landed.
        ls = pexec(node["cid"], "ls", "/tmp/tls").stdout.split()
        assert {"postgres.crt", "postgres.key", "ca.crt"} <= set(ls), ls

        # Real TLS handshake validated against the returned mesh CA cert.
        h = pexec(node["cid"], "python3", "-c", _TLS_HANDSHAKE)
        assert "HANDSHAKE_OK" in h.stdout, f"TLS handshake failed: {h.stdout}\n{h.stderr}"

        # cert-status shows it.
        st = pexec(node["cid"], "gw", "cert-status", "--out-dir", "/tmp/tls")
        assert "postgres.crt" in st.stdout and "postgres.mesh" in st.stdout, st.stdout

        # A node WITHOUT the tls cap is refused.
        plain = bring_up_node(gw_image, gw_network, gw_hub, hostname="plainnode")
        nodes.append(plain["cid"])
        r2 = pexec(plain["cid"], "gw", "cert-request",
                   "--san", "x.mesh", "--name", "x", "--out-dir", "/tmp/tls",
                   check=False)
        assert r2.returncode != 0, "cert-request should fail without the tls cap"
        assert "tls" in (r2.stdout + r2.stderr).lower(), (r2.stdout, r2.stderr)
    finally:
        for cid in nodes:
            podman("rm", "-f", cid, check=False)
