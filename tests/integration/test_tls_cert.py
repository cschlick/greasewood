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
        with cctx.wrap_socket(raw, server_hostname="postgres.dbnode.internal") as cs:
            cs.send(b"hi")
    print("HANDSHAKE_OK")
except Exception as e:
    print("HANDSHAKE_FAIL", repr(e), err)
t.join(timeout=5)
"""


# A real HTTPS server bound to the node's OVERLAY address, using the hub-issued
# leaf cert+key. argv: <overlay-addr> <port>.
_TLS_WEB_SERVER = r"""
import ssl, sys, socket
from http.server import BaseHTTPRequestHandler, HTTPServer
addr, port = sys.argv[1], int(sys.argv[2])
d = "/tmp/tls"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(d + "/server.crt", d + "/server.key")
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-over-mesh-tls"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
class S(HTTPServer):
    address_family = socket.AF_INET6
httpd = S((addr, port), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"""

# The client on the OTHER node: connects over the mesh to the server's overlay
# address, trusting only the hub's ca.crt and validating the server's SAN.
# argv: <overlay-addr> <port> <san> <cafile>.
_TLS_WEB_CLIENT = r"""
import ssl, socket, sys, time
addr, port, san, cafile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(cafile=cafile)
last = ""
for _ in range(20):
    try:
        with socket.create_connection((addr, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=san) as s:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + san.encode() + b"\r\n\r\n")
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        print("CLIENT_OK" if b"hello-over-mesh-tls" in data else "CLIENT_FAIL",
              repr(data[-40:]))
        break
    except Exception as e:
        last = repr(e)
        time.sleep(1)
else:
    print("CLIENT_FAIL", last)
"""


def test_tls_service_between_two_nodes_over_mesh(gw_hub, gw_image, gw_network):
    """End-to-end: one node runs an HTTPS server with a hub-issued leaf cert;
    another node connects to it over the overlay and validates the certificate
    against the hub's CA (by SAN). This is the real service-to-service use case —
    a mesh-CA-secured web/DB link between two nodes."""
    cids = []
    try:
        san = "webserver.internal"
        port = "8443"

        server = bring_up_node(gw_image, gw_network, gw_hub,
                               hostname="webserver", caps="mesh,tls")
        cids.append(server["cid"])
        client = bring_up_node(gw_image, gw_network, gw_hub,
                               hostname="webclient", caps="mesh,tls")
        cids.append(client["cid"])

        # The two nodes must have a direct overlay tunnel before we talk TLS.
        assert wait_for_ping(client["cid"], server["overlay"], timeout=40), \
            "client never reached the server over the overlay"

        # Server gets a leaf cert for its service name; client gets the CA cert
        # (cert-request writes ca.crt alongside — that's all the client needs).
        r = pexec(server["cid"], "gw", "cert-request",
                  "--san", san, "--name", "server", "--out-dir", "/tmp/tls",
                  check=False)
        assert r.returncode == 0, f"server cert-request failed:\n{r.stdout}\n{r.stderr}"
        r2 = pexec(client["cid"], "gw", "cert-request",
                   "--san", "webclient.internal", "--name", "client",
                   "--out-dir", "/tmp/tls", check=False)
        assert r2.returncode == 0, f"client cert-request failed:\n{r2.stdout}\n{r2.stderr}"

        # Start the HTTPS server on the server node's overlay address.
        podman("exec", "-d", server["cid"], "python3", "-c", _TLS_WEB_SERVER,
               server["overlay"], port)

        # Client connects over the mesh and validates the hub-issued cert by SAN.
        h = pexec(client["cid"], "python3", "-c", _TLS_WEB_CLIENT,
                  server["overlay"], port, san, "/tmp/tls/ca.crt")
        assert "CLIENT_OK" in h.stdout, \
            f"TLS-over-mesh failed: {h.stdout}\n{h.stderr}"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)


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

        # Request a cert for a service name UNDER this node's own name (dbnode);
        # the hub only issues SANs the node owns.
        r = pexec(node["cid"], "gw", "cert-request",
                  "--san", "postgres.dbnode.internal", "--name", "postgres",
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
        assert "postgres.crt" in st.stdout and "postgres.dbnode.internal" in st.stdout, st.stdout

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
