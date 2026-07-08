"""Tests for the HTTP control plane — directory, publish, renew endpoints."""
import datetime as dt
import json
import socket
import threading
import urllib.request

import pytest

import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from greasewood.ca import CA
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.server import ControlServer
from greasewood.wire import Credential, NodeRecord, RenewRequest, CertRequest

_UTC = dt.timezone.utc


def _make_cred(node: NodeKeys, ca: CAKeys, ttl: int = 3600,
               hostname: str = "test-node") -> Credential:
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes,
        wg_pub=node.wg_pub_bytes,
        addr=node.addr,
        hostname=hostname,
        caps=["mesh"],
        iat=now,
        exp=now + dt.timedelta(seconds=ttl),
    ).sign(ca.ca_priv)


def _make_record(node: NodeKeys, cred: Credential, seq: int = 1) -> NodeRecord:
    return NodeRecord(
        id_pub=node.id_pub_bytes,
        seq=seq,
        endpoints=["[2001:db8::1]:51820"],
        cred=cred,
    ).sign(node.id_priv)


@pytest.fixture
def ca_and_node():
    ca = CAKeys.generate()
    node = NodeKeys.generate()
    cred = _make_cred(node, ca)
    record = _make_record(node, cred)
    return ca, node, cred, record


@pytest.fixture
def running_server(ca_and_node, tmp_path):
    """Start a ControlServer on a free IPv6 loopback port; yield (srv, port)."""
    ca, node, cred, record = ca_and_node
    directory = Directory()
    directory.put(record)

    ca_obj = CA(CAKeys.generate(), tmp_path)  # separate CA for renewal tests
    # Use the real CA for verification
    ca_keys = ca

    srv = ControlServer(
        listen="[::1]:0",  # OS picks a free port
        directory=directory,
        get_ca_pubs=lambda: [ca.ca_pub_bytes],
        get_revoked=set,
        ca=None,  # no renewal in basic fixture
    )

    # Grab the actual bound port
    port = srv._server.server_address[1]

    thread = srv.start()
    yield srv, port, directory, ca, node, cred
    srv.stop()


def _get(port: int, path: str) -> dict:
    url = f"http://[::1]:{port}{path}"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post(port: int, path: str, data: dict) -> tuple[int, dict | None]:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"http://[::1]:{port}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, None  # send_error() returns HTML, not JSON


class TestServerIPv6Binding:
    def test_binds_ipv6(self, running_server):
        srv, port, *_ = running_server
        assert srv._server.address_family == socket.AF_INET6

    def test_health_reachable(self, running_server):
        _, port, *_ = running_server
        data = _get(port, "/health")
        assert data["status"] == "ok"


class TestCertSanAuthorization:
    """A node may only get a cert for names it owns — its <hostname>.<domain>,
    subdomains of it, and its own overlay address. Otherwise a tls-capable node
    could mint a cert for another node's name and impersonate it."""

    def _anchor_with_tls_node(self, tmp_path, hostname="db"):
        ca_keys = CAKeys.generate()
        ca = CA(ca_keys, tmp_path)
        node = NodeKeys.generate()
        ca.issue(node.id_pub_bytes, node.wg_pub_bytes, hostname, ["mesh", "tls"])
        srv = ControlServer(
            listen="[::1]:0", directory=Directory(),
            get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
            ca=ca, mesh_domain="internal",
        )
        port = srv._server.server_address[1]
        srv.start()
        return srv, port, node

    def _req(self, node, dns=None, ips=None):
        leaf = Ed25519PrivateKey.generate()
        leaf_pub = leaf.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return CertRequest(
            id_pub=node.id_pub_bytes, leaf_pub=leaf_pub, cn="",
            dns=dns or [], ips=ips or [], nonce=secrets.token_hex(8),
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv).to_dict()

    def test_own_name_issued(self, tmp_path):
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["db.internal"]))
            assert status == 200 and "cert" in body
        finally:
            srv.stop()

    def test_subdomain_of_own_name_issued(self, tmp_path):
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["pg.db.internal"]))
            assert status == 200, body
        finally:
            srv.stop()

    def test_foreign_name_refused(self, tmp_path):
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["other.internal"]))
            assert status == 403 and "not authorized" in body["error"]
        finally:
            srv.stop()

    def test_foreign_ip_refused(self, tmp_path):
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert",
                                 self._req(node, ips=["fd8d:e5c1:db1a:7::dead"]))
            assert status == 403
        finally:
            srv.stop()

    def test_default_san_is_own_name(self, tmp_path):
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node))  # no SANs
            assert status == 200 and "cert" in body
        finally:
            srv.stop()

    def test_wrong_length_leaf_pub_is_400_not_500(self, tmp_path):
        """A validly-signed cert request carrying a non-32-byte leaf_pub must be
        a clean 400 — not a 500 from Ed25519PublicKey.from_public_bytes blowing
        up deep inside issuance. (The fuzz suite can't reach this: it mutates
        after signing, so a bad leaf_pub breaks the self-sig first.)"""
        srv, port, node = self._anchor_with_tls_node(tmp_path, "db")
        try:
            req = CertRequest(
                id_pub=node.id_pub_bytes, leaf_pub=b"short", cn="",
                dns=[], ips=[], nonce=secrets.token_hex(8),
                ts=dt.datetime.now(_UTC).replace(microsecond=0),
            ).sign(node.id_priv).to_dict()
            status, body = _post(port, "/cert", req)
            assert status == 400, f"expected 400, got {status}: {body}"
            assert "leaf_pub" in body["error"]
        finally:
            srv.stop()


class TestRerootReissue:
    """The re-root fallback: an anchor that never enrolled a node (no local
    node_info) still renews it if it holds a directory record for that identity
    signed by a currently-trusted CA — using the record's CA-attested
    hostname/caps. This is what lets nodes migrate to a new anchor without copying
    the nodes/ directory."""

    def _anchor_b(self, tmp_path, trusted, directory):
        """Server for anchor B (its own CA) that trusts the CAs in `trusted`."""
        b_ca = CAKeys.generate()
        srv = ControlServer(
            listen="[::1]:0", directory=directory,
            get_ca_pubs=lambda: [c.ca_pub_bytes for c in trusted],
            get_revoked=set, ca=CA(b_ca, tmp_path),
        )
        return srv, srv._server.server_address[1], b_ca

    def _renew_req(self, node):
        return RenewRequest(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes, nonce="rr",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv).to_dict()

    def test_reissues_from_trusted_old_record(self, tmp_path):
        a_ca = CAKeys.generate()          # the outgoing anchor's CA
        node = NodeKeys.generate()
        # A record issued by the OLD anchor (A), present in B's directory.
        cred_a = _make_cred(node, a_ca, hostname="db")
        directory = Directory()
        directory.put(_make_record(node, cred_a))
        # B trusts both its own CA and A during the overlap.
        srv, port, b_ca = self._anchor_b(tmp_path, trusted=[a_ca], directory=directory)
        srv.start()
        try:
            status, body = _post(port, "/renew", self._renew_req(node))
            assert status == 200, body
            new = Credential.from_dict(body)
            new.verify([b_ca.ca_pub_bytes])          # now signed by B's CA
            assert new.hostname == "db"              # attested name carried over
        finally:
            srv.stop()

    def test_unknown_without_record_still_refused(self, tmp_path):
        a_ca = CAKeys.generate()
        node = NodeKeys.generate()
        srv, port, _ = self._anchor_b(tmp_path, trusted=[a_ca], directory=Directory())
        srv.start()
        try:
            status, body = _post(port, "/renew", self._renew_req(node))
            assert status == 400 and "unknown node" in body["error"]
        finally:
            srv.stop()

    def test_untrusted_old_record_refused(self, tmp_path):
        a_ca = CAKeys.generate()          # a CA B does NOT trust
        node = NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(node, _make_cred(node, a_ca, hostname="db")))
        # B trusts only itself — the old record's CA is not in the trusted set.
        srv, port, _ = self._anchor_b(tmp_path, trusted=[], directory=directory)
        srv.start()
        try:
            status, body = _post(port, "/renew", self._renew_req(node))
            assert status == 400 and "unknown node" in body["error"]
        finally:
            srv.stop()

    def test_revoked_node_not_reissued_via_fallback(self, tmp_path):
        # A node revoked on B must NOT slip back in through the re-root fallback,
        # even with a still-trusted old record (the RUNBOOK's "re-apply revokes on
        # B before dropping A"). The revoke check in ca.renew fires before the
        # unknown-node path, so the fallback never runs.
        a_ca = CAKeys.generate()
        node = NodeKeys.generate()
        directory = Directory()
        directory.put(_make_record(node, _make_cred(node, a_ca, hostname="db")))
        b_ca = CAKeys.generate()
        b = CA(b_ca, tmp_path)
        b.add_revoke(node.id_pub_bytes)                 # revoked on the new anchor
        srv = ControlServer(listen="[::1]:0", directory=directory,
                            get_ca_pubs=lambda: [a_ca.ca_pub_bytes],
                            get_revoked=set, ca=b)
        port = srv._server.server_address[1]
        srv.start()
        try:
            status, body = _post(port, "/renew", self._renew_req(node))
            assert status == 400
            assert "revoke" in body["error"].lower()    # refused, not re-issued
        finally:
            srv.stop()


class TestCaCertEndpoint:
    def test_ca_cert_served_when_anchor_has_ca(self, tmp_path):
        ca_keys = CAKeys.generate()
        ca = CA(ca_keys, tmp_path)
        srv = ControlServer(
            listen="[::1]:0", directory=Directory(),
            get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set, ca=ca,
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            data = _get(port, "/ca-cert")
            assert "BEGIN CERTIFICATE" in data["ca_cert"]
        finally:
            srv.stop()

    def test_ca_cert_404_without_ca(self, running_server):
        import urllib.error
        _, port, *_ = running_server  # fixture builds the server with ca=None
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(port, "/ca-cert")
        assert e.value.code == 404


class TestAnchorClock:
    """The anchor stamps its own UTC time into /health and /directory so nodes
    (sync loop, gw diagnose) can detect clock skew — the silent killer of an
    expiry-based trust system — instead of mis-diagnosing it as bad creds."""

    def _assert_recent_utc(self, raw: str):
        ts = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        assert ts.tzinfo is not None
        assert abs((dt.datetime.now(_UTC) - ts).total_seconds()) < 30

    def test_health_carries_anchor_time(self, running_server):
        _, port, *_ = running_server
        data = _get(port, "/health")
        self._assert_recent_utc(data["now"])

    def test_directory_carries_anchor_time(self, running_server):
        _, port, *_ = running_server
        data = _get(port, "/directory")
        self._assert_recent_utc(data["now"])


class TestDirectoryEndpoint:
    def test_returns_records(self, running_server):
        _, port, directory, ca, node, cred = running_server
        data = _get(port, "/directory")
        assert isinstance(data, dict)
        assert "renew_after" in data          # fleet renew hint (None unless set)
        recs = data["records"]
        assert len(recs) == 1
        assert recs[0]["cred"]["hostname"] == "test-node"

    def test_empty_directory(self, ca_and_node, tmp_path):
        srv = ControlServer(
            listen="[::1]:0",
            directory=Directory(),
            get_ca_pubs=lambda: [],
            get_revoked=set,
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            data = _get(port, "/directory")
            assert data["records"] == [] and data["renew_after"] is None
        finally:
            srv.stop()

    def test_serves_renew_after_hint(self, ca_and_node, tmp_path):
        # The fleet renew hint is read fresh per request via get_renew_after.
        srv = ControlServer(
            listen="[::1]:0",
            directory=Directory(),
            get_ca_pubs=lambda: [],
            get_revoked=set,
            get_renew_after=lambda: "2026-07-01T12:00:00+00:00",
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            data = _get(port, "/directory")
            assert data["renew_after"] == "2026-07-01T12:00:00+00:00"
        finally:
            srv.stop()


class TestPublishEndpoint:
    def test_valid_record_accepted(self, running_server):
        _, port, directory, ca, node, cred = running_server
        node2 = NodeKeys.generate()
        cred2 = _make_cred(node2, ca)
        record2 = _make_record(node2, cred2)

        status, body = _post(port, "/publish", record2.to_dict())
        assert status == 200
        assert body == {"status": "ok"}
        assert directory.get(node2.id_pub_hex) is not None

    def test_tampered_record_rejected(self, running_server):
        from dataclasses import replace
        _, port, directory, ca, node, cred = running_server
        node2 = NodeKeys.generate()
        cred2 = _make_cred(node2, ca)
        record2 = _make_record(node2, cred2)
        bad = replace(record2, endpoints=["[2001:db8::99]:1"])  # invalidates self-sig

        status, body = _post(port, "/publish", bad.to_dict())
        assert status == 400
        assert "error" in body

    def test_expired_credential_rejected(self, running_server):
        _, port, directory, ca, node, cred = running_server
        node2 = NodeKeys.generate()
        cred2 = _make_cred(node2, ca, ttl=-1)  # already expired
        record2 = _make_record(node2, cred2)

        status, body = _post(port, "/publish", record2.to_dict())
        assert status == 400
        assert "error" in body

    def test_revoked_node_rejected(self, ca_and_node, tmp_path):
        ca, node, cred, record = ca_and_node
        directory = Directory()
        revoked = {node.id_pub_bytes.hex()}
        srv = ControlServer(
            listen="[::1]:0",
            directory=directory,
            get_ca_pubs=lambda: [ca.ca_pub_bytes],
            get_revoked=lambda: revoked,
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            status, body = _post(port, "/publish", record.to_dict())
            assert status == 400
        finally:
            srv.stop()

    def test_higher_seq_replaces_lower(self, running_server):
        _, port, directory, ca, node, cred = running_server
        # node already has seq=1 in directory; publish seq=2
        record2 = _make_record(node, cred, seq=2)
        _post(port, "/publish", record2.to_dict())
        assert directory.get(node.id_pub_hex).seq == 2


class TestRenewEndpoint:
    def test_no_renew_without_ca(self, running_server):
        _, port, *_ = running_server
        status, body = _post(port, "/renew", {})
        assert status == 403

    def test_renew_with_ca(self, tmp_path):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = _make_cred(node, ca)
        record = _make_record(node, cred)

        directory = Directory()
        directory.put(record)

        ca_obj = CA(ca, tmp_path)
        # Pre-populate node caps so renewal works
        ca_obj._save_node_caps(node.id_pub_bytes, "test-node", ["mesh"])

        srv = ControlServer(
            listen="[::1]:0",
            directory=directory,
            get_ca_pubs=lambda: [ca.ca_pub_bytes],
            get_revoked=set,
            ca=ca_obj,
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            import secrets
            req = RenewRequest(
                id_pub=node.id_pub_bytes,
                wg_pub=node.wg_pub_bytes,
                nonce=secrets.token_hex(16),
                ts=dt.datetime.now(_UTC).replace(microsecond=0),
            ).sign(node.id_priv)
            status, body = _post(port, "/renew", req.to_dict())
            assert status == 200
            new_cred = Credential.from_dict(body)
            new_cred.verify([ca.ca_pub_bytes])

            # Replaying the exact same signed request must be rejected (the
            # nonce is now spent), not silently re-issued.
            status2, body2 = _post(port, "/renew", req.to_dict())
            assert status2 == 400
            assert "replay" in body2.get("error", "").lower()
        finally:
            srv.stop()


class TestRenewalPropagation:
    def test_renewal_republishes_to_anchor(self, tmp_path):
        """After renewing, the node must re-publish so the anchor (and thus peers,
        which pull from the anchor) sees the fresh credential — otherwise the mesh
        tears down one credential TTL after start."""
        from greasewood.renewal import RenewalLoop

        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = _make_cred(node, ca, ttl=3600)
        record = _make_record(node, cred, seq=1)

        anchor_dir = Directory()          # the anchor's directory
        anchor_dir.put(record)            # node's initial (seq=1) record on the anchor
        ca_obj = CA(ca, tmp_path)
        ca_obj._save_node_caps(node.id_pub_bytes, "test-node", ["mesh"])

        srv = ControlServer(
            listen="[::1]:0", directory=anchor_dir,
            get_ca_pubs=lambda: [ca.ca_pub_bytes], get_revoked=set, ca=ca_obj,
        )
        port = srv._server.server_address[1]
        srv.start()
        try:
            own_dir = Directory()               # node's own (separate) directory
            own_dir.put(record)                 # the node knows its own seq=1 record
            loop = RenewalLoop(
                node_keys=node,
                directory=own_dir,
                get_anchor_url=lambda: f"http://[::1]:{port}",
                current_cred=cred,
                hostname="test-node",
                endpoints=["[2001:db8::1]:51900"],
                cache_path=tmp_path / "dir.json",
            )
            loop._renew_and_publish()
            # The anchor's directory now carries the renewed (seq=2) record.
            on_anchor = anchor_dir.get(node.id_pub_hex)
            assert on_anchor is not None and on_anchor.seq == 2
            on_anchor.cred.verify([ca.ca_pub_bytes])  # fresh, valid credential
        finally:
            srv.stop()


class TestControlServerConcurrency:
    """The control plane serves the whole fleet from one process. A single
    stalled or malicious client (mesh-authenticated or on loopback) must not be
    able to wedge /renew, /publish, and /directory for everyone: requests are
    handled concurrently, and a connection that stops sending is dropped after
    request_timeout."""

    def _stalled_conn(self, port: int) -> socket.socket:
        """Open a connection that sends headers claiming a body, then stalls."""
        s = socket.create_connection(("::1", port), timeout=5)
        s.sendall(
            b"POST /publish HTTP/1.1\r\n"
            b"Host: [::1]\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 4096\r\n"
            b"\r\n"
        )  # ...and never send the body
        return s

    def test_stalled_client_does_not_block_others(self, running_server):
        _, port, *_ = running_server
        stall = self._stalled_conn(port)
        try:
            import time
            time.sleep(0.3)  # let the server start reading the stalled request
            # A concurrent request must still be answered promptly.
            data = _get(port, "/health")
            assert data["status"] == "ok"
        finally:
            stall.close()

    def test_bounded_pool_sheds_load_at_capacity(self, ca_and_node):
        """The worker pool is capped: with all workers occupied by stalled
        clients, a further connection is dropped promptly (not queued forever
        and not spawning an unbounded thread) — and capacity returns once the
        stalls clear. This is the load-shedding backstop for the threaded
        server: a connection flood can't exhaust the anchor."""
        import socket as _socket
        ca, node, cred, record = ca_and_node
        srv = ControlServer(
            listen="[::1]:0", directory=Directory(),
            get_ca_pubs=lambda: [ca.ca_pub_bytes], get_revoked=set,
            request_timeout=10.0, max_workers=2,
        )
        port = srv._server.server_address[1]
        srv.start()
        stalls = []
        try:
            import time
            # Occupy both workers with stalled requests.
            for _ in range(2):
                stalls.append(self._stalled_conn(port))
            time.sleep(0.5)  # let the server admit both into the pool

            # A further connection must be dropped fast (server closes it),
            # not hang for the full 10s request timeout.
            over = _socket.create_connection(("::1", port), timeout=5)
            try:
                over.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                over.settimeout(3)
                # Dropped → EOF (b"") promptly, well under the 10s timeout.
                assert over.recv(64) == b"", "over-capacity connection was not shed"
            finally:
                over.close()

            # Free the workers; the plane serves again.
            for s in stalls:
                s.close()
            stalls.clear()
            time.sleep(0.5)
            assert _get(port, "/health")["status"] == "ok"
        finally:
            for s in stalls:
                s.close()
            srv.stop()

    def test_stalled_connection_is_dropped_after_timeout(self, ca_and_node):
        ca, node, cred, record = ca_and_node
        srv = ControlServer(
            listen="[::1]:0",
            directory=Directory(),
            get_ca_pubs=lambda: [ca.ca_pub_bytes],
            get_revoked=set,
            request_timeout=1.0,
        )
        port = srv._server.server_address[1]
        srv.start()
        stall = self._stalled_conn(port)
        try:
            stall.settimeout(5)
            # The server must give up on the stalled read and close the
            # connection (it may send a 400 first) rather than holding it open
            # forever. If it never closes, recv times out and the test fails.
            try:
                while stall.recv(4096):
                    pass  # drain any error response until EOF
            except socket.timeout:
                pytest.fail("server kept the stalled connection open past its "
                            "request_timeout")
        finally:
            stall.close()
            srv.stop()


class TestRequestHardening:
    def test_oversized_body_rejected(self, running_server):
        _, port, directory, ca, node, cred = running_server
        huge = {"junk": "A" * (300 * 1024)}  # over the 256 KiB cap
        status, _ = _post(port, "/publish", huge)
        assert status == 400  # rejected, not OOM

    def test_forged_high_seq_record_cannot_shadow(self, running_server):
        """A directory response carrying a forged, high-seq record for a victim
        must not be able to evict/shadow the victim's real record: the forgery
        fails structural verification and never enters the directory."""
        from dataclasses import replace
        _, port, directory, ca, node, cred = running_server
        real = directory.get(node.id_pub_hex)
        assert real.seq == 1
        # Attacker lacks node.id_priv, so any record they craft for node's
        # id_pub has a broken self-signature — even with a huge seq.
        forged = replace(real, seq=999999, endpoints=["[2001:db8::dead]:51900"])
        dropped = directory.merge([forged])  # not signed by node → invalid
        assert dropped == 0
        assert directory.get(node.id_pub_hex).seq == 1


def test_negative_content_length_rejected():
    """A negative Content-Length would make rfile.read(-1) read to EOF, bypassing
    the _MAX_BODY cap. It must be a clean 400, not an unbounded read."""
    import io
    from greasewood import server
    h = server._Handler.__new__(server._Handler)
    h.headers = {"Content-Length": "-1"}
    h.rfile = io.BytesIO(b"{}")
    import pytest
    with pytest.raises(ValueError, match="invalid request body length"):
        h._read_json()


def test_addr_in_use_surfaces_clean_error_not_pool_attributeerror():
    """Regression: when the control port is already bound, the real EADDRINUSE
    must surface as a clear ControlPlaneAddrInUse — not the AttributeError from
    server_close touching _pool before __init__ set it."""
    import socket as _s
    from greasewood import server
    # Hold a port, then ask ControlServer to bind the same one.
    held = _s.socket(_s.AF_INET6, _s.SOCK_STREAM)
    held.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    held.bind(("::1", 0))
    port = held.getsockname()[1]
    held.listen(1)
    try:
        with pytest.raises(server.ControlPlaneAddrInUse) as e:
            server.ControlServer(f"[::1]:{port}", Directory(),
                                 get_ca_pubs=list, get_revoked=set)
        assert "already in use" in str(e.value) and str(port) in str(e.value)
        assert "_pool" not in str(e.value)          # the masking bug is gone
    finally:
        held.close()
