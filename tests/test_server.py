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
        inbound="yes",
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
        assert data == {"status": "ok"}


class TestCertSanAuthorization:
    """A node may only get a cert for names it owns — its <hostname>.<domain>,
    subdomains of it, and its own overlay address. Otherwise a tls-capable node
    could mint a cert for another node's name and impersonate it."""

    def _hub_with_tls_node(self, tmp_path, hostname="db"):
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
        srv, port, node = self._hub_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["db.internal"]))
            assert status == 200 and "cert" in body
        finally:
            srv.stop()

    def test_subdomain_of_own_name_issued(self, tmp_path):
        srv, port, node = self._hub_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["pg.db.internal"]))
            assert status == 200, body
        finally:
            srv.stop()

    def test_foreign_name_refused(self, tmp_path):
        srv, port, node = self._hub_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node, dns=["other.internal"]))
            assert status == 403 and "not authorized" in body["error"]
        finally:
            srv.stop()

    def test_foreign_ip_refused(self, tmp_path):
        srv, port, node = self._hub_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert",
                                 self._req(node, ips=["fd8d:e5c1:db1a:7::dead"]))
            assert status == 403
        finally:
            srv.stop()

    def test_default_san_is_own_name(self, tmp_path):
        srv, port, node = self._hub_with_tls_node(tmp_path, "db")
        try:
            status, body = _post(port, "/cert", self._req(node))  # no SANs
            assert status == 200 and "cert" in body
        finally:
            srv.stop()


class TestCaCertEndpoint:
    def test_ca_cert_served_when_hub_has_ca(self, tmp_path):
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


class TestDirectoryEndpoint:
    def test_returns_records(self, running_server):
        _, port, directory, ca, node, cred = running_server
        data = _get(port, "/directory")
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["cred"]["hostname"] == "test-node"

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
            assert data == []
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
    def test_renewal_republishes_to_hub(self, tmp_path):
        """After renewing, the node must re-publish so the hub (and thus peers,
        which pull from the hub) sees the fresh credential — otherwise the mesh
        tears down one credential TTL after start."""
        from greasewood.renewal import RenewalLoop

        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = _make_cred(node, ca, ttl=3600)
        record = _make_record(node, cred, seq=1)

        hub_dir = Directory()          # the hub's directory
        hub_dir.put(record)            # node's initial (seq=1) record on the hub
        ca_obj = CA(ca, tmp_path)
        ca_obj._save_node_caps(node.id_pub_bytes, "test-node", ["mesh"])

        srv = ControlServer(
            listen="[::1]:0", directory=hub_dir,
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
                get_root_url=lambda: f"http://[::1]:{port}",
                current_cred=cred,
                inbound="yes", hostname="test-node",
                endpoints=["[2001:db8::1]:51900"],
                cache_path=tmp_path / "dir.json",
            )
            loop._renew_and_publish()
            # The hub's directory now carries the renewed (seq=2) record.
            on_hub = hub_dir.get(node.id_pub_hex)
            assert on_hub is not None and on_hub.seq == 2
            on_hub.cred.verify([ca.ca_pub_bytes])  # fresh, valid credential
        finally:
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
