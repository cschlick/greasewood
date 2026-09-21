"""
The anchor offer: `gw anchor offer <node>` on a holder seals the anchor file
to the target's CA-attested WireGuard key and serves it over the control
plane; `gw anchor adopt` (no args) on the target collects and opens it with
its own key. No file shuttling, no permissions dance, nothing a bystander —
or the wrong node — can use: the ciphertext is bound to the named machine,
the offer is single-use and time-boxed, and the claim is authenticated and
replay-guarded like /renew.
"""
import datetime as dt
import json
import secrets
import types
import urllib.request

import pytest

from greasewood import anchorfile, cli
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.server import ControlServer
from greasewood.wire import AnchorClaimRequest, LeaveRequest
from tests._membership import enroll_record

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


# ---------------------------------------------------------------------------
# sealing primitive
# ---------------------------------------------------------------------------

def test_seal_roundtrip_and_wrong_key_refused():
    right, wrong = NodeKeys.generate(), NodeKeys.generate()
    sealed = anchorfile.seal_to_wg(right.wg_pub_bytes, b"root key material")
    assert anchorfile.unseal_with_wg(sealed, right.wg_priv) == b"root key material"
    with pytest.raises(ValueError, match="sealed to a different node"):
        anchorfile.unseal_with_wg(sealed, wrong.wg_priv)


def test_seal_tamper_refused():
    k = NodeKeys.generate()
    sealed = anchorfile.seal_to_wg(k.wg_pub_bytes, b"secret")
    import base64
    ct = bytearray(base64.b64decode(sealed["ct"]))
    ct[0] ^= 1
    sealed["ct"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(ValueError):
        anchorfile.unseal_with_wg(sealed, k.wg_priv)


# ---------------------------------------------------------------------------
# offer lifecycle on disk
# ---------------------------------------------------------------------------

def test_offer_expires_and_consumes(tmp_path, monkeypatch):
    k = NodeKeys.generate()
    sealed = anchorfile.seal_to_wg(k.wg_pub_bytes, b"x")
    anchorfile.write_offer(tmp_path, k.id_pub_hex, "gp2", sealed)
    assert anchorfile.read_offer(tmp_path)["to_hostname"] == "gp2"
    anchorfile.consume_offer(tmp_path)
    assert anchorfile.read_offer(tmp_path) is None       # single-use

    anchorfile.write_offer(tmp_path, k.id_pub_hex, "gp2", sealed)
    real_now = dt.datetime.now
    monkeypatch.setattr(anchorfile.dt, "datetime", types.SimpleNamespace(
        now=lambda tz=None: real_now(tz) + anchorfile.OFFER_TTL
        + dt.timedelta(minutes=1),
        fromisoformat=dt.datetime.fromisoformat))
    assert anchorfile.read_offer(tmp_path) is None       # expired → dropped
    monkeypatch.undo()
    assert not anchorfile.offer_path(tmp_path).exists()  # and deleted


# ---------------------------------------------------------------------------
# domain separation: a leave signature must never verify as a claim
# ---------------------------------------------------------------------------

def test_claim_and_leave_signatures_are_not_interchangeable():
    k = NodeKeys.generate()
    ts = _now()
    leave = LeaveRequest(id_pub=k.id_pub_bytes, nonce="n1", ts=ts).sign(k.id_priv)
    forged = AnchorClaimRequest(id_pub=k.id_pub_bytes, nonce="n1", ts=ts,
                                sig=leave.sig)
    with pytest.raises(ValueError, match="invalid anchor-claim"):
        forged.verify_self_sig()


# ---------------------------------------------------------------------------
# the endpoint
# ---------------------------------------------------------------------------

def _holder_server(tmp_path, ca_keys):
    from greasewood.ca import CA
    d = Directory()
    srv = ControlServer(
        listen="[::1]:0", directory=d,
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=CA(ca_keys, tmp_path, directory=d), data_dir=tmp_path,
    )
    srv.start()
    return srv, srv._server.server_address[1]


def _claim(port, k, nonce=None):
    req = AnchorClaimRequest(id_pub=k.id_pub_bytes,
                             nonce=nonce or secrets.token_hex(16),
                             ts=_now()).sign(k.id_priv)
    http_req = urllib.request.Request(
        f"http://[::1]:{port}/anchor-claim",
        data=json.dumps(req.to_dict()).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(http_req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_claim_serves_once_to_the_named_node_only(tmp_path):
    ca_keys = CAKeys.generate()
    target, bystander = NodeKeys.generate(), NodeKeys.generate()
    sealed = anchorfile.seal_to_wg(target.wg_pub_bytes, b"the anchor file")
    anchorfile.write_offer(tmp_path, target.id_pub_hex, "gp2", sealed)
    srv, port = _holder_server(tmp_path, ca_keys)
    try:
        # A different (authenticated!) member is refused WITHOUT consuming.
        status, body = _claim(port, bystander)
        assert status == 403 and "not for this node" in body["error"]
        assert anchorfile.read_offer(tmp_path) is not None

        # The named node collects it — and can open it.
        status, body = _claim(port, target)
        assert status == 200
        assert anchorfile.unseal_with_wg(body["sealed"], target.wg_priv) \
            == b"the anchor file"

        # Single-use: gone now, even for the rightful claimant.
        status, body = _claim(port, target)
        assert status == 404 and "no outstanding" in body["error"]
    finally:
        srv.stop()


def test_claim_requires_valid_signature_and_fresh_nonce(tmp_path):
    ca_keys = CAKeys.generate()
    target = NodeKeys.generate()
    anchorfile.write_offer(tmp_path, target.id_pub_hex, "gp2",
                           anchorfile.seal_to_wg(target.wg_pub_bytes, b"x"))
    srv, port = _holder_server(tmp_path, ca_keys)
    try:
        req = AnchorClaimRequest(id_pub=target.id_pub_bytes, nonce="n",
                                 ts=_now()).sign(target.id_priv)
        d = req.to_dict()
        d["nonce"] = "tampered"
        http_req = urllib.request.Request(
            f"http://[::1]:{port}/anchor-claim",
            data=json.dumps(d).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(http_req, timeout=5) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 400

        nonce = secrets.token_hex(16)
        assert _claim(port, target, nonce=nonce)[0] == 200
        anchorfile.write_offer(tmp_path, target.id_pub_hex, "gp2",
                               anchorfile.seal_to_wg(target.wg_pub_bytes, b"x"))
        status, body = _claim(port, target, nonce=nonce)   # replayed nonce
        assert status == 400 and "replay" in body["error"]
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# the two-command ceremony, end to end
# ---------------------------------------------------------------------------

def _cfg_file(dirpath, role, root_url="", ca_key=None, trusted=()):
    trusted_line = f'trusted_pubs = {list(trusted)!r}\n' if trusted else ""
    anchor_sec = (f'[anchor]\nca_key_file = "{ca_key}"\n' if ca_key else "")
    p = dirpath / "gw.toml"
    p.write_text(f'''[node]
hostname = "{dirpath.name}"
data_dir = "{dirpath}"
role = "{role}"
[network]
seeds = []
root_url = "{root_url}"
mesh_domain = "test.internal"
[ca]
{trusted_line}{anchor_sec}''')
    return p


def test_offer_then_adopt_over_the_mesh(tmp_path, monkeypatch, capsys):
    """The whole point: two commands, zero files. Holder mints the offer;
    the target claims it over the control plane, opens it with its own wg
    key, installs, and grants itself the anchor roles."""
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_service_restart", lambda *a, **k: True)
    ca_keys = CAKeys.generate()

    # The holder: has the anchor file + the target's record in its directory.
    holder = tmp_path / "holder"
    holder.mkdir()
    NodeKeys.load_or_generate(holder)
    anchorfile.AnchorFile.build("test.internal", ca_keys, b"d" * 32).save(holder)
    target_keys = NodeKeys.load_or_generate(_mk(tmp_path, "gp2"))
    enroll_record(ca_keys, holder, target_keys, "gp2", caps=["role:node"])
    hcfg = _cfg_file(holder, "node", trusted=[ca_keys.ca_pub_hex])
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(hcfg), action="offer", path="gp2")) == 0
    assert "sealed to its WireGuard key" in capsys.readouterr().out

    # Serve the holder's control plane (what its daemon would do).
    from greasewood.ca import CA
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=CA(ca_keys, holder), data_dir=holder,
    )
    srv.start()
    port = srv._server.server_address[1]
    try:
        # The target: enrolled member, no anchor file, claims with NO PATH.
        node_dir = tmp_path / "gp2"
        enroll_record(ca_keys, node_dir, target_keys, "gp2", caps=["role:node"])
        ncfg = _cfg_file(node_dir, "node",
                         root_url=f"http://[::1]:{port}",
                         trusted=[ca_keys.ca_pub_hex])
        assert cli.cmd_anchor(types.SimpleNamespace(
            config=str(ncfg), action="adopt", path=None)) == 0
    finally:
        srv.stop()

    af = anchorfile.load(node_dir)
    assert af is not None and af.ca_keys().ca_pub_hex == ca_keys.ca_pub_hex
    # single-use: the holder's offer is consumed
    assert anchorfile.read_offer(holder) is None


def _mk(tmp_path, name):
    d = tmp_path / name
    d.mkdir(exist_ok=True)
    return d
