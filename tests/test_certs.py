"""
Unit tests for TLS service-cert auto-renewal (greasewood.certs + gw cert-request):

  - the managed-cert manifest round-trips and dedups by (name, out_dir);
  - cert_due_for_renewal fires when a cert is missing or past its half-life;
  - CertRenewalLoop renews only due auto-renew certs and runs their reload_cmd;
  - `gw cert-request` records the cert (with reload_cmd) for the daemon.
"""
import datetime as dt
import types

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from greasewood import certs
from greasewood.keys import NodeKeys

_UTC = dt.timezone.utc


def _write_cert(path, *, age_days, life_days):
    """Self-signed cert with notBefore = age_days ago, life = life_days."""
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    nb = (dt.datetime.now(_UTC) - dt.timedelta(days=age_days)).replace(tzinfo=None)
    na = nb + dt.timedelta(days=life_days)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .sign(key, None))                      # Ed25519 → algorithm=None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_manifest_roundtrip_and_dedup(tmp_path):
    e1 = {"name": "db", "cn": "db", "dns": ["db"], "ips": [],
          "out_dir": str(tmp_path / "tls"), "reload_cmd": None, "auto_renew": True}
    certs.record_managed(tmp_path, e1)
    certs.record_managed(tmp_path, {**e1, "reload_cmd": "reload pg"})  # same key → replace
    certs.record_managed(tmp_path, {**e1, "name": "api"})             # different → add
    m = certs.load_manifest(tmp_path)
    assert len(m) == 2
    db = [c for c in m if c["name"] == "db"][0]
    assert db["reload_cmd"] == "reload pg"        # replaced, not duplicated


def test_cert_due_for_renewal(tmp_path):
    missing = tmp_path / "tls" / "none.crt"
    assert certs.cert_due_for_renewal(missing) is True         # missing → due

    fresh = tmp_path / "tls" / "fresh.crt"
    _write_cert(fresh, age_days=0, life_days=7)                 # just issued
    assert certs.cert_due_for_renewal(fresh) is False

    old = tmp_path / "tls" / "old.crt"
    _write_cert(old, age_days=5, life_days=7)                   # 5d into a 7d cert
    assert certs.cert_due_for_renewal(old) is True             # past half-life


def test_cert_loop_renews_due_and_runs_reload(tmp_path, monkeypatch):
    certs.record_managed(tmp_path, {
        "name": "db", "cn": "db", "dns": ["db"], "ips": [],
        "out_dir": str(tmp_path / "tls"), "reload_cmd": "systemctl reload pg",
        "auto_renew": True})
    certs.record_managed(tmp_path, {
        "name": "api", "cn": "api", "dns": ["api"], "ips": [],
        "out_dir": str(tmp_path / "tls"), "reload_cmd": None,
        "auto_renew": False})                                  # opted out → skipped

    issued, reloads = [], []
    monkeypatch.setattr(certs, "cert_due_for_renewal", lambda p: True)
    monkeypatch.setattr(certs, "issue_cert",
                        lambda hub, keys, **kw: issued.append(kw["name"]))
    monkeypatch.setattr(certs.subprocess, "run",
                        lambda cmd, **kw: reloads.append(cmd) or
                        types.SimpleNamespace(returncode=0, stderr=""))

    loop = certs.CertRenewalLoop(node_keys=object(),
                                 get_hub_url=lambda: "http://hub", data_dir=tmp_path)
    loop.check_all()
    assert issued == ["db"]                        # only the auto-renew cert
    assert reloads == [["systemctl", "reload", "pg"]]  # ran as argv, no shell


def test_cert_request_records_manifest(tmp_path, monkeypatch):
    NodeKeys.load_or_generate(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}"
role = "node"
[network]
interface = "gw-mesh"
seeds = []
root_url = "http://[fd8d:e5c1:db1a:7::1]:51902"
mesh_domain = "gw.internal"
[ca]
trusted_pubs = []
""")
    from greasewood import cli
    monkeypatch.setattr(certs, "issue_cert", lambda *a, **k: (
        tmp_path / "tls" / "db.key", tmp_path / "tls" / "db.crt",
        tmp_path / "tls" / "ca.crt"))

    ns = types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                               san=["db.gw.internal"], cn=None, name="db",
                               out_dir=None, hub=None,
                               reload_cmd="systemctl reload pg", no_auto_renew=False)
    assert cli.cmd_cert_request(ns) == 0
    m = certs.load_manifest(tmp_path)
    assert len(m) == 1
    assert m[0]["name"] == "db"
    assert m[0]["reload_cmd"] == "systemctl reload pg"
    assert m[0]["auto_renew"] is True
