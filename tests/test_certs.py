"""
Unit tests for TLS service-cert auto-renewal (greasewood.certs + gw cert-request):

  - the managed-cert manifest round-trips and keys on name (re-request relocates);
  - entry_paths honours explicit per-file paths and derives legacy out_dir ones;
  - cert_due_for_renewal fires when a cert is missing or past its half-life;
  - CertRenewalLoop renews only due auto-renew certs and runs their reload_cmd;
  - `gw cert-request` records the cert (with reload_cmd) for the daemon;
  - key/cert/ca can target three different directories; re-request relocates.
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


def test_manifest_roundtrip_and_keys_on_name(tmp_path):
    e1 = {"name": "db", "cn": "db", "dns": ["db"], "ips": [],
          "key_path": str(tmp_path / "a" / "db.key"),
          "crt_path": str(tmp_path / "a" / "db.crt"),
          "ca_path": str(tmp_path / "a" / "ca.crt"),
          "reload_cmd": None, "auto_renew": True}
    certs.record_managed(tmp_path, e1)
    # Same name, DIFFERENT paths → relocate (replace), not a duplicate.
    certs.record_managed(tmp_path, {**e1, "key_path": str(tmp_path / "b" / "db.key"),
                                    "reload_cmd": "reload pg"})
    certs.record_managed(tmp_path, {**e1, "name": "api"})   # different name → add
    m = certs.load_manifest(tmp_path)
    assert len(m) == 2
    db = [c for c in m if c["name"] == "db"][0]
    assert db["reload_cmd"] == "reload pg"                  # replaced
    assert db["key_path"] == str(tmp_path / "b" / "db.key")  # relocated


def test_entry_paths_explicit_and_legacy(tmp_path):
    # Explicit per-file paths are honoured verbatim.
    explicit = {"name": "svc", "key_path": "/etc/ssl/private/svc.key",
                "crt_path": "/etc/svc/svc.crt", "ca_path": "/usr/share/ca.crt"}
    k, c, a = certs.entry_paths(explicit)
    assert (str(k), str(c), str(a)) == (
        "/etc/ssl/private/svc.key", "/etc/svc/svc.crt", "/usr/share/ca.crt")

    # Legacy entry (out_dir + name, no explicit paths) → derived layout.
    legacy = {"name": "db", "out_dir": "/var/lib/greasewood/tls"}
    k, c, a = certs.entry_paths(legacy)
    assert str(k).endswith("/tls/db.key")
    assert str(c).endswith("/tls/db.crt")
    assert str(a).endswith("/tls/ca.crt")


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
        "key_path": str(tmp_path / "priv" / "db.key"),
        "crt_path": str(tmp_path / "certs" / "db.crt"),
        "ca_path": str(tmp_path / "certs" / "ca.crt"),
        "reload_cmd": "systemctl reload pg", "auto_renew": True})
    certs.record_managed(tmp_path, {
        "name": "api", "cn": "api", "dns": ["api"], "ips": [],
        "out_dir": str(tmp_path / "tls"), "reload_cmd": None,
        "auto_renew": False})                                  # opted out → skipped

    issued, reloads = [], []
    monkeypatch.setattr(certs, "cert_due_for_renewal", lambda p: True)
    monkeypatch.setattr(certs, "issue_cert",
                        lambda anchor, keys, **kw: issued.append(kw))
    monkeypatch.setattr(certs.subprocess, "run",
                        lambda cmd, **kw: reloads.append(cmd) or
                        types.SimpleNamespace(returncode=0, stderr=""))

    loop = certs.CertRenewalLoop(node_keys=object(),
                                 get_anchor_url=lambda: "http://anchor", data_dir=tmp_path)
    loop.check_all()
    # Only the auto-renew cert, re-issued to its explicit per-file paths.
    assert len(issued) == 1
    kw = issued[0]
    assert str(kw["key_path"]) == str(tmp_path / "priv" / "db.key")
    assert str(kw["crt_path"]) == str(tmp_path / "certs" / "db.crt")
    assert str(kw["ca_path"]) == str(tmp_path / "certs" / "ca.crt")
    assert reloads == [["systemctl", "reload", "pg"]]  # ran as argv, no shell


def test_cert_request_records_manifest(tmp_path, monkeypatch, capsys):
    from greasewood import cli
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
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
    # issue_cert echoes back the paths it was told to write (the CLI resolves
    # them), so the manifest records exactly those.
    monkeypatch.setattr(certs, "issue_cert",
                        lambda *a, **k: (k["key_path"], k["crt_path"], k["ca_path"]))

    ns = types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                               san=["db.gw.internal"], name="db",
                               out_dir=None, key_out=None, cert_out=None,
                               ca_out=None, anchor=None,
                               reload_cmd="systemctl reload pg", no_auto_renew=False)
    assert cli.cmd_cert_request(ns) == 0
    m = certs.load_manifest(tmp_path)
    assert len(m) == 1
    assert m[0]["name"] == "db"
    assert m[0]["reload_cmd"] == "systemctl reload pg"
    assert m[0]["auto_renew"] is True
    # Default layout: all three under <data_dir>/tls.
    assert m[0]["key_path"] == str(tmp_path / "tls" / "db.key")
    assert m[0]["crt_path"] == str(tmp_path / "tls" / "db.crt")
    assert m[0]["ca_path"] == str(tmp_path / "tls" / "ca.crt")
    # The output names the config file (and the manifest) so the operator knows
    # where the managed-cert record lives.
    out = capsys.readouterr().out
    assert str(tmp_path / "gw.toml") in out
    assert str(certs.manifest_path(tmp_path)) in out


def test_cert_request_registers_subdomain_san_as_alias(tmp_path, monkeypatch, capsys):
    from greasewood import cli
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
    """A subdomain --san (a name under the node's own mesh name) is auto-added to
    [network] aliases so the daemon publishes it — but a foreign or bare-name SAN
    is not."""
    NodeKeys.load_or_generate(tmp_path)
    cfg_path = tmp_path / "gw.toml"
    cfg_path.write_text(f"""[node]
hostname = "db01"
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
    from greasewood.config import load_config
    monkeypatch.setattr(certs, "issue_cert",
                        lambda *a, **k: (k["key_path"], k["crt_path"], k["ca_path"]))

    def ns(**o):
        base = dict(config=str(cfg_path), san=[], name="svc", out_dir=None,
                    key_out=None, cert_out=None, ca_out=None, anchor=None,
                    reload_cmd=None, no_auto_renew=False)
        base.update(o); return types.SimpleNamespace(**base)

    # Subdomain of our own name → registered as label "pg".
    assert cli.cmd_cert_request(ns(san=["pg.db01.gw.internal"], name="pg")) == 0
    assert load_config(cfg_path).aliases == ["pg"]
    assert "pg.db01.gw.internal" in capsys.readouterr().out

    # A second subdomain merges in.
    assert cli.cmd_cert_request(ns(san=["metrics.db01.gw.internal"], name="m")) == 0
    assert load_config(cfg_path).aliases == ["metrics", "pg"]

    # A foreign name (someone else's) is NOT registered (and the anchor would refuse
    # the cert anyway); the bare own-name isn't a subdomain, so not registered.
    assert cli.cmd_cert_request(ns(san=["evil.other.gw.internal"], name="x")) == 0
    assert cli.cmd_cert_request(ns(san=["db01.gw.internal"], name="base")) == 0
    assert load_config(cfg_path).aliases == ["metrics", "pg"]   # unchanged


def test_cert_request_per_file_paths_and_relocate(tmp_path, monkeypatch, capsys):
    from greasewood import cli
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
    """key/cert/ca can each target a different directory, and re-requesting the
    same name relocates the entry (single manifest row) and flags the orphaned
    old files."""
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

    def fake_issue(*a, **k):
        # Actually create the files so the orphan check sees them on relocate.
        for p in (k["key_path"], k["crt_path"], k["ca_path"]):
            from pathlib import Path as _P
            _P(p).parent.mkdir(parents=True, exist_ok=True)
            _P(p).write_text("x")
        return k["key_path"], k["crt_path"], k["ca_path"]
    monkeypatch.setattr(certs, "issue_cert", fake_issue)

    def ns(**over):
        base = dict(config=str(tmp_path / "gw.toml"), san=["db.gw.internal"],
                    name="db", out_dir=None, key_out=None, cert_out=None,
                    ca_out=None, anchor=None, reload_cmd=None, no_auto_renew=False)
        base.update(over)
        return types.SimpleNamespace(**base)

    # 1. Three different directories.
    assert cli.cmd_cert_request(ns(
        key_out=str(tmp_path / "priv" / "db.key"),
        cert_out=str(tmp_path / "pub" / "db.crt"),
        ca_out=str(tmp_path / "trust" / "ca.crt"))) == 0
    m = certs.load_manifest(tmp_path)
    assert len(m) == 1
    assert m[0]["key_path"] == str(tmp_path / "priv" / "db.key")
    assert m[0]["crt_path"] == str(tmp_path / "pub" / "db.crt")
    assert m[0]["ca_path"] == str(tmp_path / "trust" / "ca.crt")
    assert (tmp_path / "priv" / "db.key").exists()

    # 2. Re-request same name at new paths → one entry (relocated) + orphan note.
    assert cli.cmd_cert_request(ns(out_dir=str(tmp_path / "newtls"))) == 0
    m = certs.load_manifest(tmp_path)
    assert len(m) == 1
    assert m[0]["key_path"] == str(tmp_path / "newtls" / "db.key")
    out = capsys.readouterr().out
    assert "orphaned" in out
    assert str(tmp_path / "priv" / "db.key") in out


def test_grace_dual_names_bidirectional():
    from greasewood.certs import _grace_dual_names
    # A cert under the NEW domain gains the old-domain variant (and vice versa),
    # covering a manifest frozen with either.
    out = _grace_dual_names(["db.new.internal"], "new.internal", "old.internal")
    assert set(out) == {"db.new.internal", "db.old.internal"}
    out = _grace_dual_names(["pg.db.old.internal"], "new.internal", "old.internal")
    assert "pg.db.new.internal" in out and "pg.db.old.internal" in out
    # Non-mesh SANs are untouched.
    out = _grace_dual_names(["service.corp.example"], "new.internal", "old.internal")
    assert out == ["service.corp.example"]


def test_grace_old_domain_expiry(tmp_path):
    import datetime as dt
    import json
    from greasewood.certs import _rename_grace_old_domain
    assert _rename_grace_old_domain(tmp_path) is None            # no marker
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    (tmp_path / "rename_grace.json").write_text(
        json.dumps({"old_domain": "old.internal", "until": future}))
    assert _rename_grace_old_domain(tmp_path) == "old.internal"  # active
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
    (tmp_path / "rename_grace.json").write_text(
        json.dumps({"old_domain": "old.internal", "until": past}))
    assert _rename_grace_old_domain(tmp_path) is None            # expired → retire


def test_migrate_rewrites_cert_manifest(tmp_path):
    """rename-mesh repoints managed certs old→new so post-grace renewals use
    the new names."""
    import json
    from greasewood import cli
    from greasewood.certs import manifest_path
    data = tmp_path / "d"; (data / "tls").mkdir(parents=True)
    manifest_path(data).write_text(json.dumps([
        {"name": "self", "dns": ["db.old.internal"], "cn": "db.old.internal",
         "ips": ["fd8d::1"]},
        {"name": "svc", "dns": ["pg.db.old.internal", "keep.corp.example"],
         "cn": "pg.db.old.internal"},
    ]))
    cli._rewrite_cert_manifest_domain(data, "old.internal", "new.internal")
    entries = json.loads(manifest_path(data).read_text())
    assert entries[0]["dns"] == ["db.new.internal"]
    assert entries[0]["cn"] == "db.new.internal"
    assert entries[1]["dns"] == ["pg.db.new.internal", "keep.corp.example"]  # non-mesh kept


def test_manifest_writes_are_atomic(tmp_path, monkeypatch):
    """A torn manifest write must not be possible: record/remove go through
    keys.atomic_write (temp + rename), so load_manifest never sees a truncated
    file that it would swallow as [] — silently disabling all renewal."""
    import inspect
    from greasewood import certs
    for fn in (certs.record_managed, certs.remove_managed, certs.snapshot_profile):
        src = inspect.getsource(fn)
        assert "atomic_write" in src and "write_text" not in src, fn.__name__


def test_place_cert_files_no_privkey_tmp_left_on_owner_failure(tmp_path):
    """If chown fails (unknown owner), the 0600 temp holding the leaf private key
    must be cleaned up, not left as <dest>.gwtmp in the service dir."""
    import pytest
    from greasewood import certs
    dest = tmp_path / "server.key"
    files = [{"role": "key", "path": str(dest), "owner": "no_such_user_zzz9"}]
    with pytest.raises(RuntimeError):
        certs.place_cert_files(files, "KEYPEM\n", "C\n", "A\n")
    assert not dest.exists()
    assert not (tmp_path / "server.key.gwtmp").exists()      # no leaked key temp
    assert list(tmp_path.iterdir()) == []                    # nothing left behind
