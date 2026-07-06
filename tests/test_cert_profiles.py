"""
Cert PROFILES — one command issues a TLS cert, places the key/cert/ca where a
service expects them (right owner + mode), registers the reload, and the daemon
RE-PLACES them on every renewal (so a service's key stays readable across
renewals — the real friction win). Shipped templates are starting points, not
turnkey; they self-document the OS/software version they were written against.
"""
import os
import pwd
import types

import pytest

from greasewood import certs, cli
from greasewood.keys import NodeKeys


def _me():
    return pwd.getpwuid(os.getuid()).pw_name


def test_compose_role_formats():
    assert certs.compose_role("key", "K\n", "C\n", "A\n") == "K\n"
    assert certs.compose_role("fullchain", "K\n", "C\n", "A\n") == "C\nA\n"     # cert+ca
    assert certs.compose_role("bundle", "K\n", "C\n", "A\n") == "C\nA\nK\n"     # cert+ca+key
    # missing trailing newline is normalized
    assert certs.compose_role("fullchain", "K", "C", "A") == "C\nA\n"
    with pytest.raises(ValueError):
        certs.compose_role("nonsense", "K", "C", "A")


def test_place_cert_files_content_mode_owner(tmp_path):
    files = [
        {"role": "key", "path": str(tmp_path / "s.key"), "owner": _me(), "mode": "0600"},
        {"role": "cert", "path": str(tmp_path / "s.crt")},                     # default 0644
        {"role": "fullchain", "path": str(tmp_path / "full.pem")},
        {"role": "bundle", "path": str(tmp_path / "b.pem"), "mode": "0640"},
    ]
    certs.place_cert_files(files, "KEY\n", "CERT\n", "CA\n")
    assert (tmp_path / "s.key").read_text() == "KEY\n"
    assert (tmp_path / "full.pem").read_text() == "CERT\nCA\n"
    assert (tmp_path / "b.pem").read_text() == "CERT\nCA\nKEY\n"
    assert oct(os.stat(tmp_path / "s.key").st_mode & 0o777) == "0o600"
    assert oct(os.stat(tmp_path / "s.crt").st_mode & 0o777) == "0o644"          # role default
    assert oct(os.stat(tmp_path / "b.pem").st_mode & 0o777) == "0o640"


def test_place_creates_one_subdir_under_existing_root(tmp_path):
    # A cert subdir is created under an EXISTING directory (the common
    # /etc/<svc>/tls case where the service root exists but tls/ doesn't).
    dest = tmp_path / "tls" / "s.crt"
    certs.place_cert_files([{"role": "cert", "path": str(dest)}], "K", "C\n", "A")
    assert dest.read_text() == "C\n"


def test_place_refuses_to_fabricate_a_deep_tree(tmp_path):
    # A missing PARENT of the target dir means the service isn't installed or the
    # path is wrong (e.g. postgres profile's /var/lib/postgresql/17/main on a
    # PG-16 host). It must fail loudly, not invent the tree and mis-place a key.
    dest = tmp_path / "deep" / "nested" / "s.crt"
    with pytest.raises(RuntimeError) as e:
        certs.place_cert_files([{"role": "cert", "path": str(dest)}], "K", "C\n", "A")
    assert "doesn't exist" in str(e.value)
    assert not dest.parent.exists()             # nothing fabricated


def test_place_multi_level_subdirs_when_earlier_file_makes_intermediate(tmp_path):
    # minio's shape: certs/public.crt then certs/CAs/ca.crt — the first file
    # creates certs/, so the second can create CAs/ under it (order matters, and
    # the shipped profiles are ordered for it).
    (tmp_path / "svc").mkdir()                   # the service root exists
    files = [
        {"role": "cert", "path": str(tmp_path / "svc" / "certs" / "public.crt")},
        {"role": "ca", "path": str(tmp_path / "svc" / "certs" / "CAs" / "ca.crt")},
    ]
    certs.place_cert_files(files, "K", "C\n", "A")
    assert (tmp_path / "svc" / "certs" / "public.crt").read_text() == "C\n"
    assert (tmp_path / "svc" / "certs" / "CAs" / "ca.crt").read_text() == "A\n"


def test_resolve_owner_unknown_fails_loudly():
    with pytest.raises(RuntimeError) as e:
        certs._resolve_owner("definitely_no_such_user_zzz")
    assert "no such user" in str(e.value)


def test_load_shipped_profiles_valid():
    names = cli._shipped_profile_names()
    assert {"postgres", "nginx", "haproxy", "redis", "nats", "minio", "mosquitto"} <= set(names)
    for name in names:
        p = cli._load_cert_profile(name)
        assert p["files"]
        for f in p["files"]:
            assert f["role"] in ("key", "cert", "ca", "fullchain", "bundle")
            assert f["path"].startswith("/")
    # haproxy uses the bundle role; postgres uses three separate files
    assert any(f["role"] == "bundle" for f in cli._load_cert_profile("haproxy")["files"])
    assert [f["role"] for f in cli._load_cert_profile("postgres")["files"]] == \
        ["key", "cert", "ca"]
    # reload is optional: NATS reloads via SIGHUP; MinIO hot-reloads its certs
    # dir, so its profile has no reload command at all.
    assert cli._load_cert_profile("nats")["reload"] == "systemctl reload nats-server"
    assert cli._load_cert_profile("minio")["reload"] is None


def test_load_profile_unknown_name_lists_shipped():
    with pytest.raises(SystemExit) as e:
        cli._load_cert_profile("nope")
    assert "postgres" in str(e.value)                     # names the shipped set


def test_load_profile_bad_role(tmp_path):
    f = tmp_path / "x.toml"
    f.write_text('[[file]]\nrole = "wat"\npath = "/x"\n')
    with pytest.raises(SystemExit) as e:
        cli._load_cert_profile(str(f))
    assert "unknown role" in str(e.value)


def test_cert_profiles_command_lists_provenance(capsys):
    assert cli.cmd_cert_profiles(types.SimpleNamespace()) == 0
    out = capsys.readouterr().out
    assert "postgres" in out and "PostgreSQL 17" in out    # version is surfaced


def test_cert_request_profile_places_and_records(tmp_path, monkeypatch):
    """--profile issues, places every file with owner/mode, and records `files`
    in the manifest so the daemon can re-place on renewal."""
    NodeKeys.load_or_generate(tmp_path)
    prof = tmp_path / "svc.toml"
    prof.write_text(f'''reload = "true"
[[file]]
role = "key"
path = "{tmp_path}/place/svc.key"
owner = "{_me()}"
mode = "0600"
[[file]]
role = "fullchain"
path = "{tmp_path}/place/svc.pem"
''')
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f'''[node]
hostname = "db"
data_dir = "{tmp_path}"
role = "node"
[network]
interface = "gw"
seeds = []
root_url = "http://[fd8d::1]:51902"
mesh_domain = "m.internal"
[ca]
trusted_pubs = []
''')
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("KEYPEM\n", "CERTPEM\n", "CAPEM\n"))
    args = types.SimpleNamespace(
        config=str(cfg), profile=str(prof), show=False, san=[], name=None,
        out_dir=None, key_out=None, cert_out=None, ca_out=None, anchor=None,
        reload_cmd=None, no_auto_renew=False)
    assert cli.cmd_cert_request(args) == 0
    assert (tmp_path / "place" / "svc.key").read_text() == "KEYPEM\n"
    assert (tmp_path / "place" / "svc.pem").read_text() == "CERTPEM\nCAPEM\n"
    entry = certs.load_manifest(tmp_path)[0]
    assert entry["reload_cmd"] == "true"
    assert [f["role"] for f in entry["files"]] == ["key", "fullchain"]


def test_cert_request_profile_bad_owner_fails_before_fetch(tmp_path, monkeypatch):
    """A typo'd owner fails instantly — the anchor is never even contacted."""
    NodeKeys.load_or_generate(tmp_path)
    prof = tmp_path / "svc.toml"
    prof.write_text(f'''[[file]]
role = "key"
path = "{tmp_path}/svc.key"
owner = "no_such_user_zzz"
''')
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f'''[node]
hostname = "db"
data_dir = "{tmp_path}"
role = "node"
[network]
interface = "gw"
seeds = []
root_url = "http://[fd8d::1]:51902"
mesh_domain = "m.internal"
[ca]
trusted_pubs = []
''')
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    called = []
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: called.append(1) or ("K", "C", "A"))
    args = types.SimpleNamespace(
        config=str(cfg), profile=str(prof), show=False, san=[], name=None,
        out_dir=None, key_out=None, cert_out=None, ca_out=None, anchor=None,
        reload_cmd=None, no_auto_renew=False)
    with pytest.raises(SystemExit) as e:
        cli.cmd_cert_request(args)
    assert "no such user" in str(e.value)
    assert not called                                      # anchor never contacted


def test_renewal_reissues_and_replaces_profile_files(tmp_path, monkeypatch):
    """THE win: on renewal the daemon re-fetches AND re-places every profile
    file (content + owner/mode), so a service key doesn't revert to root:root."""
    certs.record_managed(tmp_path, {
        "name": "svc", "cn": "db.m.internal", "dns": ["db.m.internal"], "ips": [],
        "files": [
            {"role": "cert", "path": str(tmp_path / "svc.crt")},
            {"role": "key", "path": str(tmp_path / "svc.key"),
             "owner": _me(), "mode": "0600"},
        ],
        "reload_cmd": None, "auto_renew": True})
    monkeypatch.setattr(certs, "cert_due_for_renewal", lambda p: True)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("NEWKEY\n", "NEWCERT\n", "NEWCA\n"))
    loop = certs.CertRenewalLoop(node_keys=None, get_anchor_url=lambda: "http://x",
                                 data_dir=tmp_path)
    loop.check_all()
    assert (tmp_path / "svc.crt").read_text() == "NEWCERT\n"
    assert (tmp_path / "svc.key").read_text() == "NEWKEY\n"
    assert oct(os.stat(tmp_path / "svc.key").st_mode & 0o777) == "0o600"


def _profile_cfg(tmp_path):
    NodeKeys.load_or_generate(tmp_path)
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f'''[node]
hostname = "db"
data_dir = "{tmp_path}"
role = "node"
[network]
interface = "gw"
seeds = []
root_url = "http://[fd8d::1]:51902"
mesh_domain = "m.internal"
[ca]
trusted_pubs = []
''')
    return cfg


def _profile_file(tmp_path, extra=""):
    prof = tmp_path / "svc.toml"
    prof.write_text(f'''reload = "true"
[[file]]
role = "cert"
path = "{tmp_path}/place/svc.crt"
[[file]]
role = "key"
path = "{tmp_path}/place/svc.key"
mode = "0600"
{extra}''')
    return prof


def _args(cfg, prof, **over):
    base = dict(config=str(cfg), profile=str(prof), show=False, san=[], name=None,
                out_dir=None, key_out=None, cert_out=None, ca_out=None, anchor=None,
                reload_cmd=None, no_auto_renew=False, renew=False)
    base.update(over)
    return types.SimpleNamespace(**base)


def _fresh_cert_pem():
    """A real, currently-valid leaf cert PEM (so cert_expiry/due checks work)."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    k = ed25519.Ed25519PrivateKey.generate()
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "db.m.internal")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")]))
            .public_key(k.public_key())
            .serial_number(1)
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=7))
            .sign(k, None))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_cert_request_idempotent_noop_on_rerun(tmp_path, monkeypatch, capsys):
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    calls = []
    cert_pem = _fresh_cert_pem()
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: calls.append(1) or ("K\n", cert_pem, "CA\n"))
    assert cli.cmd_cert_request(_args(cfg, prof)) == 0        # first issue
    assert len(calls) == 1
    capsys.readouterr()
    # Rerun, unchanged → no-op, anchor NOT contacted again.
    assert cli.cmd_cert_request(_args(cfg, prof)) == 0
    assert len(calls) == 1
    out = capsys.readouterr().out
    assert "nothing to do" in out and "--renew" in out


def test_cert_request_renew_forces_reissue(tmp_path, monkeypatch, capsys):
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    calls = []
    cert_pem = _fresh_cert_pem()
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: calls.append(1) or ("K\n", cert_pem, "CA\n"))
    cli.cmd_cert_request(_args(cfg, prof))
    cli.cmd_cert_request(_args(cfg, prof, renew=True))        # --renew
    assert len(calls) == 2                                    # re-issued


def test_cert_request_changed_placement_reissues(tmp_path, monkeypatch):
    """Editing the profile (a new path) is a material change → not a no-op."""
    cfg = _profile_cfg(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    calls = []
    cert_pem = _fresh_cert_pem()
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: calls.append(1) or ("K\n", cert_pem, "CA\n"))
    cli.cmd_cert_request(_args(cfg, _profile_file(tmp_path)))
    # Different cert path in the profile → re-issue.
    prof2 = tmp_path / "svc.toml"
    prof2.write_text(f'''reload = "true"
[[file]]
role = "cert"
path = "{tmp_path}/other/svc.crt"
''')
    cli.cmd_cert_request(_args(cfg, prof2))
    assert len(calls) == 2


def test_cert_request_snapshots_profile(tmp_path, monkeypatch):
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("K\n", _fresh_cert_pem(), "CA\n"))
    cli.cmd_cert_request(_args(cfg, prof))
    snap = certs.profile_snapshot_path(tmp_path, "svc")
    assert snap.exists() and snap.read_text() == prof.read_text()
    entry = certs.load_manifest(tmp_path)[0]
    assert entry["profile"] == "svc"


def test_cert_remove_deregisters_and_keeps_files(tmp_path, monkeypatch, capsys):
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("K\n", _fresh_cert_pem(), "CA\n"))
    cli.cmd_cert_request(_args(cfg, prof))
    crt = tmp_path / "place" / "svc.crt"
    assert crt.exists() and certs.load_manifest(tmp_path)
    capsys.readouterr()
    # default: deregister, keep files
    assert cli.cmd_cert_remove(types.SimpleNamespace(
        config=str(cfg), name="svc", delete_files=False)) == 0
    assert certs.load_manifest(tmp_path) == []               # gone from manifest
    assert not certs.profile_snapshot_path(tmp_path, "svc").exists()
    assert crt.exists()                                      # files LEFT
    assert "LEFT in place" in capsys.readouterr().out


def test_cert_remove_delete_files(tmp_path, monkeypatch):
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("K\n", _fresh_cert_pem(), "CA\n"))
    cli.cmd_cert_request(_args(cfg, prof))
    crt = tmp_path / "place" / "svc.crt"
    key = tmp_path / "place" / "svc.key"
    cli.cmd_cert_remove(types.SimpleNamespace(config=str(cfg), name="svc",
                                              delete_files=True))
    assert not crt.exists() and not key.exists()             # files removed


def test_cert_remove_unknown_name(tmp_path, monkeypatch):
    cfg = _profile_cfg(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    with pytest.raises(SystemExit) as e:
        cli.cmd_cert_remove(types.SimpleNamespace(config=str(cfg), name="ghost",
                                                  delete_files=False))
    assert "no managed cert named 'ghost'" in str(e.value)


def test_cert_status_reads_manifest(tmp_path, monkeypatch, capsys):
    """cert-status shows manifest certs wherever placed — incl. /etc-style paths
    outside <data_dir>/tls that the old glob would miss."""
    cfg, prof = _profile_cfg(tmp_path), _profile_file(tmp_path)
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(certs, "fetch_cert",
                        lambda *a, **k: ("K\n", _fresh_cert_pem(), "CA\n"))
    cli.cmd_cert_request(_args(cfg, prof))
    capsys.readouterr()
    assert cli.cmd_cert_status(types.SimpleNamespace(config=str(cfg))) == 0
    out = capsys.readouterr().out
    assert "svc" in out and "profile: svc" in out
    assert "expires" in out and str(tmp_path / "place" / "svc.crt") in out
