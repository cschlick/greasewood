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


def test_place_creates_parent_dirs(tmp_path):
    dest = tmp_path / "deep" / "nested" / "s.crt"
    certs.place_cert_files([{"role": "cert", "path": str(dest)}], "K", "C\n", "A")
    assert dest.read_text() == "C\n"


def test_resolve_owner_unknown_fails_loudly():
    with pytest.raises(RuntimeError) as e:
        certs._resolve_owner("definitely_no_such_user_zzz")
    assert "no such user" in str(e.value)


def test_load_shipped_profiles_valid():
    for name in ("postgres", "nginx", "haproxy", "redis"):
        p = cli._load_cert_profile(name)
        assert p["reload"] and p["files"]
        for f in p["files"]:
            assert f["role"] in ("key", "cert", "ca", "fullchain", "bundle")
            assert f["path"].startswith("/")
    # haproxy uses the bundle role; postgres uses three separate files
    assert any(f["role"] == "bundle" for f in cli._load_cert_profile("haproxy")["files"])
    assert [f["role"] for f in cli._load_cert_profile("postgres")["files"]] == \
        ["key", "cert", "ca"]


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
