"""
Unit tests for greasewood.hosts — the managed /etc/hosts block.

These check the managed-block rendering, idempotent write/replace, that user
lines are preserved, removal, and the shared mesh_name() (which is also the
default TLS cert name, so the two layers agree).
"""
from dataclasses import dataclass

from greasewood import hosts


@dataclass
class _Cred:
    addr: str


@dataclass
class _Rec:
    hostname: str
    cred: _Cred


def _rec(hostname, addr):
    return _Rec(hostname=hostname, cred=_Cred(addr=addr))


def test_mesh_name_sanitizes():
    assert hosts.mesh_name("db", "internal") == "db.internal"
    assert hosts.mesh_name("root@node01", "internal") == "root-node01.internal"
    assert hosts.mesh_name("Weird Name!", "mesh") == "weird-name.mesh"
    assert hosts.mesh_name("", "internal") == "node.internal"


def test_sanitize_collapses_dots_to_single_label():
    # A dotted (FQDN-like) explicit name becomes one valid label, not a
    # multi-label name that would mix with the mesh domain.
    assert hosts.sanitize("sub.domain.com") == "sub-domain-com"
    assert hosts.mesh_name("sub.domain.com", "internal") == "sub-domain-com.internal"


def test_sanitize_handles_linux_hostname_oddities():
    assert hosts.sanitize("DB_Primary") == "db-primary"   # upper + underscore
    assert hosts.sanitize("-weird-") == "weird"           # leading/trailing hyphen
    assert hosts.sanitize("()") == "node"                 # nothing usable -> fallback


def test_sanitize_caps_at_dns_label_limit():
    long_name = "a" * 80
    out = hosts.sanitize(long_name)
    assert out == "a" * 63 and len(out) == 63

    # Truncation must not leave a trailing hyphen.
    cut_on_hyphen = "a" * 63 + "-tail"
    assert not hosts.sanitize(cut_on_hyphen).endswith("-")


def test_render_block_sorted_and_suffixed():
    recs = [_rec("db", "fd8d::2"), _rec("api", "fd8d::3")]
    block = hosts.render_block(recs, "internal")
    lines = block.splitlines()
    assert lines[0] == hosts._BEGIN and lines[-1] == hosts._END
    # sorted by hostname → api before db
    assert lines[1] == "fd8d::3\tapi.internal"
    assert lines[2] == "fd8d::2\tdb.internal"


def test_sync_preserves_user_lines(tmp_path):
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n::1 localhost\n")
    changed = hosts.sync([_rec("db", "fd8d::2")], "internal", path=p)
    assert changed
    text = p.read_text()
    assert "127.0.0.1 localhost" in text          # user lines kept
    assert "fd8d::2\tdb.internal" in text
    assert hosts._BEGIN in text and hosts._END in text


def test_sync_is_idempotent(tmp_path):
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    recs = [_rec("db", "fd8d::2")]
    assert hosts.sync(recs, "internal", path=p) is True
    assert hosts.sync(recs, "internal", path=p) is False  # no change second time


def test_sync_replaces_old_block(tmp_path):
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("db", "fd8d::2")], "internal", path=p)
    hosts.sync([_rec("db", "fd8d::9"), _rec("api", "fd8d::3")], "internal", path=p)
    text = p.read_text()
    assert text.count(hosts._BEGIN) == 1          # exactly one block
    assert "fd8d::9\tdb.internal" in text          # updated addr
    assert "fd8d::2" not in text                    # stale addr gone
    assert "api.internal" in text


def test_remove_block(tmp_path):
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("db", "fd8d::2")], "internal", path=p)
    assert hosts.remove_block(path=p) is True
    text = p.read_text()
    assert hosts._BEGIN not in text and "db.internal" not in text
    assert "127.0.0.1 localhost" in text           # user line survives
    assert hosts.remove_block(path=p) is False      # nothing left to remove
