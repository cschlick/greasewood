"""
Unit tests for greasewood.hosts — the managed /etc/hosts block.

These check the managed-block rendering, idempotent write/replace, that user
lines are preserved, removal, and the shared mesh_name() (which is also the
default TLS cert name, so the two layers agree).
"""
from dataclasses import dataclass, field

from greasewood import hosts


@dataclass
class _Cred:
    addr: str


@dataclass
class _Rec:
    hostname: str
    cred: _Cred
    aliases: list = field(default_factory=list)


def _rec(hostname, addr, aliases=None):
    return _Rec(hostname=hostname, cred=_Cred(addr=addr), aliases=aliases or [])


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


def test_valid_label():
    assert hosts.valid_label("pg")
    assert hosts.valid_label("pg-replica")
    assert hosts.valid_label("a1")
    assert not hosts.valid_label("")
    assert not hosts.valid_label("-pg")          # leading hyphen
    assert not hosts.valid_label("pg.replica")   # a dot is not a single label
    assert not hosts.valid_label("PG")           # uppercase
    assert not hosts.valid_label("pg_db")        # underscore


def test_render_block_expands_aliases_under_own_name():
    # A node's aliases expand to <label>.<its mesh name> → its own address.
    recs = [_rec("db01", "fd8d::2", aliases=["pg", "metrics"])]
    block = hosts.render_block(recs, "internal")
    assert "fd8d::2\tdb01.internal" in block          # base name
    assert "fd8d::2\tpg.db01.internal" in block       # alias
    assert "fd8d::2\tmetrics.db01.internal" in block


def test_render_block_drops_invalid_alias_labels():
    # Junk labels must not reach /etc/hosts (they'd be attacker-influenced in a
    # compromised record, and are meaningless anyway).
    recs = [_rec("db01", "fd8d::2", aliases=["ok", "bad label", "a.b", ""])]
    block = hosts.render_block(recs, "internal")
    assert "fd8d::2\tok.db01.internal" in block
    assert "bad label" not in block
    assert "a.b.db01.internal" not in block           # dotted → rejected


def test_render_block_sorted_and_suffixed():
    recs = [_rec("db", "fd8d::2"), _rec("api", "fd8d::3")]
    block = hosts.render_block(recs, "internal")
    lines = block.splitlines()
    assert lines[0] == hosts._begin("internal") and lines[-1] == hosts._end("internal")
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
    assert hosts._begin("internal") in text and hosts._end("internal") in text


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
    assert text.count(hosts._begin("internal")) == 1   # exactly one block
    assert "fd8d::9\tdb.internal" in text          # updated addr
    assert "fd8d::2" not in text                    # stale addr gone
    assert "api.internal" in text


def test_remove_block(tmp_path):
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("db", "fd8d::2")], "internal", path=p)
    assert hosts.remove_block("internal", path=p) is True
    text = p.read_text()
    assert hosts._begin("internal") not in text and "db.internal" not in text
    assert "127.0.0.1 localhost" in text           # user line survives
    assert hosts.remove_block("internal", path=p) is False   # nothing left


def test_two_meshes_coexist_and_remove_independently(tmp_path):
    """A host on two meshes keeps a separate, independently-managed block per
    mesh domain — syncing/removing one must not touch the other."""
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("db", "fd8d::2")], "alpha", path=p)
    hosts.sync([_rec("web", "fdcc::5")], "beta", path=p)
    text = p.read_text()
    assert "db.alpha" in text and "web.beta" in text          # both blocks present
    assert hosts._begin("alpha") in text and hosts._begin("beta") in text

    hosts.remove_block("alpha", path=p)                        # drop only alpha
    text = p.read_text()
    assert "db.alpha" not in text and hosts._begin("alpha") not in text
    assert "web.beta" in text and hosts._begin("beta") in text  # beta untouched


def test_shared_domain_collision_warns_on_reclobber(tmp_path, caplog):
    """Two meshes on ONE mesh_domain clobber each other's block. The guard
    warns on the SECOND consecutive foreign sighting — one sighting is
    indistinguishable from a harmless stale block, but a concurrent mesh
    re-clobbers, so its block is foreign again by the next cycle."""
    import logging
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    a = [_rec("me-a", "fd8d::1"), _rec("db", "fd8d::2")]
    b = [_rec("me-b", "fdcc::1"), _rec("web", "fdcc::9")]
    with caplog.at_level(logging.WARNING, logger="greasewood.hosts"):
        hosts.sync(a, "gw.internal", path=p)      # mesh A writes the block
        hosts.sync(b, "gw.internal", path=p)      # B sees foreign (1st) — quiet
        assert not any("mesh_domain" in r.message for r in caplog.records)
        hosts.sync(a, "gw.internal", path=p)      # foreign AGAIN (2nd) — warn
    assert any("share mesh_domain" in r.message for r in caplog.records)
    assert any("distinct" in r.message for r in caplog.records)


def test_stale_block_from_previous_mesh_does_not_warn(tmp_path, caplog):
    """Field false-positive: a purged + re-created anchor (new identity, same
    mesh_domain) found its predecessor's block — foreign addresses, but NOT a
    concurrent mesh. First sync overwrites it; there must be no warning."""
    import logging
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("bastion", "fd8d::aaaa")], "gw.internal", path=p)  # old mesh
    new = [_rec("bastion", "fd8d::bbbb")]                # re-created: new addr
    with caplog.at_level(logging.WARNING, logger="greasewood.hosts"):
        hosts.sync(new, "gw.internal", path=p)           # stale block seen once
        hosts.sync(new, "gw.internal", path=p)           # now it's OURS again
        hosts.sync(new, "gw.internal", path=p)
    assert not any("mesh_domain" in r.message for r in caplog.records)


def test_no_collision_warning_on_normal_churn(tmp_path, caplog):
    """Adding/removing a node keeps the local node's own (stable) address in the
    set, so the overlap is non-empty — no false collision warning."""
    import logging
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts.sync([_rec("me", "fd8d::1"), _rec("db", "fd8d::2")], "gw.internal", path=p)
    with caplog.at_level(logging.WARNING, logger="greasewood.hosts"):
        hosts.sync([_rec("me", "fd8d::1")], "gw.internal", path=p)        # db left
        hosts.sync([_rec("me", "fd8d::1"), _rec("db", "fd8d::2"),
                    _rec("web", "fd8d::3")], "gw.internal", path=p)       # two joined
    assert not any("mesh_domain" in r.message for r in caplog.records)


def test_distinct_domains_do_not_warn(tmp_path, caplog):
    """Proper multi-mesh (distinct domains → distinct tags) never collides."""
    import logging
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    with caplog.at_level(logging.WARNING, logger="greasewood.hosts"):
        hosts.sync([_rec("db", "fd8d::2")], "alpha", path=p)
        hosts.sync([_rec("web", "fdcc::5")], "beta", path=p)
    assert not any("mesh_domain" in r.message for r in caplog.records)
