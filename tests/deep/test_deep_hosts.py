"""
DEEP: /etc/hosts management invariants.

The hosts block is the one file greasewood shares with the operator and other
software, so the properties are about never damaging what isn't ours:

  * sanitize() is idempotent and always yields a valid DNS label — for ANY
    Linux hostname (which permits nearly arbitrary bytes);
  * sync() then remove_block() returns the file to exactly the user's content
    (modulo trailing-newline normalization), for arbitrary user content and
    arbitrary record sets;
  * two meshes with distinct domain tags never touch each other's block.
"""
from dataclasses import dataclass, field

import pytest
from hypothesis import assume, given, strategies as st

from greasewood import hosts

pytestmark = pytest.mark.deep


@dataclass
class _Cred:
    addr: str


@dataclass
class _Rec:
    hostname: str
    cred: _Cred
    aliases: list = field(default_factory=list)


_hostname = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1, max_size=80)
_addr = st.integers(1, 2**32).map(lambda n: f"fd8d:e5c1:db1a:7::{n:x}")
_records = st.lists(
    st.builds(lambda h, a: _Rec(hostname=h, cred=_Cred(addr=a)), _hostname, _addr),
    max_size=6)
# User content: any lines that aren't greasewood markers.
_user_content = st.lists(
    st.text(alphabet=st.characters(blacklist_categories=("Cs",),
                                   blacklist_characters="\n\r"),
            max_size=60).filter(lambda l: "greasewood" not in l),
    max_size=10).map(lambda ls: "\n".join(ls))


@given(_hostname)
def test_sanitize_idempotent_and_valid(name):
    s = hosts.sanitize(name)
    assert hosts.sanitize(s) == s
    assert hosts.valid_label(s), s
    assert len(s) <= 63


@given(_hostname, st.text(min_size=1, max_size=30).filter(
    lambda d: d.strip() and "\n" not in d))
def test_mesh_name_is_dot_joined_sanitized(name, domain):
    m = hosts.mesh_name(name, domain)
    assert m == f"{hosts.sanitize(name)}.{domain}"


@given(user=_user_content, recs=_records)
def test_sync_then_remove_restores_user_content(tmp_path_factory, user, recs):
    p = tmp_path_factory.mktemp("hosts") / "hosts"
    p.write_text(user + "\n" if user else "")
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()

    hosts.sync(recs, "gw.internal", path=p)
    text = p.read_text()
    for line in user.splitlines():
        assert line in text                      # user lines survive the sync
    hosts.remove_block("gw.internal", path=p)
    assert p.read_text().rstrip("\n") == user.rstrip("\n")


@given(user=_user_content, a=_records, b=_records)
def test_distinct_domains_never_interfere(tmp_path_factory, user, a, b):
    assume(a or b)
    p = tmp_path_factory.mktemp("hosts") / "hosts"
    p.write_text(user + "\n" if user else "")
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()

    hosts.sync(a, "alpha.internal", path=p)
    before_beta = p.read_text()
    hosts.sync(b, "beta.internal", path=p)
    hosts.remove_block("beta.internal", path=p)
    # Removing beta's block restores exactly the alpha-only file.
    assert p.read_text().rstrip("\n") == before_beta.rstrip("\n")


@given(recs=_records)
def test_sync_is_idempotent(tmp_path_factory, recs):
    p = tmp_path_factory.mktemp("hosts") / "hosts"
    p.write_text("127.0.0.1 localhost\n")
    hosts._warned_collisions.clear()
    hosts._foreign_seen.clear()

    hosts.sync(recs, "gw.internal", path=p)
    once = p.read_text()
    assert hosts.sync(recs, "gw.internal", path=p) is False   # no rewrite
    assert p.read_text() == once
