"""
`hostname-pinned` is an anchor-DERIVED cap: the invite path adds it, and only it,
when --hostname fixes a node's name. It must never be hand-supplied via --caps or
[anchor] default_caps.

Without this guard, `gw invite --standing --caps hostname-pinned` (or a plain
`gw invite --standing` with default_caps carrying it) writes a STANDING door whose
window has hostname=None but caps=[..,"hostname-pinned"] — every node then names
ITSELF at join yet is permanently barred from `gw rename-node`/rename-at-renew
(ca.py, cli.cmd_rename_node). That's exactly the "one pinned name for many nodes"
state the --hostname + --standing guard forbids, reached via the cap spelling. The
same footgun exists without --standing: an un-renameable node with no pinned name.
"""
import pytest

from greasewood import cli


def test_helper_rejects_hostname_pinned_cap():
    with pytest.raises(SystemExit, match="added automatically by --hostname"):
        cli._reject_derived_caps(["tls", "hostname-pinned"])


def test_helper_allows_ordinary_caps():
    cli._reject_derived_caps(["tls", "role:web", "role:db"])   # must not raise
    cli._reject_derived_caps([])


def test_guard_runs_before_hostname_path_readds_it():
    """The screen sees only user-supplied caps: the --hostname path appends
    `hostname-pinned` AFTER the screen, so a legitimate pin isn't self-rejected.
    Asserted structurally — the guard call precedes the caps.append in source."""
    import inspect
    src = inspect.getsource(cli.cmd_invite)
    assert src.index("_reject_derived_caps(caps)") < src.index('caps.append("hostname-pinned")')
