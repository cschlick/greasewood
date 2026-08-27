"""
`gw leave` — a node voluntarily departs: the signed LeaveRequest reaches the
anchor FIRST (over the still-up tunnel), and only a confirmed departure tears
the local side down. A failed or refused request must change nothing locally.
"""
import json
import types
import urllib.request

import pytest

from greasewood import cli


def _cfg(tmp_path, role="node"):
    from greasewood.keys import NodeKeys
    NodeKeys.load_or_generate(tmp_path)
    p = tmp_path / "gw.toml"
    p.write_text(f"""[node]
hostname = "leaver"
data_dir = "{tmp_path}"
role = "{role}"
[network]
interface = "gw-mesh"
mesh_domain = "home.internal"
seeds = []
root_url = "http://[fd8d::1]:51902"
[ca]
trusted_pubs = []
""")
    return types.SimpleNamespace(config=str(p), yes=True)


class _Mgr:
    def __init__(self, order): self.order = order
    def disable_now(self, key): self.order.append(f"disable:{key}"); return True
    def unit_name(self, key): return f"svc@{key}"


def _wire(monkeypatch, order, response=None, error=None):
    """Record the anchor call + teardown calls in one ordered list."""
    def fake_urlopen(req, timeout=0):
        order.append(f"POST:{req.full_url.rsplit('/', 1)[-1]}")
        if error is not None:
            raise error
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return json.dumps(response).encode()
        return R()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    mgr = _Mgr(order)
    monkeypatch.setattr(cli, "_service_backend", lambda: mgr)
    monkeypatch.setattr("greasewood.wg.destroy_interface",
                        lambda iface: order.append(f"destroy:{iface}"))
    monkeypatch.setattr("greasewood.hosts.remove_block", lambda dom: False)
    return mgr


def test_leave_talks_to_anchor_before_teardown(tmp_path, monkeypatch, capsys):
    order = []
    _wire(monkeypatch, order, response={"status": "left", "hostname_freed": True})
    assert cli.cmd_leave(_cfg(tmp_path)) == 0
    assert order[0] == "POST:leave"                      # anchor FIRST
    assert "disable:home" in order and "destroy:gw-mesh" in order
    assert order.index("POST:leave") < order.index("destroy:gw-mesh")
    out = capsys.readouterr().out
    assert "hostname freed" in out and "gw purge" in out


def test_unreachable_anchor_changes_nothing(tmp_path, monkeypatch):
    import urllib.error
    order = []
    _wire(monkeypatch, order, error=urllib.error.URLError("timed out"))
    with pytest.raises(SystemExit) as e:
        cli.cmd_leave(_cfg(tmp_path))
    assert "nothing was changed locally" in str(e.value).lower()
    assert order == ["POST:leave"]                       # no teardown happened


def test_anchor_refusal_changes_nothing(tmp_path, monkeypatch):
    order = []
    _wire(monkeypatch, order, response={"error": "replay detected"})
    with pytest.raises(SystemExit) as e:
        cli.cmd_leave(_cfg(tmp_path))
    assert "refused" in str(e.value)
    assert order == ["POST:leave"]


def test_anchor_role_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as e:
        cli.cmd_leave(_cfg(tmp_path, role="anchor"))
    assert "anchor can't leave" in str(e.value)


def test_declined_prompt_changes_nothing(tmp_path, monkeypatch, capsys):
    order = []
    _wire(monkeypatch, order, response={"status": "left"})
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    args = _cfg(tmp_path); args.yes = False
    assert cli.cmd_leave(args) == 1
    assert order == []                                   # not even the request
