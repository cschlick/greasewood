"""
No-nftables host — a materially different surface. greasewood must degrade
cleanly: never crash, never claim a firewall check it can't make, and (when set
up correctly) run UNENFORCED. Everything that touches nft changes here — the
watch firewall blocks, the diagnose firewall verdict, port-enforcement
availability, and the setup advisory. The distro CI containers all HAVE nft, so
this path isn't exercised end-to-end elsewhere; these tests pin the behavior.
"""
import datetime as dt
import logging
import subprocess
import types

import pytest

from greasewood import status, firewall, portfilter

_UTC = dt.timezone.utc


@pytest.fixture
def no_nft(monkeypatch):
    """Simulate a host with NO nftables: `nft` off PATH, and any nft exec raises
    FileNotFoundError — the two independent ways the code detects its absence."""
    import shutil
    orig_which = shutil.which
    monkeypatch.setattr(shutil, "which",
                        lambda n, *a, **k: None if n == "nft" else orig_which(n, *a, **k))
    orig_run = subprocess.run

    def run(cmd, *a, **k):
        if isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "nft":
            raise FileNotFoundError("nft")
        return orig_run(cmd, *a, **k)
    monkeypatch.setattr(subprocess, "run", run)


def _cfg(role="node", enforce=False):
    return types.SimpleNamespace(role=role, listen_port=51900, wg_interface="gw-pm",
                                 enforce_ports=enforce, mesh_domain="pm.internal",
                                 control_listen=":51902")


# --- the primitives ---

def test_load_ruleset_is_none(no_nft):
    assert firewall._load_ruleset() is None


def test_nft_usable_false_and_ensure_available_raises(no_nft):
    assert portfilter.nft_usable() is False
    with pytest.raises(portfilter.NftUnavailable, match="not installed"):
        portfilter.ensure_available()


def test_firewall_check_degrades_to_advisory_not_alarm(no_nft):
    # No ruleset to read → check() must return True (don't cry wolf) and log the
    # ports to make reachable, not warn about a block it can't confirm.
    assert firewall.check(firewall.node_rules(51900), logging.getLogger("t")) is True


# --- the watch / diagnose presentation surface ---

def test_watch_host_firewall_block_is_omitted(no_nft):
    # Nothing to check against → the whole "main firewall" block disappears.
    assert status._main_firewall_lines(_cfg("anchor")) == []


def test_gw_table_block_says_enforcement_off_when_unenforced(no_nft):
    # The realistic no-nft host: create/join wrote enforce_ports=false.
    lines = status._nft_table_lines(_cfg(enforce=False))
    assert any("port enforcement off" in l for l in lines)


def test_gw_table_block_says_not_installed_when_misconfigured(no_nft):
    # enforce_ports=true but nft absent (a misconfig) → honest "nft not installed".
    lines = status._nft_table_lines(_cfg(enforce=True))
    assert any("nft not installed" in l for l in lines)


def test_diagnose_self_firewall_verdict_is_unknowable(no_nft):
    assert "nft unreadable" in status._self_firewall_verdict(51900)


# --- end to end: the whole snapshot renders without a crash ---

def test_watch_snapshot_renders_cleanly_on_a_no_nft_host(no_nft, tmp_path, capsys):
    from greasewood import cli
    from greasewood.config import load_config
    from greasewood.directory import Directory
    from greasewood.keys import CAKeys, NodeKeys, derive_addr
    from greasewood.wire import Credential, NodeRecord

    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "api1"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:mesh"]
endpoint_auto = false
[network]
interface = "gw-pm"
enforce_ports = false
seeds = []
mesh_domain = "pm.internal"
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    cfg = load_config(tmp_path / "gw.toml")
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=me.id_pub_bytes, wg_pub=me.wg_pub_bytes,
                      addr=derive_addr(me.id_pub_bytes), hostname="api1",
                      caps=["role:mesh"], iat=now, exp=now + dt.timedelta(hours=24)).sign(ca.ca_priv)
    d = Directory()
    d.put(NodeRecord(id_pub=me.id_pub_bytes, seq=1, endpoints=[], cred=cred).sign(me.id_priv))
    d.save(cfg.dir_cache_path)

    rc = cli.cmd_watch(types.SimpleNamespace(config=str(tmp_path / "gw.toml"), snapshot=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "main firewall" not in out           # host-firewall block omitted (no nft)
    assert "port enforcement off" in out         # gw-table block honest about no table
    assert "api1" in out                          # the roster still renders
