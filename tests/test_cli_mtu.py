"""
PMTU blackhole probe for `gw diagnose`. A WireGuard-over-cloud MTU blackhole is
miserable to debug by hand: small pings and SSH work, but TLS handshakes and
large transfers hang, because full-size tunnel packets exceed the underlay path
MTU and the ICMP-too-big messages are filtered. The probe sends a DF ping at the
tunnel's interface MTU across a linked peer: if the small ping passes but the
full-size one is dropped, that's the blackhole, reported with the fix.
"""
import datetime as dt
import os
import subprocess
import time
import types

from greasewood import cli, wg
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _fake_run(mapping):
    """subprocess.run stub: `mapping` maps a match-substring in the argv to a
    returncode (and optional stdout)."""
    def run(cmd, *a, **k):
        argv = " ".join(cmd)
        for needle, spec in mapping.items():
            if needle in argv:
                rc, out = spec if isinstance(spec, tuple) else (spec, "")
                return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return run


def test_iface_mtu_parses(monkeypatch):
    out = "42: gw-mesh: <POINTOPOINT,NOARP,UP> mtu 1420 qdisc noqueue state UNKNOWN\n"
    monkeypatch.setattr(cli.subprocess, "run",
                        _fake_run({"link show": (0, out)}))
    assert cli._iface_mtu("gw-mesh") == 1420


def test_iface_mtu_missing_is_none(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "run", _fake_run({"link show": (1, "")}))
    assert cli._iface_mtu("gw-mesh") is None


def test_probe_clean_path_no_warning(monkeypatch):
    # ping available; both small and full-size succeed → no blackhole.
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/bin/ping")
    monkeypatch.setattr(cli.subprocess, "run", _fake_run({"ping": 0}))
    assert cli._mtu_probe("gw-mesh", "fd8d::2", iface_mtu=1420) is None


def test_probe_detects_blackhole(monkeypatch):
    # small ping (-s 100) passes, the full-size one (-s 1372) is dropped.
    def run(cmd, *a, **k):
        argv = " ".join(cmd)
        if "ping" in argv:
            ok = "-s 100 " in argv + " "
            return subprocess.CompletedProcess(cmd, 0 if ok else 1)
        return subprocess.CompletedProcess(cmd, 0)
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/bin/ping")
    monkeypatch.setattr(cli.subprocess, "run", run)
    warn = cli._mtu_probe("gw-mesh", "fd8d::2", iface_mtu=1420)
    assert warn is not None
    assert "MTU" in warn and "1420" in warn      # names the interface MTU
    assert "1372" in warn                         # and the payload it dropped (1420-48)


def test_probe_small_ping_fails_is_inconclusive(monkeypatch):
    # If even the small ping fails, the link is just down right now — not an MTU
    # problem; stay quiet rather than cry wolf.
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/bin/ping")
    monkeypatch.setattr(cli.subprocess, "run", _fake_run({"ping": 1}))
    assert cli._mtu_probe("gw-mesh", "fd8d::2", iface_mtu=1420) is None


def test_probe_no_ping_binary_is_none(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert cli._mtu_probe("gw-mesh", "fd8d::2", iface_mtu=1420) is None


def test_probe_unknown_mtu_is_none(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/bin/ping")
    assert cli._mtu_probe("gw-mesh", "fd8d::2", iface_mtu=None) is None


# --- end-to-end: the blackhole warning reaches diagnose output --------------

def _linked_peer_diagnose(tmp_path, monkeypatch):
    """A minimal node with one LINKED peer; returns the peer's overlay addr."""
    ca = CAKeys.generate()
    peer = NodeKeys.generate()
    NodeKeys.load_or_generate(tmp_path)  # our own identity
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "self"
data_dir = "{tmp_path}"
role = "node"
inbound = "yes"
caps = ["segment:mesh"]
[network]
interface = "gw-mesh"
seeds = []
root_url = ""
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(
        id_pub=peer.id_pub_bytes, wg_pub=peer.wg_pub_bytes,
        addr=derive_addr(peer.id_pub_bytes), hostname="db", caps=["segment:mesh"],
        iat=now, exp=now + dt.timedelta(hours=1),
    ).sign(ca.ca_priv)
    rec = NodeRecord(id_pub=peer.id_pub_bytes, seq=1,
                     endpoints=["203.0.113.7:51900"], inbound="yes",
                     cred=cred).sign(peer.id_priv)

    from greasewood.config import load_config
    cfg = load_config(tmp_path / "gw.toml")
    d = Directory()
    d.put(rec)
    d.save(cfg.dir_cache_path)

    live = {peer.wg_pub_b64: wg.LivePeer(
        wg_pub_b64=peer.wg_pub_b64, endpoint="203.0.113.7:51900",
        allowed_ips=derive_addr(peer.id_pub_bytes) + "/128",
        latest_handshake=int(time.time()) - 10, rx_bytes=1, tx_bytes=1)}

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: live)
    monkeypatch.setattr(cli, "_iface_mtu", lambda iface: 1420)
    return cfg, derive_addr(peer.id_pub_bytes)


def test_diagnose_reports_blackhole_on_linked_peer(tmp_path, monkeypatch, capsys):
    cfg, addr = _linked_peer_diagnose(tmp_path, monkeypatch)
    # Simulate the blackhole: small DF ping passes, full-MTU one is dropped.
    monkeypatch.setattr(cli, "_ping6_df",
                        lambda a, payload, timeout=1: payload <= 100)
    cli.cmd_diagnose(types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                                           hostname=None, no_mtu_probe=False))
    out = capsys.readouterr().out
    assert "LINKED" in out
    assert "PATH MTU BLACKHOLE" in out and "1372" in out


def test_diagnose_no_mtu_probe_flag_skips_it(tmp_path, monkeypatch, capsys):
    cfg, addr = _linked_peer_diagnose(tmp_path, monkeypatch)
    # If the probe DID run it would warn; the flag must prevent it entirely.
    monkeypatch.setattr(cli, "_ping6_df",
                        lambda a, payload, timeout=1: payload <= 100)
    cli.cmd_diagnose(types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                                           hostname=None, no_mtu_probe=True))
    out = capsys.readouterr().out
    assert "LINKED" in out
    assert "BLACKHOLE" not in out
