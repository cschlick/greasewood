"""
Unit tests for greasewood.firewall — the pure logic over `nft -j` JSON.

No nftables needed: we feed fixture rulesets and check the detection +
command-generation. The side-effecting check()/apply() are thin wrappers.

test_generated_rules_parse_with_nft additionally runs the real generated
commands through `nft` when it's available (skips otherwise) to catch any
syntax/quoting mistakes the fixtures can't.
"""
import os
import shutil
import subprocess

import pytest

from greasewood import firewall as fw


def _chain(policy="drop", family="inet", table="filter", name="input"):
    return {"chain": {"family": family, "table": table, "name": name,
                      "type": "filter", "hook": "input", "prio": 0,
                      "policy": policy}}


def _accept_rule(proto, port, iif=None, family="inet", table="filter",
                 chain="input", right=None):
    exprs = []
    if iif:
        exprs.append({"match": {"op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": iif}})
    exprs.append({"match": {"op": "==",
                            "left": {"payload": {"protocol": proto, "field": "dport"}},
                            "right": right if right is not None else port}})
    exprs.append({"accept": None})
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": exprs}}


def _ruleset(*items):
    return {"nftables": [{"metainfo": {}}, *items]}


# --- required rule sets ---

def test_hub_rules_cover_control_and_door():
    rules = fw.hub_rules()
    ports = {(r.proto, r.port, r.iif) for r in rules}
    assert ("udp", 51900, None) in ports
    assert ("udp", 51901, None) in ports
    assert ("tcp", 51902, "gw-mesh") in ports
    assert ("tcp", 51903, "gw-door") in ports


def test_node_rules_inbound_yes_is_mesh_port_only():
    rules = fw.node_rules(inbound="yes")
    assert all(r.proto == "udp" and r.iif is None for r in rules)
    assert {r.port for r in rules} == {51900}  # door 51901 is hub-only


def test_node_rules_inbound_no_needs_nothing():
    assert fw.node_rules(inbound="no") == []


# --- default-drop detection ---

def test_default_drop_detected():
    assert fw.default_drop(_ruleset(_chain(policy="drop")))
    assert not fw.default_drop(_ruleset(_chain(policy="accept")))
    assert not fw.default_drop(_ruleset())  # no input chain


# --- missing-rule detection ---

def test_missing_when_port_absent():
    # ruleset has only the door port; the mesh port (51900) is missing
    rs = _ruleset(_chain("drop"), _accept_rule("udp", 51901))
    missing = fw.missing_rules(rs, fw.node_rules(inbound="yes"))
    assert {r.port for r in missing} == {51900}


def test_nothing_missing_when_all_present():
    rs = _ruleset(_chain("drop"),
                  _accept_rule("udp", 51900),
                  _accept_rule("udp", 51901))
    assert fw.missing_rules(rs, fw.node_rules()) == []


def test_port_in_a_set_counts_as_present():
    rs = _ruleset(_chain("drop"),
                  _accept_rule("udp", 0, right={"set": [51900, 51901]}))
    assert fw.missing_rules(rs, fw.node_rules()) == []


def test_iifname_scoped_rule_must_match_interface():
    # An accept for tcp/51902 with NO iifname does NOT satisfy a rule that
    # requires iifname gw-mesh... actually it does (broader allow). But a rule
    # scoped to the WRONG interface must not count.
    rs = _ruleset(_chain("drop"), _accept_rule("tcp", 51902, iif="eth0"))
    hub = [r for r in fw.hub_rules() if r.port == 51902]
    assert fw.missing_rules(rs, hub) == hub  # gw-mesh rule still missing


def test_iifname_match_satisfies():
    rs = _ruleset(_chain("drop"), _accept_rule("tcp", 51902, iif="gw-mesh"))
    hub = [r for r in fw.hub_rules() if r.port == 51902]
    assert fw.missing_rules(rs, hub) == []


# --- insert command generation ---

def test_find_input_chain_prefers_inet():
    rs = _ruleset(_chain("drop", family="ip", name="INPUT"),
                  _chain("drop", family="inet", table="filter", name="input"))
    assert fw.find_input_chain(rs) == ("inet", "filter", "input")


def test_insert_commands_shape():
    target = ("inet", "filter", "input")
    cmds = fw.insert_commands(target, fw.node_rules())
    assert cmds[0][:6] == ["nft", "insert", "rule", "inet", "filter", "input"]
    joined = " ".join(cmds[0])
    assert "udp dport 51900" in joined
    assert joined.endswith('accept comment "greasewood"')


def test_insert_command_includes_iifname():
    target = ("inet", "filter", "input")
    hub = [r for r in fw.hub_rules() if r.iif == "gw-mesh"]
    cmd = fw.insert_commands(target, hub)[0]
    joined = " ".join(cmd)
    assert 'iifname "gw-mesh"' in joined and "tcp dport 51902" in joined


# --- live nft validation (skipped where nft/root unavailable) ---

def test_generated_rules_parse_with_nft():
    """Run the exact generated insert commands through nft, against an isolated
    hook-less throwaway table (no effect on live traffic), to validate syntax +
    quoting on a real host with nftables."""
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    if os.geteuid() != 0:
        pytest.skip("nft needs root")

    table = "greasewood_argv_test"
    setup = subprocess.run(["nft", "add", "table", "inet", table],
                           capture_output=True, text=True)
    if setup.returncode != 0:
        pytest.skip(f"cannot create nft test table: {setup.stderr.strip()}")
    try:
        # A regular chain (no type/hook) holds the same rule syntax but never
        # sees packets.
        subprocess.run(["nft", "add", "chain", "inet", table, "c"], check=True)
        # hub_rules is the superset (udp underlay + iifname-scoped tcp).
        for cmd in fw.insert_commands(("inet", table, "c"), fw.hub_rules()):
            r = subprocess.run(cmd, capture_output=True, text=True)
            assert r.returncode == 0, \
                f"nft rejected {' '.join(cmd)}:\n{r.stderr.strip()}"
        # The rules + comment landed.
        listing = subprocess.run(["nft", "list", "table", "inet", table],
                                 capture_output=True, text=True).stdout
        assert "greasewood" in listing
        assert "51900" in listing and "51902" in listing
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)
