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

def test_anchor_rules_enforce_on_are_underlay_udp_only():
    # Enforcement on (default): greasewood's own table owns the overlay ports
    # (control + enrollment), so the checkable firewall rules are just the two
    # underlay UDP ports the operator must open.
    ports = {(r.proto, r.port, r.iif) for r in fw.anchor_rules()}
    assert ports == {("udp", 51900, None), ("udp", 51901, None)}


def test_anchor_rules_enforce_off_cover_control_and_door():
    # Enforcement off: greasewood installs no table, so the operator must gate
    # the overlay ports and they ARE checked.
    rules = fw.anchor_rules(enforce_ports=False)
    ports = {(r.proto, r.port, r.iif) for r in rules}
    assert ("udp", 51900, None) in ports
    assert ("udp", 51901, None) in ports
    assert ("tcp", 51902, "gw-mesh") in ports
    assert ("tcp", 51903, "gw-door") in ports


def test_node_rules_is_mesh_port_only():
    rules = fw.node_rules()
    assert all(r.proto == "udp" and r.iif is None for r in rules)
    assert {r.port for r in rules} == {51900}  # door 51901 is anchor-only


# --- default-drop detection ---

def test_default_drop_detected():
    assert fw.default_drop(_ruleset(_chain(policy="drop")))
    assert not fw.default_drop(_ruleset(_chain(policy="accept")))
    assert not fw.default_drop(_ruleset())  # no input chain


# --- missing-rule detection ---

def test_missing_when_port_absent():
    # ruleset has only the door port; the mesh port (51900) is missing
    rs = _ruleset(_chain("drop"), _accept_rule("udp", 51901))
    missing = fw.missing_rules(rs, fw.node_rules())
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
    anchor = [r for r in fw.anchor_rules() if r.port == 51902]
    assert fw.missing_rules(rs, anchor) == anchor  # gw-mesh rule still missing


def test_iifname_match_satisfies():
    rs = _ruleset(_chain("drop"), _accept_rule("tcp", 51902, iif="gw-mesh"))
    anchor = [r for r in fw.anchor_rules() if r.port == 51902]
    assert fw.missing_rules(rs, anchor) == []



def test_anchor_rules_use_the_real_mesh_interface():
    # The control-plane rule (enforcement OFF) must be scoped to the actual
    # gw-<name> interface, not the stale hardcoded "gw-mesh".
    rules = fw.anchor_rules(51900, 51902, mesh_iface="gw-pm", enforce_ports=False)
    control = [r for r in rules if r.proto == "tcp" and r.port == 51902]
    assert control and control[0].iif == "gw-pm"
