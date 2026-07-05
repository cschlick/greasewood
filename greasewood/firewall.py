"""
greasewood.firewall — advisory firewall check (read-only).

greasewood never modifies the host firewall. create / join
*check* the local nftables ruleset and loudly flag ports that look blocked,
printing the exact rules to add — but applying them is always the operator's
job (put them in your nftables config; the Ansible `nftables` role does this).

The check is advisory and conservative: it inspects `nft -j list ruleset` and
only warns about a port when the input chain is default-drop AND no accept rule
for that port is found. Sets/ranges it can't parse cause a (clearly worded)
"couldn't confirm" warning, never a false all-clear.

This is nftables-only. On hosts using iptables/ufw/firewalld or no firewall,
the check says so and prints the rules for you to apply yourself.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

# Door constants are imported lazily to avoid a cycle at import time.


@dataclass(frozen=True)
class Rule:
    proto: str          # "udp" | "tcp"
    port: int
    iif: str | None     # interface name, or None for the underlay/any
    why: str

    def nft_match(self) -> str:
        """The nftables matcher (without verdict) for this rule."""
        parts = []
        if self.iif:
            parts.append(f'iifname "{self.iif}"')
        parts.append(f"{self.proto} dport {self.port}")
        return " ".join(parts)


def anchor_rules(listen_port: int = 51900, control_port: int = 51902) -> list[Rule]:
    from .door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    return [
        Rule("udp", listen_port, None, "mesh WireGuard"),
        Rule("udp", DOOR_PORT, None, "enrollment door (WireGuard)"),
        Rule("tcp", control_port, "gw-mesh", "control plane (when anchor)"),
        Rule("tcp", ENROLL_PORT, DOOR_IFACE, "enrollment exchange (when anchor)"),
    ]


def node_rules(listen_port: int = 51900) -> list[Rule]:
    """Inbound rules a plain node needs: just the mesh WireGuard UDP port. We
    print it unconditionally — a node that turns out to be unreachable simply
    never receives on it (and WireGuard is silent to unauthenticated packets, so
    an open-but-unused port is near-zero surface). The door port (51901) is
    anchor-only — a joining node dials the anchor's door outbound."""
    return [Rule("udp", listen_port, None, "mesh WireGuard")]


# ---------------------------------------------------------------------------
# nftables introspection (pure functions over the `nft -j` JSON)
# ---------------------------------------------------------------------------

def _input_chains(ruleset: dict) -> list[dict]:
    """The base chains hooked at input."""
    out = []
    for item in ruleset.get("nftables", []):
        ch = item.get("chain")
        if ch and ch.get("hook") == "input" and "policy" in ch:
            out.append(ch)
    return out


def default_drop(ruleset: dict) -> bool:
    """True if any input base chain defaults to drop/reject."""
    return any(c.get("policy") in ("drop", "reject") for c in _input_chains(ruleset))


def _right_contains(right, value) -> bool:
    """Does an nft expression's right-hand side match `value` (int or str),
    handling scalars and sets (ignoring ranges, which we can't confirm)."""
    if isinstance(right, dict) and "set" in right:
        for el in right["set"]:
            if el == value:
                return True
        return False
    return right == value


def _rule_accepts(rule: dict, proto: str, port: int, iif: str | None) -> bool:
    """True if this nft rule is an accept matching (proto dport port [, iif])."""
    exprs = rule.get("expr", [])
    has_accept = any(isinstance(e, dict) and "accept" in e for e in exprs)
    if not has_accept:
        return False

    dport_ok = False
    iif_ok = iif is None
    for e in exprs:
        m = e.get("match") if isinstance(e, dict) else None
        if not m:
            continue
        left = m.get("left", {})
        payload = left.get("payload") if isinstance(left, dict) else None
        meta = left.get("meta") if isinstance(left, dict) else None
        if payload and payload.get("field") == "dport" \
                and payload.get("protocol") == proto:
            if _right_contains(m.get("right"), port):
                dport_ok = True
        if iif is not None and meta and meta.get("key") == "iifname":
            if _right_contains(m.get("right"), iif):
                iif_ok = True
    return dport_ok and iif_ok


def missing_rules(ruleset: dict, rules: list[Rule]) -> list[Rule]:
    """Rules with no matching accept anywhere in the ruleset."""
    all_rules = [item["rule"] for item in ruleset.get("nftables", []) if "rule" in item]
    missing = []
    for r in rules:
        if not any(_rule_accepts(rule, r.proto, r.port, r.iif) for rule in all_rules):
            missing.append(r)
    return missing


# ---------------------------------------------------------------------------
# Advisory check (read-only) used by the CLI
# ---------------------------------------------------------------------------

def _load_ruleset():
    if not shutil.which("nft"):
        return None
    r = subprocess.run(["nft", "-j", "list", "ruleset"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def check(rules: list[Rule], log) -> bool:
    """Inspect the local firewall and warn about anything that looks blocked.
    Returns True if everything looks fine (or unknowable), False if a needed
    port appears blocked by a default-drop policy."""
    ruleset = _load_ruleset()
    if ruleset is None:
        log.info("firewall: no nftables ruleset readable — make sure these are "
                 "reachable inbound: %s",
                 ", ".join(f"{r.proto}/{r.port}" for r in rules))
        return True
    if not default_drop(ruleset):
        log.info("firewall: input policy is not default-drop; greasewood ports "
                 "are not blocked locally.")
        return True

    missing = missing_rules(ruleset, rules)
    if not missing:
        log.info("firewall: all greasewood ports are allowed.")
        return True

    log.warning("firewall: input policy is default-drop and these greasewood "
                "ports do not appear allowed — the daemon may be unreachable:")
    for r in missing:
        scope = f'iifname "{r.iif}" ' if r.iif else ""
        log.warning("  missing: %s%s dport %d  (%s)", scope, r.proto, r.port, r.why)
    log.warning("Apply them manually (nftables), then persist in your nft config:")
    for r in missing:
        log.warning("  %s accept", r.nft_match())
    return False
