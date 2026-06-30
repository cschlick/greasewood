"""
greasewood.firewall — advisory firewall check + opt-in nftables rule apply.

greasewood never touches the firewall on its own. But setup-hub / join can
*check* the local nftables ruleset and loudly flag ports that look blocked, and
— only when the operator passes --open-firewall — insert the needed accept
rules into the host's input chain (tagged with a "greasewood" comment so
they're easy to find and remove).

The check is advisory and conservative: it inspects `nft -j list ruleset`,
and only warns about a port when the input chain is default-drop AND no accept
rule for that port is found. Sets/ranges it can't parse cause a (clearly worded)
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


def hub_rules(listen_port: int = 51900, control_port: int = 51902) -> list[Rule]:
    from .door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    return [
        Rule("udp", listen_port, None, "mesh WireGuard"),
        Rule("udp", DOOR_PORT, None, "enrollment door (WireGuard)"),
        Rule("tcp", control_port, "gw0", "control plane (when hub)"),
        Rule("tcp", ENROLL_PORT, DOOR_IFACE, "enrollment exchange (when hub)"),
    ]


def node_rules(listen_port: int = 51900, inbound: str = "yes") -> list[Rule]:
    """Inbound rules a plain node needs. An outbound-only node (inbound=no)
    needs none — it dials peers (and the hub's door) outbound and relies on the
    base ct established,related rule for replies. It only opens the mesh port if
    it accepts inbound. The door port (51901) is hub-only — a joining node
    connects to the hub's door outbound, so it never needs it inbound."""
    if inbound == "no":
        return []
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


def find_input_chain(ruleset: dict) -> tuple[str, str, str] | None:
    """Return (family, table, chain) of the input base chain to insert into,
    preferring an `inet` chain. None if there isn't exactly one obvious target."""
    chains = _input_chains(ruleset)
    if not chains:
        return None
    inet = [c for c in chains if c.get("family") == "inet"]
    chosen = inet[0] if inet else (chains[0] if len(chains) == 1 else None)
    if chosen is None:
        return None
    return chosen["family"], chosen["table"], chosen["name"]


def insert_commands(target: tuple[str, str, str], rules: list[Rule]) -> list[list[str]]:
    """nft argv commands to insert accept rules (tagged) at the top of the
    input chain. `insert` prepends, so our accepts win over a later drop."""
    family, table, chain = target
    cmds = []
    for r in rules:
        # nft re-joins argv with spaces and re-lexes, so quotes embedded in a
        # token survive to the parser. The comment must be a quoted string.
        cmds.append([
            "nft", "insert", "rule", family, table, chain,
            *r.nft_match().split(), "accept", "comment", '"greasewood"',
        ])
    return cmds


# ---------------------------------------------------------------------------
# Side-effecting entry points used by the CLI
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
    log.warning("Add them with `--open-firewall`, or apply manually (nftables):")
    for r in missing:
        log.warning("  %s accept", r.nft_match())
    return False


def apply(rules: list[Rule], log) -> bool:
    """Insert accept rules into the host's input chain. Returns True on success.
    Idempotent: skips rules already present (greasewood-tagged or otherwise)."""
    if not shutil.which("nft"):
        log.error("firewall: nft not found — cannot --open-firewall; apply rules "
                  "manually.")
        return False
    ruleset = _load_ruleset()
    if ruleset is None:
        log.error("firewall: could not read nftables ruleset; not applying.")
        return False
    target = find_input_chain(ruleset)
    if target is None:
        log.error("firewall: no single input base chain found; not applying. "
                  "Add these rules to your input chain manually:")
        for r in rules:
            log.error("  %s accept", r.nft_match())
        return False

    to_add = missing_rules(ruleset, rules)
    if not to_add:
        log.info("firewall: nothing to add — all ports already allowed.")
        return True

    ok = True
    for cmd in insert_commands(target, to_add):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log.error("firewall: failed to add rule (%s): %s",
                      " ".join(cmd), r.stderr.strip())
            ok = False
        else:
            log.info("firewall: added %s", " ".join(cmd[6:]))
    if ok:
        log.info("firewall: rules added to %s %s %s (tagged \"greasewood\"). "
                 "Persist them in your nftables config to survive reboot.",
                 *target)
    return ok
