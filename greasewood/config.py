"""
greasewood.config — TOML configuration loading.

All nodes share one config format. Role ("anchor", "node") is a runtime setting,
not a build distinction. An anchor is just a node that additionally holds ca_priv
and serves the control plane + enrollment door.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Node identity  [node]
    data_dir: Path
    hostname: str
    role: str              # "anchor" | "node"
    caps: list[str]
    endpoints: list[str]   # explicit endpoints e.g. ["[2001:db8::1]:51900"]

    # Network  [network]
    wg_interface: str
    listen_port: int
    overlay_prefix: str    # the fleet's overlay /64, e.g. "fd8d:e5c1:db1a:7::"

    # Name resolution: maintain a managed /etc/hosts block mapping overlay
    # addresses to "<hostname>.<mesh_domain>". The domain is also the default
    # TLS cert name (gw cert-request), so a node's address name == its cert SAN.
    hosts_sync: bool
    mesh_domain: str
    # Extra service names this node publishes into the mesh's /etc/hosts, as
    # bare labels under its own mesh name (e.g. ["pg"] → pg.<hostname>.<domain>).
    # `gw cert-request` appends one automatically for a subdomain --san.
    aliases: list[str]
    # Durable data-plane command trail (the daemon appends every ip/wg command
    # here). Default <data_dir>/audit.log; set audit_log = "" to disable.
    audit_log: Path | None

    # Control plane
    seeds: list[str]       # http://[addr]:port — seeds to pull directory from
    root_url: str          # where to send enroll/renew requests

    # CA trust set — hex-encoded raw Ed25519 public keys. The _hex suffix is
    # load-bearing: everywhere ELSE in the codebase `ca_pubs` is raw bytes (what
    # verify() wants), and cli/status decode this with bytes.fromhex at use.
    ca_pubs_hex: list[str]

    # Anchor-only (written under the [anchor] section)
    ca_key_file: Path | None
    ca_key_passphrase_env: str | None
    control_listen: str
    credential_ttl: dt.timedelta
    renew_before: dt.timedelta
    door_window: dt.timedelta
    tls_cert_ttl: dt.timedelta
    door_port: int
    # Defaults granted to NEW nodes at `gw invite` when the operator doesn't pass
    # --segments / --caps. Read fresh at each invite, so editing them changes what
    # future enrollments get (no restart). `default_caps` ships with "tls" on.
    default_segments: list[str]
    default_caps: list[str]

    @property
    def dir_cache_path(self) -> Path:
        return self.data_dir / "directory.json"

    @property
    def wg_key_path(self) -> Path:
        return self.data_dir / "wg.key"


def membership_key(domain: str) -> str:
    """The membership key for a mesh domain: '<name>.internal' → '<name>';
    anything else (a --mesh-domain override like corp.example.internal) is
    sanitized to a single DNS-safe label. Every name-keyed artifact —
    /etc/greasewood_<key>.toml, /var/lib/greasewood_<key>, gw-<key>, the
    greasewood@<key> unit — derives from this."""
    from .hosts import sanitize, valid_label
    stem = domain[:-len(".internal")] if domain.endswith(".internal") else domain
    return stem if valid_label(stem) else sanitize(stem)


def _duration(section: dict, key: str, default: str) -> dt.timedelta:
    """Parse a duration config value, exiting with a clean `config:` message on a
    bad one — the same posture as overlay_prefix, not a raw ValueError traceback
    at startup."""
    raw = section.get(key, default)
    try:
        return _parse_duration(raw)
    except ValueError as e:
        sys.exit(f"config: bad {key} {raw!r}: {e}")


def _parse_duration(s: str) -> dt.timedelta:
    """Parse simple duration strings: '24h', '12h', '7d', '30m'. Rejects
    non-positive values — a zero/negative credential_ttl would have an anchor
    issue already-expired credentials, and no duration greasewood uses is ever
    meant to be <= 0."""
    unit = {"h": "hours", "d": "days", "m": "minutes"}.get(s[-1:] if s else "")
    if unit is None:
        raise ValueError(f"unrecognized duration {s!r} — use '24h', '7d', or '30m'")
    try:
        n = int(s[:-1])
    except ValueError:
        raise ValueError(f"unrecognized duration {s!r} — use '24h', '7d', or '30m'")
    if n <= 0:
        raise ValueError(f"duration {s!r} must be positive")
    return dt.timedelta(**{unit: n})


def render_config(*, hostname: str, data_dir, role: str, caps: list,
                  endpoints: "list | None" = None, interface: str,
                  listen_port: int, overlay_prefix: str, seeds: list,
                  root_url: str, hosts_sync: bool, mesh_domain: str,
                  trusted_pubs: list, anchor: "dict | None" = None) -> str:
    """The ONE writer of /etc/greasewood_<name>.toml — create, join, and
    anchor-promote all render through it, so a config field is added in exactly
    two places: the Config dataclass above (the reader) and this template (the
    writer). `anchor` (the anchor-only section) is a dict with ca_key_file,
    control_port, credential_ttl, door_port; None on a plain node."""
    endpoint_line = f"\nendpoints = {json.dumps(list(endpoints))}" if endpoints else ""
    text = f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "{role}"
caps = {json.dumps(list(caps))}{endpoint_line}

[network]
interface = "{interface}"
listen_port = {listen_port}
overlay_prefix = "{overlay_prefix}"
seeds = {json.dumps(list(seeds))}
root_url = {json.dumps(root_url or "")}
hosts_sync = {"true" if hosts_sync else "false"}
mesh_domain = "{mesh_domain}"

[ca]
trusted_pubs = {json.dumps(list(trusted_pubs))}
"""
    if anchor:
        text += f"""
[anchor]
ca_key_file = "{anchor["ca_key_file"]}"
control_listen = ":{anchor["control_port"]}"
credential_ttl = "{anchor["credential_ttl"]}"
renew_before = "12h"
door_window = "15m"
door_port = {anchor["door_port"]}
# Defaults granted to new nodes at `gw invite` (when --segments/--caps are
# omitted). Edit anytime — the next invite reads them fresh, no restart.
default_segments = ["mesh"]
default_caps = ["tls"]
"""
    return text


def load_config(path: Path) -> Config:
    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    node = raw.get("node", {})
    net = raw.get("network", {})
    ca_sec = raw.get("ca", {})
    anchor = raw.get("anchor", {})

    if not node.get("hostname"):
        sys.exit("config: [node] hostname is required")

    data_dir = Path(node.get("data_dir", "/var/lib/greasewood")).expanduser()
    # Default to <data_dir>/audit.log; "" (explicitly empty) disables it.
    raw_audit = net.get("audit_log")
    audit_log = (None if raw_audit == ""
                 else Path(raw_audit).expanduser() if raw_audit
                 else data_dir / "audit.log")

    cfg = Config(
        data_dir=data_dir,
        hostname=node["hostname"],
        role=node.get("role", "node"),
        # Default must be a segment: tag — peering is decided by shared
        # segments, so a bare "mesh" cap would silently peer with nobody.
        caps=node.get("caps", ["segment:mesh"]),
        endpoints=node.get("endpoints", []),

        wg_interface=net.get("interface", "gw-mesh"),
        listen_port=int(net.get("listen_port", 51900)),
        overlay_prefix=net.get("overlay_prefix", "fd8d:e5c1:db1a:7::"),

        seeds=net.get("seeds", []),
        root_url=net.get("root_url", ""),

        hosts_sync=bool(net.get("hosts_sync", True)),
        mesh_domain=net.get("mesh_domain", "gw.internal"),
        aliases=list(net.get("aliases", [])),
        audit_log=audit_log,

        ca_pubs_hex=ca_sec.get("trusted_pubs", []),

        ca_key_file=Path(anchor["ca_key_file"]).expanduser() if "ca_key_file" in anchor else None,
        ca_key_passphrase_env=anchor.get("ca_key_passphrase_env"),
        control_listen=anchor.get("control_listen", ":51902"),
        credential_ttl=_duration(anchor, "credential_ttl", "24h"),
        renew_before=_duration(anchor, "renew_before", "12h"),
        door_window=_duration(anchor, "door_window", "15m"),
        tls_cert_ttl=_duration(anchor, "tls_cert_ttl", "7d"),
        door_port=int(anchor.get("door_port", 51901)),
        default_segments=list(anchor.get("default_segments", ["mesh"])),
        default_caps=list(anchor.get("default_caps", ["tls"])),
    )

    # Activate this config's overlay prefix process-wide, so address
    # construction (own address, cred issuance) uses the fleet's /64. One daemon
    # serves one mesh, so a process-global is correct. Verification is
    # prefix-agnostic, so a bad value here never affects trust.
    from .keys import set_overlay_prefix, parse_overlay_prefix
    try:
        set_overlay_prefix(parse_overlay_prefix(cfg.overlay_prefix))
    except ValueError as e:
        # Fail loudly: silently keeping the DEFAULT /64 on a typo'd prefix
        # would address this node (or issue credentials, on an anchor) under
        # the wrong prefix with zero signal.
        sys.exit(f"config: bad overlay_prefix {cfg.overlay_prefix!r}: {e}")
    return cfg
