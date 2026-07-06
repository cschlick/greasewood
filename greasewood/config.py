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

    # CA trust set — list of hex-encoded raw Ed25519 public keys
    ca_pubs: list[str]

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


def _parse_duration(s: str) -> dt.timedelta:
    """Parse simple duration strings: '24h', '12h', '7d', '30m'."""
    if s.endswith("h"):
        return dt.timedelta(hours=int(s[:-1]))
    if s.endswith("d"):
        return dt.timedelta(days=int(s[:-1]))
    if s.endswith("m"):
        return dt.timedelta(minutes=int(s[:-1]))
    raise ValueError(f"unrecognized duration {s!r} — use '24h', '7d', or '30m'")


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

        ca_pubs=ca_sec.get("trusted_pubs", []),

        ca_key_file=Path(anchor["ca_key_file"]).expanduser() if "ca_key_file" in anchor else None,
        ca_key_passphrase_env=anchor.get("ca_key_passphrase_env"),
        control_listen=anchor.get("control_listen", ":51902"),
        credential_ttl=_parse_duration(anchor.get("credential_ttl", "24h")),
        renew_before=_parse_duration(anchor.get("renew_before", "12h")),
        door_window=_parse_duration(anchor.get("door_window", "15m")),
        tls_cert_ttl=_parse_duration(anchor.get("tls_cert_ttl", "7d")),
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
