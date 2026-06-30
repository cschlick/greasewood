"""
greasewood.config — TOML configuration loading.

All nodes share one config format. Role ("hub", "seed", "node") is a runtime
setting, not a build distinction. "Special" is a function of holding ca_priv
and being pointed-to as a seed — nothing else.

"hub" is the canonical name for the coordinating node; "root" is accepted as
an alias in existing configs.
"""
from __future__ import annotations

import datetime as dt
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Node identity
    data_dir: Path
    hostname: str
    role: str              # "root" | "seed" | "node"
    inbound: str           # "yes" | "no" | "unknown"
    caps: list[str]
    endpoints: list[str]   # explicit endpoints e.g. ["[2001:db8::1]:51820"]

    # Network
    wg_interface: str
    listen_port: int

    # Control plane
    seeds: list[str]       # http://[addr]:port — seeds to pull directory from
    root_url: str          # where to send enroll/renew requests

    # CA trust set — list of hex-encoded raw Ed25519 public keys
    ca_pubs: list[str]

    # Hub-only (written under [hub] section; [root] accepted as alias)
    ca_key_file: Path | None
    ca_key_passphrase_env: str | None
    control_listen: str
    credential_ttl: dt.timedelta
    renew_before: dt.timedelta
    door_window: dt.timedelta

    @property
    def dir_cache_path(self) -> Path:
        return self.data_dir / "directory.json"

    @property
    def wg_key_path(self) -> Path:
        return self.data_dir / "wg.key"


def _parse_duration(s: str) -> dt.timedelta:
    """Parse simple duration strings: '24h', '12h', '7d', '30m'."""
    if s.endswith("h"):
        return dt.timedelta(hours=int(s[:-1]))
    if s.endswith("d"):
        return dt.timedelta(days=int(s[:-1]))
    if s.endswith("m"):
        return dt.timedelta(minutes=int(s[:-1]))
    raise ValueError(f"unrecognized duration {s!r} — use '24h', '7d', or '30m'")


def load_config(path: Path) -> Config:
    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    node = raw.get("node", {})
    net = raw.get("network", {})
    ca_sec = raw.get("ca", {})
    # [hub] is canonical; [root] accepted for backwards compatibility
    root = raw.get("hub", raw.get("root", {}))

    if not node.get("hostname"):
        sys.exit("config: [node] hostname is required")

    return Config(
        data_dir=Path(node.get("data_dir", "/var/lib/greasewood")).expanduser(),
        hostname=node["hostname"],
        role=node.get("role", "node"),
        inbound=node.get("inbound", "unknown"),
        caps=node.get("caps", ["mesh"]),
        endpoints=node.get("endpoints", []),

        wg_interface=net.get("interface", "gw0"),
        listen_port=int(net.get("listen_port", 51820)),

        seeds=net.get("seeds", []),
        root_url=net.get("root_url", ""),

        ca_pubs=ca_sec.get("trusted_pubs", []),

        ca_key_file=Path(root["ca_key_file"]).expanduser() if "ca_key_file" in root else None,
        ca_key_passphrase_env=root.get("ca_key_passphrase_env"),
        control_listen=root.get("control_listen", ":7946"),
        credential_ttl=_parse_duration(root.get("credential_ttl", "24h")),
        renew_before=_parse_duration(root.get("renew_before", "12h")),
        door_window=_parse_duration(root.get("door_window", "15m")),
    )
