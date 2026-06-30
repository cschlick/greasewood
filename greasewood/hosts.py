"""
greasewood.hosts — optional name resolution via a managed /etc/hosts block.

Opt-in (config [network] hosts_sync). When enabled, the daemon keeps a clearly
marked block in /etc/hosts mapping each node's overlay address to
"<hostname>.<domain>" (domain defaults to "internal"), regenerated from the
local directory cache each reconcile cycle. So `ping db.internal` (and psql,
curl, anything that uses getaddrinfo) just works, with no DNS server and no
dependency on the hub being reachable.

It only ever touches the region between its markers — user lines are never
modified. Disabling it (and restarting) removes the block; so does `gw purge`.

Names are sanitized to a DNS-safe form ([a-z0-9-]); collisions (two nodes whose
names sanitize the same) are left as duplicate lines — enforce unique hostnames
at the hub if that matters to you.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

DEFAULT_HOSTS = Path("/etc/hosts")
_BEGIN = "# BEGIN greasewood — managed, do not edit"
_END = "# END greasewood"


def sanitize(hostname: str) -> str:
    """DNS-safe form of a hostname ([a-z0-9-]); the key used for name uniqueness
    and the label in mesh names. 'root@node01' -> 'root-node01'."""
    s = re.sub(r"[^a-z0-9-]+", "-", hostname.strip().lower()).strip("-")
    return s or "node"


def mesh_name(hostname: str, domain: str) -> str:
    """The DNS-safe mesh FQDN for a node: "<sanitized-hostname>.<domain>".

    The single source of truth for naming — used both for the /etc/hosts block
    and as the default TLS cert CN/SAN (gw cert-request), so the name a node is
    reachable by is exactly the name its certificate is valid for.
    """
    return f"{sanitize(hostname)}.{domain}"


def _strip_managed(text: str) -> str:
    """Return `text` with any existing greasewood block removed."""
    out, skip = [], False
    for line in text.splitlines():
        if line.strip() == _BEGIN:
            skip = True
            continue
        if skip:
            if line.strip() == _END:
                skip = False
            continue
        out.append(line)
    return "\n".join(out)


def render_block(records, domain: str) -> str:
    """The managed block (between markers) for the given NodeRecords."""
    lines = [_BEGIN]
    for r in sorted(records, key=lambda r: r.hostname.lower()):
        lines.append(f"{r.cred.addr}\t{mesh_name(r.hostname, domain)}")
    lines.append(_END)
    return "\n".join(lines)


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".gw.tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    try:
        os.replace(tmp, path)
    except OSError:
        # /etc/hosts is often a bind mount (containers) or on another fs, where
        # rename-over fails (EBUSY/EXDEV). Fall back to an in-place write — not
        # atomic, but fine for this small, infrequently-written file.
        try:
            with open(path, "w") as f:
                f.write(text)
        finally:
            tmp.unlink(missing_ok=True)


def sync(records, domain: str, path: Path = DEFAULT_HOSTS) -> bool:
    """Ensure /etc/hosts carries the managed block for `records`. Returns True
    if the file changed."""
    current = path.read_text() if path.exists() else ""
    base = _strip_managed(current).rstrip("\n")
    block = render_block(records, domain)
    new = f"{base}\n\n{block}\n" if base else f"{block}\n"
    if new != current:
        _atomic_write(path, new)
        return True
    return False


def remove_block(path: Path = DEFAULT_HOSTS) -> bool:
    """Remove the managed block (clean opt-out). Returns True if it changed."""
    if not path.exists():
        return False
    current = path.read_text()
    base = _strip_managed(current)
    new = base.rstrip("\n") + "\n" if base.strip() else base
    if new != current:
        _atomic_write(path, new)
        return True
    return False
