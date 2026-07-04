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

import contextlib
import fcntl
import logging
import os
import re
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_HOSTS = Path("/etc/hosts")


def _begin(tag: str) -> str:
    return f"# BEGIN greasewood [{tag}] — managed, do not edit"


def _end(tag: str) -> str:
    return f"# END greasewood [{tag}]"


@contextlib.contextmanager
def _lock(path: Path):
    """Serialize read-modify-write of the hosts file across processes, so two
    daemons (a host on two meshes) don't clobber each other's block. Best-effort
    — if the lock file can't be created, proceed unlocked (blocks are per-tag, so
    the worst case is a transient overwrite that self-heals next reconcile)."""
    lockp = Path(str(path) + ".gwlock")
    try:
        f = open(lockp, "w")
    except OSError:
        yield
        return
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            f.close()


_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def valid_label(label: str) -> bool:
    """True if `label` is a single DNS-safe label (the form an alias must take).
    Strict, not coercive: a bad label is rejected, never silently mangled — so
    it can't inject an unexpected name into /etc/hosts."""
    return bool(_LABEL_RE.match(label))


def sanitize(hostname: str) -> str:
    """DNS-safe single label ([a-z0-9-], <=63 chars); the key used for name
    uniqueness and the label in mesh names.

    Linux hostnames are far more permissive than DNS (any bytes, up to 64 chars,
    uppercase/underscores/dots/unicode all allowed), so we force a valid label:
    lowercase, non-[a-z0-9-] runs collapsed to '-' (this includes dots, so
    'sub.domain.com' -> 'sub-domain-com' rather than a multi-label name), no
    leading/trailing '-', and capped at the 63-char DNS label limit.
    'ops@node01' -> 'ops-node01'."""
    s = re.sub(r"[^a-z0-9-]+", "-", hostname.strip().lower()).strip("-")
    s = s[:63].rstrip("-")  # DNS label max is 63; re-strip if the cut left a '-'
    return s or "node"


def mesh_name(hostname: str, domain: str) -> str:
    """The DNS-safe mesh FQDN for a node: "<sanitized-hostname>.<domain>".

    The single source of truth for naming — used both for the /etc/hosts block
    and as the default TLS cert CN/SAN (gw cert-request), so the name a node is
    reachable by is exactly the name its certificate is valid for.
    """
    return f"{sanitize(hostname)}.{domain}"


def _managed_block_addrs(text: str, tag: str) -> set:
    """The set of addresses currently in THIS tag's greasewood block."""
    begin, end = _begin(tag), _end(tag)
    addrs, inside = set(), False
    for line in text.splitlines():
        s = line.strip()
        if s == begin:
            inside = True
            continue
        if inside:
            if s == end:
                break
            parts = line.split()
            if parts and not parts[0].startswith("#"):
                addrs.add(parts[0])
    return addrs


# Warn at most once per (domain) per process about a shared-tag collision — a
# flapping block would otherwise log every reconcile cycle.
_warned_collisions: set = set()


def _warn_domain_collision(domain: str) -> None:
    if domain in _warned_collisions:
        return
    _warned_collisions.add(domain)
    log.warning(
        "another greasewood mesh is writing the [%s] /etc/hosts block — its "
        "entries are for addresses this mesh doesn't have, so two meshes on this "
        "host share mesh_domain=%r. Their name blocks clobber each other every "
        "reconcile, and the names themselves collide (each '<host>.%s' would "
        "resolve to two different overlay addresses). Give each mesh a distinct "
        "[network] mesh_domain (as you already give each a distinct interface).",
        domain, domain, domain)


def _strip_managed(text: str, tag: str) -> str:
    """Return `text` with THIS tag's greasewood block removed (only ours, so a
    second mesh's block on the same host is left untouched)."""
    begin, end = _begin(tag), _end(tag)
    out, skip = [], False
    for line in text.splitlines():
        if line.strip() == begin:
            skip = True
            continue
        if skip:
            if line.strip() == end:
                skip = False
            continue
        out.append(line)
    return "\n".join(out)


def render_block(records, domain: str) -> str:
    """The managed block (between markers) for the given NodeRecords. The domain
    doubles as the block tag, so each mesh gets its own block on a shared host.

    Each node also gets a line per alias it publishes: a bare label expanded to
    `<label>.<node-mesh-name>` pointing at the node's own address. Because the
    domain part is always the record's attested mesh name (never something the
    node chose), a node can only ever name things in its OWN namespace — no
    ownership check needed and no cross-node collision possible."""
    lines = [_begin(domain)]
    for r in sorted(records, key=lambda r: r.hostname.lower()):
        base = mesh_name(r.hostname, domain)
        lines.append(f"{r.cred.addr}\t{base}")
        for label in sorted(set(getattr(r, "aliases", []) or [])):
            if valid_label(label):        # strict: skip anything not a clean label
                lines.append(f"{r.cred.addr}\t{label}.{base}")
    lines.append(_end(domain))
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
    """Ensure /etc/hosts carries this mesh's managed block for `records` (the
    block is tagged by `domain`, so a host on two meshes keeps two blocks).
    Returns True if the file changed."""
    with _lock(path):
        current = path.read_text() if path.exists() else ""
        # Silent-misconfig guard: if the block under our tag holds addresses this
        # mesh doesn't have, another mesh on this host shares our mesh_domain.
        # Our own (stable) address is always in `records`, so normal churn keeps
        # a non-empty overlap; a foreign mesh is fully disjoint.
        new_addrs = {r.cred.addr for r in records}
        existing_addrs = _managed_block_addrs(current, domain)
        if new_addrs and existing_addrs and not (existing_addrs & new_addrs):
            _warn_domain_collision(domain)
        base = _strip_managed(current, domain).rstrip("\n")
        block = render_block(records, domain)
        new = f"{base}\n\n{block}\n" if base else f"{block}\n"
        if new != current:
            _atomic_write(path, new)
            return True
    return False


def remove_block(domain: str, path: Path = DEFAULT_HOSTS) -> bool:
    """Remove this mesh's managed block (clean opt-out). Returns True if it
    changed. Other meshes' blocks are left untouched."""
    with _lock(path):
        if not path.exists():
            return False
        current = path.read_text()
        base = _strip_managed(current, domain)
        new = base.rstrip("\n") + "\n" if base.strip() else base
        if new != current:
            _atomic_write(path, new)
            return True
    return False
