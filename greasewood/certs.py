"""
greasewood.certs — TLS service certs: issuance + auto-renewal.

`gw cert-request` issues a short-lived leaf cert from the anchor (default 7d TTL)
and records it in a small manifest (<data_dir>/tls/managed.json). The daemon then
runs a CertRenewalLoop that re-issues each managed cert at ~half its lifetime —
the same "short-lived + rotate" model the mesh credential already uses — and runs
an optional per-cert reload command so the consuming service picks up the new
files. This removes the need to cron `gw cert-request`.

A managed entry stores the three destination paths independently (key_path /
crt_path / ca_path), so a service that wants its key under /etc/ssl/private and
its cert elsewhere is supported — the three need not share a directory. Entries
are keyed by `name`, so re-requesting the same name relocates it in place.
Legacy entries (an `out_dir` + `name`, no explicit paths) still renew via the
derived <out_dir>/<name>.{key,crt} + <out_dir>/ca.crt layout.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import secrets
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .keys import atomic_write
from .loop import Loop

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc


class CertRejected(RuntimeError):
    """The anchor refused the request (4xx) — won't change on retry."""


def fetch_cert(anchor_url: str, keys, *, dns: list[str], ips: list[str], cn: str,
               timeout: float = 10.0, attempts: int = 5) -> "tuple[str, str, str]":
    """Request a leaf TLS cert from the anchor and return (key_pem, cert_pem,
    ca_pem) as PEM strings. The leaf private key is generated locally and never
    sent. Raises CertRejected on an anchor 4xx (no retry) or RuntimeError after
    exhausting retries. Callers place the PEMs (see issue_cert / place_cert_files)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .wire import CertRequest

    leaf = Ed25519PrivateKey.generate()
    leaf_pub = leaf.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    req = CertRequest(
        id_pub=keys.id_pub_bytes, leaf_pub=leaf_pub, cn=cn, dns=list(dns),
        ips=list(ips), nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(keys.id_priv)

    body = json.dumps(req.to_dict()).encode()
    url = f"{anchor_url.rstrip('/')}/cert"
    data, last_err = None, None
    for attempt in range(attempts):
        http_req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(http_req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", str(e))
            except Exception:
                msg = str(e)
            if 400 <= e.code < 500:          # bad request / no tls cap — fail fast
                raise CertRejected(msg) from e
            last_err = msg
            if attempt < attempts - 1:
                time.sleep(3)
        except urllib.error.URLError as e:
            last_err = e
            if attempt < attempts - 1:
                time.sleep(3)
    if data is None:
        raise RuntimeError(str(last_err))
    if "error" in data:
        raise CertRejected(data["error"])

    leaf_key_pem = leaf.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return leaf_key_pem, data["cert"], data["ca_cert"]


def issue_cert(anchor_url: str, keys, *, dns: list[str], ips: list[str], cn: str,
               key_path, crt_path, ca_path, timeout: float = 10.0,
               attempts: int = 5) -> "tuple[Path, Path, Path]":
    """Request a leaf TLS cert and write the leaf key, leaf cert, and CA cert to
    their three (independent) paths — they need not share a directory. The key
    is written 0600. Returns (key_path, crt_path, ca_path)."""
    key_pem, cert_pem, ca_pem = fetch_cert(
        anchor_url, keys, dns=dns, ips=ips, cn=cn, timeout=timeout, attempts=attempts)
    key_path, crt_path, ca_path = Path(key_path), Path(crt_path), Path(ca_path)
    atomic_write(key_path, key_pem)                 # 0600: private key
    atomic_write(crt_path, cert_pem, mode=0o644)
    atomic_write(ca_path, ca_pem, mode=0o644)
    return key_path, crt_path, ca_path


# --- cert PROFILES: place composed files where a service expects them ------

_ROLE_MODE = {"key": 0o600, "cert": 0o644, "ca": 0o644,
              "fullchain": 0o644, "bundle": 0o600}


def compose_role(role: str, key_pem: str, cert_pem: str, ca_pem: str) -> str:
    """The file content for a profile [[file]] role:
      key        leaf private key
      cert       leaf certificate
      ca         mesh CA certificate
      fullchain  cert + CA (servers that want the chain in one file)
      bundle     cert + CA + key (haproxy-style single PEM)"""
    def nl(s):
        return s if s.endswith("\n") else s + "\n"
    parts = {"key": [key_pem], "cert": [cert_pem], "ca": [ca_pem],
             "fullchain": [cert_pem, ca_pem], "bundle": [cert_pem, ca_pem, key_pem]}
    if role not in parts:
        raise ValueError(f"unknown cert file role {role!r} "
                         f"(key|cert|ca|fullchain|bundle)")
    return "".join(nl(p) for p in parts[role])


def _resolve_owner(owner: str) -> "tuple[int, int]":
    """('user:group' | 'user') → (uid, gid). Raises a clear error if the user or
    group doesn't exist on this host — the loud failure that tells you to
    install the service (or fix the profile) rather than mis-own a key."""
    import grp
    import pwd
    user, _, group = owner.partition(":")
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        raise RuntimeError(
            f"profile owner {user!r}: no such user on this host — install the "
            f"service first, or correct the [[file]] owner in the profile") from None
    if not group:
        return pw.pw_uid, pw.pw_gid
    try:
        return pw.pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        raise RuntimeError(f"profile owner group {group!r}: no such group on "
                           f"this host") from None


def place_cert_files(files: list, key_pem: str, cert_pem: str, ca_pem: str) -> None:
    """Write each profile [[file]] with its composed content, mode, and owner —
    atomically (temp + rename), so a service reading the file never sees a
    half-written cert or a wrong-mode key. Fails loudly on a bad role, an
    unwritable directory, or an unknown owner; never silently mis-places."""
    for f in files:
        role, dest = f["role"], Path(f["path"])
        content = compose_role(role, key_pem, cert_pem, ca_pem).encode()
        mode = int(f["mode"], 8) if f.get("mode") else _ROLE_MODE.get(role, 0o644)
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Deliberately NOT keys.atomic_write: the owner must change on the TEMP,
        # before the atomic swap, so the file appears fully-owned or not at all.
        tmp = dest.with_name(dest.name + ".gwtmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)                      # O_CREAT mode is umask-masked
        if f.get("owner"):
            os.chown(tmp, *_resolve_owner(f["owner"]))
        os.replace(tmp, dest)                    # atomic swap


def _profile_cert_path(files: list) -> "Path | None":
    """The file in a profile that carries the leaf cert (for the expiry check)."""
    for f in files:
        if f.get("role") in ("cert", "fullchain", "bundle"):
            return Path(f["path"])
    return None


# --- manifest of daemon-managed certs -------------------------------------

def manifest_path(data_dir) -> Path:
    return Path(data_dir) / "tls" / "managed.json"


def load_manifest(data_dir) -> list:
    try:
        return json.loads(manifest_path(data_dir).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def record_managed(data_dir, entry: dict) -> None:
    """Add/replace a managed-cert entry, keyed by NAME alone. Re-requesting the
    same name therefore RELOCATES its entry (new paths replace the old) instead
    of adding a duplicate that would keep renewing into the old location."""
    certs = [c for c in load_manifest(data_dir) if c.get("name") != entry["name"]]
    certs.append(entry)
    p = manifest_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(certs, indent=2))


def remove_managed(data_dir, name: str) -> bool:
    """Drop a managed-cert entry by name (stops the daemon renewing it). Returns
    True if an entry was actually removed. The placed files are NOT touched —
    a service may still be reading them; the caller decides."""
    entries = load_manifest(data_dir)
    kept = [c for c in entries if c.get("name") != name]
    if len(kept) == len(entries):
        return False
    manifest_path(data_dir).write_text(json.dumps(kept, indent=2))
    return True


def profile_snapshot_path(data_dir, name: str) -> Path:
    """Where the point-in-time copy of a cert's profile lives (record-keeping)."""
    return Path(data_dir) / "tls" / "profiles" / f"{name}.toml"


def snapshot_profile(data_dir, name: str, text: str) -> Path:
    """Save the profile TOML used for `name` as a record of exactly what was
    applied (with its provenance comments), separate from the manifest's
    effective config. Returns the snapshot path."""
    p = profile_snapshot_path(data_dir, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def cert_expiry(crt_path) -> "dt.datetime | None":
    """The not-after of a cert file as an aware UTC datetime, or None if the
    file is missing/unparseable."""
    from cryptography import x509
    try:
        cert = x509.load_pem_x509_certificate(Path(crt_path).read_bytes())
    except (FileNotFoundError, ValueError, OSError):
        return None
    return getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=_UTC)


def entry_cert_path(entry: dict) -> "Path | None":
    """The file carrying the leaf cert for a manifest entry — the profile's
    cert/fullchain/bundle file, or the legacy crt_path."""
    files = entry.get("files")
    return _profile_cert_path(files) if files else entry_paths(entry)[1]


def entry_paths(entry: dict) -> "tuple[Path, Path, Path]":
    """The (key, cert, ca) destinations for a managed-cert entry. Prefers the
    explicit per-file paths; falls back to the legacy out_dir + name scheme so a
    manifest written by an older greasewood keeps renewing after an upgrade."""
    if entry.get("key_path"):
        return (Path(entry["key_path"]), Path(entry["crt_path"]),
                Path(entry["ca_path"]))
    out = Path(entry["out_dir"])
    name = entry["name"]
    return out / f"{name}.key", out / f"{name}.crt", out / "ca.crt"


def cert_due_for_renewal(crt_path) -> bool:
    """True if the cert is missing/unreadable or past its half-life."""
    from cryptography import x509
    try:
        cert = x509.load_pem_x509_certificate(Path(crt_path).read_bytes())
    except (FileNotFoundError, ValueError):
        return True
    nb = getattr(cert, "not_valid_before_utc", None) or \
        cert.not_valid_before.replace(tzinfo=_UTC)
    na = getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=_UTC)
    return (dt.datetime.now(_UTC) - nb) >= (na - nb) / 2


def _rename_grace_old_domain(data_dir) -> "str | None":
    """The old mesh domain of an ACTIVE rename-mesh grace window (from
    <data_dir>/rename_grace.json), or None. Shared shape with the reconcile
    loop's hosts grace, so old TLS names and old /etc/hosts names retire
    together."""
    p = Path(data_dir) / "rename_grace.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        until = dt.datetime.fromisoformat(data["until"])
    except Exception:
        return None
    if dt.datetime.now(dt.timezone.utc) >= until:
        return None
    return data.get("old_domain")


def _grace_dual_names(dns: list, current_domain: str, old_domain: str) -> list:
    """Augment `dns` so every name under EITHER the current or the old mesh
    domain has both-domain variants — the renewed cert then verifies whether a
    client dials the new or the old name during the grace window. Robust to a
    manifest frozen with the pre-rename (old-domain) names."""
    out = set(dns)
    for name in dns:
        for a, b in ((current_domain, old_domain), (old_domain, current_domain)):
            if name.endswith("." + a):
                out.add(name[: -len(a)] + b)
    return sorted(out)


class CertRenewalLoop(Loop):
    """Re-issue each managed cert at ~half its lifetime and run its reload_cmd."""

    def __init__(self, node_keys, get_anchor_url: "Callable[[], str]", data_dir,
                 mesh_domain: "str | None" = None,
                 check_interval: float = 3600.0) -> None:
        super().__init__(check_interval, "cert-renewal")
        self._keys = node_keys
        self._get_anchor_url = get_anchor_url
        self._data_dir = data_dir
        # The mesh's CURRENT domain — during a rename-mesh grace window, renewed
        # certs must cover BOTH the new and the old name so TLS clients dialing
        # either verify (the hosts block already resolves both during grace).
        self._mesh_domain = mesh_domain

    def _run_reload(self, reload_cmd) -> None:
        if not reload_cmd:
            return
        try:
            # argv exec, no shell: this runs as root, so metacharacters in the
            # manifest string stay inert data. Operators who genuinely need
            # shell say so explicitly: --reload-cmd "sh -c '...'"
            r = subprocess.run(shlex.split(reload_cmd),
                               capture_output=True, text=True)
            if r.returncode != 0:
                log.warning("cert reload_cmd %r exited %d: %s",
                            reload_cmd, r.returncode, (r.stderr or "").strip())
            else:
                log.info("cert reload_cmd ran: %s", reload_cmd)
        except Exception as e:
            log.warning("cert reload_cmd %r failed: %s", reload_cmd, e)

    def check_all(self) -> None:
        anchor_url = self._get_anchor_url()
        grace_old = _rename_grace_old_domain(self._data_dir)
        for entry in load_manifest(self._data_dir):
            if not entry.get("auto_renew", True):
                continue
            files = entry.get("files")            # profile-placed cert?
            crt_path = entry_cert_path(entry)
            if not crt_path or not cert_due_for_renewal(crt_path):
                continue
            dns = entry.get("dns", [])
            if grace_old and self._mesh_domain:
                dns = _grace_dual_names(dns, self._mesh_domain, grace_old)
            try:
                if files:
                    # Re-fetch and RE-PLACE every file with its owner/mode, so a
                    # service's key stays readable by its user across renewals
                    # (the whole point of profiles — not just first issuance).
                    key_pem, cert_pem, ca_pem = fetch_cert(
                        anchor_url, self._keys, dns=dns,
                        ips=entry.get("ips", []), cn=entry["cn"])
                    place_cert_files(files, key_pem, cert_pem, ca_pem)
                else:
                    key_path, cp, ca_path = entry_paths(entry)
                    issue_cert(anchor_url, self._keys, dns=dns,
                               ips=entry.get("ips", []), cn=entry["cn"],
                               key_path=key_path, crt_path=cp, ca_path=ca_path)
                log.info("auto-renewed TLS cert %r", entry["name"])
                self._run_reload(entry.get("reload_cmd"))
            except Exception as e:
                log.warning("TLS cert auto-renewal for %r failed: %s",
                            entry["name"], e)

    # run/start/stop come from Loop; the tick keeps its public name
    # (check_all is also the "renew everything due, now" API).
    def _tick(self) -> None:
        self.check_all()
