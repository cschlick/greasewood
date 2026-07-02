"""
greasewood.certs — TLS service certs: issuance + auto-renewal.

`gw cert-request` issues a short-lived leaf cert from the hub (default 7d TTL)
and records it in a small manifest (<data_dir>/tls/managed.json). The daemon then
runs a CertRenewalLoop that re-issues each managed cert at ~half its lifetime —
the same "short-lived + rotate" model the mesh credential already uses — and runs
an optional per-cert reload command so the consuming service picks up the new
files. This removes the need to cron `gw cert-request`.
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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc


class CertRejected(RuntimeError):
    """The hub refused the request (4xx) — won't change on retry."""


def issue_cert(hub_url: str, keys, *, dns: list[str], ips: list[str], cn: str,
               name: str, out_dir: Path, timeout: float = 10.0,
               attempts: int = 5) -> "tuple[Path, Path, Path]":
    """Request a leaf TLS cert from the hub and write <name>.key/<name>.crt +
    ca.crt into out_dir (leaf private key 0600, generated locally and never sent).
    Returns (key_path, crt_path, ca_path). Raises CertRejected on a hub 4xx (no
    retry) or RuntimeError after exhausting retries."""
    import time as _t
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
    url = f"{hub_url.rstrip('/')}/cert"
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
                _t.sleep(3)
        except urllib.error.URLError as e:
            last_err = e
            if attempt < attempts - 1:
                _t.sleep(3)
    if data is None:
        raise RuntimeError(str(last_err))
    if "error" in data:
        raise CertRejected(data["error"])

    leaf_key_pem = leaf.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path, crt_path, ca_path = (out_dir / f"{name}.key", out_dir / f"{name}.crt",
                                   out_dir / "ca.crt")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, leaf_key_pem)
    finally:
        os.close(fd)
    crt_path.write_text(data["cert"])
    ca_path.write_text(data["ca_cert"])
    return key_path, crt_path, ca_path


# --- manifest of daemon-managed certs -------------------------------------

def manifest_path(data_dir) -> Path:
    return Path(data_dir) / "tls" / "managed.json"


def load_manifest(data_dir) -> list:
    try:
        return json.loads(manifest_path(data_dir).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def record_managed(data_dir, entry: dict) -> None:
    """Add/replace a managed-cert entry (keyed by name + out_dir)."""
    certs = [c for c in load_manifest(data_dir)
             if not (c.get("name") == entry["name"]
                     and c.get("out_dir") == entry["out_dir"])]
    certs.append(entry)
    p = manifest_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(certs, indent=2))


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


class CertRenewalLoop:
    """Re-issue each managed cert at ~half its lifetime and run its reload_cmd."""

    def __init__(self, node_keys, get_hub_url: "Callable[[], str]", data_dir,
                 check_interval: float = 3600.0) -> None:
        self._keys = node_keys
        self._get_hub_url = get_hub_url
        self._data_dir = data_dir
        self._check_interval = check_interval
        self._stop = threading.Event()

    def _run_reload(self, reload_cmd) -> None:
        if not reload_cmd:
            return
        try:
            r = subprocess.run(reload_cmd, shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                log.warning("cert reload_cmd %r exited %d: %s",
                            reload_cmd, r.returncode, (r.stderr or "").strip())
            else:
                log.info("cert reload_cmd ran: %s", reload_cmd)
        except Exception as e:
            log.warning("cert reload_cmd %r failed: %s", reload_cmd, e)

    def check_all(self) -> None:
        hub_url = self._get_hub_url()
        for entry in load_manifest(self._data_dir):
            if not entry.get("auto_renew", True):
                continue
            crt = Path(entry["out_dir"]) / f"{entry['name']}.crt"
            if not cert_due_for_renewal(crt):
                continue
            try:
                issue_cert(hub_url, self._keys, dns=entry.get("dns", []),
                           ips=entry.get("ips", []), cn=entry["cn"],
                           name=entry["name"], out_dir=Path(entry["out_dir"]))
                log.info("auto-renewed TLS cert %r", entry["name"])
                self._run_reload(entry.get("reload_cmd"))
            except Exception as e:
                log.warning("TLS cert auto-renewal for %r failed: %s",
                            entry["name"], e)

    def run(self) -> None:
        while not self._stop.wait(self._check_interval):
            try:
                self.check_all()
            except Exception as e:
                log.error("cert renewal loop error: %s", e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="cert-renewal", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
