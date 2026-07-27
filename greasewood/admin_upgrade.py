"""Entry point for the packaged admin-upgrade helper.

The actual logic lives in a shell script so it can spawn interactive ssh -t
sessions and pass sudo password prompts through. This module locates the bundled
shell script, and can generate a host list from the local mesh snapshot before
handing off to the shell.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib import resources

from greasewood.hosts import mesh_name


def _mesh_hostfile(ssh_user=None):
    """Generate a temporary host list from `gw watch --snapshot --json`.

    Returns (path, exit_code). On success, path is a temp file that the caller
    should pass to admin-upgrade.sh with -f.
    """
    cmd = [sys.executable, "-m", "greasewood.cli", "watch", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return None, result.returncode

    try:
        snapshot = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("gw-admin-upgrade --from-mesh: failed to parse gw watch --json output",
              file=sys.stderr)
        return None, 1

    domain = snapshot.get("mesh", {}).get("domain")
    if not domain:
        print("gw-admin-upgrade --from-mesh: mesh domain not found in snapshot; "
              "is the daemon running?", file=sys.stderr)
        return None, 1

    hosts = []
    for node in snapshot.get("nodes", []):
        if node.get("is_self"):
            continue
        fqdn = mesh_name(node.get("hostname", "node"), domain)
        hosts.append(f"{ssh_user}@{fqdn}" if ssh_user else fqdn)

    if not hosts:
        print("gw-admin-upgrade --from-mesh: no peers found in snapshot",
              file=sys.stderr)
        return None, 1

    fd, path = tempfile.mkstemp(prefix="gw-admin-upgrade-", suffix=".txt",
                                dir=tempfile.gettempdir())
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(hosts) + "\n")
    return path, 0


def main(argv=None):
    """Locate and exec the bundled admin-upgrade.sh, optionally building the
    host list from the mesh snapshot."""
    if argv is None:
        argv = sys.argv

    script = resources.files("greasewood") / "scripts" / "admin-upgrade.sh"
    if not script.is_file():
        print("admin-upgrade.sh not found in package resources", file=sys.stderr)
        return 1

    bash = shutil.which("bash") or "/bin/bash"

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--from-mesh", action="store_true",
                        help="generate the host list from gw watch --json")
    parser.add_argument("--user", default=None,
                        help="ssh user to prefix when --from-mesh is used")
    known, remaining = parser.parse_known_args(argv[1:])

    if known.from_mesh:
        hostfile, rc = _mesh_hostfile(known.user)
        if hostfile is None:
            return rc
        new_args = ["-f", hostfile] + remaining
        os.execvp(bash, [bash, str(script), *new_args])
        return 1  # unreachable

    os.execvp(bash, [bash, str(script), *remaining])
    return 1  # unreachable
