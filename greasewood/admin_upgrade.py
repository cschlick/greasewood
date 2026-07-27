"""Entry point for the packaged admin-upgrade helper.

The actual logic lives in a shell script so it can spawn interactive ssh -t
sessions and pass sudo password prompts through. This module simply locates the
bundled shell script and replaces the current process with bash running it,
preserving the terminal.
"""

import os
import shutil
import sys

from importlib import resources


def main(argv: "list[str] | None" = None) -> "int":
    """Locate and exec the bundled admin-upgrade.sh."""
    if argv is None:
        argv = sys.argv
    script = resources.files("greasewood") / "scripts" / "admin-upgrade.sh"
    if not script.is_file():
        print("admin-upgrade.sh not found in package resources", file=sys.stderr)
        return 1
    bash = shutil.which("bash") or "/bin/bash"
    # Preserve the invoked command name (argv[0]) and pass the rest through.
    os.execvp(bash, [bash, str(script), *argv[1:]])
    return 1  # unreachable
