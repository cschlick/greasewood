"""Enable `python -m greasewood`.

The systemd unit launches the daemon this way (see
cli._service_exec): baking `<abs-interpreter> -m greasewood` into the service,
rather than the `gw` console-script path, keeps the launch from depending on
where pip put the wrapper — so a bare `pip install` into any environment is
viable for daemon use, not just the fixed-venv install.sh path.
"""
from .cli import main

raise SystemExit(main())
