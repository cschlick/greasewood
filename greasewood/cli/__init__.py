"""
gw — CLI entry point (every subcommand lives here; `gw --help` is the index).

The core ceremony — enrollment is door-based: a transient WireGuard tunnel,
no SSH, no HTTP on the underlay:

  On the anchor:
    gw create <name>      # one-shot: CA, door key, routing, self-credential
    gw run                # start the daemon (serves control plane + door)
    gw invite             # open a window, print a single-use join token

  On the new node:
    gw join <token>       # enroll over the door, then:
    gw run                # join the mesh

Everything else groups around that: observe (watch — which now also shows the
host-firewall port check — diagnose, narrate, config), administer nodes on the
anchor (invite/close-door, revoke, set-caps,
set-roles, renew-all), maintain this node (renew, rename-node, rename-mesh,
purge), TLS service certs (cert-request/-profiles/-status/-remove), and anchor
lifecycle (anchor-promote, anchor-backup, anchor-restore, anchor-activate).
"""

# One command-line surface, many files. Every name is re-exported here so
# `from greasewood import cli` remains the single address for commands,
# helpers, and — deliberately — the test suite's monkeypatches: submodules
# call cross-cutting helpers through this namespace (cli.<name>), so a patch
# here reaches every caller, exactly as it did when this was one 6,000-line
# module.
# The original single module's import surface, preserved: code and tests
# alike reach these as cli.os, cli.sys, cli.service, cli.membership_key, …
import argparse            # noqa: F401
import base64              # noqa: F401
import datetime as dt      # noqa: F401
import ipaddress           # noqa: F401
import json                # noqa: F401
import logging             # noqa: F401
import os                  # noqa: F401
import shutil              # noqa: F401
import signal              # noqa: F401
import socket              # noqa: F401
import re                  # noqa: F401
import subprocess          # noqa: F401
import sys                 # noqa: F401
import threading           # noqa: F401
import time                # noqa: F401
from pathlib import Path   # noqa: F401

from .. import service                      # noqa: F401
from .. import platform as gwplat           # noqa: F401
from ..config import membership_key, render_config          # noqa: F401
from ..keys import (_key_file_warnings, _own_identity,      # noqa: F401
                    _secret_key_paths)
from ..upgrade import UpgradeManager                        # noqa: F401

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")

from ..status import (_dur_short, _load_revoked, _version,  # noqa: F401
                      cmd_diagnose, cmd_watch)
from ._common import (  # noqa: F401
    NOT_A_HOLDER_MSG, _IFACE_RE, _NEXT_RENEWAL_NOTE,
    _add_config_aliases, _adopt_renew_after, _anchor_ca_source,
    _anchor_membership, _anchor_urls, _config_aliases,
    _control_port, _daemon_fatal, _discover_config,
    _extract_token, _free_listen_port,
    _get_passphrase, _grants_naming_role, _holds_anchor,
    _iface_collision, _load_anchor_ca,
    _membership_for_ca, _membership_paths, _memberships,
    _print_firewall_help, _reject_bad_interface, _reject_derived_caps,
    _reject_reserved_roles, _republish_own_record, _request_fleet_renewal,
    _require_root, _require_supported_os, _require_tools,
    _resolve_node, _san_to_owned_label, _setup_logging,
    _warn_shared_overlay_prefix,
)
from .netdetect import (  # noqa: F401
    _CGNAT4, _advertised_endpoints, _default_iface6,
    _detect_public_ipv4, _detect_public_ipv6, _endpoint_with_port,
    _globally_reachable_v4, _inet6_addrs, _local_families,
    _local_global_addrs, _order_door_hosts,
)
from .svc import (  # noqa: F401
    _REPO_URL, _SERVICE_UNIT, _SYSTEMCTL_TIMEOUT,
    _UNIT_DIR, _membership_service, _pipx_install_env,
    _print_daemon_guidance, _prune_dangling_apps, _refresh_service_template,
    _service_backend, _service_exec, _service_restart,
    _svc_restart_hint, _systemctl_run, _systemd_available,
    _unit_for_config, _wait_service_settled, _write_service_template,
    cmd_service, cmd_upgrade,
)
from .bootstrap import (  # noqa: F401
    _DOOR_HANDSHAKE_TIMEOUT, _dial_door, _door_handshake_up,
    _enroll_over_door, _enroll_over_door_inner, _menu_from_grants,
    _route_join, cmd_close_door, cmd_create,
    cmd_invite, cmd_join,
)
from .membership import (  # noqa: F401
    _gw_daemons_for_mesh, _kill_daemons, _migrate_membership,
    _other_peer_count, _pid_alive, _rewrite_cert_manifest_domain,
    cmd_leave, cmd_purge, cmd_rename_mesh,
    cmd_rename_node, cmd_renew, cmd_revoke,
    cmd_set_caps, cmd_set_roles,
)
from .anchorcmds import (  # noqa: F401
    _backup_passphrase, _claim_anchor_offer, _dest_is_overlay,
    _do_handoff, _failover_passphrase, cmd_anchor,
    cmd_anchor_activate, cmd_anchor_backup, cmd_anchor_promote,
    cmd_anchor_restore, cmd_anchor_standby, cmd_anchor_transfer,
    cmd_renew_all,
    cmd_upgrade_all,
)
from .certcmds import (  # noqa: F401
    _cert_already_current, _load_cert_profile, _print_cert_noop,
    _shipped_profile_names, _shipped_profiles_dir, cmd_cert_profiles,
    cmd_cert_remove, cmd_cert_request, cmd_cert_status,
)
from .daemon import (  # noqa: F401
    _start_anchor_control_plane, cmd_run,
)
from .parser import (  # noqa: F401
    cmd_explain,
    _EVERYDAY_COMMANDS, _cmd_bare, _resolve_editor,
    build_parser, cmd_config, cmd_narrate,
    cmd_policy, main,
)
