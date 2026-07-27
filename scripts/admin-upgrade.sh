#!/usr/bin/env bash
# admin-upgrade.sh — explicit, interactive, fault-tolerant mesh node upgrade.
#
# This is intentionally NOT automatic. It is an admin tool that SSHs into a
# list of hosts and runs the configured upgrade command. It asks before every
# host by default, never upgrades silently, and keeps going through failures.
#
# Recommended setup in production: key auth + passwordless sudo. With password
# auth, `ssh -t` will prompt for SSH and sudo passwords on your terminal.
#
# Examples:
#   scripts/admin-upgrade.sh -f prod-hosts.txt
#   scripts/admin-upgrade.sh -y -c "sudo apt install --only-upgrade greasewood" host1 host2
#   ADMIN_UPGRADE_CMD="sudo systemctl restart greasewood@home" scripts/admin-upgrade.sh -n -f hosts.txt

set -u

COMMAND="${ADMIN_UPGRADE_CMD:-sudo pipx upgrade --global greasewood}"
YES="${ADMIN_UPGRADE_YES:-}"
DRY_RUN="${ADMIN_UPGRADE_DRY_RUN:-}"
SLEEP="${ADMIN_UPGRADE_SLEEP:-0}"
HOSTS=()
FAILURES=()

usage() {
    cat <<'EOF'
Usage: admin-upgrade.sh [OPTIONS] [HOST ...]

  -f FILE    read host list from FILE (one per line, blanks/comments ignored)
  -c CMD     run CMD on each remote host instead of the default
  -y         confirm yes for all hosts (still stops on individual ssh failures)
  -n         dry-run: print ssh commands, do not run them
  -s SECS    sleep SECS between hosts (default 0)
  -h         show this help

Environment variables (overridden by flags):
  ADMIN_UPGRADE_CMD    default remote command
  ADMIN_UPGRADE_YES    set to 1 to skip per-host prompts
  ADMIN_UPGRADE_DRY_RUN set to 1 to dry-run
  ADMIN_UPGRADE_SLEEP  seconds between hosts

A host can be [user@]hostname or any ssh(1) destination.
EOF
}

read_hostfile() {
    local file="$1"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(echo "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^# ]] && continue
        HOSTS+=("$line")
    done < "$file"
}

while getopts "c:f:s:ynh" opt; do
    case "$opt" in
        c) COMMAND="$OPTARG" ;;
        f) read_hostfile "$OPTARG" ;;
        s) SLEEP="$OPTARG" ;;
        y) YES=1 ;;
        n) DRY_RUN=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))
HOSTS+=("$@")

if [[ ${#HOSTS[@]} -eq 0 ]]; then
    echo "error: no hosts given" >&2
    usage
    exit 1
fi

for h in "${HOSTS[@]}"; do
    if [[ -z "$YES" ]]; then
        read -r -p "Upgrade $h? [y/N/a(ll)/q(uit)] " ans
        case "$ans" in
            [Aa])
                YES=1
                ;;
            [Yy])
                ;;
            [Qq])
                echo "aborted by user" >&2
                break
                ;;
            *)
                echo "  skipped $h"
                continue
                ;;
        esac
    fi

    if [[ -n "$DRY_RUN" ]]; then
        echo "[dry-run] ssh -t -o ConnectTimeout=10 -o BatchMode=no $h -- bash -lc '$COMMAND'"
        continue
    fi

    echo "==> upgrading $h"
    # -t forces a pty so remote sudo can prompt for a password if needed.
    # -o BatchMode=no explicitly allows password auth.
    if ssh -t -o ConnectTimeout=10 -o BatchMode=no "$h" -- "bash -lc '$COMMAND'"; then
        echo "    OK $h"
    else
        rc=$?
        echo "!!! FAILED $h (rc=$rc)" >&2
        FAILURES+=("$h")
    fi

    if [[ "$SLEEP" -gt 0 ]]; then
        sleep "$SLEEP"
    fi
done

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo
    echo "Finished with ${#FAILURES[@]} failure(s):"
    for h in "${FAILURES[@]}"; do
        echo "  - $h"
    done
    exit 1
fi

echo
echo "All hosts upgraded successfully."
exit 0
