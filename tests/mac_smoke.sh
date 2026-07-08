#!/bin/bash
# greasewood macOS live smoke test — run ON a Mac, as an admin user.
#
#   sudo bash tests/mac_smoke.sh
#
# Exercises the real Darwin runtime the (Linux-run) unit tests can only mock:
# wireguard-go spawn + utun naming, ifconfig/route data plane, the forwarding
# assertion, the launchd job lifecycle, gw watch, and a clean purge.
#
# Uses a THROWAWAY single-node mesh named 'gwsmoke' on non-default ports —
# it does not touch any existing membership (e.g. pm) on this machine, and it
# purges itself at the end. Safe to re-run.
set -u

MESH=gwsmoke
CFG=/etc/greasewood_${MESH}.toml
PLIST=/Library/LaunchDaemons/com.greasewood.${MESH}.plist
NAMEFILE=/var/run/wireguard/gw-${MESH}.name
PASS=0; FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✓ $*"; }
bad()  { FAIL=$((FAIL+1)); say "  ✗ $*"; }
check(){ if eval "$1" >/dev/null 2>&1; then ok "$2"; else bad "$2"; fi; }
# soft: counts a pass, but a miss is a note (~), NOT a failure — for weak
# single-node signals like self-ping (a macOS self-delivery quirk, cosmetic).
soft(){ if eval "$1" >/dev/null 2>&1; then ok "$2"; else say "  ~ $2 — did not pass (cosmetic; peer connectivity needs a 2nd node)"; fi; }

[ "$(uname)" = "Darwin" ] || { say "this smoke test is for macOS"; exit 1; }
[ "$(id -u)" = "0" ] || { say "run with sudo: sudo bash tests/mac_smoke.sh"; exit 1; }

say "── prerequisites"
check 'command -v wireguard-go' "wireguard-go installed"
check 'command -v wg'           "wireguard-tools installed"
check 'command -v gw'           "gw on PATH"
[ "$FAIL" = 0 ] || { say "install: brew install wireguard-go wireguard-tools"; exit 1; }

if [ -e "$CFG" ]; then
  say "── leftover $MESH mesh from a previous run — purging first"
  gw -c "$CFG" purge -y >/dev/null 2>&1
fi

say "── create a throwaway single-node mesh ($MESH, ports 52900-52902)"
gw create $MESH --hostname smoketest --endpoint "[::1]" \
    --listen-port 52900 --door-port 52901 --control-port 52902 \
    > /tmp/gwsmoke_create.log 2>&1
check "[ -f $CFG ]"                       "config written ($CFG)"
check "[ -f $NAMEFILE ]"                  "logical→utun name file exists"
UTUN=$(cat "$NAMEFILE" 2>/dev/null | head -1)
say "  · gw-${MESH} = ${UTUN:-<none>}"
check "[ -n \"$UTUN\" ] && ifconfig $UTUN"          "utun device is up"
check "ifconfig ${UTUN:-none} | grep -q inet6"      "overlay address assigned"
check "wg show ${UTUN:-none}"                       "wg tooling reads the interface"
check "wg show ${UTUN:-none} listen-port | grep -q 52900"  "listening on the chosen port"

say "── launchd job (installed by create; boot-persistent)"
check "[ -f $PLIST ]"                     "plist installed"
check "plutil -lint $PLIST"               "plist is valid"
sleep 3
check "launchctl print system/com.greasewood.$MESH | grep -q 'state = running'" \
      "job is running"
check "[ -f /var/log/greasewood/${MESH}.log ]"  "daemon log file exists"

say "── daemon is actually working (heartbeat + door isolation)"
sleep 7   # give reconcile a couple of cycles
SNAP=$(gw -c "$CFG" watch --snapshot 2>/dev/null)
check "echo \"\$SNAP\" | grep -q 'reconciled.*ago'"   "reconcile heartbeat fresh"
check "echo \"\$SNAP\" | grep -q smoketest"           "own record in the roster"
check "echo \"\$SNAP\" | grep -q 'not available on macOS'" \
      "enforcement correctly reported unavailable"
ADDR=$(echo "$SNAP" | awk '/^addr/ {print $3}')
soft  "ping6 -c 1 ${ADDR:-none}"                      "own overlay address answers ping (self-route via lo0)"
check "grep -q 'forwarding is off' /var/log/greasewood/${MESH}.log" \
      "door isolation: forwarding-off asserted"

say "── restart resilience (launchd kickstart)"
launchctl kickstart -k system/com.greasewood.$MESH >/dev/null 2>&1
sleep 5
check "launchctl print system/com.greasewood.$MESH | grep -q 'state = running'" \
      "job running again after kickstart"

say "── purge (full teardown)"
gw -c "$CFG" purge -y > /tmp/gwsmoke_purge.log 2>&1
check "[ ! -f $CFG ]"                     "config removed"
check "[ ! -d /var/lib/greasewood_$MESH ]" "data dir removed"
check "[ ! -f $PLIST ]"                   "launchd plist removed"
check "[ ! -f $NAMEFILE ]"                "utun name file removed"
check "! launchctl print system/com.greasewood.$MESH" "launchd job gone"
sleep 1
check "! ifconfig ${UTUN:-none} 2>/dev/null | grep -q POINTOPOINT || ! ifconfig ${UTUN:-none}" \
      "utun device torn down (wireguard-go exited)"

say ""
say "══ mac smoke: $PASS passed, $FAIL failed"
say "   (create log: /tmp/gwsmoke_create.log · purge log: /tmp/gwsmoke_purge.log)"
[ "$FAIL" = 0 ]
