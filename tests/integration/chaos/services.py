"""
Service traffic for the chaos test: a trivial TCP listener per service port,
and a prober that answers "can client C open a fresh connection to server S on
port P?" — which is exactly what greasewood's port filter governs.

Real sshd/postgres/nfsd would drag in their own config surfaces; the property
under test is greasewood's, so a bare listener on the familiar port is the
faithful probe. Each listener binds the node's OVERLAY address (like a real
service would — reachable only through the mesh), on all its role's ports.
"""
from __future__ import annotations

from .model import SERVICE_PORTS
from ..helpers import pexec, podman


# A backgrounded multi-port TCP echo server. Binds "::" (all v6), NOT the
# overlay address: binding the overlay races the daemon assigning it (an early
# bind fails EADDRNOTAVAIL and that port silently never opens — a flaky
# listener). Binding :: is timing-independent, and the PORT FILTER — which
# matches on the mesh interface + source, not the bound address — still governs
# reachability, so this changes nothing the test observes except reliability.
# argv[1] is accepted and ignored (was the overlay addr) for call compatibility.
# Each port retries its bind so a transient failure self-heals.
_LISTENER = r"""
import socket, sys, threading, time
def serve(port):
    for _ in range(30):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("::", port)); s.listen(16)
            break
        except OSError:
            time.sleep(1)
    else:
        return
    while True:
        try:
            c, _ = s.accept()
            c.sendall(b"GW-SERVICE-OK\n"); c.close()
        except OSError:
            pass
for p in sys.argv[2:]:
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()
threading.Event().wait()
"""

# A one-shot probe: connect to <addr> <port>, print OPEN / REFUSED / TIMEOUT.
# Short timeout so a filtered (dropped) port reports TIMEOUT quickly rather
# than hanging the sweep.
_PROBE = r"""
import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[3]))
try:
    s.connect((addr, port))
    data = s.recv(16)
    print("OPEN" if data else "EMPTY")
except socket.timeout:
    print("TIMEOUT")           # dropped by the port filter (default-deny)
except ConnectionRefusedError:
    print("REFUSED")           # reached the host, nothing listening
except OSError as e:
    print(f"ERR {e.errno}")
finally:
    s.close()
"""


def roles_to_ports(roles) -> list:
    """The service ports a node with these roles should listen on. A role
    named after a service (or carrying its port via the catalog) implies that
    service; a node also always listens on 'ssh' (22) so lateral-SSH grants
    have something to hit."""
    ports = {SERVICE_PORTS["ssh"]}
    for r in roles:
        if r in SERVICE_PORTS:
            ports.add(SERVICE_PORTS[r])
    return sorted(ports)


def start_services(cid: str, overlay: str, ports) -> None:
    """Launch the listener on the node's overlay address for the given ports.
    Idempotent-ish: kills any prior listener first (a role change restarts it
    on the new port set)."""
    pexec(cid, "sh", "-c", "pkill -f gw-svc-listener || true", check=False)
    if not ports:
        return
    script = f"# gw-svc-listener\n{_LISTENER}"
    args = " ".join(str(p) for p in ports)
    podman("exec", "-d", cid, "sh", "-c",
           f"exec -a gw-svc-listener python3 -c '{script}' {overlay} {args} "
           f">/tmp/svc.log 2>&1")


def probe(client_cid: str, server_overlay: str, port: int,
          timeout: float = 4.0) -> str:
    """OPEN / REFUSED / TIMEOUT / EMPTY / ERR — one connection attempt from the
    client container to the server's overlay service port."""
    r = pexec(client_cid, "python3", "-c", _PROBE,
              server_overlay, str(port), str(timeout), check=False)
    return (r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr) \
        else "NO-OUTPUT"
