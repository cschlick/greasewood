# TLS certificates for services

The same CA that gates the mesh also issues ordinary **x509 TLS certificates**,
so a service on a node (Postgres, an internal API, etc) gets a cert that every
peer validates against one trust root — no second PKI (public-key
infrastructure). These are real x509 certs with SANs, distinct from the mesh
credential, but signed by the same Ed25519 CA key.

**What this is for (and isn't).** WireGuard already encrypts and authenticates
traffic between nodes, so TLS here is **not** about adding encryption — that part
would be redundant. Its value is at the layers WireGuard doesn't cover:

- **Service identity by name.** WireGuard authenticates the *node* you reached,
  not that you reached the *right* node. The `db.myfleet.internal`→address
  mapping lives outside its crypto. A cert with `SAN=db.myfleet.internal`, validated by
  the client, is what proves "this endpoint is authorized for that name."
- **Process/tenant identity.** The mesh interface is host-global, so any
  process on a node can use the tunnel. **mTLS** (client certs) narrows a
  connection to a specific identity and surfaces it into the app (e.g. Postgres
  cert→role) for authz and audit.
- **A free, mesh-rooted PKI.** Services that require TLS anyway (`sslmode=verify-full`,
  HTTPS clients) get certs without you running a second CA.

The value **requires the client to verify** — use `verify-full`/mTLS. Using the
cert only for opportunistic encryption (no SAN check) *is* just redundant with
WireGuard.

A node may request certs only if its credential carries the **`tls`**
capability. It's granted by the anchor, and **is on by default** (`[anchor]
default_caps = ["tls"]`), so a plain `gw invite` already yields a cert-capable
node — no extra flag:

```bash
TOKEN=$(sudo gw invite)                 # tls is in the default caps
sudo gw join "$TOKEN" --hostname dbnode
```

To make `tls` opt-in instead, set `default_caps = []` in `[anchor]` (effective on
the next invite) and grant it per-node with `gw invite --caps tls` or later with
`gw set-caps <node> …`. Either way `tls` is bounded by SAN authorization (below),
so a cert-capable node can still only get certs for its *own* names.

Then, on that node. A node can only get a cert for names it **owns**: its own
`<hostname>.<mesh_domain>`, any **subdomain** of that, and its own overlay
address. The anchor (the CA) enforces this, so a node can never obtain a valid cert
for *another* node's name and impersonate its service to TLS clients.

```bash
# On node "dbnode" — postgres.dbnode.myfleet.internal is a subdomain it owns:
sudo gw cert-request --san postgres.dbnode.myfleet.internal --name postgres
#   → writes <data_dir>/tls/postgres.key, postgres.crt, and ca.crt, AND
#     registers the label so peers can resolve postgres.dbnode.myfleet.internal

# With no --san, the cert defaults to the node's own name + overlay address:
sudo gw cert-request                 # SAN = dbnode.myfleet.internal (and its addr)

# The three files need not share a directory — override any of them, e.g. put
# the key where the service expects it and the CA in the system trust store:
sudo gw cert-request --name postgres \
     --key-out  /etc/postgresql/ssl/postgres.key \
     --cert-out /etc/postgresql/ssl/postgres.crt \
     --ca-out   /usr/local/share/ca-certificates/mesh-ca.crt

gw cert-status                       # list issued certs and their expiry
```

**Profiles — one command, files in the right place.** Assembling the per-file
flags (and getting the *ownership* right so the service can read its own key) is
the fiddly part — and worse, plain `--cert-out` leaves files `root:root`, so
auto-renewal months later rewrites them as `root:root` and silently breaks a
service running as `postgres`. A **profile** fixes the whole lifecycle: a small
TOML that says where each file goes, who owns it, and how to reload — and the
daemon **re-places and re-owns on every renewal**, not just the first issue.

```bash
gw cert-profiles                              # list bundled templates
gw cert-request --profile postgres --show     # print one to copy + adapt
sudo gw cert-request --profile ./postgres.toml   # issue + place + register reload
```

A profile is a set of `[[file]]` entries (`role` = `key`/`cert`/`ca`/`fullchain`/
`bundle`, plus `path`, `owner`, `mode`) and a `reload` command. Bundled templates
ship for **postgres, nginx, haproxy, redis, nats, minio, mosquitto** — they're *starting points, not
turnkey*: each records the OS/software version it was written against, and a
wrong path or missing service user **fails loudly** at request time rather than
mis-placing a cert. Copy one, adapt the paths to your system, pass it in.

`cert-request` is **idempotent**: an unchanged re-request of a still-valid cert is a no-op (safe to run from config management), so a change (new SAN, edited profile path) is what triggers a re-issue; `--renew` forces one. The profile you pass is snapshotted to `<data_dir>/tls/profiles/<name>.toml` for record-keeping (the manifest already holds the effective config). `gw cert-status` lists everything the daemon manages, and `gw cert-remove <name>` stops managing one (keeping the placed files unless `--delete-files`).

The leaf private key is generated locally and never sent to the anchor; only its
public key goes in the request, which is signed by the node's identity key. The
anchor returns the leaf cert plus the CA cert. Point the service at them — e.g.
Postgres `ssl_cert_file=postgres.crt`, `ssl_key_file=postgres.key`, and clients
`sslrootcert=ca.crt` with `sslmode=verify-full`. Certs are short-lived (default 7
days, `[anchor] tls_cert_ttl`), and **the daemon auto-renews each one at ~half its
TTL** into whatever paths you chose — pass `--reload-cmd "systemctl reload
postgresql"` so the service picks up the rotation (or `--no-auto-renew` for a
one-shot). Managed certs are keyed by `--name`, so re-running `cert-request` with
the same name **relocates** it (the daemon renews into the new paths and flags
the old files as orphaned) rather than leaving a duplicate. See
[operations.md](operations.md). Revocation is passive — stop renewing and it expires.

**Subdomain names resolve too.** A cert for `postgres.dbnode.myfleet.internal` is only
useful if clients can resolve that name — so when a `--san` is a subdomain of the
node's own mesh name, `cert-request` also **publishes** it: it adds the label
(`postgres`) to `[network] aliases`, and the daemon advertises
`postgres.dbnode.myfleet.internal → <dbnode's address>` into every node's `/etc/hosts`
block (restart the daemon, or wait for the next renewal, to propagate). Aliases
travel as bare labels in the (self-signed) `NodeRecord` and every reader expands
them under the record's *CA-attested* mesh name — so a node can only ever publish
names inside its **own** namespace, pointing at its **own** address; it can't
name or hijack anything else. You can also set `aliases = ["pg", "metrics"]`
directly in `[network]` without a cert.

**Where things live** — three files, don't conflate them:

| File | Role | Location |
|------|------|----------|
| the leaf **key/cert** + **CA cert** | what your service reads | wherever you point them (`--key-out`/`--cert-out`/`--ca-out`, else `<data_dir>/tls/`); the three need not share a directory |
| `greasewood.toml` | the daemon config; `cert-request` only *reads* it (for `data_dir` + the default SAN) and never writes it | wherever you pass `gw -c …` (default: the discovered `/etc/greasewood_<name>.toml`) |
| `<data_dir>/tls/managed.json` | the **renewal source of truth** — records each managed cert's three paths; the daemon reads it to know where to re-issue | pinned to `data_dir` (there's no separate flag; move `data_dir` in the config and it follows) |

So the file that actually "controls" where renewed certs land is the *manifest*,
not `greasewood.toml`: the TOML only locates the manifest (via `data_dir`), and
the manifest holds the per-cert paths. `cert-request` prints both so you always
know which config it read and where the renewal record is.

> **SANs are constrained to what the node owns** (its CA-registered
> `<hostname>.<mesh_domain>`, subdomains, and its overlay address) — the anchor
> refuses a cert for another node's name, so a `tls`-capable node can't
> impersonate a service it doesn't run. The `tls` capability is still the gate;
> grant it only to nodes that run services. The anchor's CA cert is also at
> `GET /ca-cert`. (After a re-root the CA changes; re-request to pick up the new
> issuer.)

### Worked example: mutual TLS for Postgres

This wires up a Postgres server that authenticates clients by their mesh
identity, with certs that rotate transparently. Nothing below hardcodes a
hostname: greasewood **binds the cert's CN and SAN to the node's own attested
`<hostname>.<mesh_domain>` automatically** — you can't set them to another
identity (the anchor *refuses* a SAN the node doesn't own and *forces* the CN to the
node's own name), so each host gets a cert for exactly its own identity with no
name typed.

**The one thing to understand about CN.** greasewood makes the CN attested, not
cosmetic, and it's the mesh FQDN — the same on the server and client cert:
- **Server cert:** clients validate `SAN = DNS:<db-host>.<mesh_domain>` under
  `sslmode=verify-full`. Connecting by overlay address works too — the node's own
  address is a SAN by default.
- **Client cert:** the CN *is* the identity Postgres maps to a role. It is the
  connecting node's `<hostname>.<mesh_domain>` (e.g. `nats01.myfleet.internal`), so
  that FQDN — not a bare label — is what your `pg_ident.conf` map keys on.

**On the database host.** Point the three files at fixed, host-agnostic paths
(the Debian `ssl-cert` group layout, which satisfies Postgres's key-permission
check with a root-owned key):

```bash
sudo gw cert-request --name pg-server \
  --key-out  /etc/ssl/private/gw-postgres.key \
  --cert-out /etc/ssl/certs/gw-postgres.crt \
  --ca-out   /etc/ssl/certs/gw-myfleet-ca.crt \
  --reload-cmd /usr/local/sbin/gw-pg-reload
# CN + SAN default to THIS node's mesh name — no --san needed.
# --name is just the manifest key (so cert-status is readable and a re-request
# relocates in place); it does NOT affect the cert's identity.
```

One-time ownership so `postgres` can read a root-owned key (needs a restart):

```bash
sudo adduser postgres ssl-cert
sudo chgrp ssl-cert /etc/ssl/private/gw-postgres.key
sudo chmod 640      /etc/ssl/private/gw-postgres.key
sudo systemctl restart postgresql
```

`postgresql.conf` — set once, never touched again:

```
ssl = on
ssl_cert_file = '/etc/ssl/certs/gw-postgres.crt'
ssl_key_file  = '/etc/ssl/private/gw-postgres.key'
ssl_ca_file   = '/etc/ssl/certs/gw-myfleet-ca.crt'   # verifies client certs
```

**Why rotation just works.** greasewood renews *in place* — it truncates and
rewrites each file at its path and never re-chmods an existing one — so the
ownership and mode you set that first time are **preserved on every rotation**.
Postgres doesn't watch the files; it re-reads them on `SIGHUP`. So the
`--reload-cmd` only needs to reload (a restart is unnecessary and drops
connections). Make it a script that asserts the key perms first, as a guard
against a botched change:

```sh
#!/bin/sh
# /usr/local/sbin/gw-pg-reload   (chmod 0755, root-owned)
set -e
key=/etc/ssl/private/gw-postgres.key
test "$(stat -c '%U:%G %a' "$key")" = "root:ssl-cert 640" || {
  echo "gw-pg-reload: $key is $(stat -c '%U:%G %a' "$key"), want root:ssl-cert 640" >&2
  exit 1   # refuse to reload with wrong perms rather than break TLS
}
exec systemctl reload postgresql
```

**On each client node.** Request its own cert (again, identity is automatic) and
point libpq at it:

```bash
sudo gw cert-request --name pg-client \
  --key-out  /etc/gw/pg-client.key \
  --cert-out /etc/gw/pg-client.crt \
  --ca-out   /etc/gw/gw-myfleet-ca.crt
# connect: sslmode=verify-full sslrootcert=/etc/gw/gw-myfleet-ca.crt \
#          sslcert=/etc/gw/pg-client.crt sslkey=/etc/gw/pg-client.key
```

**Map identities to roles on the server.** `pg_hba.conf`:

```
hostssl all all ::/0 cert map=mesh clientcert=verify-full
```

`pg_ident.conf` — the map keys on each client's mesh FQDN (its automatic CN):

```
# MAPNAME   CERT CN (= client's <hostname>.<mesh_domain>)   PG ROLE
mesh        nats01.mymesh.internal                              nats
mesh        chat01.mymesh.internal                              chat
```

This is the only place client hostnames appear, it's the allow-list of *which*
identities may connect, and each entry is that node's own automatic name.

> **CA rotation.** The `ssl_ca_file` matters only because of client-cert auth. A
> re-root changes the CA, and both the server's CA file and every client cert
> re-issue under the new CA on their next renewal, so rotate the CA (re-root)
> and let the fleet re-issue together; don't swap a CA independently, or client
> certs signed by the old one stop validating.

