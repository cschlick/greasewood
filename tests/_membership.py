"""Shared test helper: seed the enrollment state the way production leaves it
— the node's CA-signed record in the on-disk directory cache, which is what
every CLI command and holder resolves membership from (there is no private
registry anymore)."""
import datetime as dt

from greasewood.directory import Directory
from greasewood.keys import derive_addr
from greasewood.wire import Credential, NodeRecord


def enroll_record(ca_keys, data_dir, node, hostname, caps=("mesh",),
                  ttl_h=24, seq=1):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    cred = Credential(id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
                      addr=derive_addr(node.id_pub_bytes), hostname=hostname,
                      caps=list(caps), iat=now,
                      exp=now + dt.timedelta(hours=ttl_h)).sign(ca_keys.ca_priv)
    cache = data_dir / "directory.json"
    d = Directory.load(cache)
    d.put(NodeRecord(id_pub=node.id_pub_bytes, seq=seq, endpoints=[],
                     cred=cred).sign(node.id_priv))
    d.save(cache)
    return cred
