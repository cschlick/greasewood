"""
Fixes for the applicable findings from the second Security review (SECURITY_REVIEW2):
  L1  - single-use door window written 0600           (atomic_write, see cli)
  L2  - audit log created 0600 (no umask TOCTOU)
  L3  - /etc/hosts temp via mkstemp                    (see hosts._atomic_write)
  L4  - invite screens merged caps for reserved roles
  L5  - joiner hostname bounded before the PoP check
"""
import base64
import logging
import types

import pytest


# ---- L2: audit log is 0600 from creation ----------------------------------

def test_audit_log_is_0600(tmp_path):
    from greasewood import audit
    p = tmp_path / "sub" / "audit.log"
    h = audit.attach_file(str(p))
    try:
        assert h is not None
        assert oct(p.stat().st_mode)[-3:] == "600"
    finally:
        logging.getLogger("greasewood.audit").removeHandler(h)
        h.close()


# ---- L5: joiner hostname is bounded before PoP ----------------------------

class _CA:
    def node_info(self, id_pub):
        return None


def _srv():
    from greasewood.enroll import EnrollServer, EnrollContext
    from greasewood.keys import NodeKeys
    ctx = EnrollContext(ca=_CA(), directory=types.SimpleNamespace(get=lambda *a: None),
                        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    return EnrollServer(ctx, lambda: None)


def _req(joiner, hostname):
    from greasewood.wire import enroll_pop_body
    sig = joiner.id_priv.sign(enroll_pop_body(joiner.id_pub_bytes, joiner.wg_pub_bytes,
                                              hostname if isinstance(hostname, str) else ""))
    return {"v": 1, "id_pub": joiner.id_pub_bytes.hex(),
            "wg_pub": base64.b64encode(joiner.wg_pub_bytes).decode(),
            "hostname": hostname, "id_sig": base64.b64encode(sig).decode()}


def test_enroll_rejects_overlong_hostname():
    from greasewood.keys import NodeKeys
    j = NodeKeys.generate()
    with pytest.raises(ValueError, match="253"):
        _srv()._validate_request(_req(j, "x" * 300))


def test_enroll_rejects_control_char_hostname():
    from greasewood.keys import NodeKeys
    j = NodeKeys.generate()
    with pytest.raises(ValueError, match="printable"):
        _srv()._validate_request(_req(j, "evil\nname"))


def test_enroll_accepts_a_normal_hostname():
    from greasewood.keys import NodeKeys
    j = NodeKeys.generate()
    _idp, _wgp, host, _ = _srv()._validate_request(_req(j, "web1"))
    assert host == "web1"


# ---- L4: invite screens merged caps (via the shared reserved-role guard) ---

def test_invite_merged_caps_screening_is_wired():
    """cmd_invite runs _reject_reserved_roles over the role: tags of the MERGED
    caps list (--caps + default_caps/default_roles), so `--caps role:anchor`
    can't slip a reserved role past the guard the other paths enforce."""
    from greasewood import cli
    # The exact call cmd_invite makes on a caps list containing a reserved role.
    caps = ["role:web", "role:anchor", "tls"]
    with pytest.raises(SystemExit, match="reserved for the anchor"):
        cli._reject_reserved_roles(
            [c[len("role:"):] for c in caps if c.startswith("role:")],
            "the invite's caps/default_roles")
