"""Tests for key generation and address derivation (milestone 1)."""
import hashlib
import ipaddress

import pytest

from greasewood.keys import (
    OVERLAY_PREFIX_BYTES,
    CAKeys,
    NodeKeys,
    derive_addr,
    format_overlay_prefix,
    host_bits,
    overlay_prefix,
    parse_overlay_prefix,
    set_overlay_prefix,
)


class TestNodeKeys:
    def test_generate_returns_distinct_keys(self):
        a = NodeKeys.generate()
        b = NodeKeys.generate()
        assert a.id_pub_bytes != b.id_pub_bytes
        assert a.wg_pub_bytes != b.wg_pub_bytes

    def test_id_pub_is_32_bytes(self):
        k = NodeKeys.generate()
        assert len(k.id_pub_bytes) == 32

    def test_wg_pub_is_32_bytes(self):
        k = NodeKeys.generate()
        assert len(k.wg_pub_bytes) == 32

    def test_wg_pub_b64_is_valid_base64(self):
        import base64
        k = NodeKeys.generate()
        decoded = base64.b64decode(k.wg_pub_b64)
        assert decoded == k.wg_pub_bytes

    def test_id_pub_hex_matches_bytes(self):
        k = NodeKeys.generate()
        assert bytes.fromhex(k.id_pub_hex) == k.id_pub_bytes

    def test_addr_property_matches_derive_addr(self):
        k = NodeKeys.generate()
        assert k.addr == derive_addr(k.id_pub_bytes)

    def test_save_load_roundtrip(self, tmp_path):
        k = NodeKeys.generate()
        k.save(tmp_path / "node")
        loaded = NodeKeys.load(tmp_path / "node")
        assert k.id_pub_bytes == loaded.id_pub_bytes
        assert k.wg_pub_bytes == loaded.wg_pub_bytes

    def test_load_or_generate_idempotent(self, tmp_path):
        d = tmp_path / "node"
        k1 = NodeKeys.load_or_generate(d)
        k2 = NodeKeys.load_or_generate(d)
        assert k1.id_pub_bytes == k2.id_pub_bytes
        assert k1.wg_pub_bytes == k2.wg_pub_bytes

    def test_key_files_have_tight_permissions(self, tmp_path):
        import stat
        d = tmp_path / "node"
        k = NodeKeys.generate()
        k.save(d)
        mode = stat.S_IMODE(( d / "id_priv.pem").stat().st_mode)
        assert mode == 0o600
        mode = stat.S_IMODE((d / "wg.key").stat().st_mode)
        assert mode == 0o600

    def test_passphrase_roundtrip(self, tmp_path):
        k = NodeKeys.generate()
        k.save(tmp_path / "node", passphrase=b"s3cret")
        loaded = NodeKeys.load(tmp_path / "node", passphrase=b"s3cret")
        assert loaded.id_pub_bytes == k.id_pub_bytes
        assert loaded.wg_pub_bytes == k.wg_pub_bytes

    def test_wrong_passphrase_fails(self, tmp_path):
        k = NodeKeys.generate()
        k.save(tmp_path / "node", passphrase=b"s3cret")
        with pytest.raises((TypeError, ValueError)):
            NodeKeys.load(tmp_path / "node", passphrase=b"wrong")

    def test_encrypted_key_needs_passphrase(self, tmp_path):
        k = NodeKeys.generate()
        k.save(tmp_path / "node", passphrase=b"s3cret")
        with pytest.raises((TypeError, ValueError)):
            NodeKeys.load(tmp_path / "node")  # encrypted, no passphrase given


class TestCAKeysPassphrase:
    def test_roundtrip(self, tmp_path):
        ca = CAKeys.generate()
        p = tmp_path / "ca.key"
        ca.save(p, passphrase=b"rootpw")
        loaded = CAKeys.load(p, passphrase=b"rootpw")
        assert loaded.ca_pub_bytes == ca.ca_pub_bytes

    def test_wrong_or_missing_passphrase_fails(self, tmp_path):
        ca = CAKeys.generate()
        p = tmp_path / "ca.key"
        ca.save(p, passphrase=b"rootpw")
        with pytest.raises((TypeError, ValueError)):
            CAKeys.load(p, passphrase=b"nope")
        with pytest.raises((TypeError, ValueError)):
            CAKeys.load(p)  # encrypted CA root key, no passphrase


class TestDeriveAddr:
    def test_deterministic(self):
        k = NodeKeys.generate()
        assert derive_addr(k.id_pub_bytes) == derive_addr(k.id_pub_bytes)

    def test_different_keys_give_different_addrs(self):
        a = NodeKeys.generate()
        b = NodeKeys.generate()
        assert derive_addr(a.id_pub_bytes) != derive_addr(b.id_pub_bytes)

    def test_addr_is_valid_ipv6(self):
        k = NodeKeys.generate()
        addr = ipaddress.IPv6Address(k.addr)
        assert addr.version == 6

    def test_addr_has_correct_prefix(self):
        k = NodeKeys.generate()
        addr = ipaddress.IPv6Address(k.addr)
        assert addr.packed[:8] == OVERLAY_PREFIX_BYTES

    def test_host_portion_from_blake2s(self):
        k = NodeKeys.generate()
        digest = hashlib.blake2s(k.id_pub_bytes).digest()
        addr = ipaddress.IPv6Address(k.addr)
        assert addr.packed[8:] == digest[:8]

    def test_addr_unchanged_when_wg_key_rotated(self):
        # Address must derive from id_pub only, not wg_pub
        k = NodeKeys.generate()
        addr_before = k.addr
        # Simulate wg key rotation by generating a new X25519 key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        new_wg = X25519PrivateKey.generate()
        new_wg_pub = new_wg.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        from dataclasses import replace
        k2 = replace(k, wg_priv=new_wg, wg_pub_bytes=new_wg_pub)
        assert k2.addr == addr_before


class TestConfigurablePrefix:
    def test_parse_and_format_roundtrip(self):
        assert parse_overlay_prefix("fd8d:e5c1:db1a:7::") == OVERLAY_PREFIX_BYTES
        assert parse_overlay_prefix("fd8d:e5c1:db1a:7::/64") == OVERLAY_PREFIX_BYTES
        assert format_overlay_prefix(OVERLAY_PREFIX_BYTES) == "fd8d:e5c1:db1a:7::"

    def test_set_overlay_prefix_changes_derivation(self):
        k = NodeKeys.generate()
        try:
            set_overlay_prefix(parse_overlay_prefix("fdde:cafc:0ffe:e::"))
            assert overlay_prefix() == parse_overlay_prefix("fdde:cafc:0ffe:e::")
            addr = ipaddress.IPv6Address(derive_addr(k.id_pub_bytes))
            assert addr.packed[:8] == parse_overlay_prefix("fdde:cafc:0ffe:e::")
            # host portion is prefix-independent — same identity, same host bits
            assert addr.packed[8:] == host_bits(k.id_pub_bytes)
        finally:
            set_overlay_prefix(OVERLAY_PREFIX_BYTES)  # restore process default

    def test_explicit_prefix_arg_overrides_global(self):
        k = NodeKeys.generate()
        other = parse_overlay_prefix("fdaa:bbbb:cccc:d::")
        addr = ipaddress.IPv6Address(derive_addr(k.id_pub_bytes, other))
        assert addr.packed[:8] == other
        assert addr.packed[8:] == host_bits(k.id_pub_bytes)

    def test_set_overlay_prefix_rejects_bad_length(self):
        with pytest.raises(ValueError):
            set_overlay_prefix(b"\x00\x01")


class TestCAKeys:
    def test_generate(self):
        ca = CAKeys.generate()
        assert len(ca.ca_pub_bytes) == 32

    def test_save_load_roundtrip(self, tmp_path):
        ca = CAKeys.generate()
        ca.save(tmp_path / "ca.key")
        loaded = CAKeys.load(tmp_path / "ca.key")
        assert ca.ca_pub_bytes == loaded.ca_pub_bytes

    def test_pub_key_file_written(self, tmp_path):
        ca = CAKeys.generate()
        ca.save(tmp_path / "ca.key")
        pub_path = tmp_path / "ca.pub"
        assert pub_path.exists()
        assert pub_path.read_text().strip() == ca.ca_pub_hex
