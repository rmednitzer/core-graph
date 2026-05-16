"""Tests for Merkle tree computation and inclusion proofs.

The tree uses RFC 6962-style domain separation:

    leaf     = SHA256(0x00 || raw(entry_hash))
    internal = SHA256(0x01 || raw(left) || raw(right))
    odd node = promoted unchanged

These helpers mirror evidence/chain/merkle.py and (byte-for-byte) the
SQL in schema/migrations/025_merkle_domain_separation.sql.
"""

from __future__ import annotations

import hashlib

import pytest

from evidence.chain.merkle import (
    compute_merkle_root,
    generate_inclusion_proof,
    verify_inclusion_proof,
)


def _h(data: str) -> str:
    """Helper: SHA-256 hex digest of a string (a synthetic entry_hash)."""
    return hashlib.sha256(data.encode()).hexdigest()


def _leaf(hex_digest: str) -> str:
    return hashlib.sha256(b"\x00" + bytes.fromhex(hex_digest)).hexdigest()


def _node(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


class TestComputeMerkleRoot:
    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_merkle_root([])

    def test_single_hash(self) -> None:
        h = _h("leaf0")
        # A single leaf is domain-separated; the root is the leaf hash,
        # NOT the raw entry_hash (defends against leaf/root confusion).
        assert compute_merkle_root([h]) == _leaf(h)

    def test_two_hashes(self) -> None:
        h0, h1 = _h("a"), _h("b")
        assert compute_merkle_root([h0, h1]) == _node(_leaf(h0), _leaf(h1))

    def test_three_hashes_promotes_odd(self) -> None:
        h0, h1, h2 = _h("a"), _h("b"), _h("c")
        # Odd node is PROMOTED, not duplicated.
        left = _node(_leaf(h0), _leaf(h1))
        right = _leaf(h2)
        assert compute_merkle_root([h0, h1, h2]) == _node(left, right)

    def test_four_hashes(self) -> None:
        hs = [_h(str(i)) for i in range(4)]
        left = _node(_leaf(hs[0]), _leaf(hs[1]))
        right = _node(_leaf(hs[2]), _leaf(hs[3]))
        assert compute_merkle_root(hs) == _node(left, right)

    def test_seven_and_eight(self) -> None:
        for n in (7, 8):
            root = compute_merkle_root([_h(str(i)) for i in range(n)])
            assert isinstance(root, str)
            assert len(root) == 64

    def test_deterministic(self) -> None:
        hs = [_h(str(i)) for i in range(5)]
        assert compute_merkle_root(hs) == compute_merkle_root(hs)

    def test_second_preimage_resistance_cve_2012_2459(self) -> None:
        """[a,b,c] (odd promoted) must NOT collide with [a,b,c,c]."""
        a, b, c = _h("a"), _h("b"), _h("c")
        assert compute_merkle_root([a, b, c]) != compute_merkle_root([a, b, c, c])

    def test_leaf_internal_domain_separation(self) -> None:
        """A leaf value equal to an internal digest must not be confusable."""
        a, b = _h("a"), _h("b")
        internal = _node(_leaf(a), _leaf(b))
        # Feeding the internal digest in as a single 'leaf' yields a
        # distinct root because leaves are 0x00-prefixed.
        assert compute_merkle_root([internal]) != internal
        assert compute_merkle_root([internal]) != compute_merkle_root([a, b])


class TestInclusionProof:
    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            generate_inclusion_proof(0, [])

    def test_index_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            generate_inclusion_proof(5, [_h("a")])

    def test_negative_index(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            generate_inclusion_proof(-1, [_h("a")])

    def test_single_element_proof(self) -> None:
        h = _h("only")
        root = compute_merkle_root([h])
        proof = generate_inclusion_proof(0, [h])
        assert proof == []
        assert verify_inclusion_proof(h, proof, root)

    @pytest.mark.parametrize("n", [2, 3, 4, 5, 7, 8])
    def test_roundtrip(self, n: int) -> None:
        hashes = [_h(str(i)) for i in range(n)]
        root = compute_merkle_root(hashes)
        for i in range(n):
            proof = generate_inclusion_proof(i, hashes)
            assert verify_inclusion_proof(hashes[i], proof, root)

    def test_tampered_leaf_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        root = compute_merkle_root(hashes)
        proof = generate_inclusion_proof(0, hashes)
        assert not verify_inclusion_proof(_h("tampered"), proof, root)

    def test_tampered_proof_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        root = compute_merkle_root(hashes)
        proof = generate_inclusion_proof(1, hashes)
        tampered_proof = [(_h("fake"), side) for _, side in proof]
        assert not verify_inclusion_proof(hashes[1], tampered_proof, root)

    def test_wrong_root_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        proof = generate_inclusion_proof(2, hashes)
        assert not verify_inclusion_proof(hashes[2], proof, _h("wrong_root"))
