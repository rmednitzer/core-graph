"""Tests for Merkle tree computation and inclusion proofs."""

from __future__ import annotations

import hashlib

import pytest

from evidence.chain.merkle import (
    compute_merkle_root,
    generate_inclusion_proof,
    verify_inclusion_proof,
)


def _h(data: str) -> str:
    """Helper: SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Mirror the internal _hash_pair for test assertions."""
    return hashlib.sha256((left + right).encode()).hexdigest()


class TestComputeMerkleRoot:
    """Tests for compute_merkle_root."""

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_merkle_root([])

    def test_single_hash(self) -> None:
        h = _h("leaf0")
        assert compute_merkle_root([h]) == h

    def test_two_hashes(self) -> None:
        h0, h1 = _h("a"), _h("b")
        expected = _hash_pair(h0, h1)
        assert compute_merkle_root([h0, h1]) == expected

    def test_three_hashes(self) -> None:
        h0, h1, h2 = _h("a"), _h("b"), _h("c")
        # Odd layer: h2 is duplicated
        left = _hash_pair(h0, h1)
        right = _hash_pair(h2, h2)
        expected = _hash_pair(left, right)
        assert compute_merkle_root([h0, h1, h2]) == expected

    def test_four_hashes(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        left = _hash_pair(hashes[0], hashes[1])
        right = _hash_pair(hashes[2], hashes[3])
        expected = _hash_pair(left, right)
        assert compute_merkle_root(hashes) == expected

    def test_seven_hashes(self) -> None:
        hashes = [_h(str(i)) for i in range(7)]
        root = compute_merkle_root(hashes)
        assert isinstance(root, str)
        assert len(root) == 64  # SHA-256 hex

    def test_eight_hashes(self) -> None:
        hashes = [_h(str(i)) for i in range(8)]
        root = compute_merkle_root(hashes)
        assert isinstance(root, str)
        assert len(root) == 64

    def test_deterministic(self) -> None:
        hashes = [_h(str(i)) for i in range(5)]
        assert compute_merkle_root(hashes) == compute_merkle_root(hashes)


class TestInclusionProof:
    """Tests for generate_inclusion_proof and verify_inclusion_proof."""

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

    def test_roundtrip_two_elements(self) -> None:
        hashes = [_h("a"), _h("b")]
        root = compute_merkle_root(hashes)
        for i in range(2):
            proof = generate_inclusion_proof(i, hashes)
            assert verify_inclusion_proof(hashes[i], proof, root)

    def test_roundtrip_four_elements(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        root = compute_merkle_root(hashes)
        for i in range(4):
            proof = generate_inclusion_proof(i, hashes)
            assert verify_inclusion_proof(hashes[i], proof, root)

    def test_roundtrip_seven_elements(self) -> None:
        hashes = [_h(str(i)) for i in range(7)]
        root = compute_merkle_root(hashes)
        for i in range(7):
            proof = generate_inclusion_proof(i, hashes)
            assert verify_inclusion_proof(hashes[i], proof, root)

    def test_roundtrip_eight_elements(self) -> None:
        hashes = [_h(str(i)) for i in range(8)]
        root = compute_merkle_root(hashes)
        for i in range(8):
            proof = generate_inclusion_proof(i, hashes)
            assert verify_inclusion_proof(hashes[i], proof, root)

    def test_tampered_leaf_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        root = compute_merkle_root(hashes)
        proof = generate_inclusion_proof(0, hashes)
        tampered = _h("tampered")
        assert not verify_inclusion_proof(tampered, proof, root)

    def test_tampered_proof_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        root = compute_merkle_root(hashes)
        proof = generate_inclusion_proof(1, hashes)
        # Tamper with a sibling hash in the proof
        tampered_proof = [(_h("fake"), side) for _, side in proof]
        assert not verify_inclusion_proof(hashes[1], tampered_proof, root)

    def test_wrong_root_fails(self) -> None:
        hashes = [_h(str(i)) for i in range(4)]
        compute_merkle_root(hashes)
        proof = generate_inclusion_proof(2, hashes)
        assert not verify_inclusion_proof(hashes[2], proof, _h("wrong_root"))
