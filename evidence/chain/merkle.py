"""evidence.chain.merkle — Binary SHA-256 Merkle tree computation.

Provides pure functions for computing Merkle roots, generating inclusion
proofs, and verifying inclusion proofs. Used by the audit log integrity
verification pipeline.
"""

from __future__ import annotations

import hashlib


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex-encoded SHA-256 digests together.

    Concatenates the two hex strings (left + right) and produces a new
    SHA-256 hex digest. This is the internal node computation of the
    Merkle tree.
    """
    combined = (left + right).encode()
    return hashlib.sha256(combined).hexdigest()


def compute_merkle_root(hashes: list[str]) -> str:
    """Compute the root of a binary SHA-256 Merkle tree.

    Args:
        hashes: List of hex-encoded SHA-256 leaf hashes. Must not be empty.

    Returns:
        Hex-encoded SHA-256 root hash.

    Raises:
        ValueError: If the input list is empty.

    Algorithm:
        Pair adjacent hashes and hash them together. If a layer has an
        odd number of nodes, duplicate the last node. Repeat until one
        root remains.
    """
    if not hashes:
        raise ValueError("Cannot compute Merkle root of empty hash list")

    layer = list(hashes)

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        next_layer: list[str] = []
        for i in range(0, len(layer), 2):
            next_layer.append(_hash_pair(layer[i], layer[i + 1]))
        layer = next_layer

    return layer[0]


def generate_inclusion_proof(index: int, hashes: list[str]) -> list[tuple[str, str]]:
    """Generate a Merkle inclusion proof for the leaf at the given index.

    Args:
        index: Zero-based index of the leaf to prove.
        hashes: List of all leaf hashes in the tree.

    Returns:
        List of (sibling_hash, side) tuples where side is 'left' or
        'right', indicating where the sibling sits relative to the
        current node. Walking the proof from leaf to root reconstructs
        the root hash.

    Raises:
        ValueError: If hashes is empty or index is out of range.
    """
    if not hashes:
        raise ValueError("Cannot generate proof for empty hash list")
    if index < 0 or index >= len(hashes):
        raise ValueError(f"Index {index} out of range for {len(hashes)} hashes")

    layer = list(hashes)
    proof: list[tuple[str, str]] = []
    idx = index

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        if idx % 2 == 0:
            sibling = layer[idx + 1]
            proof.append((sibling, "right"))
        else:
            sibling = layer[idx - 1]
            proof.append((sibling, "left"))

        # Build next layer and track position
        next_layer: list[str] = []
        for i in range(0, len(layer), 2):
            next_layer.append(_hash_pair(layer[i], layer[i + 1]))
        layer = next_layer
        idx = idx // 2

    return proof


def verify_inclusion_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Verify a Merkle inclusion proof against an expected root.

    Args:
        leaf_hash: Hex-encoded SHA-256 hash of the leaf to verify.
        proof: List of (sibling_hash, side) tuples from
               generate_inclusion_proof.
        root: Expected hex-encoded SHA-256 Merkle root.

    Returns:
        True if the proof is valid and the recomputed root matches.
    """
    current = leaf_hash

    for sibling, side in proof:
        if side == "left":
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)

    return current == root
