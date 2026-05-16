"""evidence.chain.merkle — Binary SHA-256 Merkle tree computation.

Provides pure functions for computing Merkle roots, generating inclusion
proofs, and verifying inclusion proofs. Used by the audit log integrity
verification pipeline.

Domain separation (RFC 6962 style) defends against second-preimage /
forgery attacks (CVE-2012-2459 class):

    leaf     = SHA256(0x00 || raw(entry_hash))
    internal = SHA256(0x01 || raw(left) || raw(right))
    odd node = promoted unchanged (NOT duplicated)

This MUST stay byte-for-byte identical to compute_audit_merkle_root() in
schema/migrations/025_merkle_domain_separation.sql.
"""

from __future__ import annotations

import hashlib
import hmac

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(hex_digest: str) -> str:
    """Domain-separated leaf hash: SHA256(0x00 || raw(hex_digest))."""
    return hashlib.sha256(_LEAF_PREFIX + bytes.fromhex(hex_digest)).hexdigest()


def _node_hash(left: str, right: str) -> str:
    """Domain-separated internal node: SHA256(0x01 || raw(left) || raw(right))."""
    return hashlib.sha256(_NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _next_layer(layer: list[str]) -> list[str]:
    """Reduce one tree layer. A lone trailing node is promoted unchanged."""
    out: list[str] = []
    i = 0
    n = len(layer)
    while i < n:
        if i + 1 < n:
            out.append(_node_hash(layer[i], layer[i + 1]))
            i += 2
        else:
            out.append(layer[i])
            i += 1
    return out


def compute_merkle_root(hashes: list[str]) -> str:
    """Compute the root of a domain-separated binary SHA-256 Merkle tree.

    Args:
        hashes: List of hex-encoded SHA-256 leaf values (e.g. audit_log
            entry_hash values). Must not be empty.

    Returns:
        Hex-encoded SHA-256 root hash.

    Raises:
        ValueError: If the input list is empty.
    """
    if not hashes:
        raise ValueError("Cannot compute Merkle root of empty hash list")

    layer = [_leaf_hash(h) for h in hashes]
    while len(layer) > 1:
        layer = _next_layer(layer)
    return layer[0]


def generate_inclusion_proof(index: int, hashes: list[str]) -> list[tuple[str, str]]:
    """Generate a Merkle inclusion proof for the leaf at the given index.

    Args:
        index: Zero-based index of the leaf to prove.
        hashes: List of all leaf hashes in the tree (hex-encoded).

    Returns:
        List of (sibling_hash, side) tuples where side is 'left' or
        'right'. Walking the proof from the (domain-separated) leaf
        reconstructs the root. A node promoted past an odd layer
        contributes no proof element for that level.

    Raises:
        ValueError: If hashes is empty or index is out of range.
    """
    if not hashes:
        raise ValueError("Cannot generate proof for empty hash list")
    if index < 0 or index >= len(hashes):
        raise ValueError(f"Index {index} out of range for {len(hashes)} hashes")

    layer = [_leaf_hash(h) for h in hashes]
    proof: list[tuple[str, str]] = []
    idx = index

    while len(layer) > 1:
        n = len(layer)
        if idx % 2 == 0:
            if idx + 1 < n:
                proof.append((layer[idx + 1], "right"))
            # else: lone node promoted unchanged — no proof element.
        else:
            proof.append((layer[idx - 1], "left"))
        layer = _next_layer(layer)
        idx //= 2

    return proof


def verify_inclusion_proof(leaf_hash: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Verify a Merkle inclusion proof against an expected root.

    Args:
        leaf_hash: Hex-encoded SHA-256 hash of the leaf to verify (the
            raw entry_hash, before leaf domain separation).
        proof: List of (sibling_hash, side) tuples from
            generate_inclusion_proof.
        root: Expected hex-encoded SHA-256 Merkle root.

    Returns:
        True iff the recomputed root matches (constant-time comparison).
    """
    current = _leaf_hash(leaf_hash)

    for sibling, side in proof:
        if side == "left":
            current = _node_hash(sibling, current)
        else:
            current = _node_hash(current, sibling)

    return hmac.compare_digest(current, root)
