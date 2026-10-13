"""Append-only Merkle Mountain Range with SHA-256 domain-separated hashes.

This is a documented local protocol, not a consensus-chain wire-format MMR.
Leaves: SHA256(0x00 || data); parents: SHA256(0x01 || left || right);
peak bagging (right to left): SHA256(0x02 || left_peak || accumulator);
empty root: SHA256(0x03). Inclusion proofs are logarithmic in leaf count.
Consistency proofs disclose hashes of all appended leaves (linear in growth).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def _parent(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def _bag(peaks: list[bytes]) -> bytes:
    if not peaks:
        return _sha(b"\x03")
    root = peaks[-1]
    for peak in reversed(peaks[:-1]):
        root = _sha(b"\x02" + peak + root)
    return root


def _layout(size: int) -> list[tuple[int, int]]:
    """(start, height) for each maximal complete subtree, left to right."""
    result = []
    start = 0
    for height in range(size.bit_length() - 1, -1, -1):
        if size & (1 << height):
            result.append((start, height))
            start += 1 << height
    return result


def _hex_hash(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("Expected a 64-character SHA-256 hex digest")
    digest = bytes.fromhex(value)
    if len(digest) != 32:
        raise ValueError("Invalid SHA-256 digest")
    return digest


def _append_hash(peaks: list[tuple[int, bytes]], digest: bytes) -> None:
    height = 0
    while peaks and peaks[-1][0] == height:
        _, left = peaks.pop()
        digest = _parent(left, digest)
        height += 1
    peaks.append((height, digest))


class MerkleMountainRange:
    """In-memory SHA-256 MMR. Persist leaves/checkpoints externally if required."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._peaks: list[tuple[int, bytes]] = []

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> str:
        return _bag([digest for _, digest in self._peaks]).hex()

    @property
    def peaks(self) -> list[str]:
        return [digest.hex() for _, digest in self._peaks]

    def append(self, data: bytes | str) -> int:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, bytes):
            raise TypeError("Leaf must be bytes or str")
        digest = _leaf(data)
        self._leaves.append(digest)
        _append_hash(self._peaks, digest)
        return self.size - 1

    def inclusion_proof(self, index: int) -> dict[str, Any]:
        if type(index) is not int or not 0 <= index < self.size:
            raise IndexError("Leaf index out of range")
        layout = _layout(self.size)
        peak_index = next(i for i, (start, height) in enumerate(layout)
                          if start <= index < start + (1 << height))
        start, height = layout[peak_index]
        level = self._leaves[start:start + (1 << height)]
        offset = index - start
        siblings = []
        for _ in range(height):
            siblings.append({"side": "left" if offset & 1 else "right",
                             "hash": level[offset ^ 1].hex()})
            level = [_parent(level[j], level[j + 1])
                     for j in range(0, len(level), 2)]
            offset //= 2
        return {"index": index, "size": self.size,
                "siblings": siblings, "peaks": self.peaks,
                "peak_index": peak_index}

    def consistency_proof(self, old_size: int) -> dict[str, Any]:
        """Verifiable append-only extension; O(new_size - old_size) hashes."""
        if type(old_size) is not int or not 0 <= old_size <= self.size:
            raise ValueError("Invalid old_size")
        previous: list[tuple[int, bytes]] = []
        for digest in self._leaves[:old_size]:
            _append_hash(previous, digest)
        return {"old_size": old_size, "new_size": self.size,
                "old_peaks": [digest.hex() for _, digest in previous],
                "appended_hashes": [digest.hex() for digest in self._leaves[old_size:]]}

    @staticmethod
    def verify_inclusion(data: bytes | str, proof: Mapping[str, Any], root: str) -> bool:
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")
            if not isinstance(data, bytes):
                return False
            size, index = proof["size"], proof["index"]
            peak_index = proof["peak_index"]
            if (type(size) is not int or type(index) is not int
                    or type(peak_index) is not int or not 0 <= index < size):
                return False
            layout = _layout(size)
            peaks = [_hex_hash(x) for x in proof["peaks"]]
            if len(peaks) != len(layout):
                return False
            if not 0 <= peak_index < len(layout):
                return False
            start, height = layout[peak_index]
            if not start <= index < start + (1 << height):
                return False
            siblings = proof["siblings"]
            if not isinstance(siblings, list) or len(siblings) != height:
                return False
            node = _leaf(data)
            offset = index - start
            for sibling in siblings:
                if not isinstance(sibling, dict):
                    return False
                expected_side = "left" if offset & 1 else "right"
                if sibling.get("side") != expected_side:
                    return False
                sibling_hash = _hex_hash(sibling["hash"])
                node = (_parent(sibling_hash, node) if offset & 1
                        else _parent(node, sibling_hash))
                offset //= 2
            if not hmac.compare_digest(peaks[peak_index], node):
                return False
            return hmac.compare_digest(_bag(peaks), _hex_hash(root))
        except (KeyError, TypeError, ValueError, IndexError, OverflowError):
            return False

    @staticmethod
    def verify_consistency(old_root: str, new_root: str,
                           proof: Mapping[str, Any]) -> bool:
        try:
            old_size, new_size = proof["old_size"], proof["new_size"]
            if (type(old_size) is not int or type(new_size) is not int
                    or not 0 <= old_size <= new_size):
                return False
            old_layout = _layout(old_size)
            old_peaks = [_hex_hash(p) for p in proof["old_peaks"]]
            appended = [_hex_hash(p) for p in proof["appended_hashes"]]
            if (len(old_peaks) != len(old_layout)
                    or len(appended) != new_size - old_size):
                return False
            if not hmac.compare_digest(_bag(old_peaks), _hex_hash(old_root)):
                return False
            peaks = [(height, digest) for (_, height), digest
                     in zip(old_layout, old_peaks)]
            for digest in appended:
                _append_hash(peaks, digest)
            return hmac.compare_digest(
                _bag([digest for _, digest in peaks]), _hex_hash(new_root))
        except (KeyError, TypeError, ValueError, IndexError, OverflowError):
            return False
