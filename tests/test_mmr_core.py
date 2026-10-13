"""Regression vectors and adversarial checks for the MMR implementation."""
import copy
import hashlib

import pytest

from merkle_mountain_range.mmr import MerkleMountainRange


def independent_root(items):
    def h(x):
        return hashlib.sha256(x).digest()
    peaks = []
    for item in items:
        node, height = h(b"\x00" + item.encode()), 0
        while peaks and peaks[-1][0] == height:
            _, left = peaks.pop()
            node, height = h(b"\x01" + left + node), height + 1
        peaks.append((height, node))
    if not peaks:
        return h(b"\x03").hex()
    root = peaks[-1][1]
    for _, peak in reversed(peaks[:-1]):
        root = h(b"\x02" + peak + root)
    return root.hex()


@pytest.mark.parametrize("count", [0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 32, 33])
def test_known_structure_and_inclusion(count):
    mmr = MerkleMountainRange()
    items = [f"event {i}" for i in range(count)]
    for i, item in enumerate(items):
        assert mmr.append(item) == i
    assert mmr.size == count
    assert mmr.root == independent_root(items)
    assert len(mmr.peaks) == count.bit_count()
    for i, item in enumerate(items):
        proof = mmr.inclusion_proof(i)
        assert mmr.verify_inclusion(item, proof, mmr.root)
        assert not mmr.verify_inclusion(item + " modified", proof, mmr.root)
        assert not mmr.verify_inclusion(item, proof, "0" * 64)


def test_tamper_proof_and_invalid_data():
    mmr = MerkleMountainRange()
    for item in ("a", "b", "a", "d", "e", "f", "g"):
        mmr.append(item)
    proof = mmr.inclusion_proof(1)
    assert MerkleMountainRange.verify_inclusion("b", proof, mmr.root)
    forged = copy.deepcopy(proof)
    forged["siblings"][0]["side"] = "right"
    assert not mmr.verify_inclusion("b", forged, mmr.root)
    forged = copy.deepcopy(proof)
    forged["peaks"][0] = "0" * 64
    assert not mmr.verify_inclusion("b", forged, mmr.root)
    forged = copy.deepcopy(proof)
    forged["index"] = 2
    assert not mmr.verify_inclusion("b", forged, mmr.root)
    with pytest.raises(IndexError):
        mmr.inclusion_proof(7)
    with pytest.raises(TypeError):
        mmr.append(123)


@pytest.mark.parametrize("old", [0, 1, 2, 3, 5, 6, 9])
def test_consistency(old):
    mmr = MerkleMountainRange()
    for item in [f"event {i}" for i in range(old)]:
        mmr.append(item)
    old_root = mmr.root
    for item in [f"event {i}" for i in range(old, 9)]:
        mmr.append(item)
    proof = mmr.consistency_proof(old)
    assert mmr.verify_consistency(old_root, mmr.root, proof)
    tampered = copy.deepcopy(proof)
    if tampered["appended_hashes"]:
        tampered["appended_hashes"][0] = "0" * 64
        assert not mmr.verify_consistency(old_root, mmr.root, tampered)
    else:
        tampered["new_size"] += 1
        assert not mmr.verify_consistency(old_root, mmr.root, tampered)
    assert not mmr.verify_consistency("0" * 64, mmr.root, proof)


def test_reference_vectors():
    mmr = MerkleMountainRange()
    assert mmr.root == "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"
    for item, expected in [
        ("alpha", "2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b"),
        ("beta", "983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b"),
        ("gamma", "29c1439a00ee3e6faf7448a71127ccd3b97d6c877d9b0aa8708ca62a90d5926e"),
        ("delta", "42fc54eeb6352f90cc81fdd5791292cca3974a168208b395b06a76240b24884d"),
        ("epsilon", "c2c29efc66e6b2ef53c9c609f6774c7419986f8d0f95cd50c3d2fee2f4a2dde3"),
    ]:
        mmr.append(item)
        assert mmr.root == expected
