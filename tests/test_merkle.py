"""Merkle 树测试：根计算、奇数叶复制、认证路径、篡改检测。"""

from __future__ import annotations

import random
import unittest

from nimbus_chain.crypto import hash256
from nimbus_chain.merkle import (
    LEFT,
    RIGHT,
    MerkleProofError,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)


def _leaves(count: int, seed: int = 5) -> list[bytes]:
    rng = random.Random(seed)
    return [hash256(rng.randbytes(16)) for _ in range(count)]


class MerkleRootTests(unittest.TestCase):
    def test_single_leaf_root_is_leaf(self):
        leaf = _leaves(1)[0]
        self.assertEqual(merkle_root([leaf]), leaf)

    def test_two_leaves(self):
        a, b = _leaves(2)
        self.assertEqual(merkle_root([a, b]), hash256(a + b))

    def test_odd_leaf_count_duplicates_last(self):
        """3 片叶子的根必须等于 [a, b, c, c] 四片叶子算出来的根。"""
        a, b, c = _leaves(3)
        self.assertEqual(merkle_root([a, b, c]), merkle_root([a, b, c, c]))

    def test_root_changes_when_any_leaf_changes(self):
        leaves = _leaves(8)
        original = merkle_root(leaves)
        tampered = list(leaves)
        tampered[5] = hash256(b"evil")
        self.assertNotEqual(merkle_root(tampered), original)

    def test_root_order_matters(self):
        a, b = _leaves(2)
        self.assertNotEqual(merkle_root([a, b]), merkle_root([b, a]))

    def test_empty_rejected(self):
        with self.assertRaises(MerkleProofError):
            merkle_root([])


class MerkleProofTests(unittest.TestCase):
    def test_all_indices_verify_for_many_sizes(self):
        for size in list(range(1, 21)) + [31, 32, 33, 64, 65]:
            leaves = _leaves(size)
            root = merkle_root(leaves)
            for index in range(size):
                with self.subTest(size=size, index=index):
                    proof = merkle_proof(leaves, index)
                    self.assertTrue(verify_merkle_proof(leaves[index], proof, root))

    def test_tampered_leaf_rejected(self):
        leaves = _leaves(7)
        root = merkle_root(leaves)
        proof = merkle_proof(leaves, 3)
        forged = hash256(b"not-in-the-block")
        self.assertFalse(verify_merkle_proof(forged, proof, root))

    def test_tampered_proof_rejected(self):
        leaves = _leaves(6)
        root = merkle_root(leaves)
        proof = merkle_proof(leaves, 2)
        broken = list(proof)
        sibling, direction = broken[0]
        broken[0] = (hash256(sibling), direction)
        self.assertFalse(verify_merkle_proof(leaves[2], broken, root))

    def test_duplicate_sibling_appears_for_odd_levels(self):
        """3 片叶子的第 3 片：其 sibling 必须是它自己。"""
        leaves = _leaves(3)
        proof = merkle_proof(leaves, 2)
        self.assertEqual(proof[0][1], RIGHT)
        self.assertEqual(proof[0][0], leaves[2])

    def test_direction_ordering(self):
        """4 片叶子：索引 0 的 sibling 在右，索引 1 的 sibling 在左。"""
        leaves = _leaves(4)
        self.assertEqual(merkle_proof(leaves, 0)[0][1], RIGHT)
        self.assertEqual(merkle_proof(leaves, 1)[0][1], LEFT)

    def test_index_out_of_range(self):
        leaves = _leaves(4)
        for bad in (-1, 4, 99):
            with self.subTest(index=bad):
                with self.assertRaises(MerkleProofError):
                    merkle_proof(leaves, bad)

    def test_unknown_direction_rejected(self):
        with self.assertRaises(MerkleProofError):
            verify_merkle_proof(b"\x00" * 32, [(b"\x11" * 32, "sideways")], b"\x22" * 32)


if __name__ == "__main__":
    unittest.main()
