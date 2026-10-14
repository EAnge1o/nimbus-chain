"""Merkle 树与 Merkle 证明。

Bitcoin 的区块头只存一个 32 字节的 ``merkle_root``，就能承诺区块里成百上千笔
交易。这个模块实现三件事：

* ``merkle_root(leaves)`` —— 由交易哈希列表算出根（奇数个节点时**复制最后一个**，
  这是 Bitcoin 的规则，不是"补零"）。
* ``merkle_proof(leaves, index)`` —— 生成某笔交易到根的认证路径。
* ``verify_merkle_proof(leaf, proof, root)`` —— 只凭路径验证交易被打包。

叶子必须已经是 32 字节的哈希（交易哈希），内部节点才做 ``hash256(left + right)``
—— 叶节点**不**二次哈希。SPV 轻客户端正是靠这里生成的路径，在只下载区块头的情
况下证明"某笔交易确实在一个被 PoW 保护的区块里"。
"""

from __future__ import annotations

from .crypto import hash256

__all__ = ["merkle_root", "merkle_proof", "verify_merkle_proof", "MerkleProofError"]

RIGHT = "right"
LEFT = "left"


class MerkleProofError(ValueError):
    """Merkle 证明生成/验证失败。"""


def _combine(left: bytes, right: bytes) -> bytes:
    return hash256(left + right)


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    """自底向上展开每一层，奇数节点时复制末尾。"""
    if not leaves:
        raise MerkleProofError("cannot build a Merkle tree without leaves")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        levels.append([_combine(current[i], current[i + 1]) for i in range(0, len(current), 2)])
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    """计算 Merkle 根；单叶区块的根就是该叶自身。"""
    return _levels(leaves)[-1][0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """生成 ``index`` 处叶子的认证路径，返回 ``[(sibling_hash, direction), ...]``。

    ``direction`` 表示 sibling 位于当前节点的右侧（``'right'``）还是左侧
    （``'left'``）。当某层发生奇数复制时，最右叶子的 sibling 就是它自己——
    路径里会如实出现 ``(leaf, 'right')``，验证方必须能处理这种情况。
    """
    levels = _levels(leaves)
    if not 0 <= index < len(leaves):
        raise MerkleProofError(f"leaf index {index} out of range (0..{len(leaves) - 1})")

    proof: list[tuple[bytes, str]] = []
    idx = index
    for depth in range(len(levels) - 1):
        current = levels[depth]
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        if idx % 2 == 0:
            proof.append((current[idx + 1], RIGHT))
        else:
            proof.append((current[idx - 1], LEFT))
        idx //= 2
    return proof


def verify_merkle_proof(leaf: bytes, proof: list[tuple[bytes, str]], root: bytes) -> bool:
    """验证路径；任何一处哈希不符即返回 ``False``（不抛异常，便于调用方判断）。"""
    current = leaf
    for sibling, direction in proof:
        if direction == RIGHT:
            current = _combine(current, sibling)
        elif direction == LEFT:
            current = _combine(sibling, current)
        else:
            raise MerkleProofError(f"unknown direction: {direction!r}")
    return current == root
