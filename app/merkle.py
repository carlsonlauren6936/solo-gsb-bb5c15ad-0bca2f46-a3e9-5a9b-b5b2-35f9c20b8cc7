"""事件承诺集合的 Merkle 成员证明（纯函数实现，不依赖数据库与时钟）。

提交截止后，事件的全部承诺按 **commitment_id 升序** 构造一棵 Merkle 树，
调用方仅凭事件根与成员证明即可验证某个承诺确实进入该事件，无需下载完整
时间线。哈希方案（merkle-sha256-v1）：

空集合::

    EMPTY_ROOT = SHA-256("sealed-predictions/merkle-commitment-set/v1/empty")

叶节点（绑定事件 ID、承诺 ID 与原承诺哈希，三者均不可被证明复用者替换）::

    leaf = SHA-256( 0x00 || uuid_be(event_id)
                        || uuid_be(commitment_id)
                        || bytes(commitment_hash) )

内部节点（与叶节点使用不同单字节前缀，避免叶/内部节点的第二原像混淆）::

    parent = SHA-256( 0x01 || left(32B) || right(32B) )

配对规则：每层兄弟两两配对；该层节点数为奇数时**复制末项**后配对（即
parent(last, last)）。单叶集合不再复制，根即叶哈希本身；空集合返回固定的
EMPTY_ROOT。
"""

import hashlib
import math
from dataclasses import dataclass
from uuid import UUID

# 叶节点与内部节点使用不同前缀：内部数据无法被伪装成另一类型的节点
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

MERKLE_TREE_SCHEME = "merkle-sha256-v1"

# 空集合的明确空根：与任何非空树的根都不同，且对空集合稳定可复现
EMPTY_ROOT = hashlib.sha256(
    b"sealed-predictions/merkle-commitment-set/v1/empty"
).hexdigest()

# 层级校验的实用上限：2^64 个叶节点（64 层路径）
MAX_LEAF_COUNT = 2**64


def leaf_hash(event_id: UUID, commitment_id: UUID, commitment_hash: str) -> str:
    """计算绑定事件 ID、承诺 ID 与原承诺哈希的叶哈希（64 位小写十六进制）。

    commitment_hash 须为 64 位十六进制（大小写均可，内部按归一化后的小写
    字节摘要参与计算）。
    """
    digest = hashlib.sha256()
    digest.update(LEAF_PREFIX)
    digest.update(event_id.bytes)
    digest.update(commitment_id.bytes)
    digest.update(bytes.fromhex(commitment_hash.lower()))
    return digest.hexdigest()


def parent_hash(left: str, right: str) -> str:
    """计算内部节点哈希：SHA-256(0x01 || left || right)，左右次序敏感。"""
    digest = hashlib.sha256()
    digest.update(NODE_PREFIX)
    digest.update(bytes.fromhex(left.lower()))
    digest.update(bytes.fromhex(right.lower()))
    return digest.hexdigest()


def merkle_depth(count: int) -> int:
    """给定叶节点数所需的证明路径层数：空/单叶为 0，其余为 ceil(log2(count))。"""
    if count <= 1:
        return 0
    return (count - 1).bit_length()  # ceil(log2(count))


def _pair_level(level: list[str]) -> list[str]:
    """一层折叠：奇数个节点时复制末项配对，再两两计算父节点。"""
    nodes = list(level)
    if len(nodes) % 2 == 1:
        nodes.append(nodes[-1])
    return [
        parent_hash(nodes[i], nodes[i + 1])
        for i in range(0, len(nodes), 2)
    ]


def merkle_root(leaves: list[str]) -> str:
    """按升序叶哈希列表计算 Merkle 根；空列表返回固定 EMPTY_ROOT。"""
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        level = _pair_level(level)
    return level[0]


@dataclass(frozen=True)
class ProofStep:
    """证明路径上的一层兄弟节点。

    position 表示**兄弟节点相对当前节点的位置**：
      - ``"left"``：兄弟在左，父哈希为 parent(sibling, current)；
      - ``"right"``：兄弟在右，父哈希为 parent(current, sibling)。
    """

    sibling: str
    position: str  # left | right


def build_membership_proof(
    leaves: list[str], index: int
) -> tuple[list[ProofStep], str]:
    """为升序叶列表中下标 ``index`` 的叶构造成员证明。

    返回 (自叶向根的每层证明步骤, 树的 Merkle 根)。单叶树路径为空、根为
    叶本身。索引越界抛出 IndexError（由路由层先做存在性判定）。
    """
    if not leaves:
        raise ValueError("空叶集合无法构造成员证明")
    if index < 0 or index >= len(leaves):
        raise IndexError(f"叶下标 {index} 超出范围 [0, {len(leaves)})")

    level = list(leaves)
    current = index
    steps: list[ProofStep] = []
    while len(level) > 1:
        nodes = list(level)
        if len(nodes) % 2 == 1:
            # 奇数层复制末项：最后一个节点与自身的副本配对
            nodes.append(nodes[-1])
        if current % 2 == 0:
            steps.append(ProofStep(sibling=nodes[current + 1], position="right"))
        else:
            steps.append(ProofStep(sibling=nodes[current - 1], position="left"))
        level = [
            parent_hash(nodes[i], nodes[i + 1])
            for i in range(0, len(nodes), 2)
        ]
        current //= 2
    return steps, level[0]


def evaluate_membership_proof(leaf: str, steps: list[ProofStep]) -> str:
    """从叶哈希与自叶向根的证明路径重算 Merkle 根（不校验结构，结构由路由层校验）。"""
    node = leaf.lower()
    for step in steps:
        sibling = step.sibling.lower()
        if step.position == "left":
            node = parent_hash(sibling, node)
        else:
            node = parent_hash(node, sibling)
    return node
