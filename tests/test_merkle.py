"""Merkle 承诺集合纯函数测试（app/merkle.py，不涉及 HTTP 与数据库）。

覆盖：
  - 空集合返回固定空根，且与任何非空树不同
  - 叶绑定事件 ID / 承诺 ID / 承诺哈希（任一改动叶哈希均变）
  - 叶与内部节点使用不同前缀（第二原像不可混淆）
  - 奇数层复制末项配对；单叶树根即叶本身
  - 证明路径长度 = ceil(log2(count))；各叶证明均重算到同一根
  - 独立参考实现交叉验证根与路径折叠
  - 篡改兄弟 / 位置 / 下标顺序后校验失败
"""

import hashlib
import uuid

import pytest

from app.merkle import (
    EMPTY_ROOT,
    MAX_LEAF_COUNT,
    MERKLE_TREE_SCHEME,
    build_membership_proof,
    evaluate_membership_proof,
    leaf_hash,
    merkle_depth,
    merkle_root,
    parent_hash,
)


def ref_parent(left: str, right: str) -> str:
    """独立参考实现：SHA-256(0x01 || left || right)。"""
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def ref_root(leaves: list[str]) -> str:
    """独立参考实现：空 -> 空根；单叶 -> 叶；否则奇数层复制末项逐层折叠。"""
    if not leaves:
        return hashlib.sha256(
            b"sealed-predictions/merkle-commitment-set/v1/empty"
        ).hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [ref_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def make_leaves(n: int) -> list[tuple]:
    """生成 n 个 (event_id, commitment_id, commitment_hash) 确定性样本。"""
    event_id = uuid.uuid4()
    items = []
    for i in range(n):
        cid = uuid.uuid4()
        chash = hashlib.sha256(f"commitment-{i}".encode()).hexdigest()
        items.append((event_id, cid, chash))
    # 模拟服务端行为：按承诺 ID 升序
    items.sort(key=lambda x: x[1])
    return items


def leaf_values(items: list[tuple]) -> list[str]:
    return [leaf_hash(e, c, h) for e, c, h in items]


def test_empty_root_constant_and_scheme():
    assert EMPTY_ROOT == hashlib.sha256(
        b"sealed-predictions/merkle-commitment-set/v1/empty"
    ).hexdigest()
    assert MERKLE_TREE_SCHEME == "merkle-sha256-v1"
    assert merkle_root([]) == EMPTY_ROOT
    # 空根是 64 位十六进制，且不会与非空叶哈希碰撞
    items = make_leaves(1)
    assert all(leaf != EMPTY_ROOT for leaf in leaf_values(items))


def test_leaf_hash_binds_all_three_fields():
    event_id, cid, chash = make_leaves(1)[0]
    base = leaf_hash(event_id, cid, chash)
    # 改事件 ID
    assert leaf_hash(uuid.uuid4(), cid, chash) != base
    # 改承诺 ID
    assert leaf_hash(event_id, uuid.uuid4(), chash) != base
    # 改承诺哈希
    other_hash = hashlib.sha256(b"other").hexdigest()
    assert leaf_hash(event_id, cid, other_hash) != base
    # 承诺哈希大小写不影响结果（归一化为小写）
    assert leaf_hash(event_id, cid, chash.upper()) == base


def test_leaf_and_node_prefixes_distinct():
    event_id, cid, chash = make_leaves(1)[0]
    leaf = leaf_hash(event_id, cid, chash)
    leaf_bytes = bytes.fromhex(leaf)
    # 长度为 64 的 commitment_hash 恰好能构造出与内部节点输入长度相等的材料，
    # 但前缀不同，因此哈希不同——叶节点无法被伪造为内部节点
    forged_internal = hashlib.sha256(
        b"\x01" + event_id.bytes + cid.bytes + bytes.fromhex(chash)
    ).hexdigest()
    assert hashlib.sha256(b"\x00" + leaf_bytes).hexdigest() != parent_hash(
        hashlib.sha256(b"\x00" + leaf_bytes[:0]).hexdigest(), leaf
    )
    assert leaf != forged_internal


def test_single_leaf_root_is_leaf_without_duplication():
    items = make_leaves(1)
    leaves = leaf_values(items)
    # 单叶：根即叶本身，不再做一次自配对
    assert merkle_root(leaves) == leaves[0]
    steps, root = build_membership_proof(leaves, 0)
    assert steps == []
    assert root == leaves[0]
    assert evaluate_membership_proof(leaves[0], []) == leaves[0]
    # 与「复制后配对」的非预期构造明确不同
    assert leaves[0] != parent_hash(leaves[0], leaves[0])


def test_odd_level_duplicates_last_item():
    items = make_leaves(3)
    leaves = leaf_values(items)
    # 手动构造：底层 [l0, l1, l2, l2]，上层 [p01, p22]，根 p(p01, p22)
    p01 = parent_hash(leaves[0], leaves[1])
    p22 = parent_hash(leaves[2], leaves[2])
    assert merkle_root(leaves) == parent_hash(p01, p22)

    # 末项（下标 2）的证明：底层兄弟是自身复制且在右；折叠后位于上层
    # 右节点（下标 1），兄弟 p01 在左
    steps, root = build_membership_proof(leaves, 2)
    assert len(steps) == 2
    assert steps[0].sibling == leaves[2]
    assert steps[0].position == "right"
    assert steps[1].sibling == p01
    assert steps[1].position == "left"
    assert root == parent_hash(p01, p22)


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 100])
def test_all_leaves_verify_against_root(n):
    items = make_leaves(n)
    leaves = leaf_values(items)
    root = merkle_root(leaves)
    assert root == ref_root(leaves)
    expected_depth = merkle_depth(n)
    assert expected_depth == (0 if n <= 1 else (n - 1).bit_length())
    for i in range(n):
        steps, proof_root = build_membership_proof(leaves, i)
        assert proof_root == root
        assert len(steps) == expected_depth
        assert evaluate_membership_proof(leaves[i], steps) == root


def test_proof_positions_left_and_right():
    items = make_leaves(4)
    leaves = leaf_values(items)
    p01 = parent_hash(leaves[0], leaves[1])
    p23 = parent_hash(leaves[2], leaves[3])
    # 下标 0：底层兄弟在右；顶层兄弟 p23 也在右
    s0, _ = build_membership_proof(leaves, 0)
    assert [(x.position, x.sibling) for x in s0] == [
        ("right", leaves[1]),
        ("right", p23),
    ]
    # 下标 1：底层兄弟在左；顶层兄弟 p23 在右
    s1, _ = build_membership_proof(leaves, 1)
    assert s1[0].position == "left"
    assert s1[0].sibling == leaves[0]
    assert s1[1].sibling == p23
    # 下标 2：底层兄弟在右；顶层兄弟 p01 在左
    s2, _ = build_membership_proof(leaves, 2)
    assert [(x.position, x.sibling) for x in s2] == [
        ("right", leaves[3]),
        ("left", p01),
    ]
    # 下标 3：两层兄弟均在左
    s3, _ = build_membership_proof(leaves, 3)
    assert [(x.position, x.sibling) for x in s3] == [
        ("left", leaves[2]),
        ("left", p01),
    ]


def test_tampered_sibling_or_position_fails():
    items = make_leaves(4)
    leaves = leaf_values(items)
    root = merkle_root(leaves)
    steps, _ = build_membership_proof(leaves, 0)

    # 篡改任一层兄弟哈希 -> 重算根改变
    for k in range(len(steps)):
        tampered = [
            type(s)(sibling=("0" * 64 if j == k else s.sibling), position=s.position)
            for j, s in enumerate(steps)
        ]
        assert evaluate_membership_proof(leaves[0], tampered) != root

    # 翻转第一层兄弟左右位置 -> 重算根改变（父哈希左右次序敏感）
    partly = list(steps)
    partly[0] = type(steps[0])(
        sibling=steps[0].sibling,
        position="left" if steps[0].position == "right" else "right",
    )
    assert evaluate_membership_proof(leaves[0], partly) != root


def test_reordered_leaves_produce_different_root_when_hash_differs():
    items = make_leaves(4)
    leaves = leaf_values(items)
    root = merkle_root(leaves)
    swapped = list(leaves)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    # 交换两个不同叶的位置，根必然改变（除非哈希相等，样本下不相等）
    assert leaves[0] != leaves[1]
    assert merkle_root(swapped) != root


def test_proof_for_wrong_leaf_fails_against_root():
    items = make_leaves(4)
    leaves = leaf_values(items)
    root = merkle_root(leaves)
    # 用下标 0 的证明去验证下标 1 的叶
    steps0, _ = build_membership_proof(leaves, 0)
    assert evaluate_membership_proof(leaves[1], steps0) != root


def test_build_proof_index_out_of_range():
    leaves = leaf_values(make_leaves(3))
    with pytest.raises(IndexError):
        build_membership_proof(leaves, 3)
    with pytest.raises(IndexError):
        build_membership_proof(leaves, -1)
    with pytest.raises(ValueError):
        build_membership_proof([], 0)


def test_depth_values():
    assert [merkle_depth(n) for n in range(0, 8)] == [0, 0, 1, 2, 2, 3, 3, 3]
    assert merkle_depth(1024) == 10
    assert merkle_depth(1025) == 11
    assert MAX_LEAF_COUNT == 2**64
