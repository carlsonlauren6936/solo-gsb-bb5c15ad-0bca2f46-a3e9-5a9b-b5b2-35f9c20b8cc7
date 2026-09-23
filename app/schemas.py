from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

COMMITMENT_HASH_PATTERN = r"^[0-9a-fA-F]{64}$"


def require_timezone_aware(v: datetime) -> datetime:
    if v.tzinfo is None or v.utcoffset() is None:
        raise ValueError("截止时间必须携带时区偏移（建议使用 UTC，如 2030-01-01T00:00:00Z）")
    return v


class EventCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    commit_deadline: datetime = Field(description="提交截止时间（须含时区，建议 UTC）")
    reveal_deadline: datetime = Field(description="揭示截止时间（须含时区，建议 UTC）")

    @field_validator("commit_deadline", "reveal_deadline")
    @classmethod
    def must_be_timezone_aware(cls, v: datetime) -> datetime:
        return require_timezone_aware(v)


class CommitmentCreate(BaseModel):
    commitment_hash: str = Field(
        pattern=COMMITMENT_HASH_PATTERN,
        description="SHA-256 承诺值，64 位十六进制",
        examples=["9f2c..."],
    )


class CommitmentBatchCreate(BaseModel):
    # 元素不在这里做 pattern 校验：格式非法是逐项冲突（409）而非请求体 422
    commitment_hashes: list[str] = Field(
        min_length=1,
        max_length=100,
        description="1～100 个 SHA-256 承诺值（64 位十六进制），按输入顺序在同一事务中原子提交",
    )


class RevealCreate(BaseModel):
    original_text: str = Field(description="预测原文（UTF-8）")
    salt: str = Field(min_length=1, max_length=256, description="随机盐（UTF-8）")


class RevealBatchItem(BaseModel):
    # 不在此处施加盐的长度约束：盐为空/超长是逐项冲突（INVALID_FORMAT，409），
    # 而非整个请求体的 422；字段类型错误或字段缺失才是请求体 422
    original_text: str = Field(description="预测原文（UTF-8）")
    salt: str = Field(description="随机盐（UTF-8，1～256 字符）")


class RevealBatchCreate(BaseModel):
    reveals: list[RevealBatchItem] = Field(
        min_length=1,
        max_length=100,
        description="1～100 组原文与盐，按输入顺序在同一事务中原子揭示",
    )


class DeadlineExtensionCreate(BaseModel):
    commit_deadline: datetime = Field(description="新的提交截止时间（须含时区，建议 UTC）")
    reveal_deadline: datetime = Field(description="新的揭示截止时间（须含时区，建议 UTC）")
    reason: str = Field(min_length=1, max_length=500, description="延长原因（记录进审计与时间线）")

    @field_validator("commit_deadline", "reveal_deadline")
    @classmethod
    def must_be_timezone_aware(cls, v: datetime) -> datetime:
        return require_timezone_aware(v)


class DeadlineExtensionOut(BaseModel):
    event_id: UUID
    old_commit_deadline: datetime
    old_reveal_deadline: datetime
    new_commit_deadline: datetime
    new_reveal_deadline: datetime
    reason: str
    extended_at: datetime


class EventOut(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    commit_deadline: datetime
    reveal_deadline: datetime
    created_at: datetime
    status: str  # commit | reveal | closed
    commitment_count: int
    reveal_count: int


class EventSnapshotOut(BaseModel):
    """事件在指定历史时刻的只读重建视图（不反映该时刻之后的任何写入）。"""

    event_id: UUID
    title: str
    description: Optional[str]
    created_at: datetime = Field(description="事件创建时间（UTC，回放的起点）")
    snapshot_at: datetime = Field(description="快照时刻（按 UTC 归一化回显，即请求中的 at）")
    commit_deadline: datetime = Field(description="快照时刻生效的提交截止时间（已回放到当时的延长）")
    reveal_deadline: datetime = Field(description="快照时刻生效的揭示截止时间（已回放到当时的延长）")
    status: str = Field(description="按快照时刻与回放截止时间判定：commit | reveal | closed")
    commitment_count: int = Field(description="快照时刻之前（含）已写入的承诺数量")
    reveal_count: int = Field(description="快照时刻之前（含）已写入的揭示数量")


class CommitmentOut(BaseModel):
    id: UUID
    event_id: UUID
    commitment_hash: str
    created_at: datetime
    revealed: bool


class CommitmentBatchOut(BaseModel):
    count: int = Field(description="本次创建的承诺数量（等于输入哈希数量）")
    commitments: list[CommitmentOut] = Field(description="按输入顺序创建的承诺记录")


class RevealOut(BaseModel):
    id: UUID
    event_id: UUID
    commitment_id: UUID
    commitment_hash: str
    recomputed_hash: str
    hash_scheme: str
    revealed_at: datetime
    verified: bool


class RevealBatchOut(BaseModel):
    count: int = Field(description="本次写入的揭示数量（等于输入组数）")
    reveals: list[RevealOut] = Field(description="按输入顺序写入的揭示记录，全部 verified=true")


class TimelineEntry(BaseModel):
    seq: int
    type: str  # event_created | commitment_submitted | reveal_accepted | deadline_extended
    at: datetime
    detail: dict[str, Any]


class TimelineOut(BaseModel):
    event_id: UUID
    status: str
    generated_at: datetime
    hash_scheme: str
    entries: list[TimelineEntry]


class SettlementCreate(BaseModel):
    standard_result: str = Field(
        min_length=1,
        description="非空标准结果（UTF-8，按揭示原文逐字符精确匹配）",
    )


class SettlementOut(BaseModel):
    event_id: UUID
    status: str = Field(description="unsettled | settled")
    standard_result: Optional[str] = Field(
        default=None,
        description="已永久确认的标准结果；未结算时为 null",
    )
    correct_count: Optional[int] = Field(
        default=None,
        description="已揭示且原文与标准结果精确匹配的承诺数；未结算时为 null",
    )
    incorrect_count: Optional[int] = Field(
        default=None,
        description="已揭示但原文与标准结果不匹配的承诺数；未结算时为 null",
    )
    unrevealed_count: Optional[int] = Field(
        default=None,
        description="从未揭示的承诺数；未结算时为 null",
    )
    settled_at: Optional[datetime] = Field(
        default=None,
        description="结算永久确认时间（UTC）；未结算时为 null",
    )


class ConflictRequest(BaseModel):
    event_ids: list[UUID] = Field(
        default_factory=list,
        description="待分析的事件 ID 列表（重复 ID 自动去重，空列表返回空结果）",
    )


class ConflictSegmentOut(BaseModel):
    start: datetime = Field(description="片段起点（含，UTC）")
    end: datetime = Field(description="片段终点（不含，UTC，半开边界）")
    phase: str  # commit | reveal
    event_ids: list[UUID] = Field(description="该时段同时处于同一阶段的事件 ID（已排序）")


class ConflictsOut(BaseModel):
    generated_at: datetime
    phases: list[str]
    count: int = Field(description="冲突片段数量")
    segments: list[ConflictSegmentOut]


class ScheduleRequest(BaseModel):
    event_ids: list[UUID] = Field(
        default_factory=list,
        description="待排程的事件 ID 列表（重复 ID 自动去重，空列表返回空结果）",
    )
    # 不用 int 类型约束：非法上限（缺失、null、非整数、布尔、小于 1）须走统一
    # 错误结构（api_error 的 400 INVALID_TRACK_LIMIT），而不是 pydantic 的 422
    track_limit: Any = Field(default=None, description="可用 track 数（>= 1 的整数）")


class ScheduleAssignmentOut(BaseModel):
    event_id: UUID
    commit_track: Optional[int] = Field(
        description="commit 阶段分配的轨道（1 起编号）；零长度窗口为 null"
    )
    reveal_track: Optional[int] = Field(
        description="reveal 阶段分配的轨道（1 起编号，与 commit 轨道相互独立）；零长度窗口为 null"
    )


class ScheduleConflictPairOut(BaseModel):
    phase: str  # commit | reveal
    event_id_1: UUID = Field(description="冲突对中按 UUID 升序的第一个事件")
    event_id_2: UUID = Field(description="冲突对中按 UUID 升序的第二个事件")


class ScheduleOut(BaseModel):
    track_limit: int = Field(description="请求的可用 track 数")
    required_tracks: int = Field(
        description="最小所需 track 数（commit / reveal 两阶段各自最大并发深度的较大值）"
    )
    feasible: bool = Field(description="最小所需轨道数是否不超过 track_limit")
    assignments: list[ScheduleAssignmentOut] = Field(
        description="按 event_id 升序的逐事件轨道分配"
    )
    conflicts: list[ScheduleConflictPairOut] = Field(
        description="feasible=false 时导致超出上限的同阶段冲突事件对（去重排序）；feasible=true 时为空"
    )


class HashOut(BaseModel):
    commitment_hash: str
    hash_scheme: str


# --------------------------------------------------------------------------- #
# 事件承诺集合 Merkle 证明
# --------------------------------------------------------------------------- #

# Merkle 哈希字段统一接受 64 位十六进制（大小写均可，服务端归一化为小写）
MERKLE_HEX_PATTERN = r"^[0-9a-fA-F]{64}$"
PROOF_POSITIONS = ("left", "right")


class MerkleSetOut(BaseModel):
    """提交截止后事件承诺集合的 Merkle 承诺（根 + 数量 + 方案）。"""

    event_id: UUID
    merkle_root: str = Field(
        description="按承诺 ID 升序构造的 Merkle 根（64 位十六进制）；空集合为固定空根"
    )
    commitment_count: int = Field(description="进入 Merkle 树的承诺数量（空集合为 0）")
    tree_scheme: str = Field(description="Merkle 树与哈希方案标识")
    generated_at: datetime = Field(description="承诺签发时间（服务端 UTC）")


class MerkleProofStepOut(BaseModel):
    sibling: str = Field(
        pattern=MERKLE_HEX_PATTERN,
        description="该层兄弟节点哈希（64 位十六进制）",
    )
    position: Literal["left", "right"] = Field(
        description="兄弟节点相对当前节点的位置：left 表示兄弟在左，right 表示兄弟在右"
    )


class MerkleProofOut(BaseModel):
    """指定承诺在事件承诺集合中的 Merkle 成员证明。"""

    event_id: UUID
    commitment_id: UUID
    commitment_hash: str = Field(description="被证明承诺的原始承诺哈希（叶数据的一部分）")
    leaf_index: int = Field(
        description="叶节点在「按承诺 ID 升序」排列的叶序列中的下标（0 起）"
    )
    merkle_root: str = Field(description="事件承诺集合的 Merkle 根（64 位十六进制）")
    commitment_count: int = Field(description="事件承诺总数（叶节点数，>= 1）")
    tree_scheme: str
    proof: list[MerkleProofStepOut] = Field(
        description="自叶向根的每层兄弟节点（含左右位置）；单叶集合为空列表"
    )
    generated_at: datetime


class MerkleVerifyRequest(BaseModel):
    """本地 Merkle 成员证明校验请求：调用方把证明接口的全部数据原样回传。

    commitment_count 不使用 int 类型：布尔值、非整数等协议级非法输入须走
    统一业务错误（400 INVALID_MERKLE_PROOF），而不是 pydantic 的 422。
    """

    event_id: UUID
    commitment_id: UUID
    commitment_hash: str = Field(pattern=MERKLE_HEX_PATTERN)
    commitment_count: Any = Field(description="叶节点总数（必须是 >= 0 的整数）")
    merkle_root: str = Field(pattern=MERKLE_HEX_PATTERN)
    proof: list[MerkleProofStepOut] = Field(
        description="自叶向根的每层兄弟节点；单叶集合为空列表，空集合无成员证明"
    )


class MerkleVerifyOut(BaseModel):
    """本地 Merkle 校验结果：结构非法时返回 400；结构合法但根不匹配时 200 + valid=false。"""

    valid: bool
    reason: str = Field(description="valid=true 时为 ok；否则给出根不匹配的说明")
    leaf_hash: str = Field(description="由事件 ID / 承诺 ID / 承诺哈希严格重算的叶哈希")
    computed_root: str = Field(description="按叶数据与证明路径重算出的 Merkle 根")
    expected_root: str = Field(description="请求中声明的事件 Merkle 根（归一化为小写）")
    tree_scheme: str
