"""事件承诺集合 Merkle 证明的 API 测试。

覆盖：
  - 未过提交截止：根与成员证明均返回 409 MERKLE_PROOF_NOT_AVAILABLE
  - 截止时刻（边界含）即可签发；reveal / closed 阶段同样可签发
  - 非空集合：根、数量、按承诺 ID 升序的叶序与成员证明；证明可通过
    /utils/merkle/verify 严格校验，且与独立参考实现一致
  - 空集合（零承诺）：明确空根、数量 0；指定承诺仍 404
  - 单叶集合：路径为空；奇数集合复制末项
  - 不存在事件 404、不存在/跨事件承诺 404、非 UUID 422
  - 本地校验接口：篡改根 / 承诺哈希 / 事件 ID / 兄弟 / 位置均 valid=false
    或 400；层级非法（数量与路径层数不符、空集合证明、布尔数量）400；
    格式非法（非十六进制哈希、错误位置、非 UUID）422
  - 证明签发不改变提交、揭示与结算流程
"""

import hashlib
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

_tmpdir = tempfile.mkdtemp(prefix="sealed_predictions_merkle_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmpdir}/merkle.db"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.clock as clock_module  # noqa: E402
import app.main as main_module  # noqa: E402
from app.hashing import compute_commitment  # noqa: E402
from app.merkle import EMPTY_ROOT, MERKLE_TREE_SCHEME  # noqa: E402

T0 = datetime(2030, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
COMMIT_DL = T0 + timedelta(hours=1)
REVEAL_DL = T0 + timedelta(hours=2)


class MutableClock:
    def __init__(self, start: datetime):
        self.t = start

    def __call__(self) -> datetime:
        return self.t


clock = MutableClock(T0)

client = TestClient(main_module.app)


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch):
    clock.t = T0
    monkeypatch.setattr(clock_module, "now_utc", clock)
    with client:  # 触发 lifespan 建表（幂等）
        yield


def create_event() -> str:
    r = client.post("/events", json={
        "title": "Merkle 证明事件",
        "commit_deadline": COMMIT_DL.isoformat(),
        "reveal_deadline": REVEAL_DL.isoformat(),
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def commit_hash(text: str, salt: str) -> str:
    return compute_commitment(text, salt)


def submit(event_id: str, h: str) -> dict:
    r = client.post(f"/events/{event_id}/commitments", json={"commitment_hash": h})
    assert r.status_code == 201, r.text
    return r.json()


def merkle_set(event_id: str) -> dict:
    r = client.get(f"/events/{event_id}/commitments/merkle")
    assert r.status_code == 200, r.text
    return r.json()


def proof(event_id: str, commitment_id: str) -> dict:
    r = client.get(f"/events/{event_id}/commitments/{commitment_id}/proof")
    assert r.status_code == 200, r.text
    return r.json()


def verify(body: dict, expected: int = 200) -> dict:
    r = client.post("/utils/merkle/verify", json=body)
    assert r.status_code == expected, r.text
    return r.json()


def ref_leaf(event_id: str, commitment_id: str, chash: str) -> str:
    return hashlib.sha256(
        b"\x00"
        + uuid.UUID(event_id).bytes
        + uuid.UUID(commitment_id).bytes
        + bytes.fromhex(chash)
    ).hexdigest()


def ref_parent(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def ref_root(leaves: list[str]) -> str:
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [ref_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def verify_body_from_proof(p: dict) -> dict:
    return {
        "event_id": p["event_id"],
        "commitment_id": p["commitment_id"],
        "commitment_hash": p["commitment_hash"],
        "commitment_count": p["commitment_count"],
        "merkle_root": p["merkle_root"],
        "proof": p["proof"],
    }


# --------------------------------------------------------------------------- #
# 签发门禁
# --------------------------------------------------------------------------- #

def test_proof_not_available_before_commit_deadline():
    event_id = create_event()
    h = commit_hash("明天下雨", "salt-1")
    submit(event_id, h)

    # commit 阶段：根与证明都不签发
    r = client.get(f"/events/{event_id}/commitments/merkle")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "MERKLE_PROOF_NOT_AVAILABLE"

    cid = client.get(f"/events/{event_id}/commitments").json()[0]["id"]
    r = client.get(f"/events/{event_id}/commitments/{cid}/proof")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "MERKLE_PROOF_NOT_AVAILABLE"


def test_proof_available_at_and_after_commit_deadline():
    event_id = create_event()
    h = commit_hash("a", "s")
    cid = submit(event_id, h)["id"]

    # 边界：恰为提交截止时刻即可签发（提交通道关闭、证明通道开启）
    clock.t = COMMIT_DL
    body = merkle_set(event_id)
    assert body["commitment_count"] == 1
    assert body["tree_scheme"] == MERKLE_TREE_SCHEME

    # closed 阶段仍然可签发（只读）
    clock.t = REVEAL_DL
    p = proof(event_id, cid)
    assert p["merkle_root"] == body["merkle_root"]


def test_event_not_found_and_bad_uuid():
    missing = "00000000-0000-0000-0000-000000000000"
    r = client.get(f"/events/{missing}/commitments/merkle")
    assert r.status_code == 404 and r.json()["detail"]["code"] == "EVENT_NOT_FOUND"
    r = client.get(f"/events/{missing}/commitments/{missing}/proof")
    assert r.status_code == 404 and r.json()["detail"]["code"] == "EVENT_NOT_FOUND"

    r = client.get("/events/not-a-uuid/commitments/merkle")
    assert r.status_code == 422
    r = client.get(f"/events/{missing}/commitments/not-a-uuid/proof")
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# 空集合
# --------------------------------------------------------------------------- #

def test_empty_set_returns_empty_root_and_zero_count():
    event_id = create_event()
    clock.t = COMMIT_DL
    body = merkle_set(event_id)
    assert body["commitment_count"] == 0
    assert body["merkle_root"] == EMPTY_ROOT
    assert body["event_id"] == event_id

    # 空集合上查询任何承诺都 404
    r = client.get(
        f"/events/{event_id}/commitments/00000000-0000-0000-0000-000000000000/proof"
    )
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "COMMITMENT_NOT_FOUND"


def test_commitment_from_other_event_not_found():
    e1 = create_event()
    e2 = create_event()
    c = submit(e1, commit_hash("x", "s"))
    clock.t = COMMIT_DL
    r = client.get(f"/events/{e2}/commitments/{c['id']}/proof")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "COMMITMENT_NOT_FOUND"
    # 但在原事件中可正常取得
    assert proof(e1, c["id"])["commitment_id"] == c["id"]


# --------------------------------------------------------------------------- #
# 非空集合：排序、根、证明、本地校验
# --------------------------------------------------------------------------- #

def test_nonempty_root_sorted_by_commitment_id_and_proofs_verify():
    event_id = create_event()
    committed = [
        submit(event_id, commit_hash(f"预测-{i}", f"salt-{i}"))
        for i in range(5)
    ]
    clock.t = COMMIT_DL

    body = merkle_set(event_id)
    assert body["commitment_count"] == 5

    # 期望叶序：按 commitment_id 升序（与提交顺序无关）
    ordered = sorted(committed, key=lambda c: uuid.UUID(c["id"]))
    leaves = [ref_leaf(event_id, c["id"], c["commitment_hash"]) for c in ordered]
    assert body["merkle_root"] == ref_root(leaves)

    for pos, c in enumerate(ordered):
        p = proof(event_id, c["id"])
        assert p["leaf_index"] == pos
        assert p["commitment_count"] == 5
        assert p["merkle_root"] == body["merkle_root"]
        assert len(p["proof"]) == 3  # ceil(log2(5)) = 3
        # 末项复制：下标 4 的第一层兄弟为自身叶哈希且在右
        if pos == 4:
            assert p["proof"][0]["sibling"] == leaves[4]
            assert p["proof"][0]["position"] == "right"
        result = verify(verify_body_from_proof(p))
        assert result["valid"] is True
        assert result["reason"] == "ok"
        assert result["computed_root"] == result["expected_root"] == body["merkle_root"]
        assert result["leaf_hash"] == leaves[pos]


def test_root_is_stable_and_deterministic():
    event_id = create_event()
    submit(event_id, commit_hash("a", "1"))
    submit(event_id, commit_hash("b", "2"))
    clock.t = COMMIT_DL
    first = merkle_set(event_id)
    second = merkle_set(event_id)
    assert first["merkle_root"] == second["merkle_root"]
    assert first["generated_at"] is not None


def test_single_leaf_has_empty_proof_path():
    event_id = create_event()
    c = submit(event_id, commit_hash("only", "salt"))
    clock.t = COMMIT_DL
    p = proof(event_id, c["id"])
    assert p["commitment_count"] == 1
    assert p["proof"] == []
    assert p["merkle_root"] == ref_leaf(event_id, c["id"], c["commitment_hash"])
    assert verify(verify_body_from_proof(p))["valid"] is True


def test_two_leaves_proof_siblings():
    event_id = create_event()
    c1 = submit(event_id, commit_hash("a", "1"))
    c2 = submit(event_id, commit_hash("b", "2"))
    clock.t = COMMIT_DL
    l1 = ref_leaf(event_id, c1["id"], c1["commitment_hash"])
    l2 = ref_leaf(event_id, c2["id"], c2["commitment_hash"])
    if uuid.UUID(c1["id"]) < uuid.UUID(c2["id"]):
        low, high = (c1, l1), (c2, l2)
    else:
        low, high = (c2, l2), (c1, l1)

    p_low = proof(event_id, low[0]["id"])
    assert p_low["leaf_index"] == 0
    assert p_low["proof"] == [{"sibling": high[1], "position": "right"}]
    p_high = proof(event_id, high[0]["id"])
    assert p_high["leaf_index"] == 1
    assert p_high["proof"] == [{"sibling": low[1], "position": "left"}]

    expected = ref_root([low[1], high[1]])
    assert merkle_set(event_id)["merkle_root"] == expected


# --------------------------------------------------------------------------- #
# 本地校验：密码学层失败（200 valid=false）
# --------------------------------------------------------------------------- #

def _good_proof_body(n: int = 5) -> tuple[str, dict]:
    # 同一测试内可能多次调用：事件创建要求截止时间在未来，先复位时钟
    clock.t = T0
    event_id = create_event()
    committed = [
        submit(event_id, commit_hash(f"v-{i}", f"k-{i}")) for i in range(n)
    ]
    clock.t = COMMIT_DL
    ordered = sorted(committed, key=lambda c: uuid.UUID(c["id"]))
    p = proof(event_id, ordered[0]["id"])
    return event_id, verify_body_from_proof(p)


def test_verify_fails_on_tampered_root():
    _, body = _good_proof_body()
    body["merkle_root"] = "0" * 64
    result = verify(body)
    assert result["valid"] is False
    assert result["computed_root"] != result["expected_root"]
    assert result["expected_root"] == "0" * 64


def test_verify_fails_on_tampered_commitment_hash():
    _, body = _good_proof_body()
    body["commitment_hash"] = hashlib.sha256(b"forged").hexdigest()
    result = verify(body)
    assert result["valid"] is False


def test_verify_fails_on_wrong_event_binding():
    _, body = _good_proof_body()
    body["event_id"] = str(uuid.uuid4())
    assert verify(body)["valid"] is False


def test_verify_fails_on_tampered_sibling_and_position():
    _, body = _good_proof_body()
    tampered = dict(body)
    tampered["proof"] = [dict(s) for s in body["proof"]]
    tampered["proof"][0]["sibling"] = "f" * 64
    assert verify(tampered)["valid"] is False

    flipped = dict(body)
    flipped["proof"] = [dict(s) for s in body["proof"]]
    flipped["proof"][0]["position"] = (
        "left" if flipped["proof"][0]["position"] == "right" else "right"
    )
    assert verify(flipped)["valid"] is False


def test_verify_accepts_uppercase_hex_and_normalizes():
    _, body = _good_proof_body(2)
    body["commitment_hash"] = body["commitment_hash"].upper()
    body["merkle_root"] = body["merkle_root"].upper()
    body["proof"] = [{**s, "sibling": s["sibling"].upper()} for s in body["proof"]]
    assert verify(body)["valid"] is True


# --------------------------------------------------------------------------- #
# 本地校验：结构/层级层失败（400 INVALID_MERKLE_PROOF）
# --------------------------------------------------------------------------- #

def test_verify_rejects_empty_set_membership():
    _, body = _good_proof_body(1)
    body["commitment_count"] = 0
    body["proof"] = []
    r = client.post("/utils/merkle/verify", json=body)
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "INVALID_MERKLE_PROOF"


def test_verify_rejects_path_depth_mismatch():
    _, body = _good_proof_body(5)  # 需要 3 层
    shorter = dict(body, proof=body["proof"][:2])
    r = client.post("/utils/merkle/verify", json=shorter)
    assert r.status_code == 400 and r.json()["detail"]["code"] == "INVALID_MERKLE_PROOF"

    # 单叶集合要求路径为空：给一层反而非法
    _, single = _good_proof_body(1)
    single["proof"] = [{"sibling": "0" * 64, "position": "left"}]
    r = client.post("/utils/merkle/verify", json=single)
    assert r.status_code == 400 and r.json()["detail"]["code"] == "INVALID_MERKLE_PROOF"

    # 非单叶集合路径不能为空
    _, two = _good_proof_body(2)
    two["proof"] = []
    r = client.post("/utils/merkle/verify", json=two)
    assert r.status_code == 400


def test_verify_rejects_non_integer_count():
    _, body = _good_proof_body()
    for bad in (True, False, "5", 1.5, None, -1, 2**64):
        r = client.post(
            "/utils/merkle/verify", json={**body, "commitment_count": bad}
        )
        assert r.status_code == 400, (bad, r.text)
        assert r.json()["detail"]["code"] == "INVALID_MERKLE_PROOF"


# --------------------------------------------------------------------------- #
# 本地校验：格式层失败（422）
# --------------------------------------------------------------------------- #

def test_verify_rejects_bad_formats_with_422():
    _, body = _good_proof_body()

    bad_hash = dict(body, commitment_hash="xyz")
    assert client.post("/utils/merkle/verify", json=bad_hash).status_code == 422

    bad_root = dict(body, merkle_root="0" * 63)
    assert client.post("/utils/merkle/verify", json=bad_root).status_code == 422

    bad_sibling = dict(body)
    bad_sibling["proof"] = [{**s, "sibling": "zz"} for s in body["proof"]]
    assert client.post("/utils/merkle/verify", json=bad_sibling).status_code == 422

    bad_position = dict(body)
    bad_position["proof"] = [{**s, "position": "middle"} for s in body["proof"]]
    assert client.post("/utils/merkle/verify", json=bad_position).status_code == 422

    assert client.post(
        "/utils/merkle/verify", json={**body, "event_id": "not-a-uuid"}
    ).status_code == 422
    assert client.post(
        "/utils/merkle/verify", json={**body, "commitment_id": "not-a-uuid"}
    ).status_code == 422

    for missing in ("event_id", "commitment_id", "commitment_hash",
                    "commitment_count", "merkle_root", "proof"):
        partial = {k: v for k, v in body.items() if k != missing}
        assert client.post("/utils/merkle/verify", json=partial).status_code == 422


# --------------------------------------------------------------------------- #
# 与既有流程互不影响
# --------------------------------------------------------------------------- #

def test_proofs_do_not_change_commit_reveal_settlement_flow():
    event_id = create_event()
    text, salt = "明天下雨", "salt-xyz"
    h = commit_hash(text, salt)
    c = submit(event_id, h)

    # 截止前拿不到证明，但提交照常
    r = client.get(f"/events/{event_id}/commitments/merkle")
    assert r.status_code == 409
    assert client.get(f"/events/{event_id}").json()["commitment_count"] == 1

    # reveal 阶段取证明，揭示照常生效
    clock.t = COMMIT_DL
    set_before = merkle_set(event_id)
    p = proof(event_id, c["id"])
    assert verify(verify_body_from_proof(p))["valid"] is True

    r = client.post(f"/events/{event_id}/reveals",
                    json={"original_text": text, "salt": salt})
    assert r.status_code == 201, r.text

    # 揭示后根与证明不变（集合只含承诺）
    assert merkle_set(event_id)["merkle_root"] == set_before["merkle_root"]
    assert proof(event_id, c["id"])["merkle_root"] == set_before["merkle_root"]

    # closed 阶段结算照常
    clock.t = REVEAL_DL
    r = client.post(f"/events/{event_id}/settlement",
                    json={"standard_result": text})
    assert r.status_code == 200, r.text
    assert r.json()["correct_count"] == 1
    # 结算后证明依旧可签发且校验通过
    assert verify(verify_body_from_proof(proof(event_id, c["id"])))["valid"] is True


def test_post_deadline_commit_still_rejected_while_proof_available():
    event_id = create_event()
    clock.t = COMMIT_DL
    # 证明可签发的同时迟到提交依旧被拒
    assert merkle_set(event_id)["commitment_count"] == 0
    r = client.post(
        f"/events/{event_id}/commitments",
        json={"commitment_hash": commit_hash("late", "s")},
    )
    assert r.status_code == 409 and r.json()["detail"]["code"] == "COMMIT_PHASE_CLOSED"
    assert merkle_set(event_id)["commitment_count"] == 0
