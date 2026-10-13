"""BinarySession 领域模型与 LRU 会话池测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

from mcp_server_reverse.core.session import (
    BinarySession,
    SessionStore,
    generate_session_id,
)


def test_generate_session_id() -> None:
    file_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    # 单架构会话 ID 为前 12 位
    sid_single = generate_session_id(file_sha256)
    assert sid_single == "e3b0c44298fc"
    assert len(sid_single) == 12

    # 多架构 Fat 切片复合 ID
    sid_arm64 = generate_session_id(file_sha256, target_arch="arm64")
    sid_x86 = generate_session_id(file_sha256, target_arch="x86_64")
    assert sid_arm64 != sid_x86
    assert len(sid_arm64) == 12
    assert len(sid_x86) == 12


def test_session_store_lru_eviction(tmp_path: Path) -> None:
    store = SessionStore(max_sessions=3)

    # 依次存入 3 个会话
    sessions = []
    for i in range(3):
        sess = BinarySession(
            session_id=f"sess_{i:04d}",
            file_path=tmp_path / f"bin_{i}.exe",
            file_sha256=f"hash_{i}",
            file_size=1024,
            format="PE",
            arch="x86_64",
        )
        sessions.append(sess)
        store.put(sess)

    assert len(store.list_sessions()) == 3

    # 访问最老的 sess_0000，使其变活跃
    active = store.get("sess_0000")
    assert active is not None

    # 存入第 4 个会话，此时应该淘汰未被访问的 sess_0001
    new_sess = BinarySession(
        session_id="sess_0003",
        file_path=tmp_path / "bin_3.exe",
        file_sha256="hash_3",
        file_size=1024,
        format="PE",
        arch="x86_64",
    )
    _, evicted = store.put(new_sess)
    assert evicted is not None
    assert evicted.session_id == "sess_0001"

    # 校验当前驻留的 3 个会话
    current_ids = [s["session_id"] for s in store.list_sessions()]
    assert "sess_0000" in current_ids
    assert "sess_0002" in current_ids
    assert "sess_0003" in current_ids
    assert "sess_0001" not in current_ids


def test_session_store_close_operations(tmp_path: Path) -> None:
    store = SessionStore(max_sessions=5)
    for i in range(3):
        store.put(
            BinarySession(
                session_id=f"sid_{i}",
                file_path=tmp_path / f"bin_{i}.exe",
                file_sha256=f"hash_{i}",
                file_size=512,
                format="ELF",
                arch="x86_64",
            )
        )

    # 关闭指定单会话
    closed_cnt, remaining_cnt = store.close_session("sid_1")
    assert closed_cnt == 1
    assert remaining_cnt == 2
    assert store.get("sid_1") is None

    # 清空所有会话
    closed_all, remaining_all = store.close_session(None)
    assert closed_all == 2
    assert remaining_all == 0
    assert len(store.list_sessions()) == 0
