"""函数控制流图 (CFG) 抽取、基本块分析与 Mermaid 可视化 MCP 工具端到端测试套件

@author Ateng
@since 2026-10-14
"""

from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.cfg import analyze_cfg_impl
from mcp_server_reverse.tools.patch import patch_memory_impl
from mcp_server_reverse.tools.session import open_binary_impl
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def active_store_and_sid(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    pe_file = tmp_path / "target_cfg_tools.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    return store, resp["session_id"], pe_file


def test_analyze_cfg_basic_blocks_and_mermaid(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 对入口点执行控制流分析
    resp = analyze_cfg_impl(
        session_id=sid,
        target="0x140001000",
        max_blocks=50,
        session_store=store,
    )
    assert resp["ok"] is True
    data = resp["data"]

    assert data["entry_point"] == "0x140001000"
    assert data["block_count"] >= 1
    assert data["cyclomatic_complexity"] >= 1
    assert len(data["blocks"]) == data["block_count"]

    # 2. 校验首个基本块结构
    first_block = data["blocks"][0]
    assert first_block["block_id"] == "bb_0"
    assert first_block["start_address"] == "0x140001000"
    assert first_block["instruction_count"] >= 1
    assert len(first_block["instructions"]) == first_block["instruction_count"]

    # 3. 校验原生 Mermaid 流程图输出
    mermaid = data["mermaid_diagram"]
    assert "flowchart TD" in mermaid
    assert "bb_0" in mermaid


def test_analyze_cfg_with_cow_virtual_patch(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 初始分析
    resp_before = analyze_cfg_impl(
        session_id=sid,
        target="0x140001000",
        max_blocks=50,
        session_store=store,
    )
    assert resp_before["ok"] is True

    # 2. 在入口点打入 ret 补丁 (C3)，截断后续执行流
    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="C3",
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 3. 再次执行 CFG 分析，应当即时感知打了补丁后的控制流截断
    resp_after = analyze_cfg_impl(
        session_id=sid,
        target="0x140001000",
        max_blocks=50,
        session_store=store,
    )
    assert resp_after["ok"] is True
    blocks_after = resp_after["data"]["blocks"]
    assert len(blocks_after) == 1
    assert blocks_after[0]["instruction_count"] == 1
    assert blocks_after[0]["terminator_mnemonic"] == "ret"
    assert blocks_after[0]["successors"] == []


def test_analyze_cfg_errors_and_validation(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 无效 session_id
    err_sid = analyze_cfg_impl(
        session_id="non_exist_sid",
        target="0x140001000",
        session_store=store,
    )
    assert err_sid["ok"] is False
    assert err_sid["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value

    # 2. 目标符号或地址不存在
    err_addr = analyze_cfg_impl(
        session_id=sid,
        target="0xFFFFFFFFFF",
        session_store=store,
    )
    assert err_addr["ok"] is False
    assert err_addr["error"]["code"] == ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND.value

    # 3. max_blocks 非法
    err_blocks = analyze_cfg_impl(
        session_id=sid,
        target="0x140001000",
        max_blocks=0,
        session_store=store,
    )
    assert err_blocks["ok"] is False
    assert err_blocks["error"]["code"] == ErrorCode.INVALID_PARAMETER.value


def test_analyze_cfg_conditional_branching(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 在入口点注入包含真实 JZ 和 JMP 的分支序列:
    # 0x140001000: 85 C9 (test ecx, ecx)
    # 0x140001002: 74 04 (jz +4 -> 0x140001008)
    # 0x140001004: EB 02 (jmp +2 -> 0x140001008)
    # 0x140001006: 90 90 (nop nop)
    # 0x140001008: C3 (ret)
    patch_hex = "85 C9 74 04 EB 02 90 90 C3"
    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex=patch_hex,
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 2. 执行 CFG 抽取
    resp = analyze_cfg_impl(
        session_id=sid,
        target="0x140001000",
        session_store=store,
    )
    assert resp["ok"] is True
    data = resp["data"]
    assert data["block_count"] >= 3

    # 3. 首块应当具有 true_branch 和 false_branch
    bb0 = data["blocks"][0]
    assert bb0["block_id"] == "bb_0"
    assert bb0["terminator_mnemonic"] in ("jz", "je")
    branch_types = {s["branch_type"] for s in bb0["successors"]}
    assert "true_branch" in branch_types
    assert "false_branch" in branch_types

    # 4. 校验 Mermaid 流程图包含分支标签
    mermaid = data["mermaid_diagram"]
    assert f'|"true ({bb0["terminator_mnemonic"]})"|' in mermaid
    assert '|"false"|' in mermaid


def test_analyze_cfg_by_symbol_name(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 使用自动恢复的 .pdata 函数符号名进行 CFG 分析
    resp = analyze_cfg_impl(
        session_id=sid,
        target="sub_140001000",
        session_store=store,
    )
    assert resp["ok"] is True
    assert resp["data"]["entry_point"] == "0x140001000"
    assert resp["data"]["block_count"] >= 1


def test_analyze_cfg_branch_inversion_patch(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 注入 JZ 条件分支序列: 85 C9 74 04 EB 02 90 90 C3
    patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="85 C9 74 04 EB 02 90 90 C3",
        address_type="va",
        session_store=store,
    )
    resp_jz = analyze_cfg_impl(session_id=sid, target="0x140001000", session_store=store)
    assert resp_jz["ok"] is True
    assert resp_jz["data"]["blocks"][0]["terminator_mnemonic"] in ("jz", "je")

    # 2. 动态打入补丁将 JZ (0x74) 颠倒为 JNZ (0x75)
    patch_invert = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001002",
        patch_hex="75",
        address_type="va",
        session_store=store,
    )
    assert patch_invert["ok"] is True

    # 3. 再次分析，控制流终结指令即时翻转为 jnz / jne
    resp_jnz = analyze_cfg_impl(session_id=sid, target="0x140001000", session_store=store)
    assert resp_jnz["ok"] is True
    assert resp_jnz["data"]["blocks"][0]["terminator_mnemonic"] in ("jnz", "jne")
    assert (
        '|"true (jnz)"|' in resp_jnz["data"]["mermaid_diagram"]
        or '|"true (jne)"|' in resp_jnz["data"]["mermaid_diagram"]
    )


def test_analyze_cfg_nested_and_backward_loop(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 注入真实回跳循环与嵌套分支机器码:
    # 0x140001000: B9 0A 00 00 00 (mov ecx, 10)
    # 0x140001005: FF C9 (dec ecx)
    # 0x140001007: 75 FC (jnz -4 -> 0x140001005 回跳循环)
    # 0x140001009: 83 F9 00 (cmp ecx, 0)
    # 0x14000100C: 74 02 (jz +2 -> 0x140001010)
    # 0x14000100E: 90 90 (nop nop)
    # 0x140001010: C3 (ret)
    code_hex = "B9 0A 00 00 00 FF C9 75 FC 83 F9 00 74 02 90 90 C3"
    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex=code_hex,
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 分析控制流图
    resp = analyze_cfg_impl(session_id=sid, target="0x140001000", session_store=store)
    assert resp["ok"] is True
    data = resp["data"]

    # 至少应识别出回跳目标、循环头和嵌套跳转
    assert data["block_count"] >= 3
    assert data["cyclomatic_complexity"] >= 2

    # 寻找包含回跳目标 0x140001005 的分支边
    loop_back_found = False
    for b in data["blocks"]:
        for succ in b["successors"]:
            if succ["target_address"] == "0x140001005" and succ["branch_type"] == "true_branch":
                loop_back_found = True
                break
    assert loop_back_found is True
