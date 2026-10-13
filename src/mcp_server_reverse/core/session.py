"""BinarySession 领域模型与 LRU 会话缓存池

@author Ateng
@since 2026-10-13
"""

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def generate_session_id(file_sha256: str, target_arch: str | None = None) -> str:
    """生成唯一的 12 位 session_id

    单架构二进制取文件 SHA-256 前 12 位；
    Fat Mach-O 多架构通用二进制取复合哈希 sha256(f"{file_sha256}:{target_arch}") 的前 12 位。

    @param file_sha256 目标文件的完整 SHA-256 十六进制字符串
    @param target_arch 可选的目标切片架构名称 (如 arm64, x86_64)
    @return str 12 位的唯一 session_id
    """
    if not target_arch:
        return file_sha256[:12].lower()

    composite = f"{file_sha256.lower()}:{target_arch.lower()}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()[:12].lower()


@dataclass
class BinarySession:
    """二进制分析内存会话上下文对象

    @author Ateng
    @since 2026-10-13
    @param session_id 唯一 12 位哈希标识
    @param file_path 宿主机上的物理绝对路径
    @param file_sha256 物理文件 SHA-256
    @param file_size 文件字节体积
    @param format 二进制文件格式 (PE / ELF / Mach-O)
    @param arch 目标 CPU 架构 (x86_64 / arm64 等)
    @param bits 指针位宽 (32 / 64)
    @param endianness 字节端序 (little / big)
    @param entry_point 入口点虚拟地址数值
    @param image_base 镜像基址数值
    @param target_arch Fat 切片指定的架构名 (若有)
    @param created_at 会话创建时间戳
    @param last_accessed_at 最后访问时间戳
    @param file_info 完整文件基础信息与哈希字典
    @param format_info 格式与安全防护特性字典
    @param triage_overview 全景逆向分诊概览字典
    @param forensic_metadata 纵深取证元数据字典
    @param lief_binary 内存中驻留的 LIEF 二进制对象实例
    @param pefile_binary 内存中驻留的 pefile 实例 (仅 PE)
    """

    session_id: str
    file_path: Path
    file_sha256: str
    file_size: int
    format: str
    arch: str
    bits: int = 64
    endianness: str = "little"
    entry_point: int = 0
    image_base: int = 0
    target_arch: str | None = None
    created_at: float = field(default_factory=time.time)
    last_accessed_at: float = field(default_factory=time.time)
    file_info: dict[str, Any] = field(default_factory=dict)
    format_info: dict[str, Any] = field(default_factory=dict)
    triage_overview: dict[str, Any] = field(default_factory=dict)
    forensic_metadata: dict[str, Any] = field(default_factory=dict)
    lief_binary: Any = None
    pefile_binary: Any = None
    strings_cache: Any = None
    _xref_index: Any = None

    def touch(self) -> None:
        """更新最后访问时间戳"""
        self.last_accessed_at = time.time()

    def to_full_data_dict(self) -> dict[str, Any]:
        """导出用于 open_binary 响应的完整数据载荷字典"""
        return {
            "session_id": self.session_id,
            "file_info": self.file_info,
            "format_info": self.format_info,
            "triage_overview": self.triage_overview,
            "forensic_metadata": self.forensic_metadata,
        }

    def to_summary_dict(self) -> dict[str, Any]:
        """导出用于 list_sessions 的会话摘要字典"""
        return {
            "session_id": self.session_id,
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "target_arch": self.target_arch,
            "created_at": self.created_at,
            "last_accessed_at": self.last_accessed_at,
        }


class SessionStore:
    """基于 OrderedDict 的线程安全进程内 LRU 会话缓存池

    @author Ateng
    @since 2026-10-13
    """

    def __init__(self, max_sessions: int = 8) -> None:
        self._max_sessions = max_sessions
        self._store: OrderedDict[str, BinarySession] = OrderedDict()
        self._lock = threading.RLock()

    def put(self, session: BinarySession) -> tuple[BinarySession, BinarySession | None]:
        """将新会话存入缓存池，若已达上限则淘汰最久未访问的会话

        @param session 待存入的 BinarySession 实例
        @return tuple[BinarySession, BinarySession | None] (存入的会话, 被淘汰驱逐的旧会话)
        """
        with self._lock:
            evicted: BinarySession | None = None
            if session.session_id in self._store:
                self._store.move_to_end(session.session_id)
            else:
                if len(self._store) >= self._max_sessions:
                    # 弹出头部最老项 (FIFO / LRU)
                    _, evicted = self._store.popitem(last=False)

            session.touch()
            self._store[session.session_id] = session
            return session, evicted

    def get(self, session_id: str) -> BinarySession | None:
        """根据 session_id 获取会话，并将其刷新至 LRU 活跃末尾

        @param session_id 目标会话 ID
        @return BinarySession | None 目标会话实例，未命中返回 None
        """
        with self._lock:
            session = self._store.get(session_id)
            if session is not None:
                session.touch()
                self._store.move_to_end(session_id)
            return session

    def exists(self, session_id: str) -> bool:
        """检查指定会话是否存在于内存池中

        @param session_id 目标会话 ID
        @return bool 是否存在
        """
        with self._lock:
            return session_id in self._store

    def close_session(self, session_id: str | None = None) -> tuple[int, int]:
        """关闭指定会话或清空全部会话

        @param session_id 待关闭的 session_id，为 None 时关闭全部
        @return tuple[int, int] (已关闭的会话数量, 剩余驻留的会话数量)
        """
        with self._lock:
            if session_id is None:
                count = len(self._store)
                self._store.clear()
                return count, 0

            if session_id in self._store:
                del self._store[session_id]
                return 1, len(self._store)

            return 0, len(self._store)

    def list_sessions(self) -> list[dict[str, Any]]:
        """获取所有当前驻留会话的摘要列表

        @return list[dict[str, Any]] 会话摘要列表，无数据返回空列表
        """
        with self._lock:
            return [sess.to_summary_dict() for sess in self._store.values()]
