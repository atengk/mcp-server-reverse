"""跨格式 (PE / ELF / Mach-O) 二进制取证与全景逆向解析内核

@author Ateng
@since 2026-10-13
"""

import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief
import pefile

from mcp_server_reverse.core.forensic import (
    compute_fuzzy_hash,
    extract_macho_code_signing_and_entitlements,
    extract_rich_header_entries,
)
from mcp_server_reverse.core.models import ForensicMetadata

logger = logging.getLogger(__name__)

# 8 类敏感行为 API 匹配关键词表
SENSITIVE_API_KEYWORDS: dict[str, list[str]] = {
    "process_injection": [
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "setthreadcontext",
        "queueuserapc",
        "ntwritevirtualmemory",
        "ptrace",
    ],
    "anti_debug": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "outputdebugstring",
        "ntqueryinformationprocess",
        "findwindow",
    ],
    "crypto": [
        "cryptacquirecontext",
        "cryptencrypt",
        "cryptdecrypt",
        "bcryptencrypt",
        "aes_",
        "sha256_",
        "md5_",
    ],
    "network": [
        "wsastartup",
        "socket",
        "connect",
        "send",
        "recv",
        "internetopen",
        "httpopenrequest",
        "urldownloadtofile",
    ],
    "dynamic_load": [
        "loadlibrary",
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryex",
        "getprocaddress",
        "dlopen",
        "dlsym",
    ],
    "execution": [
        "winexec",
        "shellexecute",
        "createprocess",
        "system",
        "execve",
        "popen",
    ],
    "filesystem": [
        "createfile",
        "writefile",
        "deletefile",
        "remove",
        "unlink",
        "copyfile",
    ],
    "registry": [
        "regopenkey",
        "regsetvalue",
        "regqueryvalue",
        "regcreatekey",
        "regdeletekey",
    ],
}


def calculate_entropy(data: bytes) -> float:
    """计算字节流的香农熵 (Shannon Entropy)

    @param data 待计算的原始字节序列
    @return float 介于 0.0 至 8.0 之间的香农熵数值
    """
    if not data:
        return 0.0

    length = len(data)
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


@dataclass
class FileHashBundle:
    """物理文件基础数据与特征哈希载荷

    @param raw_bytes 文件全量字节序列
    @param file_size 文件字节体积
    @param md5 MD5 十六进制校验码
    @param sha1 SHA-1 十六进制校验码
    @param sha256 SHA-256 十六进制校验码
    """

    raw_bytes: bytes
    file_size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class ParseResult:
    """二进制解析与数字取证全景结果

    @author Ateng
    @since 2026-10-13
    @param file_info 物理文件哈希与体积元数据
    @param format_info 架构格式与安全缓解措施状态
    @param triage_overview 逆向分诊概览与敏感 API 统计
    @param forensic_metadata 纵深取证特征与 Overlay 附加数据
    @param resolved_arch 实际解析决议出的 CPU 架构
    @param lief_binary 内存中驻留的 LIEF 解析对象
    @param pefile_binary 内存中驻留的 pefile 解析对象 (仅 PE)
    """

    file_info: dict[str, Any] = field(default_factory=dict)
    format_info: dict[str, Any] = field(default_factory=dict)
    triage_overview: dict[str, Any] = field(default_factory=dict)
    forensic_metadata: dict[str, Any] = field(default_factory=dict)
    resolved_arch: str = "x86_64"
    lief_binary: Any = None
    pefile_binary: Any = None


class BinaryParser:
    """跨平台统一二进制取证与解析器

    @author Ateng
    @since 2026-10-13
    """

    def __init__(self) -> None:
        pass

    def parse(self, path: Path, target_arch: str | None = None) -> ParseResult:
        """解析目标二进制并生成全景画像

        @param path 目标可执行文件绝对物理路径
        @param target_arch Fat Mach-O 多架构切片名称
        @return ParseResult 结构化全景解析结果对象
        """
        raw_bytes = path.read_bytes()
        bundle = FileHashBundle(
            raw_bytes=raw_bytes,
            file_size=len(raw_bytes),
            md5=hashlib.md5(raw_bytes).hexdigest(),
            sha1=hashlib.sha1(raw_bytes).hexdigest(),
            sha256=hashlib.sha256(raw_bytes).hexdigest(),
        )

        if raw_bytes.startswith(b"MZ"):
            return self._parse_pe(path, bundle)
        elif raw_bytes.startswith(b"\x7fELF"):
            return self._parse_elf(path, bundle)
        else:
            return self._parse_macho(path, bundle, target_arch)

    def _classify_apis(self, import_names: list[str]) -> dict[str, int]:
        """按 8 大行为维度对导入 API 进行分类统计"""
        categories = {cat: 0 for cat in SENSITIVE_API_KEYWORDS}
        for name in import_names:
            lower_name = name.lower()
            for cat, keywords in SENSITIVE_API_KEYWORDS.items():
                if any(kw in lower_name for kw in keywords):
                    categories[cat] += 1
        return categories

    def _parse_pe(self, path: Path, bundle: FileHashBundle) -> ParseResult:
        """解析 Windows PE 格式二进制"""
        pe_obj: pefile.PE | None = None
        try:
            pe_obj = pefile.PE(data=bundle.raw_bytes)
        except Exception as exc:
            logger.debug("pefile 初始化失败: %s", exc)

        lief_bin = None
        try:
            lief_bin = lief.parse(str(path))
        except Exception as exc:
            logger.debug("lief 初始化解析 PE 失败: %s", exc)

        # Imphash
        imphash_val = None
        if pe_obj:
            try:
                imphash_val = pe_obj.get_imphash()
            except Exception as exc:
                logger.debug("计算 imphash 异常: %s", exc)

        file_info: dict[str, Any] = {
            "file_name": path.name,
            "size_bytes": bundle.file_size,
            "md5": bundle.md5,
            "sha1": bundle.sha1,
            "sha256": bundle.sha256,
            "imphash": imphash_val,
        }

        is_pie = False
        has_nx = False
        entry_point = 0
        image_base = 0
        is_64 = True

        if lief_bin:
            entry_point = lief_bin.entrypoint
            image_base = lief_bin.imagebase
            has_nx = getattr(lief_bin, "has_nx", False)
            if hasattr(lief_bin, "optional_header"):
                dll_char = getattr(lief_bin.optional_header, "dll_characteristics", 0)
                is_pie = bool(dll_char & 0x0040)
            if hasattr(lief_bin, "header"):
                is_64 = lief_bin.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64

        # 若 LIEF 未成功解析或关键属性为空，回退到 pefile
        if (not lief_bin or (entry_point == 0 and image_base == 0)) and pe_obj:
            opt = getattr(pe_obj, "OPTIONAL_HEADER", None)
            file_hdr = getattr(pe_obj, "FILE_HEADER", None)
            machine = getattr(file_hdr, "Machine", 0) if file_hdr else 0
            opt_magic = getattr(opt, "Magic", 0) if opt else 0

            # 0x14C: IMAGE_FILE_MACHINE_I386; 0x10B: PE32 (32位)
            if machine == 0x14C or opt_magic == 0x10B:
                is_64 = False
            elif machine == 0x8664 or opt_magic == 0x20B:
                is_64 = True

            if opt:
                image_base = getattr(opt, "ImageBase", 0)
                rva = getattr(opt, "AddressOfEntryPoint", 0)
                entry_point = image_base + rva
                dll_char = getattr(opt, "DllCharacteristics", 0)
                is_pie = bool(dll_char & 0x0040)
                has_nx = bool(dll_char & 0x0100)

        # 探测 .NET CLR 托管程序与元数据 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14)
        is_managed = False
        if (
            pe_obj
            and hasattr(pe_obj, "OPTIONAL_HEADER")
            and hasattr(pe_obj.OPTIONAL_HEADER, "DATA_DIRECTORY")
        ):
            if len(pe_obj.OPTIONAL_HEADER.DATA_DIRECTORY) > 14:
                com_desc = pe_obj.OPTIONAL_HEADER.DATA_DIRECTORY[14]
                va = getattr(com_desc, "VirtualAddress", 0)
                sz = getattr(com_desc, "Size", 0)
                is_managed = bool(va != 0 and sz != 0)
        elif lief_bin and hasattr(lief_bin, "data_directory"):
            try:
                clr_dir = lief_bin.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER)
                is_managed = bool(clr_dir and clr_dir.rva != 0 and clr_dir.size != 0)
            except Exception:
                pass

        clr_runtime_version: str | None = None
        if is_managed:
            # 尝试通过 ECMA-335 BSJB 签名提取 CLR 运行时版本 (如 v4.0.30319)
            bsjb_idx = bundle.raw_bytes.find(b"BSJB")
            if bsjb_idx != -1 and len(bundle.raw_bytes) >= bsjb_idx + 20:
                import struct

                v_len = struct.unpack_from("<I", bundle.raw_bytes, bsjb_idx + 12)[0]
                if 0 < v_len <= 32 and len(bundle.raw_bytes) >= bsjb_idx + 16 + v_len:
                    raw_v = bundle.raw_bytes[bsjb_idx + 16 : bsjb_idx + 16 + v_len]
                    clr_runtime_version = raw_v.rstrip(b"\x00").decode("ascii", errors="ignore")
            if not clr_runtime_version:
                m = re.search(rb"v[1-4]\.[0-9]+\.[0-9]+", bundle.raw_bytes)
                if m:
                    clr_runtime_version = m.group(0).decode("ascii", errors="ignore")

        resolved_arch = "x86_64" if is_64 else "i386"
        format_info: dict[str, Any] = {
            "format": "PE",
            "arch": resolved_arch,
            "available_architectures": [resolved_arch],
            "bits": 64 if is_64 else 32,
            "endianness": "little",
            "entry_point": f"0x{entry_point:X}",
            "image_base": f"0x{image_base:X}",
            "is_pie": is_pie,
            "has_nx": has_nx,
            "has_canary": False,
            "is_stripped": True,
            "is_managed": is_managed,
            "runtime": ".NET CLR" if is_managed else "Native",
            "clr_runtime_version": clr_runtime_version,
        }

        # 节区熵与高熵列表
        high_entropy_sections: list[str] = []
        sections_count = 0
        if lief_bin and hasattr(lief_bin, "sections") and len(lief_bin.sections) > 0:
            sections_count = len(lief_bin.sections)
            for sec in lief_bin.sections:
                ent = getattr(sec, "entropy", 0.0)
                if ent > 7.0:
                    high_entropy_sections.append(sec.name)
        elif pe_obj and hasattr(pe_obj, "sections"):
            sections_count = len(pe_obj.sections)
            for sec in pe_obj.sections:
                raw_name = getattr(sec, "Name", b"")
                sec_name = (
                    raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                    if isinstance(raw_name, bytes)
                    else str(raw_name)
                )
                try:
                    ent = sec.get_entropy()
                    if ent > 7.0:
                        high_entropy_sections.append(sec_name)
                except Exception:
                    pass

        # 收集导入 API
        import_names: list[str] = []
        needed_libraries: list[str] = []
        if lief_bin and hasattr(lief_bin, "imports") and len(lief_bin.imports) > 0:
            for imp in lief_bin.imports:
                needed_libraries.append(imp.name)
                for entry in imp.entries:
                    if entry.name:
                        import_names.append(entry.name)
        elif pe_obj and hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                raw_dll = getattr(entry, "dll", b"")
                dll_name = (
                    raw_dll.decode("utf-8", errors="ignore")
                    if isinstance(raw_dll, bytes)
                    else str(raw_dll)
                )
                if dll_name:
                    needed_libraries.append(dll_name)
                for imp in getattr(entry, "imports", []):
                    raw_imp_name = imp.name
                    if raw_imp_name and isinstance(raw_imp_name, bytes):
                        import_names.append(raw_imp_name.decode("utf-8", errors="ignore"))
                    elif getattr(imp, "ordinal", None) is not None:
                        import_names.append(f"Ordinal_{imp.ordinal}")

        sensitive_cats = self._classify_apis(import_names)

        exports_count = 0
        if lief_bin and hasattr(lief_bin, "exported_functions"):
            exports_count = len(lief_bin.exported_functions)
        elif pe_obj and hasattr(pe_obj, "DIRECTORY_ENTRY_EXPORT"):
            exports_count = len(getattr(pe_obj.DIRECTORY_ENTRY_EXPORT, "symbols", []))

        clr_guidance = (
            (
                "目标文件为 .NET 托管程序 (CIL 字节码)，原生反汇编仅包含引导桩代码。"
                "推荐优先使用 ILSpy、dnSpy 或 python-net-decompiler 等专用 .NET "
                "反编译工具获取高可读性 C# 源码。"
            )
            if is_managed
            else None
        )

        triage_overview: dict[str, Any] = {
            "sections_count": sections_count,
            "high_entropy_sections": high_entropy_sections,
            "imports_count": len(import_names),
            "exports_count": exports_count,
            "sensitive_api_categories": sensitive_cats,
            "packing_hint": "高熵节区检出，疑似存在加密或压缩壳" if high_entropy_sections else None,
            "is_managed": is_managed,
            "runtime": ".NET CLR" if is_managed else "Native",
            "clr_runtime_version": clr_runtime_version,
            "clr_guidance": clr_guidance,
        }

        # Overlay 提取
        overlay_info: dict[str, Any] | None = None
        if pe_obj:
            overlay_offset = pe_obj.get_overlay_data_start_offset()
            if overlay_offset is not None and overlay_offset < bundle.file_size:
                overlay_bytes = bundle.raw_bytes[overlay_offset:]
                overlay_info = {
                    "offset": overlay_offset,
                    "size": len(overlay_bytes),
                    "entropy": calculate_entropy(overlay_bytes),
                }

        # TLS 回调
        tls_callbacks: list[str] = []
        if pe_obj and hasattr(pe_obj, "DIRECTORY_ENTRY_TLS"):
            tls_struct = getattr(pe_obj.DIRECTORY_ENTRY_TLS, "struct", None)
            if tls_struct and hasattr(tls_struct, "AddressOfCallBacks"):
                tls_callbacks.append(f"0x{tls_struct.AddressOfCallBacks:X}")

        # PDB 路径提取
        pdb_path: str | None = None
        if pe_obj and hasattr(pe_obj, "DIRECTORY_ENTRY_DEBUG"):
            for debug_entry in pe_obj.DIRECTORY_ENTRY_DEBUG:
                entry_data = getattr(debug_entry, "entry", None)
                if entry_data and hasattr(entry_data, "PdbFileName"):
                    raw_pdb = entry_data.PdbFileName
                    if isinstance(raw_pdb, bytes):
                        pdb_path = raw_pdb.rstrip(b"\x00").decode("utf-8", errors="ignore")

        # Rich Header 哈希提取
        rich_header_hash: str | None = None
        if pe_obj and hasattr(pe_obj, "RICH_HEADER"):
            try:
                rich_header_hash = pe_obj.get_rich_header_hash()
            except Exception as exc:
                logger.debug("提取 Rich Header 哈希失败: %s", exc)

        timestamp = pe_obj.FILE_HEADER.TimeDateStamp if pe_obj else None
        debug_info: dict[str, Any] = {
            "pdb_path": pdb_path,
            "timestamp": timestamp,
            "rich_header_hash": rich_header_hash,
        }

        rich_entries = extract_rich_header_entries(pe_obj)
        fuzzy_hash = compute_fuzzy_hash(bundle.raw_bytes)

        forensic = ForensicMetadata(
            tls_callbacks=tls_callbacks,
            debug_info=debug_info,
            overlay=overlay_info,
            code_signing={"is_signed": False},
            needed_libraries=needed_libraries,
            rich_header_entries=rich_entries,
            fuzzy_hash=fuzzy_hash,
            entitlements={},
        )
        forensic_metadata = forensic.to_dict()

        return ParseResult(
            file_info=file_info,
            format_info=format_info,
            triage_overview=triage_overview,
            forensic_metadata=forensic_metadata,
            resolved_arch=resolved_arch,
            lief_binary=lief_bin,
            pefile_binary=pe_obj,
        )

    def _parse_elf(self, path: Path, bundle: FileHashBundle) -> ParseResult:
        """解析 Linux ELF 格式二进制"""
        lief_bin = lief.parse(str(path))

        file_info: dict[str, Any] = {
            "file_name": path.name,
            "size_bytes": bundle.file_size,
            "md5": bundle.md5,
            "sha1": bundle.sha1,
            "sha256": bundle.sha256,
            "imphash": None,
        }

        entry_point = lief_bin.entrypoint if lief_bin else 0
        image_base = lief_bin.imagebase if lief_bin else 0
        is_64 = (
            lief_bin.header.identity_class == lief.ELF.Header.CLASS.ELF64
            if (lief_bin and hasattr(lief_bin, "header"))
            else True
        )

        resolved_arch = "x86_64" if is_64 else "i386"
        format_info: dict[str, Any] = {
            "format": "ELF",
            "arch": resolved_arch,
            "available_architectures": [resolved_arch],
            "bits": 64 if is_64 else 32,
            "endianness": "little",
            "entry_point": f"0x{entry_point:X}",
            "image_base": f"0x{image_base:X}",
            "is_pie": False,
            "has_nx": getattr(lief_bin, "has_nx", False) if lief_bin else False,
            "has_canary": getattr(lief_bin, "has_canary", False) if lief_bin else False,
            "is_stripped": True,
            "is_managed": False,
            "runtime": "Native",
            "clr_runtime_version": None,
        }

        high_entropy_sections: list[str] = []
        sections_count = (
            len(lief_bin.sections) if (lief_bin and hasattr(lief_bin, "sections")) else 0
        )
        if lief_bin and hasattr(lief_bin, "sections"):
            for sec in lief_bin.sections:
                if getattr(sec, "entropy", 0.0) > 7.0:
                    high_entropy_sections.append(sec.name)

        needed_libraries = list(getattr(lief_bin, "libraries", [])) if lief_bin else []

        triage_overview: dict[str, Any] = {
            "sections_count": sections_count,
            "high_entropy_sections": high_entropy_sections,
            "imports_count": 0,
            "exports_count": 0,
            "sensitive_api_categories": {cat: 0 for cat in SENSITIVE_API_KEYWORDS},
            "packing_hint": None,
            "is_managed": False,
            "runtime": "Native",
            "clr_runtime_version": None,
            "clr_guidance": None,
        }

        fuzzy_hash = compute_fuzzy_hash(bundle.raw_bytes)
        forensic = ForensicMetadata(
            tls_callbacks=[],
            debug_info={"pdb_path": None, "timestamp": None, "rich_header_hash": None},
            overlay=None,
            code_signing={"is_signed": False},
            needed_libraries=needed_libraries,
            rich_header_entries=[],
            fuzzy_hash=fuzzy_hash,
            entitlements={},
        )
        forensic_metadata = forensic.to_dict()

        return ParseResult(
            file_info=file_info,
            format_info=format_info,
            triage_overview=triage_overview,
            forensic_metadata=forensic_metadata,
            resolved_arch=resolved_arch,
            lief_binary=lief_bin,
            pefile_binary=None,
        )

    def _parse_macho(
        self,
        path: Path,
        bundle: FileHashBundle,
        target_arch: str | None = None,
    ) -> ParseResult:
        """解析 macOS Mach-O 格式二进制 (支持 Fat 通用二进制切片决议)"""
        fat_bin = None
        available_archs: list[str] = []
        arch_map: dict[str, Any] = {}
        try:
            fat_bin = lief.MachO.parse(str(path))
            if fat_bin:
                for b in fat_bin:
                    cpu_type = str(b.header.cpu_type).lower()
                    if "arm64" in cpu_type or "aarch64" in cpu_type:
                        arch_name = "arm64"
                    elif "x86_64" in cpu_type:
                        arch_name = "x86_64"
                    else:
                        arch_name = cpu_type
                    available_archs.append(arch_name)
                    if arch_name not in arch_map:
                        arch_map[arch_name] = b
        except Exception as exc:
            logger.debug("解析 MachO 异常: %s", exc)

        if not available_archs:
            available_archs = ["arm64"]

        # 决议目标架构：显式入参 > arm64 > x86_64 > 第 0 个切片
        resolved_arch = target_arch
        if not resolved_arch or resolved_arch not in available_archs:
            if "arm64" in available_archs:
                resolved_arch = "arm64"
            elif "x86_64" in available_archs:
                resolved_arch = "x86_64"
            else:
                resolved_arch = available_archs[0]

        target_bin = arch_map.get(resolved_arch)
        if target_bin is None and fat_bin and len(fat_bin) > 0:
            target_bin = fat_bin[0]

        file_info: dict[str, Any] = {
            "file_name": path.name,
            "size_bytes": bundle.file_size,
            "md5": bundle.md5,
            "sha1": bundle.sha1,
            "sha256": bundle.sha256,
            "imphash": None,
        }

        format_info: dict[str, Any] = {
            "format": "Mach-O",
            "arch": resolved_arch,
            "available_architectures": available_archs,
            "bits": 64,
            "endianness": "little",
            "entry_point": "0x100000000",
            "image_base": "0x100000000",
            "is_pie": True,
            "has_nx": True,
            "has_canary": False,
            "is_stripped": True,
            "is_managed": False,
            "runtime": "Native",
            "clr_runtime_version": None,
        }

        triage_overview: dict[str, Any] = {
            "sections_count": 0,
            "high_entropy_sections": [],
            "imports_count": 0,
            "exports_count": 0,
            "sensitive_api_categories": {cat: 0 for cat in SENSITIVE_API_KEYWORDS},
            "packing_hint": None,
            "is_managed": False,
            "runtime": "Native",
            "clr_runtime_version": None,
            "clr_guidance": None,
        }

        code_signing, entitlements = extract_macho_code_signing_and_entitlements(
            target_bin, bundle.raw_bytes
        )
        fuzzy_hash = compute_fuzzy_hash(bundle.raw_bytes)

        forensic = ForensicMetadata(
            tls_callbacks=[],
            debug_info={"pdb_path": None, "timestamp": None, "rich_header_hash": None},
            overlay=None,
            code_signing=code_signing,
            needed_libraries=[],
            rich_header_entries=[],
            fuzzy_hash=fuzzy_hash,
            entitlements=entitlements,
        )
        forensic_metadata = forensic.to_dict()

        return ParseResult(
            file_info=file_info,
            format_info=format_info,
            triage_overview=triage_overview,
            forensic_metadata=forensic_metadata,
            resolved_arch=resolved_arch,
            lief_binary=fat_bin,
            pefile_binary=None,
        )
