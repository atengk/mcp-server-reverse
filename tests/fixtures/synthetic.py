"""合成合法最小 PE64 与 ELF64 二进制测试夹具生成器

@author Ateng
@since 2026-10-13
"""

import struct
from pathlib import Path

# 标准 AES S-Box 256 字节常量表
AES_SBOX = bytes(
    [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5E,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]
)


def build_synthetic_pe64(output_path: Path) -> Path:
    """动态合成最小合法的 64 位 PE64 (.exe) 文件并落盘

    包含：
    - .text 代码节区：包含真实 x86_64 相对寻址指令 (lea rcx, [rip + disp])、call、ret、int3
    - 导入表：包含 KERNEL32.dll (VirtualAllocEx) 与 WS2_32.dll (WSAStartup)
    - 导出表：包含 reverse_test_entry
    - 异常目录 (.pdata)：包含运行时函数条目
    - .rdata 数据载荷：包含测试 URL、IPv4、UTF-16LE 宽字符与 AES S-Box 256 字节表
    - 文件尾部 Overlay 附加数据

    @param output_path 目标输出物理文件路径
    @return Path 成功落盘的文件路径
    """
    # 1. DOS Header (0x80 字节)
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew = 0x80

    # 2. PE 签名与 File Header (24 字节)
    pe_sig = b"PE\x00\x00"
    file_header = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)

    # 3. Optional Header (PE32+, 240 字节)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # Magic = PE32+ (64-bit)
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint (.text 起始)
    struct.pack_into("<Q", opt_header, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 2)  # Subsystem = WINDOWS_GUI
    struct.pack_into("<H", opt_header, 70, 0x0140)  # DYNAMIC_BASE | NX_COMPAT
    struct.pack_into("<I", opt_header, 108, 16)  # NumberOfRvaAndSizes

    # 配置 DataDirectory (从偏移 112 开始，每个 8 字节)
    # DataDirectory[0] (Export): RVA 0x2000, Size 0x80
    struct.pack_into("<II", opt_header, 112, 0x2000, 0x80)
    # DataDirectory[1] (Import): RVA 0x2100, Size 60
    struct.pack_into("<II", opt_header, 120, 0x2100, 60)
    # DataDirectory[3] (Exception): RVA 0x2200, Size 12
    struct.pack_into("<II", opt_header, 136, 0x2200, 12)

    # 4. Section Headers (每个 40 字节)
    # 4.1 .text 节区 (VA 0x1000, Raw 0x200, Offset 0x200)
    sec_text = bytearray(40)
    sec_text[0:5] = b".text"
    struct.pack_into("<I", sec_text, 8, 0x200)
    struct.pack_into("<I", sec_text, 12, 0x1000)
    struct.pack_into("<I", sec_text, 16, 0x200)
    struct.pack_into("<I", sec_text, 20, 0x200)
    struct.pack_into("<I", sec_text, 36, 0x60000020)  # CODE | EXECUTE | READ

    # 4.2 .rdata 节区 (VA 0x2000, Raw 0x800, Offset 0x400)
    sec_rdata = bytearray(40)
    sec_rdata[0:6] = b".rdata"
    struct.pack_into("<I", sec_rdata, 8, 0x800)
    struct.pack_into("<I", sec_rdata, 12, 0x2000)
    struct.pack_into("<I", sec_rdata, 16, 0x800)
    struct.pack_into("<I", sec_rdata, 20, 0x400)
    struct.pack_into("<I", sec_rdata, 36, 0x40000040)  # INITIALIZED_DATA | READ

    headers = bytes(dos_header + pe_sig + file_header + opt_header + sec_text + sec_rdata)
    headers += b"\x00" * (0x200 - len(headers))

    # 5. .text 机器指令序列 (0x200 字节)
    # 0x140001000: lea rcx, [rip + 0x1249] -> 0x140002250 (指向 .rdata URL)
    code_bytes = b"\x48\x8d\x0d\x49\x12\x00\x00\xe8\x00\x00\x00\x00\x31\xc0\xc3\xcc"
    text_section = code_bytes + b"\x90" * (0x200 - len(code_bytes))

    # 6. .rdata 数据结构与载荷 (0x800 字节)
    rdata_buf = bytearray(0x800)

    # 6.1 导出表 (RVA 0x2000, 相对偏移 0)
    struct.pack_into(
        "<IIIIIIIIII",
        rdata_buf,
        0,
        0,
        0,
        0,
        0x2050,
        1,
        1,
        1,
        0x2030,
        0x2034,
        0x2038,
    )
    struct.pack_into("<I", rdata_buf, 0x30, 0x1000)  # Function RVA (entry)
    struct.pack_into("<I", rdata_buf, 0x34, 0x2060)  # Name Pointer RVA
    struct.pack_into("<H", rdata_buf, 0x38, 0)  # Ordinal
    rdata_buf[0x50 : 0x50 + 14] = b"synthetic.dll\x00"
    rdata_buf[0x60 : 0x60 + 19] = b"reverse_test_entry\x00"

    # 6.2 导入表 (RVA 0x2100, 相对偏移 0x100)
    # Descriptor 0: KERNEL32.dll -> VirtualAllocEx
    struct.pack_into("<IIIII", rdata_buf, 0x100, 0x2140, 0, 0, 0x2180, 0x2150)
    # Descriptor 1: WS2_32.dll -> WSAStartup
    struct.pack_into("<IIIII", rdata_buf, 0x114, 0x2160, 0, 0, 0x2190, 0x2170)
    # ILT / IAT (64位 Thunk)
    struct.pack_into("<QQ", rdata_buf, 0x140, 0x21A0, 0)
    struct.pack_into("<QQ", rdata_buf, 0x150, 0x21A0, 0)
    struct.pack_into("<QQ", rdata_buf, 0x160, 0x21C0, 0)
    struct.pack_into("<QQ", rdata_buf, 0x170, 0x21C0, 0)
    # DLL 名称与 Hint/Name
    rdata_buf[0x180 : 0x180 + 13] = b"KERNEL32.dll\x00"
    rdata_buf[0x190 : 0x190 + 11] = b"WS2_32.dll\x00"
    struct.pack_into("<H", rdata_buf, 0x1A0, 0)
    rdata_buf[0x1A2 : 0x1A2 + 15] = b"VirtualAllocEx\x00"
    struct.pack_into("<H", rdata_buf, 0x1C0, 0)
    rdata_buf[0x1C2 : 0x1C2 + 11] = b"WSAStartup\x00"

    # 6.3 异常目录条目 (.pdata, RVA 0x2200, 相对偏移 0x200)
    struct.pack_into("<III", rdata_buf, 0x200, 0x1000, 0x1010, 0x2210)

    # 6.4 字符串与特征常数 (RVA 0x2250 开始)
    url_bytes = b"https://api.example.com/v1/token\x00"
    rdata_buf[0x250 : 0x250 + len(url_bytes)] = url_bytes

    ip_bytes = b"192.168.10.25\x00"
    rdata_buf[0x290 : 0x290 + len(ip_bytes)] = ip_bytes

    reg_bytes = "Software\\ReverseTest\\Config\x00".encode("utf-16le")
    rdata_buf[0x2B0 : 0x2B0 + len(reg_bytes)] = reg_bytes

    rdata_buf[0x300 : 0x300 + 256] = AES_SBOX

    # 7. Overlay 尾部未映射数据
    overlay_data = b"OVERLAY_PAYLOAD_DATA_FOR_FORENSIC_ANALYSIS\x01\x02\x03\x04"

    full_payload = headers + text_section + bytes(rdata_buf) + overlay_data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(full_payload)
    return output_path


def build_synthetic_pe64_large_text(output_path: Path) -> Path:
    """动态合成包含 8KB .text 大节区的 64 位 PE64 (.exe) 文件

    用于节区滑动窗口局部高熵块细粒度探测等专项测试。
    .text 节区尺寸 0x2000 (8192 字节)，初始填充低熵指令与 NOP 序列，整体平均熵值 < 3.0。

    @param output_path 目标输出物理文件路径
    @return Path 成功落盘的文件路径
    """
    # 1. DOS Header (0x80 字节)
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew = 0x80

    # 2. PE 签名与 File Header (24 字节)
    pe_sig = b"PE\x00\x00"
    file_header = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x0022)

    # 3. Optional Header (PE32+, 240 字节)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # Magic = PE32+ (64-bit)
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint (.text 起始)
    struct.pack_into("<Q", opt_header, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x5000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 2)  # Subsystem = WINDOWS_GUI
    struct.pack_into("<H", opt_header, 70, 0x0140)  # DYNAMIC_BASE | NX_COMPAT
    struct.pack_into("<I", opt_header, 108, 16)  # NumberOfRvaAndSizes

    # 4. Section Headers (每个 40 字节)
    # 4.1 .text 节区 (VA 0x1000, VirtualSize 0x2000, Raw 0x2000, Offset 0x200)
    sec_text = bytearray(40)
    sec_text[0:5] = b".text"
    struct.pack_into("<I", sec_text, 8, 0x2000)
    struct.pack_into("<I", sec_text, 12, 0x1000)
    struct.pack_into("<I", sec_text, 16, 0x2000)
    struct.pack_into("<I", sec_text, 20, 0x200)
    struct.pack_into("<I", sec_text, 36, 0x60000020)  # CODE | EXECUTE | READ

    # 4.2 .rdata 节区 (VA 0x3000, VirtualSize 0x800, Raw 0x800, Offset 0x2200)
    sec_rdata = bytearray(40)
    sec_rdata[0:6] = b".rdata"
    struct.pack_into("<I", sec_rdata, 8, 0x800)
    struct.pack_into("<I", sec_rdata, 12, 0x3000)
    struct.pack_into("<I", sec_rdata, 16, 0x800)
    struct.pack_into("<I", sec_rdata, 20, 0x2200)
    struct.pack_into("<I", sec_rdata, 36, 0x40000040)  # INITIALIZED_DATA | READ

    headers = bytes(dos_header + pe_sig + file_header + opt_header + sec_text + sec_rdata)
    headers += b"\x00" * (0x200 - len(headers))

    # 5. .text 机器指令与低熵 NOP 序列 (0x2000 字节)
    code_bytes = b"\x48\x8d\x0d\x49\x12\x00\x00\xe8\x00\x00\x00\x00\x31\xc0\xc3\xcc"
    text_section = code_bytes + b"\x90" * (0x2000 - len(code_bytes))

    # 6. .rdata 数据载荷 (0x800 字节)
    rdata_buf = b"\x00" * 0x800

    full_payload = headers + text_section + rdata_buf
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(full_payload)
    return output_path


def build_synthetic_elf64(output_path: Path) -> Path:
    """动态合成最小合法的 64 位 ELF64 可执行文件并落盘

    包含：
    - ELF64 Header 与 Program Header (PT_LOAD)
    - .text 代码指令段与只读数据段
    - 包含测试 URL、IPv4 与 AES S-Box 表

    @param output_path 目标输出物理文件路径
    @return Path 成功落盘的文件路径
    """
    e_ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elf_hdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,
        0x3E,
        1,
        0x401000,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )

    ph = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        0x400,
        0x400,
        0x1000,
    )

    header_block = elf_hdr + ph
    padding = b"\x00" * (0x100 - len(header_block))

    code_bytes = b"\x48\x8d\x0d\xf9\x0f\x00\x00\xe8\x00\x00\x00\x00\x31\xc0\xc3"
    code_block = code_bytes + b"\x90" * (0x100 - len(code_bytes))

    data_block = bytearray(0x200)
    url = b"https://api.example.com/v1/token\x00"
    data_block[0 : len(url)] = url
    ip = b"192.168.10.25\x00"
    data_block[0x30 : 0x30 + len(ip)] = ip
    data_block[0x80 : 0x80 + 256] = AES_SBOX

    full_elf = header_block + padding + code_block + bytes(data_block)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(full_elf)
    return output_path


def build_synthetic_macho64(output_path: Path) -> Path:
    """动态合成最小合法的 64 位 ARM64 Mach-O 可执行文件并落盘

    包含：
    - Mach-O 64-bit Header (MH_MAGIC_64, ARM64, MH_EXECUTE, MH_PIE)
    - 基础指令填充与字符串常量

    @param output_path 目标输出物理文件路径
    @return Path 成功落盘的文件路径
    """
    # 1. Mach-O 64-bit Header (32 字节)
    # flags: MH_PIE (0x200000) | MH_DYLDLINK (0x4) | MH_TWOLEVEL (0x80) | 1
    flags = 0x00200085
    macho_hdr = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # magic
        0x0100000C,  # cputype (ARM64)
        0,  # cpusubtype
        2,  # filetype (MH_EXECUTE)
        0,  # ncmds
        0,  # sizeofcmds
        flags,
        0,  # reserved
    )

    padding = b"\x00" * 224
    payload = macho_hdr + padding
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return output_path
