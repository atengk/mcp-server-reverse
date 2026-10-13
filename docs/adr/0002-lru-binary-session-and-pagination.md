# 0002. 进程内 LRU 二进制会话缓存与渐进式上下文防爆

- **状态**: accepted

## 背景与问题

大型二进制文件（数十 MB 的 PE/ELF/Mach-O）包含成千上万条导入符号、字符串与反汇编指令。若每次 MCP Tool 调用均重新从磁盘读取并全量解析二进制结构，不仅会产生严重的 I/O 与 CPU 重复开销，且一次性返回未裁剪的符号表或字符串列表会瞬间撑爆大语言模型（LLM）的上下文窗口。同时，macOS Fat Mach-O（Universal Binary）在同一物理文件中包含多个不同架构切片（如 `x86_64` 与 `arm64`），单纯使用文件 `SHA-256` 作为会话键会导致多架构切片互相覆盖。

## 决策

1. **进程内 LRU `BinarySession` 缓存池与多架构复合键**：
   - 单架构二进制文件以物理文件 `SHA-256` 前 12 位作为唯一 `session_id`；
   - 针对包含多个架构切片的 Fat Mach-O，`open_binary` 支持通过可选参数 `target_arch` 指定目标架构（未指定时默认优先选择 `arm64`，次选 `x86_64` 或首个切片），并以 `sha256(f"{file_sha256}:{resolved_arch}")[:12]` 作为唯一 `session_id`，支持同一 Fat 文件的不同架构切片在 LRU 池中独立驻留（默认最大驻留 `8` 个会话，可通过 `--max-sessions` 配置）；
   - 会话内部惰性缓存已提取的字符串列表与交叉引用倒排索引（`_xref_index`），使同一会话内的重复查询达到 $O(1)$ 毫秒级响应。
2. **强制分页与渐进式披露**：
   - 所有列表与检索型 Tool 强制实施分页参数（默认 `offset=0, limit=50`，硬上限 `limit=500`）与正则/分类过滤，在统一响应信封中返回 `pagination: { total, offset, limit, has_more }`；
   - 反汇编输出采用单行紧凑格式（`VA: HexBytes | Mnemonic OpStr ; InlineComment`），最大化单位 Token 的信息密度。
