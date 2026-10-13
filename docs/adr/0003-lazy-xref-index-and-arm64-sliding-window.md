# 0003. 会话级惰性交叉引用倒排索引与 ARM64 4 指令滑动窗口配对

- **状态**: accepted

## 背景与问题

在二进制逆向分析中，定位某个敏感字符串（如 C2 URL、密钥常量）或关键函数被哪些代码指令引用（Cross-References / Xrefs）是高频核心诉求。然而，基于纯 Python + `capstone` 构建跨架构交叉引用引擎面临三大矛盾：

1. **全量扫描耗时与打开速度的矛盾**：开启 `capstone.detail = True` 对可执行节区逐指令提取操作数属于典型的 CPU 密集型计算。若在 `open_binary` 阶段同步建立全量交叉引用索引，将显著拖慢初次打开二进制文件的响应延迟，且阻塞 `asyncio` 事件循环。
2. **超大/加壳二进制内存失控风险**：部分恶意样本或大型游戏二进制包含数十 MB 甚至上百 MB 的巨型节区，无上限全量反汇编会导致进程内存峰值剧增。
3. **ARM64 页相对寻址跨指令分裂**：不同于 `x86_64` 单条指令即可通过 `[rip + disp]` 完整表达目标地址，`ARM64` 架构通常采用 `ADRP Xn, #page`（加载 4KB 对齐页基址）配合后续 `ADD Xd, Xn, #pageoff` 或 `LDR Xt, [Xn, #pageoff]` 双指令组合来寻址全局数据。若引入完整控制流图（CFG）与静态单赋值（SSA）数据流分析，纯 Python 实现复杂度与耗时将激增两个数量级；若仅做单指令独立扫描，则会漏掉绝大多数 `ARM64` 字符串与全局常量引用。

## 决策

1. **会话级惰性构建与后台线程卸载**：
   - `open_binary` 阶段仅初始化 `BinarySession._xref_index = None`，保持亚秒级会话创建体验；
   - 当 Agent 首次针对某会话调用 `find_xrefs` 时，通过 `await asyncio.to_thread(build_xref_index, session)` 在后台工作线程执行一次性全节区扫描并将构建好的倒排索引（`target_va -> list[XrefRecord]`）挂载至会话实例；
   - 同一会话后续所有 `find_xrefs` 调用直接通过内存字典 $O(1)$ 命中返回。
2. **单可执行节区 `16MB` 扫描熔断上限**：
   - 对每个可执行节区（含 `x` 权限或 `.text`/`__text`）设置 `MAX_EXEC_SECTION_SCAN_SIZE = 16MB` 的硬性扫描截断边界，兼顾常规二进制 100% 覆盖与极端大文件下的内存安全。
3. **ARM64 4 指令寄存器滑动窗口配对（`ARM64_ADRP_WINDOW_SIZE = 4`）**：
   - 在线性扫描 `ARM64` 指令流（含 `find_xrefs` 与 `disassemble` 内联注释）时，维护轻量级寄存器状态表 `adrp_window: dict[reg_id, (page_base_va, seq_idx)]`；
   - 遇到 `ADRP` 指令时记录目标寄存器与页基址；在随后的 4 条指令窗口内，若遇到以同一寄存器为基址寄存器的 `ADD`（立即数偏移）或 `LDR`（内存位移），立即合成精确目标地址 `target_va = page_base + offset` 并归类为 `pc_relative` 引用，以 $O(N)$ 线性单遍扫描代价覆盖主流编译器生成的 `ARM64` 页相对寻址模式。
