# 0006. 下一代控制流拓扑、局部滑动高熵、缓解机制审计、YARA 匹配与纵深取证增强

- **状态**: accepted

## 背景与问题

随着 `v1.0.0` 基础静态逆向内核的稳定运行，在面对复杂的现代混淆恶意代码研判、漏洞利用防御评估以及攻防推演时，暴露出若干深层能力诉求：

1. **线性反汇编的拓扑盲区**：平铺直叙的反汇编流难以直观呈现函数的条件分支跳转、循环回跳及圈复杂度，且 LLM 缺乏图形化流程视图；
2. **全局香农熵的大节区稀释效应**：大型可执行节区（如数 MB 的 `.text`）中若混入 1KB~4KB 的微型加密 Shellcode 或压缩 Payload，整体平均熵值并不会超过 7.2 阈值，导致传统全局熵检测失效；
3. **安全缓解机制缺乏跨平台量化模型**：安全分析人员需要一键评估 Windows、Linux 与 macOS 各自特有的编译器与内核加固机制及利用难度；
4. **威胁规则生态隔离**：无法直接复用已有的工业级 YARA 特征规则资产进行即时规则匹配与文件偏移/VA 双重映射；
5. **取证同源分析指纹浅薄**：缺少微观编译器工具链版本追溯（PE Rich Header）、对抗微小变异的同源模糊哈希（SSDEEP）以及 Apple 生态代码签名特权清单（Entitlements）。

## 决策

1. **单入口单出口基本块切分与 Mermaid CFG 拓扑可视化 (`analyze_cfg`)**：
   - 基于 Capstone 静态反汇编分析分支跳转目标与返回指令，切分原子 `BasicBlock` 并构建有向控制流图；
   - 提取各块后继边类型（条件为真、条件为假、无条件跳转），计算函数整体圈复杂度，并直接输出紧凑规范的 Mermaid `flowchart TD` 语法文本；
   - 与 COW 虚拟补丁（ADR-0005）无缝联动，补丁修改分支后即时动态反映新流向。
2. **滑动窗口局部异常高熵块探测 (`get_sections`)**：
   - 引入可配置的滑动窗口（默认 2048 字节窗口、1024 字节步长），对节区内各数据切片进行细粒度香农熵扫描；
   - 聚合连续命中高熵（$\ge 7.2$）的重叠切片，生成合并后的紧凑 `LocalHighEntropyBlock` 区间，并在超大节区上设置采样熔断保护。
3. **全平台利用缓解机制跨架构画像与安全评分 (`audit_mitigations`)**：
   - 跨平台解析 Windows（DEP/NX、ASLR、SafeSEH、CFG、CET）、Linux（NX、PIE、RELRO、Stack Canary、FORTIFY）与 macOS（PIE、Code Signature、Hardened Runtime）；
   - 输出统一加权安全评分（0~100）并映射利用难度评级（Low/Medium/High/Extreme）。
4. **独立 YARA 规则匹配与结构化优雅降级 (`scan_yara`)**：
   - 支持实时规则文本（`source`）与规则文件路径（`filepath`）编译扫描，映射命中特征字符串的文件偏移与虚拟内存地址（VA）；
   - 可选依赖优雅降级：若宿主机未安装 `yara-python`，返回语义化错误码与明确安装指导，不破坏核心运行时。
5. **深度取证指纹扩展 (`open_binary`)**：
   - **PE Rich Header**：解析 `comp_id` 映射已知 Visual Studio 编译器与工具链名称（`RichHeaderEntry`）；
   - **纯 Python SSDEEP 模糊哈希**：基于 7 字节 Adler-like 滚动哈希与 32 位 FNV-1 分块哈希，以轻量无 C 库依赖方式计算 `<blocksize>:<h1>:<h2>`，容错隔离不阻塞主干解析；
   - **Mach-O Entitlements**：深入解析 `LC_CODE_SIGNATURE` SuperBlob 中的 `CSSLOT_ENTITLEMENTS`，反序列化 XML 权限清单为结构化字典。
