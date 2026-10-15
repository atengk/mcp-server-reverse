# 0007. .NET CLR 托管程序识别、架构降级防御与专属反编译指引

- **状态**: accepted

## 背景与问题

在跨平台逆向分析与数字取证中，Windows 平台存在大量基于 C# / F# / Visual Basic 构建的 .NET 托管程序（Managed Assembly）：

1. **托管与原生混合的二元性**：.NET 程序在物理上具备标准 PE/COFF 头部与节区布局，但核心业务逻辑由 Common Intermediate Language (CIL/MSIL) 字节码构成，其机器码入口点通常仅为指向 `mscoree.dll!_CorExeMain` 的单条微型跳转桩；
2. **原生汇编盲区与 Agent 试错陷阱**：旧版服务将其视同原生 C/C++ 二进制处理，导致 Capstone 原生反汇编与控制流图（CFG）仅能分析无意义的加载引导桩，丢失真实业务逻辑，导致 AI Agent 陷入在原生汇编层盲目穷举的泥潭；
3. **加壳/非标 PE 的解析健壮性脆弱**：在混淆或被加壳（如 ASPack、UPX）样本中，LIEF 解析失败直接回退为默认 64 位初始值，导致 32 位被误判为 64 位、基址/入口点清零，破坏指令语义；
4. **非受支持格式的粗暴拒绝**：当用户传入 Flash SWF、Android DEX/APK、WASM 或网络抓包归档时，直接抛出无上下文的泛化不支持报错，无法提供可行动的工具链转向指引。

## 决策

1. **PE COM 描述符与 CLR 托管标志探测 (`is_managed`)**：
   - 在 PE 解析流程中，优先检查 PE 数据目录项（Data Directories）索引 14：`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`（CLR Runtime Header）；
   - 若其 `VirtualAddress != 0` 且 `Size != 0`，判定为 .NET 托管程序，将 `format_info` 与 `triage_overview` 的 `is_managed` 设为 `True`，`runtime` 设为 `".NET CLR"`。
2. **ECMA-335 BSJB 签名与 CLR 运行时版本提取 (`clr_runtime_version`)**：
   - 针对托管程序，在物理字节流中检索 ECMA-335 CLI 元数据根签名 `BSJB`（`0x424A5342`）；
   - 依规范读取版本字符串长度与内容（如 `v4.0.30319`、`v2.0.50727`），并辅助以正则回退，输出精准的 CLR 目标运行时版本。
3. **面向 AI Agent 的专属反编译引导建议 (`clr_guidance`)**：
   - 在全景分诊概览中注入明晰的行动指引：提示该文件由 CIL 字节码构成、原生反汇编仅含引导桩代码，明确建议优先转译使用 ILSpy、dnSpy 或 `python-net-decompiler` 等专用反编译器以还原高质量 C# 源码。
4. **LIEF 到 pefile 的全量双轨降级防御**：
   - 当 LIEF 解析失败或关键属性为空时，完整回退至 `pefile` 读取 `FILE_HEADER.Machine`（`0x14C` 决议为 i386，`0x8664` 决议为 x86_64）与 `OPTIONAL_HEADER`（基址与入口点换算），保证加壳 32 位样本的架构准确度。
5. **轻量魔数格式嗅探器 (`FormatSniffer`)**：
   - 在 `SecurityGuard` 格式校验层集成针对 Adobe Flash (SWF)、Android (DEX/APK)、WebAssembly (WASM)、网络流量 (HAR) 与底层抓包 (PCAP/PCAPNG) 的特征魔数识别；
   - 在 `UNSUPPORTED_FORMAT` 错误信封中提供针对性的专用工具链推荐（如 FFDec、jadx、wabt、traffic-inspector MCP 等），赋能 Agent 快速智能自纠偏。
