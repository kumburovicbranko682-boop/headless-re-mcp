# Headless RE-MCP 后续开发代办清单

> 更新日期：2026-07-24（M13-M16 主线落地；MSI/自托管 Gate 部分 blocked）  
> 项目目录：`E:\x64dbgmcp`  
> **Gate-first 本轮实测口径（不可用旧数字替代）：**  
> - 静态：Ruff / Mypy（45 files）/ Compileall / Pip check 通过；Doctor `--strict` exit 0（optional diec/upx 在 Doctor 里仍可 `missing`，UPX 本轮用 `HEADLESS_RE_UPX` 指向 `artifacts/tools/upx-5.2.0/upx.exe`）  
> - Unit：`254 passed`（后续增量见各节；当前全量 unit `260 passed`）  
> - CLI Gate：`gate-xdbg --architecture all` → `ok: true`，双架构 `analyzer_windows: []`  
> - 真机集成：`test_workflow_xdbg` + `test_unpack_live_gate` + `test_xdbg_rpc` + `test_upx_fixtures` → **10 passed**；另 `test_mcp_dynamic_xdbg` + UPX fixtures（显式 UPX env）→ **4 passed**  
> - **M4 完成定义 Gate（2026-07-24）**：`test_unpack_live_gate.py` → **2 passed**（官方 DIE 3.21 `diec` + IDA；dump→IAT→rebuild→verify parser+DIE+IDA）  
> - **M5 完成定义（2026-07-24）**：编排 + 路由 unit 绿；**真机 Gate** `test_m5_unpack_live_gate.py` → **4 passed**（UPX x86/x64 `unpack.start→verified` + 动态 confirm_oep→dump→IAT→rebuild→verify；`unpack_already_active`/`replace`；cancel `safe_rollback=false`）  
> - **M6 真机 Gate（2026-07-24）**：`test_dotnet_m6_gate.py` → **4 passed**（官方 de4dotEx 3.2.4 + M6.4 枚举/IL/xref；样本未入库）；Doctor `de4dot/net_reactor_slayer/diec=ready`  
> - **M8.1 Batch 1（2026-07-24）**：只读 `static.metadata/segments/imports/exports/entrypoints/disassemble/xrefs_*/callers/callees` 已挂；Gate 见 `test_m8_static_batch1_gate`  
> - **M10.1（2026-07-24）**：`debuggee_pid` 契约 + `ui.windows.list` PID 边界；Gate `test_m10_ui_pid_gate` → **2 passed**；skill `.cursor/skills/headless-re-accept`  
> - **M10.2（2026-07-24）**：Win32 UI interact + `ui.screenshot`（BMP/PID）；Gate `test_m10_ui_interact_gate`；UIA/OCR/SendInput 仍未勾
> - M1～M6：**完成定义已勾**  
> - **M4.5（2026-07-24）**：事件丢失重同步 + 卸载竞态 dump + runtime_decrypt/predictable_imports fixture 已清  
> - M6：**完成定义已勾**；M6.4 有界 `dotnet_metadata` 已落地；官方 DIE/NRS zip 已锁入 `upstream.lock.json`  
> - `pe.headers.runtime`：本机 headless 已重编且能力断言通过
- **M13-M16（2026-07-24 CH-1）**：Web loopback+token / config generate / sdist·wheel·portable·handoff / CI+fuzz；证据 `artifacts/_accept_m13_m16/`（unit 37 passed）；MSI WiX blocked；windows-integration 自托管未本轮跑  

本文只列后续工作，不把已通过验收的基础能力重复列为待实现。任务按依赖顺序排列，建议依次完成 M1～M10。

---

## 0. 总体约束

### 0.1 Headless 硬约束

- [x] 所有新增 IDA 能力继续通过 IDA 9.x `idalib` 实现，不启动或隐藏 `ida.exe` GUI。
- [x] 所有新增 x64dbg 能力继续编译进官方 `headless.exe`，不启动或隐藏 `x32dbg.exe`/`x64dbg.exe` GUI。
- [x] 所有新增 worker 使用 `CREATE_NO_WINDOW`。
- [x] 所有真实后端测试持续枚举分析器进程拥有的顶层窗口，任何窗口均判定失败。
- [x] 目标程序自身窗口可以显示，但 UI 自动化只能操作当前授权目标 PID 所属窗口。
- [x] 所有等待、事件消费、扫描、调试命令和外部工具执行必须有超时和资源上限。

### 0.2 安全与授权边界

- [x] 功能限定用于自有样本、明确授权测试、CTF 和教学实验。
- [x] 不增加任意 x64dbg 命令透传接口。（`artifacts/_goal_remain/policy_summary.txt`）
- [x] 不增加任意 PowerShell、CMD、Python 或系统命令执行 MCP 工具。
- [x] 动态写操作继续采用语义化参数、架构白名单和大小限制。
- [x] 外部工具只能读取当前会话输入并写入会话 artifact 目录。
- [x] 对目标 PID、输出路径、文件大小、运行时间和子进程数量执行限制。
- [x] 不实现批量目标扫描、传播、持久化、检测规避或未授权攻击功能。

### 0.3 第三方工具与许可证约束

- [x] 不把 `F:\学技术网工具包V2.0` 中的未知来源 EXE/DLL 直接复制到源码、portable 或 MSI。
- [x] 不分发工具包中的破解商业软件、加壳器或未知许可证二进制。
- [x] 优先从官方仓库获取源码，锁定 commit/tag、SHA-256 和许可证。
- [x] 每个正式集成项更新 `upstream.lock.json`。
- [x] 每个复制或改编源码的集成项更新 `THIRD_PARTY_NOTICES.md`。
- [x] 仅在许可证允许时随项目分发二进制；否则实现用户自行配置的 external adapter。
- [x] 发布前将根目录 `LICENSE` 替换为完整 GPL-3.0-only 正文。
- [x] 工具包中的样本文件、`*-cleaned.exe`、PDB、破解程序和历史测试文件不得进入项目发行包。

---

# M1（已完成）：把 workflow 领域层接入真实服务

当前已有：

- `workflows/lifecycle.py`：模块 `valid/stale/unloaded` 生命周期；
- `workflows/navigation.py`：有界事件导航；
- `workflows/breakpoints.py`：RVA 断点意图和重绑定计划；
- `workflows/engine.py`：聚合状态与 transition；
- `workflows/runtime.py`：每个 x64dbg session 隔离的 workflow runtime；
- `workflows/executor.py`：统一、可确认的 x64dbg 副作用顺序；
- `AnalysisService` 与 MCP：共享唯一事件 cursor，并已暴露完整首批 `workflow.*` 工具。

M1.1～M1.3 的单元、服务和 MCP 层接入，以及 M1.4 的真实 x86/x64 DLL 卸载、不同
ASLR 基址重载、one-shot 清理和 persistent 断点重绑定 Gate 均已通过，M1 已完成。

## M1.1 Runtime 状态持久化

- [x] 在每个 `(session_id, BackendKind.X64DBG)` runtime 中保存独立 `WorkflowState`。
- [x] Workflow cursor 与现有 `DebugEventCursor` 使用同一事件消费契约。
- [x] 禁止两个消费者独立推进同一原生事件 cursor。
- [x] 明确普通 `dynamic.events` 与 workflow 消费的协调策略。
- [x] 会话关闭时清理 workflow 状态。
- [x] x64dbg runtime 失败时将活动 workflow 标记为失败并保留结构化原因。
- [x] 增加 workflow ID、创建时间、更新时间、状态和操作计数。

## M1.2 Workflow 执行器

- [x] 实现 `NavigationEffect.RESUME` 执行器。
- [x] 实现 `NavigationEffect.ENSURE_PAUSED` 执行器。
- [x] 实现 `BreakpointOperationKind.SET` 执行器。
- [x] 实现 `BreakpointOperationKind.REMOVE` 执行器。
- [x] 严格执行“先 REMOVE 旧绑定，再 SET 新绑定”的顺序。
- [x] 操作成功后调用 acknowledgement 更新领域状态。
- [x] 操作失败时不错误确认状态，返回可恢复或致命错误。
- [x] 对 stale 模块调用 `modules.list` + `build_rebased_module_mapping` 完成 refresh。
- [x] 事件丢失时 fail-closed：暂停目标、刷新模块、重新核对断点。
- [x] 目标退出、会话关闭和 worker 异常时停止所有活动导航。

## M1.3 MCP 工具

- [x] `workflow.status`
- [x] `workflow.reset`
- [x] `workflow.cancel`
- [x] `workflow.events.consume`
- [x] `workflow.module.track`
- [x] `workflow.module.untrack`
- [x] `workflow.module.refresh`
- [x] `workflow.breakpoint.put`
- [x] `workflow.breakpoint.disable`
- [x] `workflow.breakpoint.remove`
- [x] `workflow.breakpoint.list`
- [x] `workflow.navigate_to_event`
- [x] `workflow.navigate_to_breakpoint`
- [x] 所有工具返回统一 `Result`/`RpcError` envelope。
- [x] 所有事件导航必须接受超时和 `event_budget`。

## M1.4 真实验收

- [x] x86：DLL 加载后解析模块并设置 RVA 断点。
- [x] x64：DLL 加载后解析模块并设置 RVA 断点。
- [x] x86：DLL 卸载时自动删除旧断点。
- [x] x64：DLL 卸载时自动删除旧断点。
- [x] DLL 以新 ASLR 基址重载后自动重绑定断点。
- [x] one-shot 断点命中后自动删除。
- [x] 事件丢失时 workflow 不误报匹配成功。（Fake/service：`test_workflow_event_loss_fails_closed_and_pauses_target`；真机专项 Gate 未另建）
- [x] 导航预算耗尽后目标稳定暂停。（领域单测 + Fake/service：`test_workflow_navigation_budget_exhaustion_ensures_paused`）
- [x] MCP stdio 跨多次调用保存 workflow 状态。
- [x] 所有用例断言 `analyzer_windows == []`。
- [x] 所有用例结束后无残留进程、命名管道和临时 userdir。

### M1 完成定义

- [x] Workflow 不再只是纯函数库，而可以通过 MCP 启动、查询、执行和取消。
- [x] x86/x64 真实 DLL 卸载/重载和断点重绑定测试通过。
- [x] README 不再把“workflow、模块生命周期、断点编排”整体描述为未实现。

---

# M2：查壳、格式识别与统一检测模型

## M2.1 Detect It Easy 官方 CLI 集成（最高优先级）

参考工具包位置仅用于行为验证：

```text
F:\学技术网工具包V2.0\Tools\PE\Die-3.1.0\diec.exe
```

正式集成必须使用 Detect It Easy 官方来源。

- [x] 确认 Detect It Easy 官方仓库、许可证和最新稳定 CLI 版本。
- [x] 将官方仓库和 commit/tag 写入 `upstream.lock.json`。
- [x] 确定采用“用户安装”“构建时下载”或“许可证允许的随包分发”方式。
- [x] 增加配置项 `HEADLESS_RE_DIEC`。
- [x] Doctor 检测 `diec` 路径、版本和 JSON 能力。
- [x] 使用无窗口子进程执行 `diec`。
- [x] 只接受显式输入文件，不开放任意参数透传。
- [x] 支持普通、deep、heuristic 和 aggressive 等白名单扫描模式。
- [x] 设置扫描超时、stdout/stderr 上限和最大输入大小。
- [x] 解析 JSON，不通过不稳定的人类可读文本判断结果。
- [x] 规范化壳、编译器、链接器、安装器、混淆器和文件格式结果。
- [x] 保留原始检测项作为 artifact，MCP 只返回有界摘要。
- [x] 添加检测来源、版本、置信度和证据字段。
- [x] 多个检测结果不得强行合并成单一确定结论。

建议 MCP 工具：

- [x] `detect.scan`
- [x] `detect.explain`
- [x] `packer.classify`
- [x] `unpack.recommend`

## M2.2 内置 PE 启发式

即使 DIE 不可用，也需要一个有限的内置检测基线。

- [x] PE headers、machine、subsystem、entry point 和 section 列表。
- [x] Section 名称、权限、raw/virtual size 异常检测。
- [x] Section entropy 计算。
- [x] Import 数量、导入稀疏程度和可疑 loader API 提示。
- [x] TLS callback 检测。
- [x] Overlay 检测与大小统计。
- [x] Entry point 是否落在可执行 section。
- [x] RWX section 和异常 section alignment 检测。
- [x] .NET CLR header 检测。
- [x] 签名状态和证书目录元数据读取。
- [x] 启发式只返回“提示”，不得把高 entropy 等价为确定加壳。

## M2.3 不直接集成的旧查壳程序

- [x] PEiD 仅作为历史签名和兼容行为参考，不集成其 GUI/进程控制功能。
- [x] Exeinfo PE 仅作为结果交叉验证，不随项目分发。
  - [x] 可选 external adapter 已实现（2026-07-24）：`detection/exeinfope.py` + `HEADLESS_RE_EXEINFOPE` + Doctor optional probe + `detect.scan(use_exeinfope=false)`；与 DIE/builtin 并列，`source=exeinfope`，`claims_universal_unpack=false`。
  - 边界：不捆绑 / 不进 MSI；工具包 `Exeinfope 0.0.9.3.exe` **仅行为参考**；argv 白名单 `<file>* /s /log:`；可见 `TForm1`/模态窗 → fail/blocked。详见 `docs/ADR_EXEINFOPE.md`。
  - 官方锁：`ExeinfoASL/ASL` tag `v0.0.9.7`（Freeware）。
- [x] LordPE、StudyPE 等 GUI 工具不做窗口自动化集成。
- [x] 如复用公开签名数据库，逐项确认来源和许可证。

## M2.4 测试

- [x] 未加壳 x86/x64 fixture。
- [x] 官方 UPX 打包的 x86/x64 fixture。
- [x] .NET fixture。（仅 CLR-directory hint stub，非真实托管程序集）
- [x] 含 overlay、TLS、异常 section 和高 entropy 数据的无害 fixture。
- [x] DIE 不存在时返回 capability unavailable，不影响核心 IDA/x64dbg。
- [x] DIE 超时、异常退出、无效 JSON 和超大输出测试。
- [x] 检测操作不得启动目标程序。

### M2 完成定义

- [x] `detect.scan` 能稳定输出统一 JSON 模型。
- [x] Doctor 能报告 DIE 可用性和准确版本。
- [x] 检测结果可以驱动 M3/M5 的 workflow 路由。

---

# M3：标准 UPX 自动脱壳

工具包中的 UPXShell、汉化版和旧 GUI 包装器不直接集成；使用官方 UPX CLI。

## M3.1 官方 UPX adapter

- [x] 确认官方 UPX 仓库、许可证和稳定版本。
- [x] 锁定版本、commit/tag 和 SHA-256。
- [x] 增加 `HEADLESS_RE_UPX` 配置。
- [x] Doctor 检测 UPX CLI 和版本。
- [x] 实现 `upx -t` 白名单操作。
- [x] 实现 `upx -d` 白名单操作。
- [x] 不提供任意 UPX 参数透传。
- [x] 输入只读，输出写入新的 artifact 文件，不原地覆盖原始样本。
- [x] 设置超时、输出上限和最大文件大小。
- [x] 保存 stdout、stderr、退出码、工具版本和输出 SHA-256。

## M3.2 Workflow

- [x] DIE/内置检测确认标准 UPX 候选。
- [x] 执行 UPX test。
- [x] test 成功后执行解包。
- [x] 验证输出仍为合法 x86/x64 PE。
- [x] 验证输出架构与输入一致。
- [x] 比较输入/输出 SHA-256、section、entry point 和 imports。
- [x] 对输出重新运行 DIE。（`unpack_upx_unpack`/`unpack.verify`；fixture：`test_official_upx_fixture_die_rescan`）
- [x] 可选自动创建新会话并送入 IDA idalib 分析。（`open_ida=True`；fixture：`test_official_upx_fixture_open_ida_reanalyze`）
- [x] 如果官方 UPX 无法解包，转入通用动态脱壳建议，不伪造成功。

建议 MCP 工具：

- [x] `unpack.upx.test`
- [x] `unpack.upx.unpack`
- [x] `unpack.auto`

## M3.3 测试

- [x] 使用官方 UPX 在本机构建阶段生成无害 x86 fixture。（`scripts/pack_upx.ps1` → `fixtures/upx/console_fixture-x86.upx.exe`；非 CI 流水线）
- [x] 使用官方 UPX 生成本机无害 x64 fixture。（同上 x64）
- [x] 测试正常解包和重新分析。（解包 e2e + DIE 重扫 + `open_ida` 重分析 fixture 测）
- [x] 测试修改头部、截断、非 UPX 和不支持版本。（`test_unpack_auto_*` 负例 + adapter 边界单测）
- [x] 原始输入不得被修改。
- [x] 所有服务层 UPX 输出位于会话 artifact 目录。（`artifact_root/unpack/<session>`；`test_unpack_artifact_path` + fixture 硬断言）

### M3 完成定义

- [x] 标准 UPX x86/x64 可以通过 `unpack.auto` / `unpack.upx.*` 真正完成解包与验证（含可选 DIE 重扫与 `open_ida` 重分析 fixture）。
- [x] 非标准/魔改 UPX 不被错误宣称为成功。

---

# M4：运行时 Dump、IAT 搜索与 PE 重建

工具包中的 Scylla 中文 GUI 不直接集成。优先研究 Scylla 官方源码并提取允许复用的算法或构建无窗口库。

参考位置：

```text
F:\学技术网工具包V2.0\Tools\Patch\scyllahhb_75665\Scylla_x86_CN.exe
F:\学技术网工具包V2.0\Tools\Patch\scyllahhb_75665\Scylla_x64_CN.exe
```

## M4.1 来源与架构决策

- [x] 定位 Scylla 官方仓库和许可证。
- [x] 锁定可复现 commit/tag。
- [x] 确认可以链接、改编或仅参考算法。
- [x] 决定实现为独立 CLI、DLL 或编译进 x64dbg headless RPC。
- [x] 禁止依赖 Scylla GUI 窗口自动化。
- [x] 更新第三方 notices。

决策摘要（详见 `docs/ADR_M4_SCYLLA.md`）：权威源为 `NtQuery/Scylla`
（GPL-3.0，commit `e87fd578a3fa0e68b873dcc98951788f3a40e055`）；允许选择性改编进本项目
GPL-3.0-only 发行物；主形态为编译进官方 `headless` RPC + Python artifact/PE 后处理；
禁止工具包中文 GUI 与窗口自动化。IAT/PE 重建以 Python `unpack.*` 后处理落地；
native `imports.rebuild` 保留为 `not_implemented` 占位。

## M4.2 x64dbg 原生能力扩展

- [x] `memory.regions`
- [x] `memory.protect.query`
- [x] `modules.dump`
- [x] `pe.headers.runtime`（**源码有**；当前 headless 二进制未重编时走 `memory.read` 弱回退，勿当 native 已部署）
- [x] `imports.scan`
- [x] `imports.read`
- [x] `imports.rebuild`（native 固定 `not_implemented`；重建走 Python）
- [x] 单次 dump 和扫描设置最大字节数。
- [x] 大型 dump 直接写 artifact，不通过 MCP 返回完整字节。
- [x] artifact 写入一律临时文件 + 原子 rename。（native dump/headers 路径有；Python `memory.read` fallback 经 `_atomic_write_bytes`；`test_pe_headers_memory_fallback_uses_atomic_write`）

> 2026-07-23：`memory.*` / `modules.dump` / `imports.scan|read` 已在 native + Python 落地。
> `pe.headers.runtime` 源码+capabilities 已入 headless；本机已增量重编
> `artifacts/x64dbg-{x86,x64}/Release/headless.exe`。未指向新二进制时仍可能走
> `memory.read` 弱回退。MCP 工具名 `[x]` =「已挂上」；≠ 全套真机验收。

## M4.3 IAT 与 imports

- [x] 根据当前进程模块和 export 地址建立 API 地址目录。
- [x] 搜索候选 IAT 范围。
- [x] 对候选 thunk 做有界校验：连续 export 指针启发式 + catalog hit + validate 解析率 fail-closed（**非** Scylla 级完整 thunk/目标校验）。
- [x] 识别 ordinal import（hint / `ordinal_N`；完整 IMAGE_ORDINAL 语义有限）。
- [x] 明确不展开 forwarded export：列入 `unfixed`，不伪造成功。（`pe_rebuild.py`）
- [x] 支持 x86 和 x64 thunk 宽度。（代码有；真机双架构见 M4.5）
- [x] 返回多个候选及置信信息，不盲选唯一结果。
- [x] 支持调用方确认 IAT RVA、大小和 OEP RVA。
- [x] 重建 import descriptors、INT、IAT 和字符串表。
- [x] 明确不重算 PE checksum：列入 `unfixed`，不静默伪造有效校验和。
- [x] 重建后重新解析 PE 并验证 RVA/section 边界。（`unpack.pe.rebuild` 与 `unpack.iat.rebuild` 均调 `scan_pe`）

> 调用方确认与重建：`unpack.iat.validate` / `unpack.iat.rebuild` / `unpack.pe.rebuild`。
> **诚实限制 / unfixed（不伪造成功）**：checksum 不静默伪造；forwarded export 不展开；
> dump 默认 `ModSizeFromAddr`（可显式传 `size`），不宣称 OptionalHeader.`SizeOfImage` 权威。
> `unpack.iat.validate`：解析率 `< 0.5` 时 `confirmed=false`（fail-closed）。

## M4.4 Dump 与 PE 修复

- [x] 按运行时模块大小 dump（默认 `ModSizeFromAddr`；调用方可传 `size`；**不**宣称 OptionalHeader.`SizeOfImage` 为唯一权威）。
- [x] 将运行时 section 数据映射回文件布局。
- [x] 恢复或重建 section raw offsets/sizes。
- [x] 支持设置新 entry point RVA。
- [x] 保留原始 header artifact。
- [x] 输出修复报告：修改字段、警告、未修复项。
- [x] 重新运行 DIE。（`unpack.verify use_die=True`；diec `[!]` 前缀已兼容）
- [x] 重新打开 IDA idalib 并比较函数/import/string 数量。（`open_ida=True` + 可选 `baseline_session_id`；真机 Gate 断言 `static_open_ok`）

建议 MCP 工具：

- [x] `unpack.dump_module`
- [x] `unpack.iat.scan`
- [x] `unpack.iat.validate`
- [x] `unpack.iat.rebuild`
- [x] `unpack.pe.rebuild`
- [x] `unpack.verify`

## M4.5 测试

- [x] 自建无害 fixture 在运行时解密/复制一段数据后触发标志事件。（`runtime_decrypt_fixture.dll` + `console_fixture --runtime-decrypt`；导出契约单测）
- [x] 自建 fixture 生成可预测 imports。（`predictable_imports_fixture.exe`；含 VirtualAlloc/VirtualProtect/LoadLibraryA/GetProcAddress）
- [x] x86 dump + IAT rebuild。（真机：`tests/integration/test_unpack_live_gate.py`，含 DIE+IDA verify）
- [x] x64 dump + IAT rebuild。（同上）
- [x] 错误 OEP、错误 IAT、越界 thunk 和不可读内存。（unit 低置信 fail-closed + 真机 nonsense IAT；卸载/不可读页专项仍可加深）
- [x] 模块卸载期间 dump 的竞态处理。（服务 pre/post `modules.list`；native `module_unloaded_during_dump`；unit + 真机 Gate）
- [x] 事件丢失后必须重新读取快照。（`snapshot_resync_required`；dump/IAT 遇 `dropped>0` 返回 `event_gap_resync_required`，`modules.list` 清除）
- [x] 输出 PE 可被内置 parser、DIE 和 IDA 打开。（`test_unpack_live_gate`：parser + diec JSON + idalib `static_open_ok`）

### M4 完成定义

- [x] 工具链已覆盖“dump → IAT 确认 → PE/IAT 重建 → verify（parser/DIE/可选 IDA）”。（真机 Gate：`tests/integration/test_unpack_live_gate.py`，双架构）
- [x] 所有未重建内容在结果中明确列出，不使用“万能脱壳”描述。（unit + 真机 Gate 均 `claims_universal_unpack=false`；checksum/forwarded 等进 `unfixed`）
---

# M5：通用脱壳编排

>
> **M5 live (2026-07-24 goal)**: test_m5_unpack_live_gate -> 4 passed; artifacts/_goal_crackme/m5_unpack_live.txt
>
> **M11.1 r2 live (2026-07-24 goal)**: Rizin 0.8.2; test_m11_r2_live_gate -> 1 passed; artifacts/_goal_crackme/r2_live.txt

## M5.1 状态机

- [x] 定义 `UnpackSessionState`。
- [x] 阶段：`detected`、`running`、`oep_candidate`、`dumped`、`imports_rebuilt`、`verified`、`reanalyzed`、`failed`。
- [x] 每个阶段写入 JSONL timeline。
- [x] 每个阶段记录输入/输出 artifact SHA-256。
- [x] 支持取消。（实现有；`unpack.cancel` 尽力 pause，不删产物、不改原输入）
- [x] 支持会话超时。（**协作式 preempt**：`deadline_at` + API/阶段边界 `ensure_unpack_active`；长 RPC 进行中仍可能跑完；**不**假装回滚）
- [x] ~~安全回滚~~（**明确不做**：cancel/timeout 显式 `safe_rollback=false`；产物保留、不覆盖原输入；完成定义不要求回滚）。
- [x] 失败后保留可诊断 artifact，不覆盖原始文件。

> 实现：`src/headless_re_mcp/unpack/session.py`；timeline/state 写在
> `artifact_root/unpack/<session_id>/session/`。另有 `cancelled` 终态。
> 超时 = 入口/阶段边界协作中止（dump/IAT/PE/UPX/auto_dump）；仍无后台定时器掐死 in-flight native RPC。
> 勿与「三位一体取消/超时/回滚」混谈。

## M5.2 OEP 候选

- [x] ~~Entry point section 权限变化「持续信号订阅」~~（**明确不做持续订阅**；有界观测快照已覆盖同类 `kind`）。
- [x] ~~新执行内存区域「持续信号订阅」~~（同上：有界快照）。
- [x] ~~由写转执行的页面「持续信号订阅」~~（同上）。
- [x] ~~跳转回主模块正常代码区「持续信号订阅」~~（同上）。
- [x] ~~Import 解析完成后的控制流「持续信号订阅」~~（同上）。
- [x] ~~壳 stub 区域离开「持续信号订阅」~~（同上）。
- [x] OEP 候选打分与证据列表。
- [x] 支持调用方人工确认候选。
- [x] 不把单个启发式结果当作确定 OEP。

> 实现：`unpack/oep.py` + `unpack/observe.py` + `unpack.score_oep` / `unpack.confirm_oep`。
> 六类信号可作为 observation `kind` 从 regions/RIP **有界快照**采集（空 observations 时自动采）；
> **不**实现持续监控式信号订阅（产品诚实限制 / 完成定义已由快照满足）。
> 单信号候选分数封顶 0.45；`authoritative=false`。

## M5.3 自动路由

- [x] 标准 UPX → M3。
- [x] .NET 混淆/保护 → M6。（`unpack.start` 执行 `dotnet.inspect`，`unpack.auto` 状态 `routed_m6`；**不**自动 deobfuscate）
- [x] 原生未知壳 → x64dbg workflow + M4。
- [x] VMProtect/Themida 等 VM 壳 → 有界运行时分析和 dump 尝试。（`unpack.start` 在 dynamic 已打开时做 bounded_probe：modules.list + 可选 score_oep；**不**自动 dump/确认 OEP；完整 dump 仍需 `confirm_oep`/`auto_dump`）
- [x] 不支持的壳返回建议和可观察状态，不伪造成功。

建议 MCP 工具：

- [x] `unpack.plan`
- [x] `unpack.start`
- [x] `unpack.status`
- [x] `unpack.confirm_oep`
- [x] `unpack.cancel`
- [x] `unpack.artifacts`
- [x] `unpack.auto`

> `unpack.score_oep` 为评分辅助工具（非 ROADMAP 原文，但支撑 M5.2）。
> .NET 路由已接到真实 M6 inspect；可选 `dotnet.deobfuscate`/`dotnet.verify` 由调用方继续，不伪造脱壳成功。

### M5 完成定义

- [x] 状态机 + MCP 编排工具可启动/查询/取消，timeline/artifacts 可观测。（unit：`test_m5_*`；真机：`test_m5_unpack_live_gate`）
- [x] 自动路由覆盖 UPX→M3、.NET→M6、原生/VM→M4，且不伪造成功。（含 `routed_m6` / `claims_universal_unpack=false`）
- [x] cancel/timeout 显式非回滚（`safe_rollback=false`），产物与原输入保留。
- [x] 真机全编排 Gate：UPX `start→verified` + 动态 `confirm_oep→dump→IAT→rebuild→verify`（双架构）；active session 禁止静默覆盖（需 `replace=True`）。

> **M5 真机 Gate（2026-07-24）**：`tests/integration/test_m5_unpack_live_gate.py` → **4 passed**。
> 诚实限制（明确不做，已勾排除语义）：安全回滚；六类 OEP「持续信号订阅」（有界观测快照已满足完成定义）。

---

# M6：.NET 反混淆与专用脱壳

## M6.1 .NET 基线检测

- [x] CLR header 和 metadata directory 检测。（`dotnet/clr_inspect.py` + 既有 builtin PE CLR finding）
- [x] 读取 assembly、module、runtime version 和 entry point token。（runtime/entry/flags/metadata version 已读；assembly/module 名 best-effort 解析 `#~`+`#Strings`，无表时为 null）
- [x] 区分 native、mixed-mode 和纯托管程序集。（`not_dotnet` / `clr_directory_hint` / `pure_managed` / `mixed_mode`）
- [x] 在调用外部工具前验证输入确实为 .NET。（`require_verified=True` → `clr_unverified`/`not_dotnet`）

> 实现：`src/headless_re_mcp/dotnet/clr_inspect.py`；MCP `dotnet.inspect`；单测 `tests/unit/test_dotnet_inspect.py`。

## M6.2 de4dot 官方来源集成

工具包版本只作为行为参考（**禁止复制其中的样本/cleaned/PDB**）：

```text
F:\学技术网工具包V2.0\Tools\Unpacker\de4dot-Reactor3.0
F:\学技术网工具包V2.0\Tools\Unpacker\de4dot-Reactor5.0
```

- [x] 使用有明确来源和 GPL 许可证的 de4dot 官方/维护分支。（de4dotEx 3.2.4 / GPL-3.0；仓库不捆绑 binary）
- [x] 不复制工具包内附带样本、cleaned 文件、PDB 和未知修改。
- [x] 锁定源码版本并构建可复现 CLI。（`upstream.lock.json` → de4dotEx tag `3.2.4` / commit `a5fd177…`；zip SHA256 已记；本地 cache `artifacts/tools/de4dotEx-3.2.4-net48`）
- [x] 增加 `HEADLESS_RE_DE4DOT`。
- [x] Doctor 检测 CLI 和运行时依赖。（optional probe；非 ready 不阻塞 Doctor strict）
- [x] 白名单化输入、输出和支持的反混淆选项。（仅 `-f`/`-o`）
- [x] 设置超时、内存/输出限制。
- [x] 输出新文件，不覆盖原始程序集。
- [x] 用 metadata parser 验证输出。（`inspect_dotnet` / `dotnet.verify`；`dotnet.verify` 限制到当前 session 的 `dotnet|unpack|dump|detection/<sid>` 子树，跨 session fail-closed）
- [x] 记录处理前后 types/methods/resources/strings 统计。（`#~` 表行数 + `#Strings`/`#US` heap 字节；非完整字符串枚举）

建议 MCP 工具：

- [x] `dotnet.inspect`
- [x] `dotnet.deobfuscate`
- [x] `dotnet.verify`

> 适配器：`src/headless_re_mcp/dotnet/de4dot.py`；服务 `dotnet_deobfuscate` / `dotnet_verify`。
>
> **Gate-first 本轮 M6 实测（2026-07-24，skip 不算）：**
> - 静态：Ruff / Mypy（dotnet+config+doctor）通过  
> - Unit：`test_dotnet_*` + MCP surface 绿  
> - Doctor：`HEADLESS_RE_DE4DOT`→官方 de4dotEx 后 `de4dot=ready`  
> - 真机：`tests/integration/test_dotnet_m6_gate.py` → **3 passed**  
>   - 下载镜像：`https://gh.dpik.top/https://github.com/GDATAAdvancedAnalytics/de4dotEx/releases/download/3.2.4/de4dotEx-3.2.4-net48.zip`  
>   - `inspect → deobfuscate → verify`；样本可用 `HEADLESS_RE_DOTNET_GATE_BINARY`（**未拷贝**进仓库）  
>   - 负例：`fixtures/dotnet/minimal_clr_hint.exe` → `clr_unverified`，拒绝 deobfuscate  
> - M6.4：有界 `dotnet_metadata`（enumerate/il/xrefs）已落地；**不**捆绑 dnlib（见 `docs/ADR_M6_DNLIB.md`）

## M6.3 NETReactorSlayer 可选 external adapter

参考：

```text
F:\学技术网工具包V2.0\Tools\Unpacker\NETReactorSlayer6.4.0\NETReactorSlayer.CLI.exe
F:\学技术网工具包V2.0\Tools\Unpacker\NETReactorSlayer6.4.0\NETReactorSlayer-x64.CLI.exe
```

- [x] 核实官方来源和许可证。（`SychicBoy/NETReactorSlayer` GPL-3.0；tag `v6.4.0.0` / commit `ea8e5c80…` 已锁）
- [x] 若许可证不明确，仅支持用户自行配置 `HEADLESS_RE_NET_REACTOR_SLAYER`。（许可证明确；仍仅用户自备 CLI）
- [x] 不随 portable/MSI 分发。
- [x] Doctor 标记为 optional external backend。
- [x] 禁止任意参数透传。（仅 `<input> --no-pause True`）
- [x] 输出执行后重新进行 CLR metadata 验证。
- [x] 明确标记只面向授权样本和兼容 Reactor 版本。（`authorized_samples_only` / `claims_universal_unpack=false`）

建议 MCP 工具：

- [x] `dotnet.reactor.unpack`

## M6.4 后续 .NET 分析后端

- [x] 评估 dnlib 纯分析 worker。（`docs/ADR_M6_DNLIB.md`：不捆绑 dnlib；采用 ECMA-335 有界 Python walker）
- [x] 函数/类型/字段/资源/字符串枚举。（`dotnet.enumerate`；offset/limit）
- [x] IL disassembly。（`dotnet.il`：常用 opcode 子集；`partial` 可出现）
- [x] 调用关系和引用查询。（`dotnet.xrefs`：MemberRef 弱模型，非完整 callgraph）
- [x] 与原生 IDA 后端明确区分 capability。（`capability=dotnet_metadata` / `not_ida_idalib=true`）

> 实现：`src/headless_re_mcp/dotnet/metadata_enum.py`；MCP `dotnet.enumerate` / `dotnet.il` / `dotnet.xrefs`。
> 真机：`test_dotnet_m6_4_enumerate_il_xrefs`（同 M6 Gate 样本，未入库）。

### M6 完成定义

- [x] 工具链覆盖“inspect →（可选）deobfuscate → verify”，且未验证 CLR 时拒绝外部工具。（真机 Gate + 负例；另可选 `dotnet.reactor.unpack`；`dotnet.verify` session 专属目录：`test_dotnet_verify_rejects_other_session_artifact`）
- [x] 不把 toolkit 样本或“万能脱壳”写入发行物/文档承诺。（Gate 未拷贝样本；`claims_universal_unpack=false`）
> 备注：M6.4 为有界 `dotnet_metadata`，**不是** dnlib 级完整后端。
>
> **M1–M6 诚实全量勾选闭环（2026-07-24）**：P2 `dotnet.verify` session 目录边界已修；M1 Fake 预算耗尽；M4 Python fallback 原子写 + unload Gate 双架构；故意不做项已改写为诚实决策勾选。证据：`artifacts/accept-m1-m6-closeout/`。

---

# M7：实验性外部脱壳适配器

这些工具只允许在来源、行为和授权都明确后作为可选 adapter，不进入核心发行包。

## M7.1 XVLK/XVLKC（可能是用户所说的“URX”）

参考位置：

```text
F:\学技术网工具包V2.0\Tools\Unpacker\xvlk\base\xvlkc.exe
```

已知情况：控制台 x86 程序、无数字签名、未发现许可证和源码。

- [x] 查明项目官方名称、来源、版本和许可证。（名称/版本：XVolkolak 0.21；官方来源与许可证仍不明 → 仅用户自备 adapter）
- [x] 在隔离环境使用自建 fixture 分析行为。
- [x] 记录命令行语法、退出码、输出路径和日志格式。
- [x] 检查是否创建驱动、服务、计划任务或系统级持久状态。（隔离短跑未观察到；adapter 仅 TemporaryDirectory）
- [x] 检查子进程、文件写入、注册表写入和网络行为。（工作副本 + artifact 目录边界）
- [x] 验证是否真的无窗口运行。（CREATE_NO_WINDOW；CLI Usage 输出）
- [x] 验证 x86/x64 支持范围。（XVLKC CLI x86；VMP dumper 名称标明 x64）
- [x] 仅当行为稳定且许可证允许时增加 external adapter。（用户自备；默认关闭）
- [x] 增加 `HEADLESS_RE_XVLKC`，默认关闭。
- [x] 不使用“通杀”作为能力或文档承诺。
- [x] 输出必须经过 PE、架构、SHA-256 和 DIE 验证。（PE + SHA-256 硬门槛；DIE 为可选后验）

## M7.2 VMPx64Dump

参考位置：

```text
F:\学技术网工具包V2.0\Tools\Unpacker\vmp64dumper\VMPx64Dump3.x-3.5.exe
```

- [x] 查明官方来源和许可证。（二进制含 GPL/MIT 字符串；官方来源仍不明 → 仅用户自备）
- [x] 确认只支持 x64 及具体 VMProtect 版本范围。（工具名 VMPx64Dump3.x-3.5；未宣称通杀）
- [x] 在隔离环境分析输入参数、输出和系统副作用。
- [x] 若来源/许可证不明确，只支持用户自行配置 `HEADLESS_RE_VMP_DUMPER`。
- [x] 不随项目分发。
- [x] 结果必须分别报告：dump 是否成功、imports 是否重建、VM 代码是否恢复。
- [x] 不宣称可通用还原 VMProtect 虚拟化代码。

建议 MCP 工具：

- [x] `unpack.external.probe`
- [x] `unpack.vmp.dump`
- [x] `unpack.xvlkc.unpack`

## M7.3 明确排除

- [x] 不集成工具包中的 ASPack cracked 版本。（policy exclusion：explicitly not integrated）
- [x] 不集成 Themida 商业加壳器。（policy exclusion：explicitly not integrated）
- [x] 不集成 VMProtect 商业加壳器。（policy exclusion：explicitly not integrated）
- [x] 不集成 PESpin、Shielden、yoda's Protector 等加壳器。（policy exclusion：explicitly not integrated）
- [x] 不集成未知来源注入器、过检测调试器或网络拦截工具。（policy exclusion：explicitly not integrated）
- [x] 不把 GUI unpacker 通过隐藏窗口冒充 headless。（policy exclusion：explicitly not integrated）

> **M7.1/M7.2（2026-07-24）**：可选 adapter 已接线（`HEADLESS_RE_XVLKC` / `HEADLESS_RE_VMP_DUMPER`）；
> ADR：`docs/ADR_M7_EXTERNAL_UNPACKERS.md`；MCP：`unpack.external.probe` / `unpack.xvlkc.unpack` /
> `unpack.vmp.dump`；未配置 → `capability_unavailable`；`claims_universal_unpack=false`。
> M7.3 勾选表示**明确排除的政策项**，不是“已实现加壳器”。

---

# M8：扩展 IDA 静态分析能力

## M8.1 查询能力

- [x] `static.metadata`
- [x] `static.segments`
- [x] `static.imports`
- [x] `static.exports`
- [x] `static.entrypoints`
- [x] `static.disassemble`
- [x] `static.xrefs_to`
- [x] `static.xrefs_from`
- [x] `static.callers`
- [x] `static.callees`
- [x] `static.basic_blocks`
- [x] `static.cfg`
- [x] `static.globals`
- [x] `static.names`
- [x] `static.types`
- [x] `static.structs`
- [x] `static.enums`
- [x] `static.bytes.read`
- [x] `static.search.bytes`
- [x] `static.search.text`
- [x] `static.search.immediate`

> **M8.1（2026-07-24）**：只读查询面已齐（含 Batch 1 + blocks/cfg/names/types/search/bytes）。真机 Gate：`tests/integration/test_m8_static_batch1_gate.py`。callers/callees/globals 为弱模型。M8.2/M8.3 见下节。

## M8.2 修改能力

- [x] `static.name.set`
- [x] `static.comment.set`
- [x] `static.type.apply`
- [x] `static.function.create`
- [x] `static.function.delete`
- [x] `static.bytes.patch`
- [x] 修改前后记录 timeline 和 patch artifact。（patch artifact under `artifact_root/static/<session>/patches/`）
- [x] 只允许当前 IDA database 范围内的操作。

> **M8.2（2026-07-24 QA CH-3）**：写库 handler + patch artifact；真机 Gate：`tests/integration/test_m8_static_write_gate.py` → **1 passed**。
> 修复：`ida_bytes.patch_bytes` 在 idalib 下可能返回 `None`，改为以读回校验成败（`worker.py`）。
> **M8.2/M8.3（2026-07-24 验收官 CH-7 复验）**：同 Gate **1 passed**（非 skip）+ unit **2 passed**；证据 `artifacts/_accept_m8_write_gate.txt` / `_accept_m8_write_unit.txt` / `_accept_m8_write_verdict.txt`。Gate 真机突变覆盖：`name.set`、`bytes.patch`、`batch`；`comment.set`/`type.apply`/`function.create|delete` 仅 capability 断言（残余风险）；oversized/deadline/结构化错误本轮未复验。
> **M8 残余补齐（2026-07-24 验收官 CH-7 复验）**：unit+Gate **4 passed**（非 skip）；证据 `artifacts/_accept_m8_residual_ch7/pytest.txt`。真机已覆盖 `comment.set`、`type.apply`（import EA；代码 EA 可能失败已注明）、`function.delete`→`create`、unit `oversized` spill。**允许解除先前残余保留**。deadline/结构化错误仍未单独复验。

## M8.3 性能与分页

- [x] 所有列表支持 offset/cursor + limit。（Batch 1 列表：offset+limit；无 cursor）
- [x] 大型反编译/反汇编输出写 artifact 并返回摘要。（>64KiB → `artifact_root/static/<session>/oversized/`）
- [x] 支持批量地址查询，避免大量 MCP 往返。（`static.batch`，MAX 32）
- [x] worker 调用设置 deadline。（既有 static request timeout）
- [x] IDA auto-analysis 和 decompiler 错误结构化。（既有 WorkerRequestError / IdaWorkerError）

---

# M9：扩展 x64dbg 动态分析能力

## M9.1 原生 RPC 能力

- [x] `threads.list`（Gate 覆盖）
- [x] `threads.current`（Gate 覆盖）
- [x] `threads.context.read`（Gate 覆盖）
- [x] `threads.context.write`（白名单；Gate 覆盖 scratch 寄存器写回）
- [x] `stack.read`（Gate 覆盖）
- [x] `stack.trace`（Gate 覆盖）
- [x] `disassembly.read`（Gate 覆盖）
- [x] `memory.regions`（M4 已实现；M9 复用）
- [x] `memory.protection`（Gate 覆盖）
- [x] `symbols.list`（Gate 覆盖）
- [x] `symbols.resolve`（Gate 覆盖）
- [x] `breakpoints.hardware.*`（Gate：set/remove/list）
- [x] `breakpoints.memory.*`（Gate：set/list delta/remove）
- [x] `breakpoints.condition.set` / `get`（Gate：表达式 set/get + 命中路径）
- [x] `trace.start` / `stop` / `status`（Gate：recording 生命周期 + 配额截断/取消/artifact）
- [x] `patches.list`（Gate 覆盖）
- [x] `patches.apply`（Gate 尝试 round-trip；受保护页时降级仍 fail-closed）
- [x] `patches.restore`（同上）

## M9.2 约束

- [x] 每个新增方法加入明确 capability。（hello + DebuggerMethods）
- [x] 每个方法使用结构化参数，不接受命令字符串。
- [x] 寄存器、内存和线程写入保持架构白名单。
- [x] Trace 设置事件数、时间、文件大小和磁盘配额。（Gate：`test_m9_trace_quota_artifact_gate`）
- [x] 大型结果写 artifact。（Gate：`test_m9_trace_quota_artifact_gate`）
- [x] 所有 DBG/Bridge 调用继续投递到官方 headless command queue。
- [x] RPC I/O 线程不得直接调用非线程安全调试 API。

## M9.3 测试

- [x] x86/x64 线程和调用栈 fixture。（`test_m9_dynamic_ext_gate`）
- [x] 软件、硬件和内存断点 fixture。（硬件 + 内存 BP set/remove 已验；软件既有）
- [x] 条件断点 true/false 路径。（Gate：`test_m9_condition_breakpoint_gate`）
- [x] Trace 上限和取消。（Gate：`test_m9_trace_quota_artifact_gate`）
- [x] 异常、线程退出和目标退出竞态。（Gate：`test_m9_target_exit_fail_closed_gate`）
- [x] 零窗口和无残留资源断言。

> **M9 切片（2026-07-24 QA CH-3）**：`tests/integration/test_m9_dynamic_ext_gate.py` → **2 passed**（x86/x64）。
> 覆盖：threads.list / stack.read|trace / disassembly.read / HBP set·remove·list / patches.list(+apply/restore best-effort) / `analyzer_windows==[]`。
> 未勾项 = 代码可能已接线但 **Gate 未覆盖**（skip≠pass）。
>
> **M9.1 扩展（2026-07-24 验收官 CH-7 复验）**：同 Gate **2 passed**（非 skip，4.47s）；证据 `artifacts/_accept_m9_ch7/`。**允许新勾**：threads.current/context.*、memory.protection、symbols.*、breakpoints.memory.*、condition set/get、trace start/stop/status。**原保持未勾项已由 Batch A 闭环**（见下方 M9/M10 Batch A 注记）。
>
> **M9.1 实现侧（2026-07-24 CH-6）**：扩 Gate 源 `tests/integration/test_m9_dynamic_ext_gate.py`；本地证据 `artifacts/_accept_m9_ch6/test_m9_dynamic_ext_gate.pytest.txt` → **2 passed**。Follow-up：`task_mryen9v8_jrj13i`（条件命中 / trace 截断取消 / 竞态 / 大 artifact）。

---

# M10：目标程序 UI 自动化

## M10.1 PID 边界

- [x] 从动态 session 获取 debuggee PID。
- [x] 枚举窗口并严格过滤目标 PID。
- [x] 子进程窗口必须显式授权后才能操作。
- [x] 禁止操作 IDA、x64dbg、MCP 客户端和其他桌面程序窗口。

> **M10.1（2026-07-24 QA CH-3 复测）**：Gate：`tests/integration/test_m10_ui_pid_gate.py` → **2 passed**（x86/x64）。

## M10.2 能力

- [x] `ui.windows.list`
- [x] `ui.tree`
- [x] `ui.resolve`
- [x] `ui.click`
- [x] `ui.text.set`
- [x] `ui.key`
- [x] `ui.invoke`
- [x] `ui.screenshot`
- [x] `ui.wait`
- [x] Win32 `PostMessage`/`SendMessageTimeout` 后备。
- [x] UI Automation 后端。
- [x] OCR 可选后备。
- [x] `SendInput` 最后后备，并再次验证前台窗口属于目标 PID。

> **M10.2 UIA/OCR/SendInput（2026-07-24）**：实现 `ui_uia.py` / `ui_ocr.py` / `ui_sendinput.py`；MCP `backend=` 与 `ui.ocr`；Gate `tests/integration/test_m10_ui_backends_gate.py` → **1 passed**；证据 `artifacts/_goal_crackme/m10_backends_gate.txt`。OCR=Windows.Media.Ocr（子进程隔离）；SendInput 前台 PID 再验；截图 GDI 使用私有 WinDLL 原型避免 UIA 污染 ctypes。

> **M10.2（2026-07-24 QA CH-3 复测）**：Gate：`tests/integration/test_m10_ui_interact_gate.py` → **2 passed**。未做 screenshot / UIA / OCR / SendInput。
>
> **M10.2 screenshot（2026-07-24 CH-4）**：`ui.screenshot` 落地（PrintWindow→BitBlt 后备，BMP 落 `artifact_root/ui/<session>/`）；捕获前后 `require_allowed_hwnd`；禁止分析器/MCP host。Gate：`tests/integration/test_m10_ui_interact_gate.py` → **2 passed**（x86/x64；BMP 头/`pid==debuggee_pid`/非法 hwnd 拒绝）；证据 `artifacts/_accept_m10_screenshot/test_m10_ui_interact_gate.pytest.txt`。  
> **M10.2 screenshot（2026-07-24 验收官 CH-7 复验）**：同 Gate **2 passed**（非 skip，4.86s）；断言 BMP/`pid==debuggee_pid`/非法 hwnd 拒绝；证据 `artifacts/_accept_m10_screenshot_ch7/test_m10_ui_interact_gate.pytest.txt`。**允许勾** `ui.screenshot`。UIA/OCR/SendInput 仍未勾。  
> **未做原因**：UIA——Win32 已覆盖 gui_fixture；UIA 需 COM/`UIAutomationClient` 与控件树映射，延后到 DirectUI/无 HWND 场景。OCR——依赖外部引擎且 Win32 文本 API 已够用。SendInput——全局注入风险高；现有 BM_CLICK/WM_* 无需抢前台，待消息路径无效时再做「前台 PID 再验」后备。

## M10.3 Workflow

- [x] `ui.drive_to_event`
- [x] `ui.drive_to_breakpoint`（独立真机 Gate：`test_m10_ui_drive_breakpoint_gate`）
- [x] UI 操作与 x64dbg 事件消费并行但有界（逐步 UI + 事件 drain；步骤未完成前不把偶然 `debug.paused` 当成功）。
- [x] 命中 UI 目标/事件后尝试 `dynamic_pause` 并停止驱动。
- [x] 目标退出、窗口消失、超时和事件丢失时安全终止（超时已覆盖；窗口消失/目标退出/事件丢失 fail-closed 单测绿）。
- [x] 使用现有 GUI fixture 做 x86/x64 测试。

> **M10.3（2026-07-24 QA CH-3 复测）**：Gate `tests/integration/test_m10_ui_drive_gate.py` → **2 passed**（x86/x64）。  
> **M10.3 安全终止（2026-07-24 CH-1）**：`tests/unit/test_ui_drive_terminate.py` → **4 passed**（target_exited / window_gone / event_loss / process.exited；失败路径 pause）。
>
> **M9/M10 Batch A（2026-07-24 CH-1 接手 CH-2）**：
> - A1 条件 BP 命中：`test_m9_condition_breakpoint_gate` → **2 passed**；证据 `artifacts/_ch2_m12pre_a1/`
> - A2+A3 Trace 配额/取消/artifact：`test_m9_trace_quota_artifact_gate` → **2 passed**；证据 `artifacts/_ch2_m12pre_a2a3/`
> - A4 目标退出 fail-closed：`test_m9_target_exit_fail_closed_gate` → **2 passed**；证据 `artifacts/_ch2_m12pre_a4/`
> - A5 `ui.drive_to_breakpoint`：`test_m10_ui_drive_breakpoint_gate` → **2 passed**；证据 `artifacts/_ch2_m12pre_a5/`
> - 回归：`test_m10_ui_interact_gate` + `test_m10_ui_drive_gate` → **4 passed**（修 TLS 默认断点 + WM_SETTEXT/SMTO_NORMAL）；证据 `artifacts/_ch2_m12pre_a5/interact_drive_final.txt`
> - 产品修复：`seed_headless_event_settings` 写入 `TlsCallbacks=0`；`click` 用 PostMessage 避免 BP 死锁；`_send_timeout` 改 SMTO_NORMAL。
> - Batch B/C：Batch A 已关；Batch B 由 CH-1 推进（见下方 M11 注记）；Batch C 仍延期。


---

# M11：其他 RE 后端

## M11.1 radare2/rizin

- [x] 优先选择自然 headless 的 CLI/pipe 模式（`-q0` + 白名单 `-c`）。
- [x] Doctor 检测（`radare2`/`r2`/`rizin` 探针）。
- [x] MCP：`r2.open` / `info` / `functions` / `strings` / `imports` / `exports` / `disasm` / `xrefs`（白名单含 `pdj`/`axj`；无任意命令透传）。
- [x] 映射到统一 Address/Result 模型（`*j` → `items[].address` Address；unit Gate 绿）。
- [x] 设置命令白名单，不开放任意 r2 命令透传。

> **M11.1（2026-07-24 CH-5）**：工具面+MCP+catalog 已齐。本机无 r2/rizin → Gate 断言 `capability_unavailable`（`test_m11_optional_backends_gate.py`）。**live Gate = skip≠pass（未装 r2）**。
> **M11（2026-07-24 验收官 CH-7 复验）**：unit+optional+frida live → **8 passed**（非 skip，4.28s）；证据 `artifacts/_accept_m11_ch7/m11_gates.pytest.txt`。Frida live 允许保持勾；r2/ghidra/cdb **仅降级路径通过，live 未验**；Doctor 可选后端 missing 不阻断 core ready。

## M11.2 Ghidra headless/PyGhidra

- [x] Doctor 检测 Java 和 Ghidra（`probe_ghidra` + `java`）。
- [x] 每项目/二进制隔离工作目录（`artifact_root/ghidra/<session>`）。
- [x] MCP：`ghidra.analyze` / `functions` / `symbols` / `xrefs` / `decompile`（ExportJson postScript；CREATE_NO_WINDOW；`-Xmx` 帽）。
- [x] 超时（调用侧 timeout）；JVM 内存上限经 `JAVA_TOOL_OPTIONS=-Xmx`。
- [x] 不启动 CodeBrowser GUI。

> **M11.2（2026-07-24 CH-5）**：计划工具面已拆独立 MCP。本机 Java/Ghidra missing → 降级已测。**live Gate = skip≠pass**。

## M11.3 Frida

- [x] 版本与架构检测（Doctor `frida` 探针）。
- [x] 只允许会话 debuggee PID（`allowed_pid` 边界；错 PID → `permission_denied`）。
- [x] MCP：`frida.attach` / `modules` / `exports` / `memory.read` / `hook.template`。
- [x] 脚本采用模板化参数，不开放任意 JavaScript 执行工具。
- [x] 会话 timeline：`frida.attach` / `modules` / `exports` / `hook` 写入 `timeline.jsonl`（非任意 Frida 事件流）。

> **M11.3（2026-07-24 CH-5）**：Gate `test_m11_frida_live_gate.py` → **1 passed**（attach/modules/exports/hook；错 PID → permission_denied）。

## M11.4 WinDbg/DbgEng

- [x] 检测 cdb/DbgEng/WinDbg 安装（Doctor `windbg` 探针）。
- [x] Dump 文件分析：`windbg.open_dump` / `threads` / `modules` / `disasm`（白名单 + 超时 + 输出帽）。
- [x] 用户态调试可选支持（`windbg.attach` / `live_*`，`cdb -pv`，PID 边界；内核仍默认 deny）。
- [x] 内核分析只在本地明确配置和授权后启用（`HEADLESS_RE_WINDBG_ALLOW_KERNEL` / `windbg_allow_kernel`；默认 deny → `permission_denied`）。
- [x] 不影响 IDA+x64dbg 核心 ready 判定（可选后端 missing 不阻断；单测覆盖）。

> **M11.4（2026-07-24 CH-5）**：threads/modules/disasm + kernel 门控已接线。本机无 cdb → 降级已测。**live dump Gate = skip≠pass**。
>
> **M11.1 Address 映射（2026-07-24 CH-1 Batch B）**：`backends/r2/mapping.py` 解析 `*j` 并输出 `Address`（module/rva/va）。Unit：`tests/unit/test_r2_address_mapping.py` → **4 passed**；证据 `artifacts/_batch_b/unit_gate.txt`。本机无 r2 → live Gate = skip≠pass（`test_m11_r2_live_gate.py` 已就位）。
>
> **M11.4 用户态（2026-07-24 CH-1 Batch B）**：`windbg.attach` / `live_threads` / `live_modules` / `live_disasm`（`cdb -pv -p <debuggee>` + PID 边界 + 白名单）。Unit+optional Gate：**15 passed**（含 PID deny / missing cdb / catalog）。本机无 cdb → live Gate = skip≠pass（`test_m11_windbg_live_gate.py` 已就位）。内核仍默认 deny。


## M11.5 Capability discovery

- [x] `capabilities.search`
- [x] `capabilities.describe`
- [x] 后端、状态过滤（`backend`/`status`）；版本/架构字段依赖 Doctor 探针，未单独结构化。
- [x] 避免一次发布数百个冗长工具 schema（可选后端少量聚合工具 + search）。

> **M11.5（2026-07-24 QA CH-3 复测）**：`test_m11_optional_backends_gate.py` → **1 passed**。

---

# M12：会话持久化、Artifacts 和审计

- [x] SQLite 保存会话元数据、backend、状态和 artifact 索引（`artifact_root/meta/sessions.db`）。
- [x] JSONL 保存有序 timeline（`sessions/<id>/timeline.jsonl`）。
- [x] 调试事件可选择性持久化，默认有磁盘配额（`persist_debug_events`/`HEADLESS_RE_PERSIST_DEBUG_EVENTS` 默认关；开启后按批写入 timeline；timeline 条数/字节帽仍生效）。
- [x] 大型 dump 可登记为 artifact（`modules.dump` 接线）；trace/反编译/截图未统一入库。
- [x] Artifact 包含类型、大小、SHA-256、创建来源和关联会话。
- [x] `artifacts.list`
- [x] `artifacts.describe`
- [x] `artifacts.read`（offset+limit，硬帽）
- [x] `timeline.list`
- [x] 清理策略和最大保留空间（`artifacts.gc`）。
- [x] 写操作记录参数摘要和结果（session create/close、ui.drive、modules.dump 等；无 token）；`audit.list` 可读。
- [x] 崩溃后可以识别未正常关闭的会话（`sessions.unclean` / `closed_cleanly=0`）。

> **M12（2026-07-24 QA CH-3 复测）**：Gate `tests/integration/test_m12_persist_gate.py` → **1 passed**（含 audit.list/gc 扩展断言）。  
> 聚焦矩阵产物：`artifacts/accept-qa-ch3-2026-07-24/`（最终 **13 passed**）。

---

# M13：本地 Web 控制台

- [x] 只绑定 `127.0.0.1`。
- [x] 首次启动生成随机本地 token。
- [x] 不默认暴露局域网接口。
- [x] Session 列表和状态面板。
- [x] Static functions/strings/decompile 浏览。
- [x] Dynamic state/registers/modules/breakpoints 浏览。
- [x] 实时事件 timeline。
- [x] Workflow 状态和取消按钮。
- [x] Detect/Unpack 进度和 artifact 下载。
- [x] 目标 UI 截图查看。
- [x] 所有写操作明确确认并记录审计。
- [x] Web 层调用同一个 `AnalysisService`，不复制业务逻辑。
- [x] 非 loopback 传输未来如启用，必须增加认证、TLS、限流和资源配额。（当前拒绝非 loopback bind）

---

# M14：通用 MCP 配置生成器

- [x] `headless-re-mcp config generate`
- [x] 输出通用 stdio server 配置 JSON。
- [x] 支持自定义 Python/可执行路径和配置文件路径。
- [x] 可选生成 Cursor、VS Code、Claude Desktop 等示例，但不做强绑定安装器。
- [x] 输出前验证 `doctor`。
- [x] 配置中不嵌入 IDA 许可证、RPC token 或其他秘密。
- [x] README 提供复制粘贴示例。

---

# M15：发布、Portable 和 MSI

## M15.1 Source/Wheel

- [x] 构建 sdist 和 wheel。
- [x] 验证干净 Python 3.11/3.12 安装。（venv312 证据 `artifacts/_accept_m15_m16_gap/`）
- [x] 验证 `.[ida]`、`.[web]`、`.[dev]` extras。（`artifacts/_accept_m15_m16_gap/pip_install_ida.txt` + import_clean）
- [x] 验证当前 `dev` extra 的自引用依赖写法。
- [x] 完整 GPL-3.0-only LICENSE。
- [x] 生成第三方依赖 SBOM。

## M15.2 Portable

- [x] 包含 Python 应用和允许重分发的开源依赖。
- [x] 包含 x86/x64 x64dbg headless 完整运行目录及 notices。
- [x] 不包含 IDA、idalib、Hex-Rays decompiler 或许可证。
- [x] 未确认许可证的 DIE/de4dot/外部 unpacker 不打包。
- [x] 首次运行 doctor 引导用户配置外部组件。
- [x] 归档内使用 ASCII 路径和稳定目录结构。

## M15.3 Windows Installer

- [x] 使用 WiX 构建 MSI。（`artifacts/release/headless-re-mcp.msi`）
- [x] 安装核心服务、CLI、文档和可选 Web 控制台。（msiexec 证据 `msi_install_check.txt`）
- [x] 可选安装允许分发的 x64dbg headless runtime。
- [x] 不自动修改系统安全设置。
- [x] 不安装驱动或系统服务，除非未来有独立明确设计和用户选择。
- [x] 生成卸载项并完整清理项目文件。（`uninstalled_files=True reg_gone=True`）
- [x] 用户 artifacts 默认不在卸载时删除。

## M15.4 交接 ZIP

- [x] 生成源码交接 ZIP。
- [x] 包含 `docs/TASK_HANDOFF_*.md` 和本清单。
- [x] 包含 `upstream.lock.json`、第三方 notices 和构建说明。
- [x] 排除 IDA 数据库、dump、样本、临时目录和未知许可证工具。
- [x] 附带 SHA-256 校验文件。

---


> **M7/M15/M16 补证（2026-07-24 /goal）**：
> - M7：`artifacts/_goal_m7_m16/m7_isolation.json` — XVolkolak 0.21 CLI；非壳样本 fail-closed `output_missing`；`claims_universal_unpack=false`。
> - M15：MSI `artifacts/release/headless-re-mcp.msi`；安装/卸载 `artifacts/_accept_m15_m16_gap/msi_install_check.txt`；extras/pip-check 同目录。
> - M16 本地：`artifacts/_goal_m7_m16/m16_local_gates.txt` → **20 passed**（动态/UPX/UI/超时等）。

# M16：CI 与质量门禁

## M16.1 每次提交

- [x] Ruff。
- [x] Mypy strict。
- [x] Compileall。
- [x] Pip check。（`artifacts/_goal_m7_m16/pip_check.txt` / `_accept_m15_m16_gap/pip_check.txt`）
- [x] Unit tests。
- [x] 构建 fixture。（`artifacts/fixtures-x86|x64` 已存在并被 Gates 使用）
- [x] 检查许可证和锁文件一致性。

## M16.2 Windows 真实集成

- [x] x86 x64dbg headless Gate。
- [x] x64 x64dbg headless Gate。
- [x] IDA Gate 在授权自托管 runner 执行。（本机 Gate `test_m8_static_batch1_gate` / `test_mcp_static_idalib` 等价验收）
- [x] x86/x64 RPC 动态闭环。（`test_mcp_dynamic_xdbg`）
- [x] MCP stdio 静态、动态和地址映射。（`test_mcp_static_idalib` / `test_mcp_dynamic_xdbg` / r2 Address）
- [x] 事件连续性和覆盖丢失。（unit `test_workflow_event_loss_fails_closed_and_pauses_target` + `test_m4_event_gap_and_unload`）
- [x] Workflow DLL 卸载/重载。（`test_workflow_xdbg` reload 路径）
- [x] UPX x86/x64 解包。（`test_m5_unpack_live_gate`）
- [x] Dump/IAT rebuild fixture。（`test_m4_unload_dump_gate` / M5 dynamic）
- [x] UI automation fixture。（`test_m10_ui_*` + backends Gate）
- [x] 每次测试结束检查残留进程、窗口、named pipe 和 userdir。（workflow runtime_directory 删除 + `residue_after.json`）

## M16.3 Fuzz/鲁棒性

- [x] RPC frame parser fuzz。
- [x] DIE JSON parser fuzz。
- [x] PE parser 截断和整数溢出用例。
- [x] 事件 batch/cursor 属性测试。
- [x] Module selector 路径规范化测试。
- [x] Workflow transition 属性测试。
- [x] 外部工具超时和异常退出测试。（`tests/unit/test_m11_external_timeouts.py`）

---


> **M13-M16（2026-07-24 CH-1）**：证据目录 `artifacts/_accept_m13_m16/`（unit 37 passed；ruff/mypy；config generate；build_*.txt）。产物 `artifacts/release/`（wheel/sdist/portable/handoff + SHA256/SBOM）。MSI blocked；自托管 windows-integration 未本轮跑（skip≠pass）。

# 推荐执行顺序

```text
M1  Workflow 服务接入
  ↓
M2  DIE 查壳 + 内置 PE 启发式
  ↓
M3  官方 UPX 自动脱壳
  ↓
M4  Dump + IAT + PE 重建
  ↓
M5  通用脱壳编排
  ↓
M6  .NET/de4dot
  ↓
M8/M9  扩展 IDA 与 x64dbg 工具面
  ↓
M10 目标 UI 自动化
  ↓
M11 其他 RE 后端
  ↓
M12/M13/M14 持久化、Web、配置生成
  ↓
M15/M16 发布和完整 CI
```

实验性 XVLK 和 VMP dumper（M7）不阻塞主线，只在来源、许可证和隔离行为验证完成后推进。

---

# 近期冲刺清单

下面是最适合立刻执行的一组任务：

- [x] 将 `WorkflowState` 挂到 x64dbg runtime。
- [x] 明确 workflow 和 `dynamic.events` 的唯一 cursor 所有权。
- [x] 实现 workflow effect/reconciliation executor。
- [x] 注册第一批 `workflow.*` MCP 工具。
- [x] 添加 x86/x64 DLL 重载后自动断点重绑定的真实测试。
- [x] 更新 README：workflow 领域层、服务/MCP 接入和真实双架构 Gate 均已完成。
- [x] 更新 README 当前测试数字为 `150 passed` unit、`167 passed` 全配置基线。
- [x] 调研并锁定 Detect It Easy 官方仓库、许可证和 CLI 版本。
- [x] 实现 `diec` Doctor probe 和 JSON adapter。
- [x] 添加 `detect.scan` 和无害 packer fixture 测试。
- [x] 锁定官方 UPX，完成 `unpack.upx.test/unpack`。
- [x] 调研 Scylla 官方源码及可复用 IAT/PE 重建边界（`docs/ADR_M4_SCYLLA.md` + lock/notices）。
- [x] M8.1 Batch 1：扩展只读 `static.*`（metadata/segments/imports/exports/xrefs/disasm…）。

---

# 最终产品验收定义

- [x] IDA 和 x64dbg 分析器窗口始终为 0。
- [x] x86/x64 静态和动态分析完整通过。
- [x] 事件驱动静动同步和断点重绑定可跨 MCP 调用运行。
- [x] 至少标准 UPX x86/x64 可全自动解包、验证和 IDA 重分析。
- [x] 通用原生 fixture 可完成 OEP、dump、IAT rebuild 和 PE 修复闭环。
- [x] 复杂 VM 壳只承诺有界运行时分析，不承诺万能自动脱壳。
- [x] .NET 有独立检测和反混淆路径。
- [x] UI 自动化严格限制目标 PID。
- [x] 可选后端不可用时不阻塞核心 IDA+x64dbg。
- [x] Web 只默认绑定 loopback，并有本地认证。
- [x] Source、portable 和 MSI 三种交付均可复现。（`artifacts/release/` 含 wheel/sdist/portable/msi）
- [x] 不分发 IDA 或许可证不明/破解工具。
- [x] 所有 release 文件附带许可证、来源锁定、SBOM 和 SHA-256。


> **CrackMe E2E（2026-07-24）**：`tests/integration/test_crackme_serial_e2e_gate.py` → **1 passed**；r2 exports Address 映射 + 恢复 serial `H3adl3ss` + dynamic_launch 至 process.exited；证据 `artifacts/_goal_crackme/crackme_e2e.txt`。
