# ADR M4.1：Scylla 来源、许可证与实现形态

> 状态：Accepted（2026-07-23）  
> 范围：仅 M4.1 决策；不实现 M4.2+ RPC / MCP 工具  
> 相关：`docs/ROADMAP_TODO.md` §M4、`native/xdbg-headless-rpc/`、`upstream.lock.json`

## 1. 背景

Headless RE-MCP 需要在官方 `headless.exe` 会话内完成「运行到 OEP → dump → IAT 扫描/验证 → PE 重建」能力。工具包中的中文 Scylla GUI：

```text
F:\学技术网工具包V2.0\Tools\Patch\scyllahhb_75665\Scylla_x86_CN.exe
F:\学技术网工具包V2.0\Tools\Patch\scyllahhb_75665\Scylla_x64_CN.exe
```

仅允许作**行为对照**，不得作为正式来源、不得拷入发行物、不得用窗口自动化冒充 headless。

## 2. 官方来源与锁定

| 角色 | 仓库 | 锁定点 | 许可证 |
|------|------|--------|--------|
| **权威上游（primary）** | https://github.com/NtQuery/Scylla.git | `master` tip `e87fd578a3fa0e68b873dcc98951788f3a40e055`（2019-01-05） | GPL-3.0（仓库 SPDX；正文为 GPLv3） |
| 最近正式 tag（参考） | 同上 | tag `v0.9.8` → commit `db5eb01d99bdb9c992328c10bc821f5bb45b2a73`（2015-05-03） | 同上 |
| **维护 fork（secondary）** | https://github.com/x64dbg/Scylla.git | 默认分支 `vs13` tip `aa89026b9e469b0c4b3d2bedb464dd7ab521cd6e`（2022-10-19） | GPL-3.0 |

说明：

- x64dbg 官方 README 将 import reconstruction 指向 [NtQuery/Scylla](https://github.com/NtQuery/Scylla)；`x64dbg/Scylla` 是其 fork，含较新的 VS 构建修复与读内存保护相关补丁（例如 `VirtualProtectEx` 只请求 `PAGE_READONLY`），实现阶段可对照 cherry-pick，但仍以 NtQuery 为权威出处。
- 本 ADR **不复制** Scylla 源码进树；锁文件只记录可复现修订。真正改编时再更新 `THIRD_PARTY_NOTICES.md` 的版权与改动说明。
- **禁止**把工具包 `Scylla_*_CN.exe`、未知修改二进制或破解包装进 portable/MSI。

## 3. 许可证结论（可否改编进本项目）

- 本项目：`GPL-3.0-only`（根目录 `LICENSE`）。
- Scylla：`GPL-3.0`（与 GPLv3 兼容）。将算法/源码**改编并链接进**本项目发行物（含编译进官方 `headless`）在许可证上**允许**；改编物须继续以 GPL-3 条款分发，并保留版权与 notices。
- 因此：**不需要**为许可证原因被迫做成「用户自备 opaque EXE」的 external adapter。
- External adapter 边界仅保留给：来源不明、许可证不明、或无法无窗口安全运行的第三方（本 ADR 明确排除工具包中文 GUI）。
- 第三方社区 wrapper（如 `scylla_wrapper_dll`）**不**作为正式依赖；其接口仅作「无 GUI 能力面」的行为参考。

## 4. 采用 / 放弃理由

### 采用

- 成熟的 x86/x64 IAT 搜索、API 解析（含 ordinal / forwarded 相关实践）、dump 与 PE 修复启发式。
- 与本项目同为 GPL-3 家族，可合法改编进 headless 发行物。
- 已有「DLL 导出：iat search / iat fix auto」历史，证明核心逻辑可与 GUI 解耦——但我们**不**直接依赖其 GUI 进程或第三方 wrapper 二进制。

### 放弃

- **Scylla GUI / 工具包中文版**：违反 headless 硬约束；来源与修改不明。
- **窗口自动化**（隐藏/驱动 Scylla 窗口）：明确禁止。
- **独立外部 Scylla 进程以 PID 附着同一 debuggee**：与本项目已由 `headless` 独占调试会话冲突，易产生双重调试器/句柄竞争，且难以保证零分析器窗口。
- **把完整 Scylla 工程原样链进 headless 而不剥离 GUI**：会引入 Win32 UI、对话框与多余依赖，破坏 `CREATE_NO_WINDOW` / `analyzer_windows == []` 验收。

### 对源码的处理策略（M4.2+）

**允许选择性改编源码（prefer）+ 必要时按算法重写**，而不是「永久仅参考、禁止复制任何行」。

- M4.1 阶段：lock + 架构边界；**零源码拷贝**。
- M4.2+：以 NtQuery 锁定 commit 为基线，按模块摘取 IAT/API/dump 相关逻辑；GUI/对话框/进程选择器一律不纳入。每段改编必须在 notices 中列出文件、commit 与本地修改摘要。

## 5. 实现形态决策

**选定：编译进官方 x64dbg `headless` RPC（`native/xdbg-headless-rpc`）+ Python 服务层做 artifact / PE 后处理。**

| 候选 | 结论 | 理由 |
|------|------|------|
| 独立 Scylla CLI | **否（主路径）** | 缺现成官方无窗口 CLI；自造 CLI 仍要二次附着进程；与现有会话模型重复。 |
| 独立 Scylla DLL（LoadLibrary 进 MCP/旁路进程） | **否（主路径）** | 仍要通过 OpenProcess 读内存；线程与调试所有权不在 Bridge/command queue；分发与签名面更大。 |
| **注入官方 headless RPC** | **是** | 已有暂停态、`modules.list`、`memory.read`、DBG/Bridge 线程投递模型；新方法可延续同一契约与零窗口验收。 |

### 5.1 必须进入 `native/xdbg-headless-rpc` 的能力

下列操作依赖暂停态目标、Bridge/DBG 非线程安全 API，且必须经
`GUI_EXECUTE_ON_GUI_THREAD` / `GuiExecuteOnGuiThreadEx` 投递到官方 headless command queue：

- 内存区域枚举与保护查询（`memory.regions` / `memory.protect.query`）
- 按模块 `SizeOfImage` 的运行时 dump（`modules.dump`）
- 运行时 PE 头快照（`pe.headers.runtime`；需重编 headless，否则服务层可 `memory.read` 回退）
- 基于已加载模块 export 目录的 IAT 候选扫描与 thunk 读取（`imports.scan` / `imports.read`，骨架启发式）
- 需要就地读写目标进程 IAT/补丁页时的重建辅助（native `imports.rebuild` 仍为 `not_implemented`；默认 Python artifact 重建）

约束（与现有契约一致）：

- **paused-only**：与 `modules.list` 相同；running 返回可重试的结构化错误（如 `debuggee_running`）。
- 单次 dump/扫描设最大字节数；大结果**写会话 artifact**（临时文件 + 原子 rename），不经 MCP 回传完整字节。
- RPC I/O 线程禁止直接调 DBG/Bridge。
- 不引入任意命令透传。

### 5.2 可放在 Python 服务层的能力

- 读取 dump artifact、SHA-256、大小与配额校验
- 基于文件的 PE 重建（section raw 布局、目录项、checksum 字段变更报告）
- Import descriptor / INT / IAT / 字符串表的**文件侧**拼装与验证
- 重建报告、DIE 复扫、IDA idalib 重开比较（函数/import/string 计数）
- Workflow / unpack 编排状态机（M5；字段名待 M3 稳定后对齐，本 ADR **不写死**尚未存在的 `unpack.auto` 路由字段）

### 5.3 与现有 cursor / workflow / modules 契约的兼容

- **唯一事件 cursor**：dump/IAT 路径**不**新增原生事件消费者；继续由 `dynamic.events` / `workflow.events.consume` 共享 `DebugEventCursor`。
- **推荐顺序**：`workflow`/`dynamic` 导航到 OEP 候选并稳定 `paused` → 再调用 dump/imports 类 paused 快照方法。事件 `dropped > 0` 时必须重新 `modules.list` / 状态快照，不得假设可重放。
- **模块身份**：dump 目标用现有 `selector`（base / path / name + 可选 sha256），与 `modules.resolve` 一致；卸载竞态返回 `module_not_found`。
- **副作用边界**：dump 默认只读内存并写 artifact；若未来提供写 IAT 的 RPC，必须显式工具名与审计，不得静默改写。

## 6. 明确禁止

- [x] 禁止依赖 Scylla GUI 窗口自动化（含隐藏窗口）。
- [x] 禁止集成工具包 `Scylla_*_CN.exe`。
- [x] 禁止宣称「万能脱壳」。
- [x] 禁止在 M4.1 实现任何 `memory.*` / `imports.*` / `unpack.dump_*` 代码（属 M4.2+）。

## 7. M4.2 / M4.3 接口草案（实现进度）

原生 RPC（paused-only，有界）：

```text
memory.regions                 # 已实现
memory.protect.query           # 已实现
modules.dump                   # 已实现（artifact 路径）
pe.headers.runtime             # 源码已实现；需重编 headless（否则 Python memory.read 回退）
imports.scan                   # 骨架已实现（多候选+置信）
imports.read                   # 只读骨架已实现
imports.rebuild                # 固定 not_implemented（重建走 Python unpack.*）
```

MCP（服务层编排，artifact 路径回传摘要）：

```text
unpack.dump_module
unpack.iat.scan
unpack.iat.validate
unpack.iat.rebuild
unpack.pe.rebuild
unpack.verify
```

与 M3/`unpack.auto` 的衔接文案与错误码：**待 M3.3 合并后对齐**，本 ADR 不锁定字段名。

## 8. 风险

- Scylla 上游更新停滞（master 停于 2019）；现代 Windows / CFG / API set 需在实现期补测试与启发式。
- 直接移植 GUI 工程会污染 headless；必须按「算法模块」裁剪。
- IAT 扫描存在多候选；必须返回置信度列表，禁止盲选唯一结果。
- 大镜像 dump 的磁盘配额与超时必须在 M4.2 落地前写入常量。

## 9. 下一步（非本任务）

1. M4.2：在 `rpc_methods.cpp` 增加上述 paused-only 方法与 capability。
2. 按 lock 检出 NtQuery 源码到 `upstream/Scylla`（research checkout，不进 release）。
3. 摘取/改编 IAT 与 dump 核心，更新 `THIRD_PARTY_NOTICES.md`。
4. M4.3/M4.4：Python PE 重建与 MCP 工具；自建 fixture Gate。
