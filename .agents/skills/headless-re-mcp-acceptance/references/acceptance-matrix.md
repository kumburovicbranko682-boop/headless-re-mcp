# Headless RE-MCP 项目验收矩阵

本清单用于审查**当前产品代码**。它不是路线图完成声明。每项均按“实现、接线、闭环、证据”分开判定。

## A. 项目定义与范围

- 产品名、Python 版本、Pydantic/MCP SDK、GPL-3.0-only 是否一致。
- 适用范围是否持续写明：自有样本研究、授权渗透测试、CTF/教学实验。
- `local_full_access` 是否仍仅表示受限语义工具，而不是任意命令执行。
- 非 loopback/远程 transport 若存在，是否有认证、租户/会话隔离和资源限制；若无，文档不得称远程安全完成。
- Source、Portable、MSI、handoff ZIP 只在 artifact 实际存在且可核验时判定完成。

## B. 真 Headless 硬门槛

### IDA

- 使用 IDA 9.x `idapro`/`idalib`，不是 GUI executable 自动化或隐藏窗口。
- 每个 session 使用隔离 Python worker；初始化、超时、失败和退出路径清楚。
- worker 内 `idapro` 在 IDAPython 模块之前导入和初始化。
- 子进程使用 `CREATE_NO_WINDOW`；分析器 PID 的全部顶层窗口（包括 hidden）为零的 Gate 设计存在。
- target GUI 可以显示，但分析器 GUI 不得显示；两者 PID 不能混淆。

### x64dbg

- 实际使用官方 `src/headless/headless.cpp` target。
- 自研 RPC 源通过 CMake/inject 编入 headless target，不是 GUI plugin 或 x64dbg GUI 隐藏方案。
- x86/x64 architecture routing 依据 PE，而非调用者任意选择。
- `build.ps1` 的输出收集、环境传递和 `-RunGate` 逻辑本身可达；脚本报错时不能用手工成功掩盖脚本未完成。
- Gate 应枚举 analyzer PID 的所有顶层窗口；`analyzer_windows: []` 才通过。

## C. RPC、进程和安全边界

- Named Pipe 名称不可预测，worker PID 与连接目标一致。
- 每进程随机 256-bit token；首次 `rpc.hello` 完成鉴权；重复 hello fail closed。
- 验证 protocol=`headless-re-xdbg`、version=1、architecture、PID、capabilities。
- frame 为 `uint32_le + UTF-8 JSON`，最大 1 MiB；拒绝超长、负向语义、畸形 JSON 和未知方法。
- debugger dispatch 最大 30 秒；调用侧 timeout 不绕过 native 上限。
- 内存读写最大 2 MiB；module dump 最大 64 MiB；event batch 最大 256。
- 无 `dynamic.command`、任意 x64dbg 命令、shell、CMD、PowerShell、Python/system command MCP 入口。
- 所有 adapter 使用固定 argv、`shell=False`（或完全不启用 shell）、`DEVNULL`、Windows `CREATE_NO_WINDOW`、stdout/stderr 上限。
- timeout 是否只杀父进程；若无 Job Object/process-tree 约束，记录残留子进程风险。
- close/fail/timeout 后 pipe、worker、临时 userdir 和 handle 是否有明确清理路径。

## D. 会话与后端 runtime

- 状态机：created/opening/ready/running/suspended/closing/closed/failed 的转换一致。
- 同一 session 可同时持有 IDA 与 x64dbg runtime，key 为 `(session_id, BackendKind)`。
- runtime open/close/fail 不会误关闭另一个 backend。
- 每个 x64dbg runtime 具备 worker、per-runtime lock、唯一 event cursor、workflow runtime。
- 查找 runtime 和执行请求之间有 current-runtime 校验，避免 close/reopen ABA。
- `close_session`、`close_all`、失败清理可重复且不会泄漏。
- 全局锁与 runtime 锁顺序一致，无明显死锁或 read-modify-write 竞态。

## E. 静态分析

- `static.open/functions/strings/decompile` 从 MCP 到 IDA worker 全链路可达。
- 参数有分页、字符串长度、地址域边界。
- IDA 错误结构化返回，不泄露 worker traceback 为成功数据。
- image base、architecture、input SHA 等静态身份进入地址同步。
- 不把 built-in parser 或 M6 metadata walker 标成 `ida_idalib`。

## F. 动态分析

逐项核对 native capability、client 封装、service 方法和 MCP tool（适用时）：

- debug.state/launch/attach/stop/pause/resume/step_into/step_over
- registers.read/write
- memory.read/write/regions/protect.query
- modules.list/dump
- events.read
- breakpoints.list/set/remove
- pe.headers.runtime
- imports.scan/read

额外检查：

- paused-only 能力在 native 层 enforce，而不只靠文档。
- write 和 breakpoint 操作做类型、范围、长度、状态校验。
- attach 是否有授权本机进程范围和 architecture 校验。
- native 明示 `not_implemented` 的方法不得由 MCP/文档宣称 native 已完成；Python rebuild 必须如实标注实现层。

## G. 地址同步与多模块 ASLR

- 主模块：`IDA VA - IDA image base = RVA`；`runtime VA - runtime module base = RVA`。
- 显式模块：`preferred VA - PE ImageBase = RVA`；`runtime VA - loaded base = RVA`。
- `preferred` 不冒充 IDA database address。
- `ModuleSelector` 支持 base/path/name 与可选 sha256；选择歧义时 fail closed。
- 每次调用重新取 paused 模块快照，验证 path/SHA/architecture/image size。
- 加载、卸载、重载/rebase 后旧 mapping 失效。
- 地址加减检查 underflow/overflow、module range 与 64-bit JSON 边界。

## H. 原生事件与 M1 workflow

### Event journal

- 1024 固定槽，单调 sequence，cursor/next_cursor/dropped/dropped_total/has_more 一致。
- client 对 batch 的所有不变量做协议校验。
- `dynamic.events` 和 workflow 使用同一个 cursor；一批事件只读取一次再扇出。
- overflow/drop 后 fail closed：模块目录/地址/导航不得继续信任旧状态。

### Lifecycle/navigation/breakpoint intents

- lifecycle：valid/stale/unloaded；截断 identity 保守失效。
- navigation：事件预算、目标退出、取消和超时有界；非目标 pause 能继续，但不会无限 resume。
- breakpoint intent 使用 module identity + RVA；重载后绑定新 runtime VA。
- remove-before-set；one-shot 命中后清理。
- revision/intent_id/address 全量确认，陈旧删除不能误确认新 binding。
- 原生 breakpoint 已自动消失时，只有在 `breakpoints.list` 验证后置条件后才能幂等确认。

## I. M2 检测

- 内置 PE parser 纯读取目标，不执行文件；文件大小和解析边界有上限。
- DIE `diec` 为可选证据源：固定 JSON argv、无 shell、超时、输出上限、无窗口。
- 输出保留多个 candidates/evidence/confidence，不强行归并为确定结论。
- detection failure 与 `not_packed` 区分。
- ExeinfoPE 如会产生顶层窗口，应保持 deferred，不能因 silent flags 存在而接入。

## J. M3 UPX

- 只接受官方锁定 UPX（当前基线 5.2.0）或明确版本策略。
- argv 白名单仅 `--version`、`-t`、`-d -o`；无任意 flags。
- 输入执行前后 SHA 一致；不覆盖源文件；输出进入 session artifact。
- UPX section hint 在 DIE 缺失时可路由标准 UPX，但 modified/cracked 不能冒充成功。
- 输出重新检测/验证；`claims_universal_unpack=false`。

## K. M4 runtime dump / IAT / PE rebuild

- runtime PE header 和 imports 能力 paused-only。
- module dump 原子 `.partial`→replace，最大 64 MiB；模块卸载竞态如未解决需明确记录。
- IAT scan 是候选启发式，不自动确认；read/validate 有地址和数量上限。
- Python PE remap/rebuild 检查所有 offset、alignment、directory 和文件大小边界。
- `.himps` 或 import section 构造不覆盖源文件。
- 报告拆分 `changes`、`warnings`、`unfixed`。
- forwarded exports、checksum、TLS/exception/delay import、runtime IAT patch 等未实现项如实暴露。
- M4 工具成功后是否进入 M5 artifact ledger/phase bridge。

## L. M5 通用脱壳编排

### 状态与持久化

- phase：detected/running/oep_candidate/dumped/imports_rebuilt/verified/reanalyzed/failed/cancelled。
- `_FORWARD`、terminal 集合与 `transition()` 语义一致。
- state snapshot 和 timeline 使用原子写；timeline 顺序和 artifact ledger 不丢事件。
- 明确区分落盘快照与“服务重启可恢复”；无 load/recovery 时不能称 durable/resumable workflow。
- cooperative timeout 明示 in-flight RPC 仍可能完成；cancel 不宣称回滚动态内存或 artifact。

### 并发与唯一性

- `_unpack_sessions` 的读取、检查、转换、写回在统一 per-session lock/事务内。
- `unpack.start` 不得静默覆盖仍 active 的 session；需拒绝、显式 replace 或保留旧 ledger。
- `_guard_unpack_active` 和后继 phase bridge 不存在 TOCTOU 丢更新。
- 一个 operation 的 artifact、timeline、phase 是同一次原子语义更新。

### OEP 与阶段桥

- 多信号 scoring，不把候选自动确认；caller 显式 `confirm_oep`。
- write-to-execute/new executable/left stub/imports hint 等 observation 来源清楚。
- phase bridge 的 intended hops 实际可达，不能被外层 `can_transition` 条件提前阻断。
- artifact phase 与 session phase 若允许不一致，需有明确 provenance 语义；否则为不变量缺陷。
- dump → imports rebuilt → verified → reanalyzed 全链有可达产品入口。

### 路由

- UPX route 可实际执行并推进 phase。
- dynamic route 进入 running，等待 caller 观察/确认，不自动宣称 OEP。
- .NET route 不是 `deferred_m6` 桩；必须检查其 M6 artifact 是否回写 M5 ledger/phase，而不只记录 `routed_m6`。

## M. M6 .NET

### CLR inspect

- COR20 directory + 可映射 header + BSJB metadata 才是 `verified_clr`。
- 分类 not_dotnet/clr_directory_hint/pure_managed/mixed_mode 的 flags 逻辑正确。
- 外部工具调用前 `require_verified=True`。
- metadata stream offset/size 必须在 metadata blob 内；截断/溢出 fail closed。
- metadata stats 的 table walking 不因未知前置 table 或坏 row size 给虚假名称。

### de4dotEx 与 NETReactorSlayer

- config/Doctor/service/MCP 全链路存在；固定 argv，不接受任意参数。
- 输入最大 256 MiB、执行前后 SHA、输出不覆盖、失败删除 partial。
- stdout/stderr 上限与**实际生成 artifact 文件大小上限**分别检查；只有 capture 上限不等于 artifact 上限。
- NRS 在隔离工作副本执行，只收集明确的 `*_Slayed*` 文件；候选歧义 fail closed。
- timeout 后子进程树风险被处理或明确记录。
- probe 必须识别正确产品；`return bool(text)` 一类宽松后备可能 false-ready。
- 成功 output 再次 `inspect_dotnet(require_verified=True)`。
- 输出写入当前 session 专属目录，并回写 M5 artifact ledger/phase（若路线图宣称 M5/M6 闭环）。

### metadata walker

- capability 名为 `dotnet_metadata`，响应明确 `not_ida_idalib=true`。
- `DEFAULT_LIMIT=64`、`MAX_LIMIT=256`、`MAX_IL_BYTES=4096`、`MAX_IL_INSNS=256` 实际 enforce。
- tables/streams/index read 全部 bounds-check；禁止 Python 短 slice 被静默解析为零后继续。
- 支持出现的 metadata table row size；未知 table 需 fail closed。
- fat method header 使用 header size (`Size` dwords)，不能固定假设 12 bytes；tiny/fat format bits 校验。
- IL opcode/operand 子集：未知 opcode 或 `0xFE` 两字节 opcode不能破坏后续对齐；若无法可靠对齐，应停止并标 `partial`，而非继续给伪指令流。
- branch operand 与 metadata token 语义区分；MemberRef 列表只称 weak xref hints，不称完整 callgraph。
- enumeration 的分页不能先无界 materialize 整张恶意表；至少有 metadata/file/table rows 的全局硬上限。

### artifact ownership

- `dotnet.verify(session_id, path)` 必须限制到当前 session 专属 artifact 目录，不能只检查整个 artifact root。
- 明确允许验证哪些 M4/M5/M6 artifact；跨 session 路径 fail closed。
- symlink/junction/reparse point 和 resolve 后路径仍在 owner root。

## N. MCP surface 与错误契约

- 每个产品 service 方法的 MCP tool 是否存在；每个 MCP tool 是否调用正确 service 方法。
- Pydantic/FastMCP schema 对 timeout、limit、正数和枚举做约束。
- `ok/data/error/meta` envelope 一致；错误 code/message/details 保留 adapter/native 语义。
- docstring 不夸大：`verify`、`xref`、`unpack`、`reanalyzed` 的含义准确。
- 不注册遗留、重复、越权或任意命令工具。
- capability unavailable 与 process failed、invalid input、not found 区分。

## O. 供应链、许可证和第三方声明

- `upstream.lock.json`：官方 URL、tag、commit、license、release asset SHA、binary 名称一致。
- 镜像 URL 不能取代官方来源；下载安装始终校验 SHA。
- `THIRD_PARTY_NOTICES.md` 与锁文件一致，说明 bundled/not bundled 和修改归属。
- GPL-3.0-only 与直接复制/链接的第三方许可证兼容。
- Scylla 若仅参考未复制，声明必须保持；一旦选择性移植算法/源码，应加入 per-file copyright、commit 和 modifications。
- 非 OSI/工具包 binary（如 ExeinfoPE 中文构建）不得进入 Source/Portable/MSI。
- 工具包样本、PDB、cleaned output 不进入仓库或发行包。
- lock `generated_at`、README/ADR 版本陈旧属于文档问题，但来源/SHA 不一致可升级为阻塞发布。

## P. 文档与完成口径

- README、ROADMAP、M4/M5 status、handoff、native README 的能力列表一致。
- 测试数字必须注明命令、范围、环境和日期；不能混用 unit、全配置、Gate 数字。
- `3 passed`/`4 passed` 等冲突必须列为文档缺陷，等待原始输出统一。
- 旧“32 source files”“167 passed”等基线不代表当前 M6。
- “已接线”“源码完成”“实测通过”“发布就绪”四种措辞严格区分。
- deferred、not implemented 和 known limitations 不能藏在深层文档而在 README 宣称全完成。

## Q. 发布产物（仅发布验收）

- Source 包不含 cache、artifact、toolkit sample、许可证不明 binary、用户路径和 token。
- Portable 包含运行所需文件、默认仅 loopback/stdio、安全配置和第三方 notices。
- MSI 安装/卸载路径、升级、用户数据保留、签名状态如实记录。
- x86/x64 native 产物和 architecture 检验。
- SHA-256 清单与 ZIP/MSI 实际字节一致；ZIP CRC 可读。
- 干净机 smoke、IDA 授权依赖、可选工具缺失时降级行为。
- analyzer zero-window Gate 与 target GUI 例外仍成立。
