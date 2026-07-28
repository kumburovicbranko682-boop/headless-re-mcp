# Headless RE-MCP 任务交接文档

> 来源会话：`sess_52c8a14b-c8f7-4d06-8c46-2bfa84268c29`  
> 工作目录：`E:\x64dbgmcp`  
> 状态：静态、基础动态、主模块兼容同步、显式多模块映射和真实调试事件流均已通过更新后的完整验收

本文是当前可复现基线，不是聊天记录。旧版文档中“x64dbg 尚未构建”“统一 MCP 尚未
实现”“跨后端地址换算尚未实现”等信息已经失效，以本文为准。

---

## 1. 最终结论

当前项目已经提供一个真正无分析器窗口的统一 MCP 基线：

- IDA Professional 9.3 通过官方 `idalib` 执行静态分析；
- x86/x64 动态调试均使用 x64dbg 官方 `headless.exe` 和 Bridge/DBG core；
- 自研扩展通过 Windows 命名管道提供受限、版本化 RPC；
- Python 服务支持同一会话同时附着 IDA 和 x64dbg；
- 独立纯函数域层同时支持主模块兼容换算和显式加载模块
  `preferred VA ↔ RVA ↔ runtime VA` 映射；
- 显式 selector 可按 `base`、`path` 或 `name` 定位，按需校验 PE 架构、布局与 SHA-256；
- x64dbg 插件回调进入固定容量原生日志，服务端以独占 cursor 连续消费；
- MCP stdio 已覆盖静态查询、基础动态读写/运行控制、真实事件批次、主模块兼容同步和
  显式多模块映射；
- 不启动、隐藏或自动化普通 IDA/x64dbg GUI；
- 所有真实 Gate 中 `analyzer_windows == []`；
- 最终全测试：`128 passed in 86.01s`；
- 严格 Doctor：`ready: true`。

本基线不等同于完整逆向产品。跨调用持久化的事件驱动导航 workflow、模块生命周期
自动失效编排、断点编排、持久化事件重放、脱壳、目标 UI 自动化、Web 控制台和安装器
仍属于后续阶段。

---

## 2. 当前架构

```text
MCP stdio server
  └─ AnalysisService
      ├─ SessionRegistry
      │   └─ 状态：created/opening/ready/running/suspended/closing/closed/failed
      ├─ core/addressing.py
      │   ├─ 主模块 static VA ↔ RVA ↔ runtime VA 兼容换算
      │   └─ 显式 module selector + preferred VA ↔ RVA ↔ runtime VA
      ├─ core/events.py
      │   └─ 防御性事件协议解析 + 单向 cursor
      ├─ (session_id, BackendKind.IDA)
      │   └─ IdaWorkerClient → 独立 Python worker → idalib
      └─ (session_id, BackendKind.X64DBG)
          └─ XdbgClient → 独立 headless.exe
              └─ Windows named pipe RPC
                  └─ 官方 command queue → Bridge/DBG core
```

### 2.1 服务层职责

`src/headless_re_mcp/core/service.py` 按 `(session_id, BackendKind)` 管理 runtime，不再用
单一 worker 覆盖整个会话。因此静态和动态后端可以共存。

底层动态状态映射：

```text
x64dbg idle    → SessionState.READY
x64dbg running → SessionState.RUNNING
x64dbg paused  → SessionState.SUSPENDED
```

指定后端未打开时返回 `backend_unavailable`。致命 worker/RPC 错误会终止并移除对应
runtime，同时按当前服务语义将会话标记为 `failed`。

### 2.2 静态数据流

```text
MCP tool
  → AnalysisService.static_*
  → IdaWorkerClient（结构化 stdio）
  → idalib worker
  → Result envelope
```

已完成 `create → static.open → functions/strings/decompile → close`，同时覆盖进程内服务和
真实 MCP stdio。

### 2.3 动态数据流

```text
MCP tool
  → AnalysisService.dynamic_*
  → XdbgClient.request / wait_for_state
  → 长度前缀 JSON frame
  → 原生 RPC I/O 线程
  → 官方 headless command queue
  → Bridge/DBG core
```

运行控制只负责提交官方命令；异步状态变化由 Python 客户端有界轮询，避免把 DBG 事件
等待堵在 RPC I/O 或 command queue 上。

### 2.4 调试事件数据流与契约

```text
x64dbg plugin callback
  → 固定大小 EventRecord 快照
  → 1024 槽 EventJournal
  → events.read(cursor, limit)
  → XdbgClient 防御性协议解析
  → AnalysisService 独占推进 runtime cursor
  → MCP dynamic.events（不暴露 cursor）
```

事件不是由两次 `debug.state` 差分推断。回调线程不构造 JSON、不执行阻塞 RPC/Bridge
工作；消费线程才编码。单批范围为 1..256，sequence 严格递增。cursor 落后覆盖窗口时，
`dropped` 给出本批精确丢失数，`dropped_total` 给出原生日志累计覆盖数。MCP 调用方不能
回退或跳跃 cursor；看到丢失后应通过状态、模块等当前快照重新同步。

`src/headless_re_mcp/core/events.py` 校验批次窗口、容量、计数、next cursor、has_more、
sequence 连续性、signed 64-bit 整数边界，以及每类事件允许的 `kind/data` 字段。畸形
响应升级为致命 `rpc_protocol_error` 并使对应 runtime 失效。

### 2.5 地址同步数据流与契约

文件：`src/headless_re_mcp/core/addressing.py` 与 `core/models.py`。域层不持有 worker、会话
锁、缓存或传输状态，只负责目录解析、模块身份、范围校验和地址换算；
`AnalysisService` 每次读取当前运行时快照后调用域层，MCP handler 只处理参数和
`Result` envelope。职责分成三段：

```text
Runtime module catalog
  → 解析当前 x64dbg modules.list 快照
ModuleSelector
  → 显式按唯一 base、规范化 path 或唯一 name 定位
  → 可选 sha256 文件身份校验
Rebased mapping
  → PE preferred VA ↔ RVA ↔ x64dbg runtime VA
```

主模块兼容接口仍为 `sync.static_to_runtime` / `sync.runtime_to_static`：

```text
IDA static VA - IDA image base = RVA
x64dbg runtime VA - main module base = RVA
```

显式多模块接口为 `modules.list`、`modules.resolve`、
`sync.module_preferred_to_runtime` 和 `sync.module_runtime_to_preferred`。其中
`preferred` 明确指 PE Optional Header 的 `ImageBase`，不是 IDA 当前数据库地址，也不会
实际 rebase IDA 数据库。只有显式选中的模块才读取 PE 头并计算 SHA-256，不会批量哈希
系统 DLL。

每次 resolve/映射都重新取得当前模块快照，不缓存已卸载模块。校验覆盖 PE machine/
架构、preferred base、`SizeOfImage`、运行时范围、SHA-256、选择唯一性和 `[base,
base + size)` 地址边界。结构化错误覆盖 `backend_unavailable`、`module_not_found`、
`module_ambiguous`、`module_identity_mismatch`、`architecture_mismatch`、
`address_out_of_range` 及无效 PE/模块元数据。

模块目录与映射只能在稳定 `paused` 状态读取。生命周期验证采用：

```text
dynamic.resume
  → 有界轮询 dynamic.events
  → module.loaded 按 name 识别 / module.unloaded 按已知 runtime base 识别
  → dynamic.pause 并等待稳定 paused
  → modules.list / resolve / mapping
```

这条链避免在运行中调用 `modules.list`，也不使用固定长 sleep 掩盖竞态。

---

## 3. x64dbg 原生 RPC

### 3.1 文件与注入方式

新增：

```text
native\xdbg-headless-rpc\headless_rpc.h
native\xdbg-headless-rpc\rpc_internal.h
native\xdbg-headless-rpc\rpc_methods.cpp
native\xdbg-headless-rpc\rpc_events.cpp
native\xdbg-headless-rpc\rpc_server.cpp
native\xdbg-headless-rpc\inject.cmake
```

修改：

```text
native\xdbg-headless-rpc\build.ps1
upstream\x64dbg\src\headless\headless.cpp
```

`headless.cpp` 仅包含受 `HEADLESS_RE_XDBG_RPC` 保护的 RPC 生命周期钩子。主体在外部
模块中；`inject.cmake` 向官方 `headless` target 注入源码、include、宏和 Jansson，并
防止重复注入。未注入时官方 stdin command loop 行为保持不变。

注意：工作目录不是 Git 仓库，尤其要手工跟踪 `upstream\x64dbg` 中的改动。

### 3.2 启动与鉴权

旧版 `-rpc-pipe`/`-rpc-token` 参数已经废弃，因为 x64dbg 自身参数解析器会拒绝它们。
`XdbgClient` 只给新子进程注入：

```text
HEADLESS_RE_XDBG_RPC_PIPE
HEADLESS_RE_XDBG_RPC_TOKEN
```

原生端读取后立即从自身环境删除。每次启动都使用随机 pipe nonce、256-bit token 和隔离
临时 userdir。客户端校验：

- headless PE 架构；
- 命名管道 server PID；
- hello PID；
- hello 架构；
- capability 数组。

应用配置变量是：

```text
HEADLESS_RE_X64DBG_HEADLESS_X86
HEADLESS_RE_X64DBG_HEADLESS_X64
```

### 3.3 帧与错误模型

```text
protocol = "headless-re-xdbg"
version = 1
frame = uint32_le(encoded_json_size) + UTF-8 JSON object
max encoded JSON = 1 MiB
max dispatch timeout = 30 s
```

请求/响应严格匹配字符串 ID。错误包含 `code`、`message`、`details` 和 `retryable`。
Jansson 使用 `json_dump_callback` 在编码期间执行 1 MiB 上限；当前仓库版本不导出
`json_get_alloc_funcs`，不要依赖该符号。

RPC I/O 线程只做收发/解析。DBG/Bridge 调用通过
`GUI_EXECUTE_ON_GUI_THREAD`/`GuiExecuteOnGuiThreadEx` 投递到官方 headless command
queue。

### 3.4 能力白名单

```text
debug.state
debug.launch
debug.attach
debug.stop
debug.pause
debug.resume
debug.step_into
debug.step_over
registers.read
registers.write
memory.read
memory.write
modules.list
events.read
breakpoints.list
breakpoints.set
breakpoints.remove
```

没有任意 x64dbg 命令入口。寄存器按架构白名单；内存单次最多 256 KiB；断点接口只接受
明确地址。

### 3.5 `debug.pause` 状态机

运行控制响应描述的是命令提交瞬间，可能仍是 `running`；调用方随后等待稳定状态。
`debug.pause` 现在幂等：

```text
无 debuggee → not_debugging
running      → 提交官方 pause，随后轮询 paused
paused       → 直接成功返回当前状态
```

这解决了目标在 x64dbg 后续事件上自行暂停时，紧随其后的 `pause` 因竞态失败的问题。
`XdbgClient.wait_for_state` 还必须先确认本次命令对应的转换事件，再采样转换后的状态；若
先采样旧 `paused`、后读到新 `debug.resumed`，会把转换前状态误判为命令完成。该交错已
有稳定单元回归测试。

### 3.6 原生事件实现

`rpc_events.cpp` 注册 17 类插件回调，使用固定容量纯值快照环形日志。日志容量 1024，
默认批次 100，最大批次 256。事件覆盖调试启停、process/thread、module load/unload、
breakpoint、exception、pause/resume/step 和 attach/detach，来源固定为
`x64dbg.plugin_callback`。

官方 headless 不链接 debugger DLL 导入库，因此启动时从已加载的 x86
`x32dbg.dll` 或 x64 `x64dbg.dll` 动态解析 `_plugin_registercallback` /
`_plugin_unregistercallback` 两个接口。缺失接口会使 RPC 启动明确失败，避免引入
headless↔debugger DLL 静态循环依赖。

RPC 停止时先停止事件捕获并注销所有回调，再停止 transport 和销毁状态。真实测试在
2048 线程事件生成期间关闭客户端，双架构均无死锁、UAF、窗口或进程残留。

### 3.7 正常关闭顺序

已确认必须使用：

```text
停止 active debuggee（如有）
  → 保持 RPC pipe 连接
  → 向官方 stdin command loop 写入 exit
  → 等待 headless.exe 退出
  → 关闭本地 pipe handle
  → 删除临时 userdir
```

先断管道再发送 `exit` 曾导致 x64 关闭等待 15 秒后被终止。修复后双架构均退出码 0，
无残留分析器窗口、进程或 `headless-re-xdbg-rpc-*` 临时目录。

---

## 4. Python 客户端与 MCP

### 4.1 `XdbgClient`

文件：`src/headless_re_mcp/backends/x64dbg/client.py`。

已实现：

- x86/x64 PE 匹配与子进程生命周期；
- `CREATE_NO_WINDOW` 和隐藏 startup info；
- 隔离 `-userdir`；
- Win32 `ctypes` overlapped named-pipe I/O；
- 严格帧边界、ID、hello 和超时；
- 异常退出诊断；
- 顶层分析器窗口持续监测；
- 有界状态轮询；
- `events.read` 窄客户端 API 与畸形批次致命协议错误映射；
- 可观测的 `pid`、`exit_code`、`runtime_directory`；
- 正确的正常关闭与强制终止后备。

协议单测覆盖：帧上限/下限、请求 ID、错误响应、错误 token 的结构化错误、超时、异常
退出诊断、事件请求边界、畸形事件响应升级，以及
`exit → wait → pipe close → userdir cleanup` 顺序。

### 4.2 MCP 工具

`src/headless_re_mcp/mcp/server.py` 已注册：

```text
session.create / get / list / close
static.open / functions / strings / decompile
dynamic.open / state / events / wait / launch / attach / stop / pause / resume
dynamic.step_into / step_over
dynamic.registers.read / write
dynamic.memory.read / write
dynamic.modules
modules.list / resolve
dynamic.breakpoints
dynamic.breakpoint.set / remove
sync.static_to_runtime
sync.runtime_to_static
sync.module_preferred_to_runtime
sync.module_runtime_to_preferred
```

测试精确断言工具面，确认不存在 `dynamic.command`。`dynamic.events` 的 MCP schema 只暴露
`session_id`、1..256 的 `limit` 和有界 transport timeout，不暴露原生 cursor。服务为每个
session/backend runtime 独立持有 cursor，空批次不推进，正常批次只向前推进。
`modules.resolve` 和两个 `sync.module_*` 工具要求显式嵌套 `selector`，不接受扩散到顶层
的选择参数。所有同步工具仍是白名单语义接口，不会透传任意 x64dbg 命令。服务返回统一
`Result`/`RpcError` envelope。

---

## 5. Fixture

### 5.1 当前内容

```text
fixtures\native\console_fixture.c
fixtures\native\gui_fixture.c
fixtures\native\event_fixture.c
fixtures\native\CMakeLists.txt
fixtures\native\build.ps1
fixtures\native\verify.py
```

Console/headless shared fixture：

- `console_fixture.exe` 使用 console subsystem，保留确定性输出与命令行构建自检；
- `headless_fixture.exe` 使用同一源码和 Windows subsystem，不创建 UI，供所有 x64dbg
  动态集成与地址生命周期测试使用；
- `noinline fixture_marker`；
- 确定性数值输出；
- 创建并等待线程；
- `--event-stress 1..2048` 可控生成线程创建/退出事件；
- `--module-cycle` 立即加载并卸载同目录 `event_fixture.dll`，用于事件吞吐测试；
- `--module-lifecycle-windows` 在加载后和卸载后各提供 3 秒运行窗口，供事件驱动测试在
  观察回调后主动暂停并读取稳定模块快照；
- 仅 `--debug-wait` 显式触发 5 秒等待，默认行为不变。

Event DLL fixture：无害、同架构 DLL，仅用于稳定触发真实 module load/unload 回调。

GUI fixture：

- Windows GUI subsystem；
- 无害数值输入与变换按钮；
- `noinline fixture_transform`；
- 正常消息循环；
- 不包含用户名、密码或登录语义。

### 5.2 x86 GUI 过滤问题与解决方案

本机 MinGW x86 链接器可以成功生成 `gui_fixture.exe`，但外部过滤器会在约 250 ms 内移除
该文件。去除凭据语义后现象不变，且本机无法通过 Defender cmdlet 取得归因证据，因此
不能声称具体安全产品是根因，也没有关闭或修改任何安全软件。

可靠规避方案已经固化：

- Windows 上 `build.ps1` 通过 `vswhere.exe` 优先选择 Visual Studio 2022/MSVC；
- x86 使用 `Win32` generator，x64 使用 `x64` generator；
- CMake 将单配置/多配置产物统一写到 build root；
- `headless_fixture.exe` 使用 Windows subsystem，动态测试不再弹出 console target 窗口；
- 链接后等待 500 ms，确认 headless/GUI/DLL 产物仍存在；
- 最后执行 console 行为、`CreateNoWindow` headless DLL 生命周期自检，以及 PE 架构/
  subsystem 校验；
- 若显式设置 `HEADLESS_RE_FIXTURE_CC_X86/X64`，才改用 Ninja/指定编译器；若产物被
  移除，脚本会明确失败。

最终命令已通过：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File E:\x64dbgmcp\fixtures\native\build.ps1 -Architecture all
```

结果：x86/x64 各 4 个 fixture 通过架构/subsystem 校验，并以无窗口专用目标完成测试
DLL 显式加载/卸载自检。切换后 x86/x64 动态 RPC 短冒烟各 `1 passed`。

### 5.3 产物

```text
E:\x64dbgmcp\artifacts\fixtures-x86\console_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x86\headless_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x86\gui_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x86\event_fixture.dll
E:\x64dbgmcp\artifacts\fixtures-x64\console_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x64\headless_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x64\gui_fixture.exe
E:\x64dbgmcp\artifacts\fixtures-x64\event_fixture.dll
```

---

## 6. 构建与运行环境

### 6.1 本机基线

```text
Python: 3.12.10
IDA: C:\Program Files\IDA Professional 9.3
idapro: C:\Python312\Lib\site-packages\idapro
VS Build Tools: E:\VSBuildTools
MSVC: E:\VSBuildTools\VC\Tools\MSVC\14.44.35207
x64dbg source: E:\x64dbgmcp\upstream\x64dbg
```

x64dbg 构建目录：

```text
E:\x64dbgmcp\artifacts\x64dbg-x86
E:\x64dbgmcp\artifacts\x64dbg-x64
```

运行产物：

```text
E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe
E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe
```

必须保留完整 `Release` 目录及 DLL/Qt 依赖。`build.ps1` 会 staging 同架构
`TitanEngine.dll`；缺失运行依赖时常见退出码为 `0xC06D007E`。

### 6.2 x64dbg 构建

完整配置/构建：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -BuildParallelism 2 -RunGate
```

增量构建：

```powershell
cmake --build "E:\x64dbgmcp\artifacts\x64dbg-x86" `
  --config Release --target headless --parallel 2
cmake --build "E:\x64dbgmcp\artifacts\x64dbg-x64" `
  --config Release --target headless --parallel 2
```

不要清理已配置构建目录。并行度保持 2；更高并行度曾触发 MSVC `C1060`。

Qt 下载若受可信本地 HTTPS 检查代理影响，只在配置阶段使用
`-AllowPinnedDownloadThroughLocalProxy`。固定 SHA-256 仍校验归档；禁止全局关闭 TLS。

---

## 7. 最终验收结果

### 7.1 静态质量门禁

```powershell
python -m ruff check src tests fixtures
# All checks passed!

python -m mypy src
# Success: no issues found in 24 source files

python -m compileall -q src tests
# success

python -m pip check
# No broken requirements found.
```

### 7.2 完整测试

```powershell
$env:HEADLESS_RE_IDA_GATE_BINARY = `
  "E:\x64dbgmcp\artifacts\fixtures-x64\console_fixture.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe"

python -m pytest -q
```

结果：

```text
128 passed in 86.01s
```

其中包括：

- 真实 IDA/idalib Gate；
- 真实静态服务与 MCP stdio；
- x86/x64 官方 command-loop 零窗口 Gate；
- x86/x64 原生 RPC 完整动态流程；
- x86/x64 真实 MCP stdio 动态流程；
- x86/x64 真实 IDA + x64dbg 同会话地址同步；
- 服务层和 MCP stdio 的 `static VA → RVA → runtime VA` 双向往返；
- 两种架构均断言 runtime base 不等于 IDA image base，实际覆盖 ASLR；
- 缺少后端、模块缺失、架构不匹配与越界地址的结构化错误；
- 服务层状态机、双后端共存和错误处理；
- 事件域解析、signed 64-bit 边界、种类/字段白名单和服务端独占 cursor；
- 双架构真实回调、连续 MCP 轮询、1024 槽覆盖窗口、精确丢失和模块装卸；
- 2048 线程回调生成期间关闭的双架构竞态压力；
- 客户端协议与清理单测。

完整动态流程覆盖：

```text
launch → initial paused
register read → write → verify → restore
memory read → write → verify → restore
modules
breakpoint set → list → remove → list
step into → step over
resume → pause → stable paused → idempotent pause
stop → idle
close → exit code 0 → userdir removed → no analyzer window
```

完整地址同步流程覆盖：

```text
create one session
  → static.open + dynamic.open
  → dynamic.launch --debug-wait → paused
  → read IDA image_base + x64dbg main-module base/size
  → assert runtime base != static base
  → static entry VA → RVA → runtime entry VA
  → runtime entry VA → RVA → original static entry VA
  → reject address at base + size
  → stop → close
```

该流程分别通过服务层直连和真实 MCP stdio 执行 x86/x64，共 4 个真实同步用例。

### 7.3 独立 x64dbg Gate

```powershell
python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60
```

双架构结果：

```text
ok: true
exit_code: 0
command_loop_seen: true
analyzer_windows: []
```

### 7.4 Doctor

```powershell
python -m headless_re_mcp doctor --json --strict
```

结果：

```text
ready: true
python: ready
ida_idalib: ready
x64dbg_source: ready
x64dbg_headless_binaries: ready
native_toolchain: ready
```

`radare2`、Java、WinDbg 等可选后端缺失不影响当前严格基线。

### 7.5 生命周期收尾检查

最终按本项目二进制绝对路径检查 x86/x64 `headless.exe` 和 console fixture，残留进程数
为 0。系统临时目录中以下隔离目录匹配数也均为 0：

```text
headless-re-xdbg-rpc-*
headless-re-xdbg-x86-*
headless-re-xdbg-x64-*
```

---

## 8. 关键测试文件

```text
tests\unit\test_xdbg_client.py
tests\unit\test_addressing.py
tests\unit\test_events.py
tests\unit\test_dynamic_service.py
tests\unit\test_service.py
tests\unit\test_mcp_server.py
tests\integration\test_idalib_gate.py
tests\integration\test_mcp_static_idalib.py
tests\integration\test_xdbg_headless_gate.py
tests\integration\test_xdbg_rpc.py
tests\integration\test_mcp_dynamic_xdbg.py
tests\integration\test_address_sync.py
```

`test_xdbg_rpc.py` 直接验证原生 RPC、真实回调和进程生命周期；
`test_mcp_dynamic_xdbg.py` 验证同一动态能力与连续事件 cursor 穿过真实 MCP stdio 边界。
`test_events.py` 验证事件协议纯域规则和畸形响应；`test_addressing.py` 验证主模块兼容与
显式多模块地址域规则和错误分支；`test_address_sync.py` 对 x86/x64 分别通过服务层与
MCP stdio 验证真实 ASLR 主模块换算，以及事件驱动 DLL 加载/卸载、三种 selector、
SHA-256、preferred/runtime 双向映射和卸载后无陈旧缓存。

---

## 9. 继续工作时的硬约束

1. 此目录不是 Git 仓库；不要依赖 `git status`，手工记录上游源码改动。
2. 不终止无关 Python、MCP 或调试进程。清理只能精确匹配本项目 headless/fixture
   绝对路径，以及 `headless-re-xdbg-rpc-*`、`headless-re-xdbg-x86-*`、
   `headless-re-xdbg-x64-*` 三类隔离 userdir。
3. 不使用普通 x64dbg GUI + 隐藏窗口替代官方 headless。
4. 目标程序自身 GUI 可以显示；分析器进程顶层窗口必须始终为零。
5. PowerShell 5 不支持 Bash 风格 `&&`；使用 `; if ($LASTEXITCODE -eq 0) { ... }`。
6. 不清理 x64dbg 构建目录；增量构建并保持 `--parallel 2`。
7. x86/x64 x64dbg 统一用 MSVC 构建，不要把 MinGW 对象或库混入官方构建。
8. 不复制单独 `headless.exe`；保留完整 `Release` 运行目录。
9. 不禁用或修改安全软件来生成 fixture；使用已验证的 MSVC 构建路径。
10. 验证运行控制时一次只改变一个状态变量，并以 `debug.state` 稳定轮询结果为准，而非
    命令提交瞬间的返回状态。

---

## 10. 后续产品工作

显式多模块地址域已闭环。下一阶段应建立独立 workflow 层，而不是继续把流程状态扩散到
原生回调、RPC method、backend client 或 MCP handler：

1. 在 `core/events.py`、模块目录与窄运行控制接口之上增加事件驱动导航；
2. 由 workflow 持有“等待事件 → 稳定暂停 → 刷新快照”的状态机，实现模块生命周期失效
   和断点编排；
3. 在同一独立 workflow 层实现 dump、IAT 修复和半自动脱壳；
4. 目标 GUI 自动化应是单独 backend，只约束目标窗口，不触碰分析器窗口；
5. 最后再增加 Web console、配置生成、便携包和 Windows 安装器。

当前已经交付两条地址转换链：

```text
IDA EA → static main-module RVA → runtime main-module base + RVA
runtime VA → runtime main-module RVA → IDA image base + RVA

selected PE preferred VA → RVA → selected runtime module VA
selected runtime module VA → RVA → selected PE preferred VA
```

workflow 不应缓存“模块仍已加载”的事实；收到 `module.unloaded` 或事件丢失时必须使相关
运行时选择结果失效，并在稳定暂停后从当前模块快照重新解析。

---

## 11. 优先阅读文件

```text
README.md
pyproject.toml
src\headless_re_mcp\config.py
src\headless_re_mcp\core\models.py
src\headless_re_mcp\core\session.py
src\headless_re_mcp\core\addressing.py
src\headless_re_mcp\core\events.py
src\headless_re_mcp\core\service.py
src\headless_re_mcp\mcp\server.py
src\headless_re_mcp\backends\ida\client.py
src\headless_re_mcp\backends\x64dbg\client.py
native\xdbg-headless-rpc\README.md
native\xdbg-headless-rpc\rpc_server.cpp
native\xdbg-headless-rpc\rpc_methods.cpp
native\xdbg-headless-rpc\rpc_events.cpp
native\xdbg-headless-rpc\inject.cmake
native\xdbg-headless-rpc\build.ps1
fixtures\native\build.ps1
fixtures\native\console_fixture.c
fixtures\native\event_fixture.c
tests\unit\test_addressing.py
tests\unit\test_events.py
tests\integration\test_xdbg_rpc.py
tests\integration\test_mcp_dynamic_xdbg.py
tests\integration\test_address_sync.py
```

---

## 12. 当前基线摘要

- 双架构无害 console/headless/GUI fixture 可重复构建；
- IDA 9.3 idalib 真实静态分析闭环完成；
- 官方 x64dbg headless x86/x64 构建完成；
- 命名管道 RPC、鉴权、线程调度、结构化错误和关闭顺序完成；
- 动态寄存器/内存/模块/断点/步进/继续暂停闭环完成；
- AnalysisService 双后端 runtime 与动态状态映射完成；
- 主模块兼容 `static VA ↔ RVA ↔ runtime VA` 域层与 MCP 工具完成；
- 显式 `base/path/name` selector、按需 SHA-256/PE 校验和多模块 preferred/runtime 映射完成；
- x86/x64 服务层与 MCP stdio 真实 ASLR 主模块换算完成；
- x86/x64 服务层与 MCP stdio 事件驱动 DLL 生命周期及多模块映射共 4 路通过；
- 静态、动态、真实事件和地址同步 MCP stdio 闭环完成；
- 1024 槽原生事件日志、精确覆盖丢失、模块装卸和关闭竞态验收完成；
- `wait_for_state` 转换事件/状态采样交错已有回归覆盖；
- 协议、服务、域层和真实集成测试完成；
- 所有分析器窗口 Gate 为零；
- 全测试 128 passed；
- Doctor strict ready；
- 验收后项目进程与隔离 userdir 残留为零；
- 当前基线无已知阻塞。