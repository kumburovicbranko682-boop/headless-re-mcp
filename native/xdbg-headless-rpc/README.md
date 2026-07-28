# xdbg-headless-rpc

该目录把受限、版本化的 RPC 扩展编译进 x64dbg 官方 `headless` target。它不是
`.dp32`/`.dp64` Qt 插件，也不会启动或隐藏普通 `x32dbg.exe`/`x64dbg.exe`。

## 组成与注入边界

```text
upstream/x64dbg/src/headless/headless.cpp
  └─ HEADLESS_RE_XDBG_RPC 生命周期钩子
      └─ native/xdbg-headless-rpc
          ├─ rpc_server.cpp     命名管道、帧、鉴权、I/O 生命周期
          ├─ rpc_methods.cpp    受限调试语义方法
          ├─ rpc_events.cpp     插件回调快照与固定容量事件日志
          ├─ rpc_internal.h     内部类型与常量
          ├─ headless_rpc.h     最小公开生命周期接口
          └─ inject.cmake       向官方 headless target 注入源码/依赖
```

`headless.cpp` 只保留受 `HEADLESS_RE_XDBG_RPC` 宏保护的启动/停止钩子。未启用注入时，
官方 stdin command loop 行为保持不变。`inject.cmake` 有 target 级重复注入保护，并将
Jansson 与 RPC 源码挂到官方 `headless` target。

## 构建

需要 Visual Studio 2022 Build Tools 的 MSVC x86/x64、Windows SDK 和 ATL/MFC。
默认并行度为 2；该值用于避免大型 x64dbg 编译在受限内存环境触发 MSVC `C1060`。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -BuildParallelism 2 -RunGate
```

已配置构建目录可增量编译：

```powershell
cmake --build .\artifacts\x64dbg-x86 `
  --config Release --target headless --parallel 2
cmake --build .\artifacts\x64dbg-x64 `
  --config Release --target headless --parallel 2
```

输出：

```text
artifacts\x64dbg-x86\Release\headless.exe
artifacts\x64dbg-x64\Release\headless.exe
```

`build.ps1` 会把构建树中同架构 `TitanEngine.dll` 放入 `Release`。运行时还需要该目录
内的 Bridge/DBG、Qt 和其他依赖；不能只复制 `headless.exe`。依赖缺失时 Windows 常见
退出码为 `0xC06D007E`。

若可信本地 HTTPS 检查代理只影响 Qt 下载，可加
`-AllowPinnedDownloadThroughLocalProxy`。此开关只在配置期间临时设置
`CMAKE_TLS_VERIFY=0`；x64dbg 的固定 `URL_HASH` 仍校验归档，不会全局修改 TLS。

## 启动协议

Python `XdbgClient` 为每个会话创建：

- 随机命名管道 nonce；
- 256-bit 随机 token；
- 隔离的 `headless-re-xdbg-rpc-<arch>-*` 临时 userdir；
- 使用 `CREATE_NO_WINDOW` 启动的同架构官方 `headless.exe`。

nonce 和 token 仅通过新子进程环境传入：

```text
HEADLESS_RE_XDBG_RPC_PIPE
HEADLESS_RE_XDBG_RPC_TOKEN
```

原生端读取后立即从自身环境删除。不要把旧的 `-rpc-pipe`/`-rpc-token` 参数加到命令
行；x64dbg 参数解析器会拒绝它们。应用层只配置：

```text
HEADLESS_RE_X64DBG_HEADLESS_X86
HEADLESS_RE_X64DBG_HEADLESS_X64
```

`XdbgClient` 会验证 PE 架构、命名管道 server PID、hello PID、hello 架构和能力列表。

## 传输与鉴权

协议常量：

```text
protocol = "headless-re-xdbg"
version  = 1
```

每帧为 little-endian `uint32` 长度加 UTF-8 JSON object。编码后 JSON 最大 1 MiB，零长度、
超长、错误 UTF-8/JSON、错误协议版本、错误请求 ID 或非布尔 `ok` 都会作为协议错误拒绝。
原生端使用 Jansson `json_dump_callback` 在编码期间执行上限，而不是编码后再接受超大对象。

首个请求必须是 `rpc.hello` 并携带 token。服务返回 PID、架构、版本和能力；错误 token
返回结构化 `authentication_failed`。请求和响应均携带字符串 ID，客户端严格匹配。

RPC I/O 线程只负责收发与解析，不直接调用 DBG/Bridge。调试方法通过
`GUI_EXECUTE_ON_GUI_THREAD` / `GuiExecuteOnGuiThreadEx` 投递到官方 headless command
queue。单次调度超时最大 30 秒；异步状态转换由 Python 客户端有界轮询。

## 受限方法

版本 1 暴露：

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
memory.regions
memory.protect.query
modules.list
modules.dump
pe.headers.runtime
imports.scan
imports.read
imports.rebuild
events.read
breakpoints.list
breakpoints.set
breakpoints.remove
```

没有任意 x64dbg command 方法。路径和参数经过长度/字符边界校验；寄存器按架构白名单；
单次内存读写最大 2 MiB；`modules.dump` 单次最大 64 MiB，结果只写调用方提供的绝对
`output_path`（`.partial` 临时文件 + `MoveFileEx` 原子 rename），不经 RPC 回传字节。
`memory.regions` / `memory.protect.query` / `modules.dump` / `pe.headers.runtime` /
`imports.scan` / `imports.read` 均为 paused-only。`imports.scan` 基于已加载模块 export
目录做连续指针启发式，返回多候选与置信度（`blind_selection=false`）；`imports.rebuild`
当前固定返回 `not_implemented`（IAT/PE 重建在 Python `unpack.iat.rebuild` /
`unpack.pe.rebuild` 落地）。断点接口当前只设置/删除明确地址的软件断点。

运行控制命令是异步提交：响应中的状态可能仍是提交瞬间的旧状态，调用方必须通过
`debug.state` 有界等待稳定状态。`debug.pause` 是幂等操作：

- 无 active debuggee：返回 `not_debugging`；
- running：提交官方 `pause`；
- 已 paused：直接成功返回当前状态。

## 原生事件日志

`events.read` 读取 x64dbg 官方插件回调链产生的事件，不从 `debug.state` 差分推断。
原生端注册 17 类窄回调，覆盖调试生命周期、进程/线程、模块、断点、异常、暂停/继续/
单步和 attach/detach。

回调热路径只在互斥锁内复制固定大小 `EventRecord`：路径最多 1023 字节，名称/模块最多
511 字节；不在回调线程构造 Jansson 对象，不执行 Bridge/RPC 阻塞工作。消费侧才把快照
编码为 JSON。日志参数固定为：

```text
capacity = 1024
limit default = 100
limit range = 1..256
cursor/sequence = 非负 signed 64-bit JSON integer
source = "x64dbg.plugin_callback"
```

`sequence` 从 1 严格递增。cursor 落后于当前 `oldest_sequence` 时，响应通过 `dropped`
报告该次读取丢失的精确数量；`dropped_total` 是日志启动后被覆盖的累计记录数。cursor
超前返回结构化 `invalid_cursor`。响应还包含 `next_cursor`、`has_more`、当前序列窗口和
容量，客户端会验证这些字段及各事件 `kind/data` 契约的一致性。

官方 headless 不静态链接 debugger DLL 导入库，因此事件模块仅从已加载的
`x32dbg.dll`/`x64dbg.dll` 解析 `_plugin_registercallback` 和
`_plugin_unregistercallback` 两个导出。缺少模块或导出时 RPC 启动明确失败，不引入
headless 与 debugger DLL 的静态循环依赖。

## 关闭顺序

必须保持管道存活直到官方进程收到退出命令：

```text
停止 debuggee（如有）
  → 向官方 stdin command loop 写入 exit
  → 原生 shutdown 停止接收并注销插件事件回调
  → 等待 headless.exe 正常退出
  → 关闭客户端管道句柄
  → 删除隔离 userdir
```

先断开管道再写 `exit` 会破坏原生 RPC 线程与官方 shutdown 的协作，可能导致 15 秒超时
和强制终止。当前双架构集成测试断言退出码为 0、分析器窗口为空且临时 userdir 已删除。

## 验收

```powershell
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe"

python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60
python -m pytest tests/integration/test_xdbg_rpc.py -q
python -m pytest tests/integration/test_mcp_dynamic_xdbg.py -q
```

当前验收中，两种架构均满足：官方 command loop 可见、退出码 0、
`analyzer_windows == []`，且完整寄存器/内存恢复、模块、断点、单步、继续/暂停、停止和
关闭流程通过。`test_xdbg_rpc.py` 为 `4 passed`，`test_mcp_dynamic_xdbg.py` 为
`2 passed`。事件测试另外覆盖真实回调来源、连续 cursor、1024 槽覆盖窗口、精确
`dropped`、测试 DLL 加载/卸载，以及 2048 线程回调期间的关闭竞态。
