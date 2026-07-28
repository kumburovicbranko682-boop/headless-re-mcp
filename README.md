# Headless RE-MCP

统一、无分析器窗口的逆向分析 MCP 服务。当前基线真实使用：

- IDA Professional 9.x 的 `idalib` 执行静态分析；
- 官方 x64dbg `headless.exe` 执行 x86/x64 动态调试；
- MCP stdio 暴露受限的语义工具，不开放任意调试器命令。

## 依赖发行包（不含 IDA）

GitHub Release 提供除 IDA 外的运行时依赖 zip（x64dbg / UPX / DIE / cdb / de4dot / NETReactorSlayer）：

https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0-deps

本机构建同样产物：

`powershell
powershell -File .\scripts\build_deps_bundle.ps1
# -> artifacts/release/deps-bundle/headless-re-mcp-deps-win.x64.zip
`

解压后执行 ctivate_deps.ps1，再单独设置 HEADLESS_RE_IDA_HOME。

## 快速开始

适合第一次克隆本仓库后的本机配置（Windows + Python 3.11+）。

```powershell
cd <本仓库根目录>
python -m pip install -U pip
python first_setup.py              # 终端问答（结束时控制台贴出完整 MCP JSON）
python first_setup.py --gui        # PySide6 现代原生窗口（无 WebView）
# 等价：
pip install -e ".[native]"
python -m headless_re_mcp.native_app
```


`first_setup.py` / 原生启动器会收集路径并完成配置：

1. （可选）`pip install -e ".[dev,ida,pe,web]"`
2. 询问并校验 **IDA 9.x 安装目录**、**x64/x86 headless.exe**
3. 可选询问 UPX / DIE / Rizin / cdb 等
4. 写入用户 `config.json`（`platformdirs` 下的 headless-re-mcp 配置）
5. 可选运行 IDA `idalib` Python 激活脚本
6. 同步/探针 x64dbg、生成 Cursor `.cursor/mcp.json`（本机文件，已 gitignore）
7. 运行 `doctor`；GUI 还可一键启动/停止 MCP serve

便携目录（Zerofall 风格布局，**无浏览器套壳**）：

```powershell
powershell -File .\scripts\build_native_portable.ps1
# 产物：artifacts/release/native-portable/headless-re-mcp-win.x64/
```

配置完成后：

```powershell
python -m headless_re_mcp doctor --json --strict
python -m headless_re_mcp serve
# 或本地监控台进程（系统浏览器访问，非内嵌）：
python start_web.py
```

说明：

- 需要已安装 **IDA Professional 9.x**（含 `idalib.dll`），本项目不捆绑 IDA。
- 需要本机已有 x64dbg `headless.exe`（通常在 `artifacts/x64dbg-*/Release/` 或
  `external/x64dbg-*/`）。若还没有，先按下文「构建官方 x64dbg headless RPC」构建，
  或用 `scripts/sync_upstream.ps1 -Name x64dbg` 拉取源码后再构建。
- 仅自动发现、不提问：`python first_setup.py --non-interactive`
- 跳过 pip：`python first_setup.py --skip-pip`
- 原生壳使用 **PySide6**（`pip install -e ".[native]"`），深色简洁 UI；保存后右侧与控制台都会贴出可复制 MCP JSON。
- **禁止** WebView2/Electron 浏览器套壳。

## 当前能力

```text
MCP stdio
  └─ AnalysisService（会话、状态机、服务端事件游标与副作用边界）
      ├─ Addressing domain（module identity + RVA 纯函数换算）
      ├─ Events domain（事件协议校验 + 单向游标推进）
      ├─ Workflow domain（生命周期、导航、RVA 断点意图与纯状态转换）
      ├─ IDA worker（每会话独立进程、idalib）
      └─ X64DBG runtime（每会话独立 WorkflowRuntime + 唯一事件 cursor）
          └─ XdbgClient（每架构独立进程）
              └─ Windows named pipe RPC
                  └─ 官方 x64dbg headless + Bridge/DBG core
                      └─ 固定容量 callback event journal
```

同一会话可以同时附着 IDA 静态后端和 x64dbg 动态后端。服务保留主模块的 IDA 静态
VA ↔ x64dbg 运行时 VA 兼容换算，同时支持对当前已加载 PE 模块进行显式选择、身份校验
和 `preferred VA ↔ RVA ↔ runtime VA` 双向换算。动态状态统一为
`ready/running/suspended`，底层调试状态为 `idle/running/paused`。

已注册的主要 MCP 工具：

- 会话：`session.create`、`session.get`、`session.list`、`session.close`；
- 静态：`static.open`、`static.functions`、`static.strings`、`static.decompile`；
- 动态：`dynamic.open`、`dynamic.state`、`dynamic.events`、`dynamic.wait`、
  `dynamic.launch`、`dynamic.attach`、`dynamic.stop`、`dynamic.pause`、`dynamic.resume`；
- 单步：`dynamic.step_into`、`dynamic.step_over`；
- 寄存器：`dynamic.registers.read/write`；
- 内存：`dynamic.memory.read/write`；
- 动态快照与断点：`dynamic.modules`、`dynamic.breakpoints`、
  `dynamic.breakpoint.set/remove`；
- 显式模块目录：`modules.list`、`modules.resolve`；
- 地址同步：`sync.static_to_runtime`、`sync.runtime_to_static`、
  `sync.module_preferred_to_runtime`、`sync.module_runtime_to_preferred`；
- Workflow：`workflow.status/reset/cancel`、`workflow.events.consume`、
  `workflow.module.track/untrack/refresh`、`workflow.breakpoint.put/disable/remove/list`、
  `workflow.navigate_to_event`、`workflow.navigate_to_breakpoint`。

动态写操作仅接受明确参数和白名单寄存器。服务不提供 `dynamic.command` 或其他任意
x64dbg 命令执行入口。

## 地址同步契约

主模块兼容工具 `sync.static_to_runtime` / `sync.runtime_to_static` 要求同一会话已经打开
IDA 与 x64dbg 后端，且动态目标已启动或附加。每次调用都会读取当前运行时模块列表，按
规范化完整路径优先、唯一文件名后备的规则匹配会话主模块，并验证会话与 x64dbg 架构
一致。换算链固定为：

```text
IDA static VA - IDA image base = RVA
x64dbg runtime VA - loaded module base = RVA
```

显式多模块工具只依赖暂停中的 x64dbg 目标。调用方通过嵌套 `selector` 按唯一 `base`、
规范化 `path` 或唯一 `name` 定位当前模块，也可附带 `sha256` 做文件身份校验：

```text
PE preferred VA - Optional Header ImageBase = RVA
x64dbg runtime VA - selected module base = RVA
```

`modules.resolve` 与两个 `sync.module_*` 工具只读取被选中模块的 PE 头和 SHA-256，不会
批量哈希系统 DLL，也不会实际 rebase IDA 数据库。每次调用都重新获取运行时模块快照，
因此卸载后的旧 selector 返回 `module_not_found`，不会命中陈旧缓存。两类换算都采用
`[base, base + size)` 半开区间，并对 PE machine/架构、preferred base、`SizeOfImage`、
运行时范围、SHA-256、选择唯一性和地址边界返回结构化错误。

## 调试事件契约

`dynamic.events` 返回当前会话的下一批真实 x64dbg 插件回调快照，不通过比较两次
`debug.state` 推断事件。原生端使用 1024 槽固定容量环形日志；回调线程只复制有界纯值
字段，JSON 编码和 RPC 返回在消费侧完成。单批 `limit` 为 1..256。

服务为每个 `(session_id, x64dbg)` runtime 独占保存 cursor。MCP 调用方不能提交、回退
或跳跃原生 cursor，只能连续读取下一批。事件 `sequence` 严格递增；若消费者落后于覆盖
窗口，结果通过 `dropped` 报告本次精确丢失数，通过 `dropped_total` 报告该原生日志自
启动以来的累计覆盖数。调用方看到 `dropped > 0` 时应重新读取 `dynamic.state`、模块等
当前快照，不应假设丢失区间可重放。

`modules.list`、resolve 和地址映射属于暂停态快照操作，不能作为运行中的探针。模块生命
周期的可靠顺序是：`dynamic.resume` → 有界轮询 `dynamic.events`，按加载事件的 `name`
或卸载事件的已知 `base` 定位目标 → `dynamic.pause` 并等待稳定 `paused` → 再读取模块
目录或执行映射。所有等待必须有界；不要用固定长 sleep 代替事件和状态条件。

当前事件种类覆盖调试启停/暂停/继续/单步、进程、线程、模块加载/卸载、断点、异常和
attach/detach。每条事件固定标记 `source = "x64dbg.plugin_callback"`。接口不提供任意
订阅脚本、任意 x64dbg 命令或无限队列。

## Workflow 契约

每个 x64dbg session runtime 保存独立 `WorkflowRuntime`，包含 workflow ID、创建/更新时间、
运行状态、操作计数、领域状态和结构化失败原因。会话关闭会清理该 runtime；x64dbg worker
发生致命错误时，最后确认的 workflow 状态会作为失败快照保留到会话关闭。

`dynamic.events` 与 `workflow.events.consume` 共享 runtime 内唯一的 `DebugEventCursor`，两者
都执行同一条消费路径：先用事件批推进 workflow，再返回该原始事件批。workflow 导航也在
同一 runtime 锁内推进此 cursor，不存在第二个原生消费者或可由调用方提交的 cursor。

模块卸载、重载或事件丢失触发的副作用统一按以下顺序执行：

```text
PAUSE → REMOVE 已确认旧绑定 → refresh modules → SET 新绑定 → RESUME（仅导航需要时）
```

SET 操作只在 x64dbg RPC 成功后 acknowledgement；REMOVE 在 RPC 成功，或 RPC 拒绝后经
`breakpoints.list` 确认目标地址已不存在时 acknowledgement。若删除后置条件仍不满足，
则保存最后已确认状态并将 workflow 标记为 `failed`，必须先调用 `workflow.reset` 才能继续
修改。导航同时受 `timeout` 和 `event_budget` 限制，事件丢失、预算耗尽、取消或终止路径
都会 fail-closed，确保目标稳定暂停。

M1 已完成领域层、服务执行器、MCP 工具和真实双架构验收。x86/x64 Gate 均已验证 DLL
卸载、以不同 ASLR 基址重载、one-shot 清理、persistent RVA 断点重绑定及再次命中；跨
MCP stdio 调用的 workflow ID、状态和共享 cursor 也已验证持久化。

## 环境要求

- Windows 10/11 x64；
- Python 3.11+；当前验收环境为 Python 3.12；
- IDA Professional 9.x，以及可导入且已激活的 `idapro`/idalib；
- x64dbg 官方源码；
- Visual Studio 2022 Build Tools：MSVC x86/x64、Windows SDK、ATL/MFC；
- CMake；配置 x64dbg 时需要下载其固定哈希校验的 Qt 运行时。

本项目不分发 IDA、Hex-Rays decompiler、许可证或其他专有组件。

## 仓库结构

```text
src/headless_re_mcp/   # Python 包与 MCP 服务实现
tests/                 # unit / integration / gate
native/                # x64dbg headless RPC 原生工程
fixtures/              # 无害测试样本源码与 CrackMe
  native/              # C fixtures（build.ps1 → artifacts/fixtures-*）
  upx/                 # UPX 打包样本
  dotnet/              # .NET 探测样本
  crackme/             # 本地挑战样本（simple / hard / go_hard）
scripts/               # 构建、同步、打包脚本
packaging/             # WiX 等安装包描述
docs/                  # ADR、路线图、验收清单
external/              # 本机放置的 x64dbg 等大型依赖（二进制多半 gitignore）
upstream/              # 本地上游 checkout（gitignore；由 lock + sync 脚本拉取）
artifacts/             # 本地构建/验收产物（默认 gitignore；含 headless.exe、tools）
```

根目录仅保留项目入口与元数据：`pyproject.toml`、`README.md`、`first_setup.py`、
`start_web.py`、`upstream.lock.json`、`LICENSE`、`THIRD_PARTY_NOTICES.md`。

上游源码不进 Git：优先跑 `python first_setup.py` 生成本机 `.cursor/mcp.json`；
也可复制 `.cursor/mcp.json.example` 后手改。拉取锁定上游：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\sync_upstream.ps1
# 仅 x64dbg：
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\sync_upstream.ps1 -Name x64dbg
```

## 安装

```powershell
cd E:\x64dbgmcp
python -m pip install -e ".[dev,ida,pe]"
```

## 构建无害 fixture

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\fixtures\native\build.ps1 -Architecture all
```

Windows 上脚本优先使用 `vswhere.exe` 找到的 Visual Studio/MSVC，产物固定写入：

```text
artifacts\fixtures-x86\console_fixture.exe
artifacts\fixtures-x86\headless_fixture.exe
artifacts\fixtures-x86\gui_fixture.exe
artifacts\fixtures-x86\event_fixture.dll
artifacts\fixtures-x64\console_fixture.exe
artifacts\fixtures-x64\headless_fixture.exe
artifacts\fixtures-x64\gui_fixture.exe
artifacts\fixtures-x64\event_fixture.dll
```

可用 `HEADLESS_RE_FIXTURE_VS_INSTANCE` 指定 VS 实例。只有需要显式覆盖时才设置
`HEADLESS_RE_FIXTURE_CC_X86` 或 `HEADLESS_RE_FIXTURE_CC_X64`；设置后脚本改用 Ninja
和该编译器。`headless_fixture.exe` 与 console fixture 共享调试行为，但链接为 Windows
subsystem 且不创建 UI；x64dbg 动态集成测试使用该目标，避免反复弹出测试控制台。
构建脚本会在链接后确认 headless/GUI/DLL 产物仍存在，以 `CreateNoWindow` 执行短自检，
并校验四个 PE 产物的架构以及 EXE subsystem。

## 构建官方 x64dbg headless RPC

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -BuildParallelism 2 -RunGate
```

产物：

```text
artifacts\x64dbg-x86\Release\headless.exe
artifacts\x64dbg-x64\Release\headless.exe
```

必须保留各自完整的 `Release` 目录。`headless.exe` 依赖同目录 DLL、Qt 运行时以及
同架构 `TitanEngine.dll`，不能只复制 EXE。

若本机可信 HTTPS 检查代理导致 CMake 无法验证 Qt 下载证书，可仅在配置下载时使用：

```powershell
.\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -AllowPinnedDownloadThroughLocalProxy
```

该选项只临时设置 CMake 下载的 TLS 行为；x64dbg CMake 中固定的 `URL_HASH` 仍会校验
归档。不要全局关闭 TLS。

## 配置与启动

```powershell
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = `
  "E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe"

python -m headless_re_mcp doctor --json --strict
python -m headless_re_mcp serve
```

IDA 路径通常可自动发现，也可设置 `HEADLESS_RE_IDA_HOME`。x64dbg 源码可通过
`HEADLESS_RE_X64DBG_SOURCE` 指定。

可选外部 CLI（均不随包分发，缺失时检测/脱壳会降级，不阻断核心 IDA/x64dbg）：

```powershell
$env:HEADLESS_RE_DIEC = "C:\path\to\diec.exe"   # Detect It Easy 官方 CLI
$env:HEADLESS_RE_UPX  = "C:\path\to\upx.exe"    # 官方 UPX CLI（仅 -t / -d -o）
```

检测与脱壳相关 MCP 工具（结论均为非权威路由/有界操作）：

| 工具 | 作用 |
|------|------|
| `detect.scan` | 内置 PE 启发式 + 可选 DIE JSON 扫描 |
| `detect.explain` | 返回单条 finding 证据 |
| `packer.classify` | 列出 packer/protector/obfuscator 候选 |
| `unpack.recommend` | 建议 UPX / .NET / generic / none 路由（不执行脱壳） |
| `unpack.upx.test` / `unpack.upx.unpack` / `unpack.auto` | 官方 UPX 白名单操作与自动路由 |

## 验收

独立零窗口 Gate：

```powershell
python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60
```

完整检查：

```powershell
$env:HEADLESS_RE_IDA_GATE_BINARY = `
  "E:\x64dbgmcp\artifacts\fixtures-x64\console_fixture.exe"

python -m ruff check src tests fixtures
python -m mypy src
python -m compileall -q src tests
python -m pip check
python -m pytest -q
python -m headless_re_mcp doctor --json --strict
```

当前质量基线：

- 本机 IDA 9.3 idalib 与 x86/x64 x64dbg headless 全配置测试为
  `167 passed in 93.95s`，没有 skip；完整 unit 为 `150 passed in 0.97s`；
- 全量测试覆盖真实 IDA、双架构 x64dbg RPC、MCP stdio、ASLR 主模块同步、显式多模块
  映射、事件连续性/丢失、零窗口 Gate，以及 M1 workflow DLL 卸载/换基址重载；
- M1 的独立服务级真实 Gate 为 `2 passed`，跨 MCP 动态 Gate 为 `2 passed`。两种架构均
  断言 `analyzer_windows == []`、`headless.exe` 正常退出且临时 userdir 已删除；
- Ruff、Mypy（32 个 source files）、Compileall、Pip check 均通过；Doctor strict 为
  `ready: true`，x86/x64 command-loop probe 均为退出码 0、`analyzer_windows: []`。

## 无窗口与生命周期约束

`CREATE_NO_WINDOW` 只处理控制台窗口；测试还会持续枚举 x64dbg/IDA 分析器进程拥有的
顶层窗口，任何窗口都会使 Gate 失败。目标程序自身的 GUI 不在该限制内。

每个 x64dbg 客户端使用独立临时 `-userdir`。正常关闭顺序为：停止 debuggee（如有）→
保持 RPC 管道连接并向官方 command loop 发送 `exit` → 等待 `headless.exe` 退出 →
关闭本地管道句柄 → 删除临时 userdir。

## 当前范围边界

当前版本提供可靠的静态查询、基础动态调试闭环、真实插件回调事件流、主模块兼容地址
同步、显式多模块按需映射，以及跨 MCP 调用保存的 workflow runtime。workflow 已能跟踪
模块生命周期、管理 RVA 断点意图、协调唯一事件 cursor，并执行有超时和事件预算的导航；
这些能力已完成单元、服务和 MCP 层回归。

真实 x86/x64 DLL 卸载、不同 ASLR 基址重载、断点自动重绑定、one-shot 清理和 persistent
断点再次命中的完整 headless Gate 已通过。持久化事件重放、dump/IAT 修复、脱壳编排、
目标 GUI 自动化中的 UIA/OCR/SendInput 仍延期。本地 Web 控制台、配置生成、portable/handoff 与 CI 已落地；MSI 需本机 WiX。

## Web / 配置 / 发布速查

```text
pip install -e ".[web]"
python -m headless_re_mcp serve-web          # 仅 127.0.0.1 + 本地 token
python -m headless_re_mcp config generate   # 通用 stdio MCP JSON（默认跑 doctor）
powershell -File scripts/build_sdist_wheel.ps1
powershell -File scripts/build_portable.ps1
powershell -File scripts/build_handoff_zip.ps1
powershell -File scripts/build_msi.ps1      # 需要 WiX candle/light
```

## 安全与授权

仅分析你拥有或获明确授权的二进制，包括防御研究、授权测试、CTF 和教学环境。本地
stdio 服务包含寄存器与内存写操作，不应连接到不可信代理，也不应在未隔离环境中处理
未知样本。

## License

GPL-3.0-only。详见 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`。