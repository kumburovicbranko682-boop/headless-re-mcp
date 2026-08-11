# Headless RE-MCP

Windows 上的无分析器窗口逆向 MCP（v0.1.0 早期原型）。把 IDA `idalib` 静态分析与 x64dbg `headless.exe` 动态调试收成受限语义工具，供 Cursor 等 MCP 客户端调用；不开放任意调试器命令，也不弹 IDA/x64dbg GUI。

**现状口径（偏保守）：** 公开仓库历史很短、单维护者，适合隔离环境实验，不建议当作生产级核心依赖。缺后端时集成测试会 `skip`，`skip ≠ pass`。

## 依赖

| 依赖 | 说明 |
|------|------|
| Windows 10/11 x64 + Python 3.11+ | 仅 Windows |
| IDA Professional 9.x（含 idalib） | 商业软件，本仓库不捆绑 |
| x64dbg `headless.exe`（x86/x64） | 可从 [deps Release](https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0-deps) 取，或本地构建 |
| 可选 CLI | UPX / DIE `diec` / de4dot / cdb 等：用户自备，缺失则降级 |

```powershell
powershell -File .\scripts\build_deps_bundle.ps1
# -> artifacts/release/deps-bundle/headless-re-mcp-win.x64.zip
```

解压后执行 `activate_deps.ps1`，再设置 `HEADLESS_RE_IDA_HOME`。

### 版本兼容矩阵

下表是仓库实际探测并在 `doctor` 中逐项校验的组合；缺可选项只降级，不阻塞就绪。

| 组件 | 支持范围 | 校验方式（doctor 探针） |
|------|----------|--------------------------|
| Windows | 10 / 11 x64 | 仅 Windows；隐藏桌面等能力硬校验 `os.name == "nt"` |
| Python | 3.11 / 3.12 | `python`：低于 3.11 判 `blocked` |
| IDA Professional | 9.x（含 idalib 与 `idapro` Python 包） | `ida_idalib`：查 `idalib.dll`、`import idapro`、`open_database` 可用性 |
| x64dbg headless | 官方源码含 `add_executable(headless)` 的构建 | `x64dbg_source` + `x64dbg_headless_binaries`（x86/x64 零窗口命令循环 Gate） |
| 原生工具链 | VS 2022 Build Tools + CMake + Ninja | `native_toolchain` |
| 可选 CLI | DIE `diec`（需 `--json`）、UPX、de4dot、NETReactorSlayer、Scylla、XVLKC、r2/rizin、Ghidra、frida、cdb/WinDbg | 各自独立探针，`missing` 不影响 `ready` |

`python -m headless_re_mcp doctor` 按「必需 / 可选」分组输出，并单独列出阻塞项与对应修复命令。

## 快速开始

```powershell
cd <repo-root>
python -m pip install -U pip
python first_setup.py              # 终端问答，生成本机 MCP JSON
python first_setup.py --gui        # 可选 PySide6 原生壳（无 WebView）
python -m headless_re_mcp doctor --json --strict
python -m headless_re_mcp serve
```

`first_setup.py` 会校验 IDA / headless 路径，写入用户 `config.json`，并可选生成 `.cursor/mcp.json`（本机文件，已 gitignore）。

```powershell
python -m headless_re_mcp serve-web   # 仅 loopback + 本地 token
python start_web.py                   # 监控台（系统浏览器，非内嵌）
```

非 MCP 客户端（OpenAI function calling 等）可导出工具定义：

```powershell
python openai_bridge.py --output openai_tools.json   # tools[] + 反查名映射 + 写操作清单
python openai_bridge.py --names-only                 # 只看 OpenAI 名 -> MCP 名
```

OpenAI 不允许函数名带点，导出会做安全名转换并附 `name_map` 供回调派发；`write_tools` 列出会改状态的工具，便于桥接方保留审批策略。

## 能力概览

同一会话可同时附着 IDA 与 x64dbg；支持主模块与显式模块的 `preferred VA ↔ RVA ↔ runtime VA` 换算、真实插件回调事件流（原生 1024 槽环形缓冲 + 会话级持久化 drain/重放；仅当 drain 也未能赶上覆盖窗口时才 `unrecovered_gap`）、以及 workflow 导航/断点意图。

主要工具面（节选）：

- 会话：`session.create/get/list/close`
- 静态：`static.open/functions/strings/decompile` 等
- 动态：`dynamic.open/state/events/wait/launch/attach/stop/pause/resume`、单步、寄存器/内存、模块与断点
- 地址：`sync.*`、`modules.list/resolve`；`sync.resolve_runtime_address` 把 static VA / 模块 RVA / runtime VA 一次解析成运行时地址，`dynamic.breakpoint.set` 可用 `address_space=static|rva` 直接下断（内部重定位，调用方不做地址运算）
- 复合工作流：`dynamic.analyze_function`（反编译 + 重定位下断 + 运行 + 寄存器，一次调用）、`dynamic.trace_api_arguments`（按符号或地址断 API 并捕获整型参数：x64 取 RCX/RDX/R8/R9，x86 从返回地址之上的栈读取；结束必清断点）
- 分析记录与报告：`knowledge.record/query`（按 `kind`+`key` 幂等累积函数/断点/结构体/API 等发现）、`report.generate`（渲染 Markdown 报告并落盘为产物）
- 可观测：`meta.metrics`（每工具调用数、失败数、p50/p95/max 延迟；同时以 JSON 行写入 `headless_re_mcp.telemetry` 日志）
- 自愈：`session.health`（按需检查各后端存活与连接状态）、`session.recover`（重开死掉的后端）
- Workflow：`workflow.*`
- 检测/脱壳（可选外部 CLI）：`detect.*`、`unpack.*`（非通杀承诺；`claims_universal_unpack=false`）
- 目标 UI（有界）：Win32 交互与截图；UIA/OCR/SendInput 为实验路径，勿默认依赖

动态写操作仅接受明确参数与白名单寄存器；无 `dynamic.command`。

### 故障自愈

RPC 连接掉线（例如被调试程序卡住导致一次超时）不会终结会话。worker 仍在运行、仍持有被调试进程，
后台健康检查会重建连接；即便监控关闭，下一次调用也会自行重连。失败的那次调用**不会被重放**，
因为重放可能让状态变更类操作执行两次——调用方仍会收到那次失败，但标记为 `retryable`。

worker 进程真正死亡时只上报不自动重启：重启后的调试器不再附着于任何进程，是否重新启动目标
必须由调用方决定，用 `session.recover` 显式处理。

`health_check_interval_s` 控制后台巡检间隔，设为 `0` 关闭（此时仍保留调用时重连）。

## 仓库结构

```text
src/headless_re_mcp/   # Python 包与 MCP 服务
tests/                 # unit / integration / gate
native/                # x64dbg headless RPC
fixtures/              # 无害测试样本
scripts/               # 构建、同步、打包
packaging/             # WiX 等
external/              # 本机大型依赖占位（二进制多半 gitignore）
upstream/              # 本地上游 checkout（gitignore）
artifacts/             # 本地构建产物（gitignore）
```

根目录元数据：`pyproject.toml`、`README.md`、`first_setup.py`、`start_web.py`、`upstream.lock.json`、`LICENSE`。

上游不进 Git：复制 `.cursor/mcp.json.example` 或跑 `first_setup.py`；拉取锁定上游：

```powershell
powershell -File .\scripts\sync_upstream.ps1
powershell -File .\scripts\sync_upstream.ps1 -Name x64dbg
```

## 安装与构建

```powershell
python -m pip install -e ".[dev,ida,pe,web]"

powershell -File .\fixtures\native\build.ps1 -Architecture all

powershell -File .\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -BuildParallelism 2 -RunGate
```

`headless.exe` 必须保留完整 `Release` 目录（同目录 DLL / Qt / TitanEngine）。

```powershell
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = "$PWD\artifacts\x64dbg-x86\Release\headless.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = "$PWD\artifacts\x64dbg-x64\Release\headless.exe"
$env:HEADLESS_RE_DIEC = "C:\path\to\diec.exe"   # 可选
$env:HEADLESS_RE_UPX  = "C:\path\to\upx.exe"    # 可选
```

### 安装包

发布版提供 per-user MSI（装到 `%LocalAppData%\HeadlessReMcp`，不需要管理员）。本地构建需要
WiX Toolset 3.14：

```powershell
powershell -File .\scripts\build_msi.ps1     # 产出 MSI 与 .sha256
powershell -File .\scripts\verify_msi.ps1    # 装 → 跑 → 卸，并断言零残留
```

推 `v*` 标签会由 `release` 工作流构建、跑同一套往返验证，再连同校验和发布。

## 验收

先跑零窗口 Gate，再按需跑 pytest。集成 Gate 依赖本机后端；缺环境出现 `skip` 时不能当通过。

```powershell
python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60

python -m ruff check src tests fixtures
python -m mypy
python -m compileall -q src tests
python -m pip check
python -m pytest tests/unit -q
python -m pytest tests/integration -q -rs   # 需本机后端；-rs 会列出每个 skip 的原因
python -m headless_re_mcp doctor --json --strict
```

前端（改动 `webui/` 时）：

```powershell
cd webui
npm install            # 国内网络可加 --registry=https://registry.npmmirror.com
npm run typecheck
npx vitest run
npm run build          # 产物直接写入 src/headless_re_mcp/web/spa
```

硬约束：分析器进程（IDA / x64dbg headless）顶层窗口必须为 0；目标程序 GUI 不受此限。

`tests/integration/test_m10_ui_*` 会驱动目标窗口，需要独占的交互桌面：跑这几个 gate 时不要在
同一会话里安装软件或打开别的窗口，否则前台焦点被抢会得到 `no foreground window for SendInput`
或 `SendMessageTimeout`，那是环境干扰而不是回归。

## 隔离部署

分析未知样本时调试器会真实执行目标代码，请把执行端放进可随时丢弃的环境。

| 方案 | 隔离强度 | 代价 |
|------|----------|------|
| 专用物理机（整盘可还原） | 最强，且无虚拟化特征 | 成本最高 |
| Hyper-V / VMware + 快照 | 强，恢复最快 | 部分样本检测到虚拟机会改变行为 |
| Windows Sandbox | 中等，开箱即用 | 每次重置，装 IDA 不便 |
| 宿主机直跑 | 无 | 不要用于未知样本 |

基本要求：

- 专用低权限账户，不要用管理员运行；不共享宿主目录、剪贴板与凭据
- 默认断网，确需联网走白名单代理
- Web 监控台只监听回环并带 token（`serve-web` / `start_web.py` 默认如此），不要转发到局域网
- 每次任务结束回滚快照或重装，不要在同一环境里连续分析多个未知样本

目标程序会弹窗但你不想看到时，可开隐藏桌面：设 `HEADLESS_RE_HIDDEN_DESKTOP=1`（或 `config.json` 的 `hidden_desktop`）。x64dbg 与被调试进程会创建在独立的 Win32 Desktop 对象上，全程不切换输入桌面；WebUI「虚拟桌面」面板可被动查看窗口清单并按需截图，GPU/DirectX 窗口返回空白帧时会标记 `degraded`，不会静默切桌面兜底。

隐藏桌面解决的是「不干扰你的桌面」，**不是反检测**：样本仍可能识别虚拟化、调试器或非默认桌面。

## 端到端示例：解一个 crackme

仓库自带 `fixtures/native/crackme_serial.c`（校验 8 位序列号，把输入逐字节异或 `0x41` 后与常量比对）。构建后可完整走一遍动静结合流程：

```powershell
powershell -File .\fixtures\native\build.ps1 -Architecture all
# -> artifacts/fixtures-x64/crackme_serial.exe
```

典型工具顺序：

| 步骤 | 工具 | 作用 |
|------|------|------|
| 1 | `session.create` | 绑定样本，拿到 `session_id` |
| 2 | `r2.open` / `static.open` | 打开静态后端 |
| 3 | `r2.exports` / `static.functions` | 定位导出的 `crackme_check` |
| 4 | `static.decompile` | 读校验逻辑，反推期望常量 |
| 5 | `dynamic.open` + `dynamic.launch` | 带候选序列号在调试器里实跑 |
| 6 | `dynamic.analyze_function` | 一次完成反编译 + 重定位下断 + 运行 + 读寄存器 |
| 7 | `knowledge.record` | 把结论写进会话（如 `serial=H3adl3ss`） |
| 8 | `report.generate` | 产出 Markdown 报告 |

`tests/integration/test_crackme_serial_e2e_gate.py` 是这条链路的可执行版本：它从二进制还原出序列号并在调试器下验证，跑通即说明本机环境可用。

## 范围与风险

已有较完整的静态查询、动态调试闭环、事件流、地址同步、workflow，以及 dump / IAT / UPX 等脱壳相关路径的代码与真机 Gate。连接级自愈已实测，但公开提交仍少，可选后端成熟度不一。

当前证据（在一台配好 IDA 9.x + x64dbg headless + DIE/UPX/de4dot/rizin/cdb 的机器上实测）：

- 单元测试 507 passed / 4 skipped
- 集成 Gate 64 passed / 7 skipped（含 x86 与 x64 双架构、UI 自动化、r2/frida/windbg 可选后端、隐藏桌面隔离、连接掉线自愈、crackme 端到端）
- 剩余 7 个 skip 均有明确原因：缺 .NET 样本（2）、未安装 Exeinfo PE（3）、以及 2 个有文档说明的故意跳过
- 197 个工具在敌意输入下全部返回结构化错误信封，无一抛出
- MSI 装—跑—卸往返零残留

已知不稳定：`test_m10_ui_*` 依赖独占的交互桌面，在全量并发跑时偶发失败（前台焦点被抢），
单独重跑稳定通过。判定回归前请先单独复跑。

Gate 会从 `config.json` 读取后端路径（`tests/integration/conftest.py` 负责桥接），所以配置好的机器不会因为"没设环境变量"而假跳过。**skip 仍然不等于 pass**：换一台缺后端的机器，对应 Gate 会如实跳过。

不适合：跨平台、无 IDA 授权、需要稳定长期 SLA 的生产工作流。  
适合：已有 Windows + IDA 9.x，想在隔离环境试 MCP 驱动的逆向辅助。

仅分析你拥有或获明确授权的样本。本地服务含写寄存器/内存能力，勿对不可信代理暴露，勿在未隔离环境处理未知样本。

## License

GPL-3.0-only。见根目录 `LICENSE`。第三方工具由用户自行获取与授权；上游修订锁定见 `upstream.lock.json`。
