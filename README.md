# Headless RE-MCP

Windows 与 Linux x86_64 上的无分析器窗口逆向 MCP（v0.2.1）。跨平台核心包含 MCP/Web 服务、会话管理、纯 Python 检测与 Android/Web/Ghidra/radare2 等可移植后端；授权 IDA `idalib` 可按宿主平台选配，Windows 另提供 x64dbg `headless.exe` 动态调试和 Win32 UI 能力。265 个受限语义工具供 Cursor 等 MCP 客户端调用；不开放任意调试器命令、不开放任意 JS 求值、不开放 `adb shell` 透传。

变更记录见 [CHANGELOG.md](CHANGELOG.md)。

**现状口径（偏保守）：** 公开仓库历史很短、单维护者。连接级自愈、错误契约与安装包都有真机验证（下方「范围与风险」列了具体数字），但可选后端成熟度不一，仍建议在隔离环境使用。缺后端时集成测试会 `skip`，`skip ≠ pass`。

## 依赖

| 依赖 | 说明 |
|------|------|
| Windows 10/11 x64 或 Linux x86_64 | Windows 为完整 PE 动态调试主机；Linux 支持跨平台核心与可移植后端 |
| Python 3.11+ | Linux/源码运行需要；Windows MSI 自带 3.12 运行时 |
| IDA Professional 9.x（含 idalib，可选） | 商业软件，本仓库不捆绑；doctor 按宿主查找 `idalib.dll` 或 `libidalib.so` |
| x64dbg `headless.exe`（x86/x64，仅 Windows） | 可从 [deps Release](https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0-deps) 取，或本地构建 |
| 可选 CLI | UPX / DIE `diec` / de4dot / cdb 等：用户自备，缺失则降级 |

```powershell
powershell -File .\scripts\build_deps_bundle.ps1
# -> artifacts/release/deps-bundle/headless-re-mcp-win.x64.zip
```

解压后执行 `activate_deps.ps1`，再设置 `HEADLESS_RE_IDA_HOME`。

### Linux 支持范围

Linux x86_64 可原生安装并运行 `doctor`、`serve`、`serve-web`、会话/制品/报告、纯 Python PE/.NET 检测，以及已安装的 radare2/rizin、Ghidra headless、Android/Frida、Playwright/Web、wabt/webcrack、mitmproxy、DIE/UPX 等可移植后端。

以下能力在 Linux 上明确返回 `unsupported_on_platform`，不会伪装为 ready，也不会阻塞核心 doctor readiness：

- x64dbg headless RPC 与 ScyllaHide
- WinDbg/cdb
- Win32 UI、UIA、SendInput、Windows OCR 与 hidden desktop
- Exeinfo PE GUI、Scylla/XVLKC/VMP dumper 的现有 Windows 适配
- WiX/MSI 与 PowerShell 构建、服务安装脚本

Linux 发布/分发使用标准 wheel 或 sdist；Windows MSI 保持不变。

### 版本兼容矩阵

下表是仓库实际探测并在 `doctor` 中逐项校验的组合；缺可选项只降级，不阻塞就绪。

| 组件 | 支持范围 | 校验方式（doctor 探针） |
|------|----------|--------------------------|
| 宿主平台 | Windows 10/11 x64；Linux x86_64 核心 | `platform`：报告 `full` / `core`，其它架构阻塞 |
| Python | 3.11 / 3.12 | `python`：低于 3.11 判 `blocked` |
| IDA Professional | 9.x（含 idalib 与 `idapro` Python 包） | `ida_idalib`：查宿主原生 `idalib.dll`/`libidalib.so`、`import idapro`、`open_database` 可用性 |
| x64dbg headless | 官方源码含 `add_executable(headless)` 的构建 | `x64dbg_source` + `x64dbg_headless_binaries`（x86/x64 零窗口命令循环 Gate） |
| 原生工具链 | VS 2022 Build Tools + CMake + Ninja | `native_toolchain` |
| 可选 CLI | DIE `diec`（需 `--json`）、UPX、de4dot、NETReactorSlayer、Scylla、XVLKC、r2/rizin、Ghidra、frida、cdb/WinDbg | 各自独立探针，`missing` 不影响 `ready` |
| Android（可选） | `pip install '.[android]'`（adbutils / androguard / frida）；jadx、apktool、apksigner 需自备 JRE | `androguard`/`adbutils`/`adb`/`jadx`/`apktool`/`apksigner` 各自探针 |
| Web（可选） | `pip install '.[browser]'`（Playwright，另需 `playwright install chromium`）、`.[proxy]`（mitmproxy）；webcrack 需 Node 22/24，wabt 自备 | `playwright`/`mitmproxy`/`webcrack`/`wabt` 各自探针 |

`python -m headless_re_mcp doctor` 按「当前平台必需 / 可选 / 本平台不支持」分组输出，并单独列出阻塞项与对应修复命令。Linux 必需项只有宿主平台与 Python；Windows 继续要求 IDA 与 x64dbg 双架构运行时。

## 快速开始

### Windows：用安装包（不需要先装 Python）

到 [Releases](https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/latest) 下载
`headless-re-mcp.msi`（约 33 MB，per-user 安装到 `%LocalAppData%\HeadlessReMcp`，无需管理员）。
Python 运行时与全部依赖在包内，装完直接用：

```powershell
& "$env:LOCALAPPDATA\HeadlessReMcp\start_web.cmd"                 # 监控台（系统浏览器）
& "$env:LOCALAPPDATA\HeadlessReMcp\headless-re-mcp.cmd" doctor --json
```

首次启动会自检环境并打印带 token 的本地地址。IDA 与 x64dbg 仍需自备，在监控台里填路径即可。

### Linux：从源码

```bash
cd <repo-root>
./scripts/install-linux.sh             # 默认安装 pe,web extras
# 或自行选择 extras：
python3 -m pip install -e '.[pe,web,test]'
python3 -m headless_re_mcp doctor --json --strict
python3 -m headless_re_mcp serve
# Web 控制台：
python3 -m headless_re_mcp serve-web
```

`HEADLESS_RE_EXTRAS=pe,web,android,browser,proxy ./scripts/install-linux.sh` 可扩展安装范围。Playwright 浏览器仍需按上游方式另装，例如 `python3 -m playwright install chromium`。

### Windows：从源码

```powershell
cd <repo-root>
python setup.py                    # 一条命令完成安装与配置
python -m headless_re_mcp doctor --json --strict
python -m headless_re_mcp serve
```

Windows 上 `setup.py` 会依次安装默认 extras、发现本机授权的 IDA Professional 9.x、
按固定大小与 SHA-256 校验下载缺失的 x64dbg/可选 CLI 依赖包、写入用户 `config.json`、
激活 idalib，最后生成 MCP 配置并跑一遍 Doctor。IDA、idalib、Hex-Rays 与许可证永远不进依赖包。
Linux 上运行同一入口时不会下载 Windows 依赖包或强制配置 IDA；默认 extras 也不包含 Qt native GUI/IDA。

无人值守用 `--non-interactive`；已有依赖用 `--skip-release`；不装 Python 包用 `--skip-pip`。

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
- 自愈：`session.health`（按需检查各后端存活与连接状态，并就地重建掉线的连接）、`session.recover`（重开死掉的后端）
- Workflow：`workflow.*`
- 检测/脱壳（可选外部 CLI）：`detect.*`、`unpack.*`（非通杀承诺；`claims_universal_unpack=false`）
- 目标 UI（有界）：Win32 交互与截图；UIA/OCR/SendInput 为实验路径，勿默认依赖
- Android 静态：`apk.open/manifest/permissions/certificates/components/classes/methods/strings/xrefs`（androguard 进程内）、`apk.decompile/export_sources`（jadx CLI）
- Android 改包：`apk.decode/repack/sign`（apktool + apksigner；`apk.sign` 缺省用 Android debug keystore）
- Android 设备：`device.list/connect/info/properties/packages/install/uninstall/launch/force_stop/current_activity/logcat/screenshot/pull/push/forward`
- Android 动态：`frida.devices/device.connect/server.ensure/applications/spawn/java.classes/java.methods`；hook 复用 `frida.hook.template`（含 `android_ssl_unpin` / `android_crypto_monitor` / `android_root_bypass`）
- Web 静态：`js.deobfuscate/beautify/unpack_bundle`（webcrack）、`wasm.info/wat`（wabt）；WASM 反编译复用 `ghidra.*` + ghidra-wasm-plugin
- Web 动态：`web.open/navigate/close/network.list/network.get/console/scripts/script.source/wasm.list/dom.snapshot/screenshot/har.export`（Playwright 驱动 CDP）
- 抓包（Web 与 Android 共用）：`proxy.start/stop/status/flows/flow.get/replay/export_har/ca.install_android`（mitmproxy 进程内）
- 工作方向：`workspace.mode.get/set`（`full|pe|android|web`）

### 目标类型与工作方向

`session.create` 按扩展名与魔数自动判定目标类型（MZ→PE、含 `AndroidManifest.xml` 的 zip→APK、`http(s)`/`.js`/`.wasm`→Web），也可显式传 `target`。PE 专属工具对非 PE 会话返回结构化 `target_mismatch`，不会深入后端才失败。

未干净关闭的会话会按同一 ID 从 `sessions.db` 水合回来（`state=created`，`metadata.restored=true`），不自动拉起 IDA/x64dbg。监控台重启后继续用旧 id，不要再 `session.create` 一条新的。

工作方向（`workspace_profile`）把工具面裁剪到单一场景：`pe` 隐藏 Android 与 Web 工具，`android` 隐藏 Web 工具，`web` 隐藏 Android 工具，默认 `full` 不裁剪。抓包（`proxy.*`，含 Android 专用的 `proxy.ca.install_android`）由 Web 与 Android 共用，故只在 `pe` 方向隐藏，`android`/`web` 都保留。裁剪只影响**可见性**，完整 catalog 仍是唯一权威；读写策略是另一条独立边界。监控台开屏会让你选择方向，选择同时作用于 MCP 客户端下次连接看到的工具集、监控台 Agent 的工具面，以及检查器布局（PE 虚拟桌面 / Web 页面监视 / Android APK；侧栏在 Web 方向改为 URL）。

动态写操作仅接受明确参数与白名单寄存器；无 `dynamic.command`。同样的原则贯穿新增面：**没有 `device.shell`、没有 `web.evaluate`、不接受调用方自带 Frida 脚本**——设备与浏览器上的每个能力都是具名且校验过参数的工具。设备序列号与包名按严格正则校验，杜绝参数注入。

### 故障自愈

RPC 连接掉线（例如被调试程序卡住导致一次超时）不会终结会话。worker 仍在运行、仍持有被调试进程，
后台健康检查会重建连接；即便监控关闭，下一次调用也会自行重连。失败的那次调用**不会被重放**，
因为重放可能让状态变更类操作执行两次——调用方仍会收到那次失败，但标记为 `retryable`。

worker 进程真正死亡时只上报不自动重启：重启后的调试器不再附着于任何进程，是否重新启动目标
必须由调用方决定，用 `session.recover` 显式处理。

`health_check_interval_s` 控制后台巡检间隔，设为 `0` 关闭（此时仍保留调用时重连）。

### 无人值守（加壳分析默认开；完全访问是开关）

监控台对话框右侧是两档：`请求批准`（写操作停下等人）和 `完全访问`（放开
`state_change` + `file_write`）。`PUT /api/agent/autonomy` 传
`{"mode":"request"|"full_access"}` 即可切换并持久化。

未在 config/环境里写 autonomy 键时，`Settings.load()` 默认放开加壳 PE 分析所需的
`state_change` 以及 `dynamic.stealth.set` / unpack / `static.open` 等文件写入；
`patches.apply` / `static.bytes.patch`、APK/Web 改包仍要人批。显式空列表
（`agent_auto_approve_effects: []` 且 `agent_auto_approve_tools: []`）仍是 fail-closed。

细粒度的 `agent_auto_approve_effects` / `agent_auto_approve_tools` 仍可用。
`agent_never_auto_approve` 优先级高于一切授权（含只读基线），写进去就是无条件停止。
自动执行的写操作会发 `approval.auto` 事件并写明是哪条规则批准的。
`GET /api/agent/autonomy` 可读回 `mode`、策略与它实际放开的工具清单。

加壳样本：`packer.classify` / `unpack.recommend` 给出 `stealth_profile`
（tmd/Themida/WinLicense → `themida`）。`dynamic.open` / `dynamic.launch`
省略该参数时按映射自动写 ScyllaHide ini，不必再等用户说「切到 tmd」。

- **持久目标与调度**：run 有界（分钟级、十来轮工具），mission 是跨 run 存活的目标。调度器按最早
  优先认领、一次喂一个 run，完成判据是 run 自己输出 `MISSION_COMPLETE` 标记，而不是"没有再调用
  工具"——后者会在模型停下来思考时误判。`max_runs` 是强制预算。重启时在途 mission 退回 PENDING
  而不是丢弃。接口在 `POST /api/agent/missions`。
- **进程守护**：`headless-re-mcp supervise` 在子进程退出或连续探测不到 `/readyz` 时重启它（进程
  活着但卡死是两种不同故障）。退避递增，单次探测失败不算故障，启动期不做就绪判定；快速反复崩溃
  会诚实地停下并报 `crash_loop`，而不是用重启循环伪装成正常运行。`scripts/install_service.ps1`
  注册开机自启——用计划任务而非 Windows 服务，因为后端需要交互式会话和持有 IDA 授权的用户配置。
- **看门狗**：`watchdog_interval_s` 控制巡检；发现死掉或反复掉线的后端会告警。
  `watchdog_auto_recover_backends` 默认关闭——恢复后的动态后端不再附着任何进程，是否重启目标
  是真实决策。告警走 telemetry 通道，外部采集器无需第二个端点。
- **样本间隔离**：`isolation_command` 在 mission 之间（不是 run 之间，同一 mission 的 run 共享目标）
  执行你提供的命令。本服务不管理虚拟机——hypervisor、快照名和凭据属于部署方。必需步骤失败会
  中止该 mission，因为继续下去正是会静默交叉污染结果的那种情况。
- **provider 韧性**：限流和 5xx 会退避重试，但**只在流还没吐出任何内容之前**——过了第一个 token
  重放会重复输出，还可能把工具调用再执行一遍。客户端错误不重试。

运维探针：`/healthz` 只回答存活（刻意不碰别的，慢后端不该引发重启循环），`/readyz` 单独回答就绪
并在存储或产物目录失效时返 503，`/metrics` 是 Prometheus 抓取点。后两者不需要控制台 token，
便于本机守护进程探测。

### 只读部署

`local_full_access: false` 会让所有会改变状态或写文件的工具返回 `write_disabled` 错误，
只读查询不受影响。工具仍然可见——调用方拿到的是能理解的拒绝，而不是工具凭空消失。
265 个工具的读写归类（148 只读 / 117 写）在 `tools/catalog.py` 里逐个显式声明，策略在调用时
读取，改配置不必重启。工具面裁剪（`workspace_profile`）与读写策略是两条独立的边界：前者决定
「看得见什么」，后者决定「能不能改」。

守卫下沉在 `CommandCatalog.bind_mcp`——所有绑定路径的唯一收口，所以 MCP、Web 控制台的
agent 路由与 OpenAI 桥接拿到的是同一套策略；Web 那条直接调服务方法的写入路径单独做了检查。

### 并发

工具在工作线程上执行，长调用（启动被调试程序、反编译）不会阻塞 MCP 事件循环，
同一连接上的其它请求仍能得到响应。单个后端内部仍按会话串行——调试器本身是有状态的。

## 仓库结构

```text
src/headless_re_mcp/   # Python 包与 MCP 服务
tests/                 # unit / integration / gate
native/                # x64dbg headless RPC
fixtures/              # 无害测试样本
scripts/               # Linux 安装脚本；其余 PowerShell 构建、同步、打包脚本仅 Windows
packaging/             # Windows WiX/MSI
external/              # 本机大型依赖占位（二进制多半 gitignore）
upstream/              # 本地上游 checkout（gitignore）
artifacts/             # 本地构建产物（gitignore）
```

根目录元数据：`pyproject.toml`、`README.md`、`setup.py`、`start_web.py`、`upstream.lock.json`、`LICENSE`。

上游不进 Git：复制 `.cursor/mcp.json.example` 或跑 `python setup.py`；以下同步脚本仅 Windows：

```powershell
powershell -File .\scripts\sync_upstream.ps1
powershell -File .\scripts\sync_upstream.ps1 -Name x64dbg
```

## 安装与构建

Linux x86_64：

```bash
python3 -m pip install -e '.[dev,pe,web]'
python3 -m headless_re_mcp doctor --strict

# 标准 Python 分发产物（需要 build 包）
python3 -m pip install build
python3 -m build
# -> dist/*.whl + dist/*.tar.gz
```

Windows：

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

### Windows 安装包

发布版提供 per-user MSI（装到 `%LocalAppData%\HeadlessReMcp`，不需要管理员）。**Python 运行时
与全部依赖随包发布**，装完即可用，不要求机器上已装 Python；装好后运行 `start_web.cmd` 打开
工作台，或用 `headless-re-mcp.cmd` 调 CLI。IDA 与 x64dbg 仍需自行准备。

内置解释器版本是锁定的（`pydantic-core` 只发 cp312 专用轮子，没有 abi3），所以运行时和
依赖必须成套打包。本地构建需要 WiX Toolset 3.14，会联网取一次 Python 嵌入包并缓存到
`artifacts/tools`：

```powershell
powershell -File .\scripts\build_msi.ps1     # 产出 MSI 与 .sha256
powershell -File .\scripts\verify_msi.ps1    # 装 → 跑 → 卸，并断言零残留
```

验证会清空 PATH 里的所有解释器，只允许自带运行时应答——用系统 Python 去测安装副本，
只能证明目录完整，证明不了装完能用。

推 `v*` 标签会由 `release` 工作流构建、跑同一套往返验证，再连同校验和发布。

## 验收

Windows 先跑零窗口 Gate，再按需跑 pytest。Linux 跳过 Windows-only gate，但运行完整可移植单测、doctor strict 与核心服务冒烟；缺可选环境出现 `skip` 时不能当通过。

```powershell
# 以下两个 x64dbg gate 仅 Windows
python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60

python -m ruff check src tests fixtures
python -m mypy
python -m compileall -q src tests
python -m pip check
python -m pytest tests/unit -q
python -m pytest tests/integration -q -rs   # 需本机后端；-rs 会列出每个 skip 的原因
#   开了 HEADLESS_RE_HIDDEN_DESKTOP 时 test_m10_ui_* 会跳过，见下方「硬约束」一节
python -m headless_re_mcp doctor --json --strict
```

前端（改动 `webui/` 时；使用 Node.js 24 LTS，最低版本见 `webui/package.json`）：

```powershell
cd webui
npm ci                 # 国内网络可加 --registry=https://registry.npmmirror.com
npm run typecheck
npx vitest run
npm run build          # 产物直接写入 src/headless_re_mcp/web/spa
```

Windows 硬约束：分析器进程（IDA / x64dbg headless）顶层窗口必须为 0；目标程序 GUI 不受此限。

`tests/integration/test_m10_ui_*` 会驱动目标窗口，需要独占的交互桌面：跑这几个 gate 时不要在
同一会话里安装软件或打开别的窗口，否则前台焦点被抢会得到 `no foreground window for SendInput`
或 `SendMessageTimeout`，那是环境干扰而不是回归。

它们枚举的是**当前**桌面，所以和 `HEADLESS_RE_HIDDEN_DESKTOP=1` 互斥：开着隐藏桌面时被调试进程
的窗口在另一个 Win32 Desktop 对象上，这 9 个 gate 会带 `visible_desktop` 标记明确跳过（而不是
以「窗口没观察到」失败）。要覆盖这部分就临时取消该变量再单独跑。

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

**Android 与 Web 两个目标域是新加的，成熟度明显低于 PE 那条链路**：契约（信封、读写分级、敌意输入）与降级路径有单元测试强制，但真机 Gate 只在装了对应工具的机器上才真正执行。缺 adb/jadx/apktool/webcrack/wabt 时相关 Gate 会如实跳过，**skip 不等于 pass**。

当前证据（在一台配好 x64dbg headless + Chrome/Playwright + mitmproxy + androguard 的机器上实测；
该机器**未**配置 IDA，所以 idalib 相关路径这一轮没有被执行）：

- 单元测试 1532 passed / 4 skipped（IDA UPX 夹具 1；Windows 上 3 个 shebang 探针超时测，Linux CI 会跑）
- 集成 Gate 81 passed / 9 skipped（含 x86 与 x64 双架构、UI 自动化、r2/frida/windbg 可选后端、
  provider 退避经真实 run 端到端（503 在 run 之下重试后照常 completed、401 一次请求即失败、
  流已产出后掉线绝不重放而是如实 failed,恒跑）、
  隐藏桌面隔离、连接掉线自愈、crackme 端到端、浏览器 CDP、抓包起停与端口释放、浏览器生命周期、
  浏览器跨线程驱动、关闭会话同时回收浏览器与抓包端口、长跑页面不按次泄漏句柄）
- 9 个 skip 均有明确原因：缺 .NET 样本（2）、未安装 Exeinfo PE（3）、未安装 webcrack（1）与
  wabt（1）、以及 2 个有文档说明的故意跳过
- 264 个工具（全部 265 个 MCP 工具，只排除会真删数据的 `artifacts.gc`）在敌意输入下全部返回
  结构化错误信封，无一抛出；且这条性质由 `tests/unit/test_tool_fault_contract.py` 每次运行强制
  校验（断言恰好覆盖“绑定工具数 − 1”），不是一次性测量，也不会因新增工具漏测。
  敌意**环境**同样覆盖：产物库被删除、变成只读或被损坏时，工具照常返回信封（存储类故障有专门的
  `storage_unavailable` 码并区分是否可重试），就绪探针如实报不可用，服务在目录恢复后自愈
- 长期驻留状态有专门的有界性与并发回归测试（`tests/unit/test_unattended_resource_bounds.py`）：
  抓包双缓冲同步淘汰、浏览器脚本表有界、多线程读写不撕裂、后端单例、APK 缓存随会话回收、
  会话关闭后无任何字典仍以其 id 为键、产物配额在会话开着时也生效且能扛住突发写入、失败的抓包
  启动不留残留、浏览器调用线程收敛且等待有界、产物目录被删后服务照常应答并自动重建
- 抓包的有界性用真实流量复核过：2600 次经代理的请求后保留数停在 2000（环形缓冲上限），
  内存在到达上限后不再增长（2000→2500 次请求期间 98 MB 持平），句柄 +2、线程 0
- 上述结论用压缩时间的 soak 实测复核过：600 轮会话生命周期 RSS +1 MB、线程与句柄零增长；
  20 轮抓包起停与 15 轮浏览器开关同样零增长；失败路径（上千次无后端调用、40 次端口被占的抓包
  启动、12 次浏览器启动失败）在修复后均为零增长。其中会话流失那条已固化为常驻测试
  （200 轮 create/register/close，断言线程数归位、产物根不超配额三倍），不再依赖"记得去 soak"
- 安装包：清空 PATH 里所有解释器后仍能用自带运行时启动工作台，SPA 与 `/api/sessions` 均返回 200，
  卸载后目录完全移除

已知不稳定：`test_m10_ui_*` 依赖独占的交互桌面，在全量并发跑时偶发失败（前台焦点被抢），
单独重跑稳定通过。判定回归前请先单独复跑。

Gate 会从 `config.json` 读取后端路径（`tests/integration/conftest.py` 负责桥接），所以配置好的机器不会因为"没设环境变量"而假跳过。**skip 仍然不等于 pass**：换一台缺后端的机器，对应 Gate 会如实跳过。

无人值守的机制已经具备（自动批准策略、持久目标与调度、进程守护、看门狗、隔离钩子、provider 退避），
但这不等于本项目替你承担了 SLA。仍然成立的限制：真机 Gate 只在配好后端的机器上手动跑过，
自建 runner 的那条 CI 从未绿过；单维护者、公开历史短；IDA idalib 与 x64dbg headless 本身都不是
为 7×24 无人值守设计的，可用性上限被它们锁死。要对外承诺可用性数字，这三条得先自己解决。

不适合：在 Linux 上要求 x64dbg/WinDbg/Win32 UI/MSI，或把可用性责任外包给上游的场景。  
适合：已有 Windows + IDA 9.x 的完整 PE 工作流；或在 Linux x86_64 上使用 MCP 核心、纯静态检测、Web/Android/Ghidra/radare2 等可移植能力。

仅分析你拥有或获明确授权的样本。本地服务含写寄存器/内存能力，勿对不可信代理暴露，勿在未隔离环境处理未知样本。

## License

GPL-3.0-only。见根目录 `LICENSE`。第三方工具由用户自行获取与授权；上游修订锁定见 `upstream.lock.json`。
