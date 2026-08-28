# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

## [Unreleased]

本轮在既有 PE 逆向能力之外新增 Android 与 Web 两个目标域，并把监控台重做成对话居中的
Agent 工作台。工具面从 199 增至 **266（149 只读 / 117 写）**；读写分级在
`tools/catalog.py` 里逐个显式声明（如 `memory.protection`、`workflow.breakpoint.put` /
`disable` 计入写，`static.search.text`、`patches.list` 计入读）。以下按类别列出。

新增 Linux x86_64 核心支持：wheel/sdist 与 `scripts/install-linux.sh` 可安装，`doctor --strict` 以平台动态必需项判断就绪，`serve` / `serve-web`、会话、制品和可移植后端可在 Linux 加载。doctor 与 `/readyz` 现在报告 `full`（Windows）或 `core`（Linux）支持级别。

x64dbg、WinDbg/cdb、Win32 UI/UIA/SendInput/Windows OCR、hidden desktop、MSI/WiX 及现有 Windows 专用 unpacker 适配在 Linux 明确报告 `unsupported_on_platform`，不再伪装 ready，也不阻塞 Linux 核心就绪。Windows 的原有 required 探针与 MSI/PowerShell 路径保留；IDA 探测同时识别 Windows `idalib.dll` 与 Linux `libidalib.so`。

CI 增加 Ubuntu/Python 3.11、3.12 的 lint、mypy、unit、doctor、核心服务与 wheel/sdist 构建；真实 Windows 后端 gate 继续留在 Windows job，Linux 收集时给 Windows-only 集成测试明确 skip 原因。

托管 quality job 只装 `.[test,dev,web]`：没有 PySide6 / winsdk 时 mypy 仍能过；导入 `native_app.bootstrap` 不再顺带加载 Qt GUI；没有编好的 PE 夹具时单元测试也能收集完。监控台 `webui/src/agent/state.ts` 的改动已重新打进提交的 SPA。UPX/XVLKC/Scylla/VMPDump/de4dot 在会话不是 PE 时先报 `target_mismatch`，不再因为本机没装 CLI 就说成 `capability_unavailable`。

CLI 工具超时不再可能卡死或漏杀孤儿进程。`run_bounded` 过去在 `with subprocess.Popen(...)` 里跑工具，其 `__exit__` 会在调用线程上关闭 stdout/stderr——当被启动进程派生的孙进程继承了这对管道并存活时，读取线程仍阻塞在 `read()` 上持有缓冲区锁，`close()` 便永久阻塞，有界超时变成永久挂起。现不再用上下文管理器：每个读取线程自持其流并在 `read()` 返回后关闭，主线程只回收进程、绝不碰管道。POSIX 下还让工具独立成会话，超时/取消时按进程组整体发信号（限组长，避免误杀服务自身的进程组），从而杀掉 ppid 遍历看不到、已被 init 收养的孙进程（如残留的 JVM/helper）。

die/exeinfope/upx/de4dot 各自的 `_capture_process` 采用同一范式收敛：读取线程自持自闭管道、捕获线程只在读取线程已结束时才关句柄，POSIX 下工具独立成会话。de4dot（及复用它的 NETReactorSlayer）正常退出后遗留的 runner 子进程（JVM/dotnet，常被 init 收养）以前 ppid 遍历看不到而泄漏；新增 `collect_process_group` / `terminate_process_group` 按会话组枚举并逐个按各自 `pgrp` 击杀，避免组长 pid 复用误伤无关进程组。

调用方取消（`BoundedCancelled`）在各适配器间统一为“取消不是失败”：NETReactorSlayer 适配器过去把取消重映射成 `process_failed`，与 scylla/vmp_dumper/xvlkc 等兄弟适配器不一致，现改为原样上抛；`unpack.auto` 的 UPX 阶段（`unpack_upx_test` / `unpack_upx_unpack`）过去把取消经通用 `except BaseException` 吞成 `internal_error` 事故与假的 `upx_test_failed`，现先行捕获并重抛给 `unpack.auto` 的取消处理器，最终干净地记为 `unpack_cancelled`。此外 `unpack.xvlkc/vmp/scylla` 各 CLI dump 在进入取消作用域前会像 `unpack.auto` 一样先 `_reset_unpack_cancel`，避免上一次 `unpack.cancel` 遗留的取消闩让后续同会话 dump 一进来就自我取消。

### 测试（x64dbg RPC 客户端派发与 trace 校验）

- `backends/x64dbg/client.py` 的既有测试覆盖命名管道帧、`read_events`、
  `wait_for_state`、`close` 与重连,但二十多个细请求包装器、`trace.*` 生命周期与
  `_validate_trace_result` 守卫、`request` 的能力/关闭/退出门以及若干辅助函数仍未覆盖。
  新增 `tests/unit/test_xdbg_client_dispatch.py`,只测各平台都为纯 Python 的部分,不碰
  Win32 传输:每个包装器(threads/stack/disassembly/symbols/breakpoints/patches/
  pe.headers/imports 等)的参数整形与方法名(含 `output_path`/`rights`/`limit`/
  `size` 等可选项在给与不给两种情形)、`trace_start` 的边界校验与派发、`trace_stop`/
  `trace_status` 在未初始化时跳过校验、`trace_cancel` 委派 `trace_stop`、
  `_validate_trace_result` 的布尔录制态/路径匹配(含内嵌 null 字节的非法路径)/边界
  不符/计数器归零与非法值各分支、`request` 门(已关闭报 `session_closed`、进程已退报
  `worker_exited`、无能力方法先于传输报 `capability_unavailable`、`rpc.` 前缀绕过能力
  门)、`_note_debuggee_pid` 只接受正数 pid(int/数字串/0/非数字/缺字段)、
  `seed_headless_event_settings` 写一次且幂等、`XdbgRpcError.from_payload` 非字典分支,
  以及 `pid`/`exit_code`/`capabilities`/`metadata`(防御性拷贝)属性。行覆盖 42% → 62%
  (余量为 Windows 专有的命名管道传输、`__init__` 真实拉起与桌面/收尾路径)。

### 测试（共享受管子进程 mixin 的跨平台合同）

- `backends/common/subprocess_rpc.py` 的既有 terminate 测试只验证 Win32 后代枚举、在
  Linux 上 skip，导致 mixin 的启动 kwargs、`pid` / `analyzer_windows` 属性与 `_lock`
  接缝在 Linux CI 上从未被执行。新增 `tests/unit/test_subprocess_rpc_mixin.py` 固定各
  平台都成立的部分:`no_window_popen_kwargs()` 的返回形态(Linux 上 `creationflags==0`、
  `startupinfo is None`;Windows 上抑制控制台窗口且 `wShowWindow==0`)、`pid` 属性、
  `analyzer_windows` 排序并累积目击集(窗口关闭后仍留在累积集里)、`terminate_process`
  在有无 `_lock` 两种情形下都真实回收进程且释放锁。Linux 行覆盖 44% → 89%(仅余
  Windows 专有的 `STARTUPINFO` 分支,由形态测试在 Windows job 覆盖)。

### 测试（IDA worker RPC 客户端合同测试）

- `IdaWorkerClient` 的传输层此前只有窗口历史上限一项合同有测试（行覆盖 32%）。新增
  `tests/unit/test_ida_worker_client_rpc.py`：通过 `PYTHONPATH` 遮蔽真实
  `backends.ida.worker` 模块、以脚本化假 worker 子进程走完整协议，不需要 idalib、
  Windows 与 Linux 均可运行。覆盖 ready/fatal 握手（含 capabilities 非列表、data 非
  对象、启动前崩溃携带 stderr 诊断）、请求按 id 关联与错误载荷映射、超时/未读消息
  溢出后 worker 被强制退休（不复用卡死进程）、close 的三种收尾（应答后不退出则杀树、
  worker 已死静默收尾、不应答则上抛超时且二次 close 幂等）、分析器窗口在启动与请求
  两个时点的拒答及重复目击不膨胀历史，另有 `next_receive_deadline` /
  `startup_receive_remaining` / `IdaWorkerError.from_payload` 纯函数合同。该模块行
  覆盖 32% → 98%。

### 测试（doctor 可选外部 CLI 探针）

- `doctor.py` 里 de4dot、NETReactorSlayer、XVLKC、VMP dumper、Scylla 五个可选 CLI 探针
  此前完全没有测试(x64dbg/IDA/upx 探针已有覆盖)。新增
  `tests/unit/test_doctor_optional_tool_probes.py`,参数化验证它们统一的三态诚实契约:
  未配置报 MISSING 且给出配置指引、配置了但文件缺失或底层 CLI 探针失败报 BLOCKED、只有
  底层探针确认可运行才 READY(探针在源模块里以接缝形式打桩);并补上 `probe_upx` 里
  `test_doctor` 未覆盖的两条分支(配置路径不存在、探针抛 OSError)。`doctor.py` 行覆盖
  63% → 78%(余量为 IDA/x64dbg/native 工具链/ghidra 等平台相关探针)。

### 新增（监控台工作台）

- 监控台改成对话居中的 Agent 工作台：左侧对话/会话，右侧按 target 换皮的检查器。
- 分析会话在控制台重启后按同一 ID 从 `sessions.db` 恢复（休眠，不自动拉起 IDA/x64dbg）。
- 对话框右侧增加 Codex 风格两档审核：`请求批准` / `完全访问`（没有中间档）。
  `PUT /api/agent/autonomy` 现接受 `{"mode":"request"|"full_access"}`，分别清空授权或放开
  全部写效果；`GET` 回传 `mode`。切换立即写入本机配置，完全访问时会放行当前停着的批准卡片。
- 未配置 autonomy 键时，加壳 PE 分析所需的 `state_change` 加相关 `file_write` 默认自动批准
  （patches / APK 改包除外）。

### 新增（x64dbg 用户态反检测）

- x64dbg 用户态 hide：ScyllaHide 装到**正在使用的** headless `plugins/`（不是只写 `external/`），
  AI 通过 `dynamic.stealth.status` / `dynamic.stealth.set` 和 `dynamic.launch(stealth_profile=)`
  选择白名单 profile。`packer.classify` / `unpack.recommend` 给出 `stealth_profile`
  （tmd/Themida/WinLicense → `themida`）；open/launch 省略参数时按映射自动写 ini。
  `tmd` / `winlicense` / `oreans` 是合法别名。`enabled=false` 会把 `CurrentProfile` 写成
  `Disabled`。TitanHide / VT 启动器本阶段不做。

### 变更（监控台检查器）

- 监控台检查器按工作方向和会话 `target` 换皮：Web 不再显示 x64dbg 虚拟桌面 / 打开静态 /
  打开动态，侧栏改为 URL 并创建 `target=web` 会话；关闭会话后解绑，closed / 非 PE 监控帧
  不再打 x64dbg。

### 修复（Scylla output-aliases-input 测试在 Windows 命中另一守卫）

- `test_run_scylla_refuses_output_that_resolves_to_the_input` 构造 `tmp_path/nope/../input.exe`
  作为输出路径，指望它触发 `run_scylla` 的“output_path must differ from input_path”守卫。
  但该断言依赖 POSIX 特有行为：`Path.exists()` 不会穿过不存在的中间目录 `nope` 去解析 `..`，
  于是路径读作“尚不存在”，执行落到 differ 守卫。Windows 则把 `..` 按词法折叠回已存在的
  `input.exe`，`exists()` 为真，先触发更早的“output_path must not already exist”守卫，测试遂在
  Windows 3.11/3.12 失败。产品代码本身无恙——两条守卫拒绝的是同一危险（输出别名到输入），
  且 source 必须已存在才走到这里，故 differ 守卫在 Windows 上本就不可达。断言改为接受任一
  拒绝消息（`differ` 或 `must not already exist`），并注明跨平台差异；Linux 仍照常覆盖 differ 分支。

### 修复（core/limits 的 sysconf 测试在 Windows 收集即崩）

- `test_core_limits_eviction.py` 里三条 `available_memory_bytes` 的 POSIX 分支测试把
  `sys.platform` 强制成 `linux` 后再 monkeypatch `os.sysconf`，但 Windows 的 `os` 模块
  根本没有 `sysconf` 属性，`monkeypatch.setattr` 默认 `raising=True` 便当场抛
  `AttributeError`——被测代码从未跑到。产品代码本身无恙（Windows 走
  `GlobalMemoryStatusEx`，POSIX 分支也捕获 `AttributeError`），纯属测试脚手架在
  非 POSIX 宿主上搭不起来。三处补丁改为 `raising=False`，让 monkeypatch 在属性缺席时
    创建它（用后照常清理），Linux 行为不变，Windows 上这三条测试恢复检验既定语义。

### 测试（地址同步层补齐失败关闭分支）

- `core/addressing.py` 把 x64dbg 的模块快照和磁盘上的 PE 头翻译成静态/运行时地址映射，
  三处输入都受攻击者影响（模块列表走 RPC、selector 来自模型、PE 字节来自被调试进程映射
  的任意文件）。既有测试覆盖了主路径与常见拒绝，新增
  `tests/unit/test_addressing_hostile_input.py` 钉住其余失败关闭分支：模块结果不是对象 /
  没有 modules 数组 / 条目既无名也无路径一律 `module_list_invalid`；selector 命中某模块后
  附带的 path/name 约束不符报 `module_identity_mismatch`（两处不符都如实回报）、命不中报
  `module_not_found`、`\??\` 设备前缀被规整后仍可匹配；`ModuleAddressSpace` 的 RVA 越界报
  `address_out_of_range`、负地址在做任何运算前即 `invalid_address`；运行时元数据架构非字符串
  或不受支持报 `runtime_metadata_invalid`、同一会话路径命中多个模块报 `module_ambiguous`；
  运行时模块无路径 / 指向目录报 `module_file_unavailable`、`\??\` 前缀路径能被解析读出；
  非 PE / 截断的 COFF 头 / 截断的可选头 / 可选头 magic 不符 / 镜像基址为 0 分别报
  `module_file_invalid`；并补 `RuntimeModuleCatalog` 与 `RebasedModuleMapping` 的 `to_dict`
  序列化。模块覆盖率 88% → 99%。

### 测试（cdb/WinDbg 客户端补齐输入守卫与错误映射）

- `backends/windbg/client.py` 把模型给的地址、长度和 PID 直接交给 cdb 执行；命令白名单和
  截断标注已有测试，但拒绝分支、错误映射与 cdb 发现的跨平台分支此前未覆盖（80%）。新增
  `tests/unit/test_windbg_input_guards.py`（stub 掉 `run_bounded`，跨平台可跑）钉住：
  `disasm`/`live_disasm` 的长度必须是 1..256 的整数、整数地址不得为负、字符串地址不得含
  `; | &` 分隔符，合法整数地址被渲染成十六进制并折进白名单的 `u <addr> L<n>` 形式、合法
  符号地址原样透传；PID 非正数在任何启动前即被拒、attach 到非会话调试目标报
  `permission_denied` 且都不触发启动；活体探针无法启动 / 非零退出且无输出报 `backend_error`、
  非零退出但仍有输出则如实返回；缺 dump 文件报 `not_found`、内核 dump 需显式放行、无 cdb
  报 `capability_unavailable`；dump 与活体探针超时都把被杀的 pid 随 `timeout` 回报（避免
  调试器悬在活体目标上）。cdb 发现覆盖环境变量优先、`which` 的非 Store 路径、Windows Kits
  glob 布局、以及跳过不可启动的命中与全无安装时返回 None。模块覆盖率 80% → 99%。

### 新增（`device.net_snmp` 从 `/proc/net/snmp` 报 IPv4 协议计数）

- 新增只读工具 `device.net_snmp`，解析 `/proc/net/snmp`，给出套接字表（connections/udp）不
  携带的内核 MIB 式协议计数——`Ip`/`Icmp`/`Tcp`/`Udp`。分诊价值具体:`Tcp.RetransSegs` /
  `Tcp.OutRsts` / `Tcp.CurrEstab` 与 `Udp.NoPorts` / `Udp.InErrors` 能在应用被动态分析时反映
  连接抖动、重置与无人应答的端口累积。该文件以「表头行（`Tcp: RtoAlgorithm ...`）+ 数值行
  （`Tcp: 1 200 ...`）」成对出现:列全为整数的是数值行，否则为名字行，按协议逐一 zip;计数可为
  负（`Tcp.MaxConn` 为 `-1`），一律按有符号整数保留。诚实边界:没有对应表头的数值行、以及重复的
  协议块都跳过而不臆测;解析到零个协议即读取失败（文件缺失、权限拒绝、设备离线），报
  `backend_error` 而非空结果。协议集合有界并在超过上限时置 `has_more`。新增
  `tests/unit/test_device_net_snmp_fields.py` 覆盖表头/数值配对、负值、无表头数值行跳过、重复块
  跳过、零协议报错等分支。工具面 265 → 266（只读 148 → 149）。

### 修复（device.install/uninstall 把无法核实误报成明确成败）

- `device.install` / `device.uninstall` 用 `pm path` 复核安装/卸载结果，返回 true/false/null
  三态——null 表示复核跑不起来。但 `_pm_path` 只找 `package:` 行，没做其余 adb 读取（getprop /
  pm list）都会做的 `_is_host_error_output` 判定：adbutils 的 `shell` 有时把 adb 主机端自己的
  `error:` / `adb:` 消息当 stdout 返回而不抛异常（例如设备在改动与复核之间掉线）。这种主机错误
  被读成“没有 package: 行”，于是真装上的包报成 `installed=false`（假阴性），真卸掉的复核报成
  `uninstalled=true`（假阳性）——正是三态里 null 分支要避免的误报。现让 `_pm_path` 对主机错误
  输出抛 `AdbError`，两个调用方已有的 `except AdbError` 分支即把结果如实报成 null + “could not
  verify”。真正未安装的包回的是空输出（exit 1、无文本），不算主机错误，仍如实为 null/false。
  新增两条直测：`pm path` 返回主机错误串时 install 为 null、uninstall 为 null（而非 true）。

### 修复（工作方向隐藏了 Android 共用的抓包）

- `android` 工作方向此前把整个 `proxy.*` 面一起藏掉：`excluded_prefixes` 把 `proxy.` 归在
  `_WEB_PREFIXES` 里，而 `android` 隐藏的正是这组前缀。可抓包（mitmproxy）在能力概览与
  `service_proxy` 文档里都写明「Web 与 Android 共用」，其中 `proxy.ca.install_android` 更是
  Android 专用工具——结果它在为 Android 工作准备的方向里反而不可见，Android 逆向拿不到
  拦截代理与装 CA 的入口。现把 `proxy.` 拆到独立的 `_SHARED_ANDROID_WEB_PREFIXES`，只在
  `pe` 方向（隐藏一切非核心面）里藏，`android`/`web` 都保留。原先把该行为写死的两个 profile
  测试同步更正，并新增一条直测：`proxy.start/flows/ca.install_android` 在 `android`/`web` 可见、
  在 `pe` 不可见。

### 修复（`web.console` 补齐 total 与其余读取器对齐）

- `web.console` 是唯一不回 `total` 的分页读取器——`network.list`、`scripts`、`wasm.list`、
  `proxy.flows`、`apk.*`、frida `modules`/`applications`、`js.unpack_bundle` 全都回。它的文档串
  本就承诺「填满 limit 的一页不等于整个缓冲」,但只给了布尔 `has_more`:调用方知道「还有」,
  却不知道「还有多少」,无法据此决定下次用多大的 limit 一次取完。现补上 `total`(缓冲里的
  消息条数),与其余读取器口径一致;仍回最新的尾部,且因 limit 上限等于环容量、一次即可取完
  整个缓冲,故不需要 offset。文档串同步说明,并扩展回归测试断言 `total`。

### 修复（事故日志脱敏关键字与结构化脱敏对齐）

### 修复（apk.sign / apk.decode 先验证输入是有效 zip，再启 JVM）

- `apk.sign`（apksigner）与 `apk.decode`（apktool `d`）此前只检查输入路径存在（`is_file`）就把它
  交给 JVM。APK 本质是 zip：一个被截断的下载、指错的路径，或某个漏过自身校验的构建产物一旦不是
  zip，apksigner/apktool 仍会先拉起一个 JVM、再吐出一段晦涩的 Java 错误才失败——白白付出 JVM 启动
  开销，还把「参数错」报成 `backend_error`。现两条路径在开进程前先用 `zipfile.is_zipfile` 判定输入
  确是 zip（只读归档尾部、不解压，故校验本身没有 zip 炸弹暴露面），不是就回精确的 `invalid_params`，
  与 `apk.repack` 已经校验自己的产物是有效 zip、以及 wasm 工具在启 wabt 前先查 `\0asm` 魔数属同一快速
  失败范式。直接调后端的 apk.decode / apk.sign 单测相应改用真实（极小）zip 作输入，并新增直测钉住
  非 zip 输入在开进程前即被拒、有效 zip 仍照常交给工具。

### 修复（apk.repack 不再把空/损坏产物报成重打包成功）

- `apk.repack`（apktool `b`）过去只要退出码为零且输出文件存在就报成功并回填 `size`；但 apktool
  可能退出 0 却留下一个零字节或被截断的文件（构建在创建产物后中止、磁盘写满）。APK 本质是 zip，
  这类空/非 zip 产物其实是一次失败的重打包，原样报成功会把不可用文件送进 `apk.sign` / 安装，直到
  签名那步才暴露。现要求产物非空且能通过 `zipfile.is_zipfile` 校验，否则在重打包这步就报
  `backend_error`（附 `size` 与 stderr 摘录）。


### 修复（ghidra.decompile 区分“该地址没有函数”与“反编译为空”）

- `ghidra.decompile` 过去在给定地址不落在任何函数内时返回 `decompiled: ""`，与“确实反编译出空
  函数体”无从区分，无人值守的一遍会把空串当成函数体。postScript 只有在 `getFunctionContaining`
  命中时才写 `function`/`entry`。现由脚本显式写出 `found` 布尔，客户端在解析这份跨解释器 JSON 时
  也会在缺字段时按 `function` 是否存在补齐 `found`：`found=false` 明确表示“该地址没有函数”，此时
  空的 `decompiled` 是这个原因而非空函数体。


- `error_boundary` 的行内脱敏(异常消息、事故日志、HTTP 500 体、CLI stderr 信封走的同一条
  正则)只覆盖 `api_key`/`token`/`secret`/`password` 与 `Authorization: Bearer`,而
  `redaction.py` 的结构化脱敏还把 `private_key`/`access_key`/`passwd`/`credential` 当作机密键。
  于是一个在负载里会被抹掉的值,一旦出现在异常消息里(如 `access_key=AKIA…`、`private_key=…`)
  就会明文落进事故日志与 500 响应——正是 SECURITY.md 列为漏洞的那类泄露。现补齐这四个关键字;
  仍用严格的 `[:=]` 边界(不加尾随 `\w*`),避免把 `tokenized=false` 这类诊断文本误抹。回归矩阵
  相应增加 `private_key`/`private-key`/`access_key`/`passwd`/`credential` 五种形态。

### 修复（CLI 适配器超时在后端边界夹取越界输入）

- **apk（jadx/apktool）、web（webcrack/wabt）与 r2（radare2）几条 CLI 适配器把调用方的 `timeout`
  直接塞进 `run_bounded`**，而 frida 早已用 `_bound_timeout` 在后端边界拒非正、封上限。MCP schema
  虽声明 `0 < timeout <= 上限`，但 Agent 传输是拿模型给的参数**不经 schema 校验**直接调处理器
  （`CommandCatalog.invoke` → `spec.handler(**arguments)`）——一个非正 `timeout` 会让
  `run_bounded` 先把 JVM/node/r2 拉起来、再在循环第一圈就整树杀掉，然后报一个把「参数错」说成
  「超时」的误导性错误；一个巨大 `timeout` 则让在恶意样本上卡死的工具占着 worker 直到调用方
  给的秒数耗尽。新增共享的 `clamp_cli_timeout`（拒非正/NaN、按上限封顶）并让各适配器按自己的
  schema 上限（apk/jadx=1800、js/wasm=600、js.unpack_bundle=1200、r2=120）在开进程前先夹取，越界即回
  `invalid_params`。补回归测试钉住夹取函数本身，以及各适配器的非正超时在开进程前被拒（含 r2 在
  能力检查前即拒，与 jadx 一致）、巨大超时被封到各自上限；r2 一路在真 radare2 上对本地 ELF
  验过：正常分析照旧，非正/NaN 回 `invalid_params` 不再开进程，巨大值封到 120s。

### 修复（`web.open` / `web.navigate` 不报 HTTP 状态，错误页与命中难分）

- Playwright 的 `page.goto` 只在传输层失败（DNS、拒连、超时）时抛异常；一个 4xx/5xx 主文档会
  正常返回，于是导航到一个错误页与真正命中回的信封一模一样，无人值守的一遍会把错误页当成
  成功。现在把 `goto` 的响应状态取出来，`web.open`（给了 URL 时）与 `web.navigate` 在产生了
  HTTP 响应时附带 `status`，调用方据此区分错误页与命中；`about:blank`、同文档导航等没有响应的
  情况不回 `status`（缺省即诚实，编个 200 反而不实），与 `proxy.flows` / `web.network.list`
  早已回报的状态口径一致。

### 修复（Web 导航超时在后端边界夹取越界输入）

- **`web.open` / `web.navigate` 把调用方的 `timeout` 直接算进 `Future.result(timeout=…)`**，
  而 frida 早已用 `_bound_timeout` 在后端边界拒非正、封上限。MCP schema 虽声明
  `0 < timeout <= 120`，但 Agent 传输是拿模型给的参数**不经 schema 校验**直接调处理器
  （`CommandCatalog.invoke` → `spec.handler(**arguments)`）——一个非正 `timeout` 会让
  `Future.result` 立刻返回并把 runner 置为 `_wedged`，于是**一次越界取值就把本来健康的活会话
  拍死**，直到 `web.close` 才能恢复；一个巨大 `timeout` 则反过来让会话线程和线程池 worker 陪着
  页面一直卡住。现新增 `_bound_nav_timeout`（与 frida 同款）在排入任何工作前先夹取：非正回
  `invalid_params`、超限封到 schema 上限（120s）。补回归测试钉住负超时被干净拒绝且不 wedge 活
  会话（随后正常导航仍可用）、巨大超时被封到上限。

### 修复（`frida.hook.template` 在设备会话关闭后仍会注入钩子）

- close 只翻状态、不清 `frida_authorized` 元数据，已关闭会话仍可解析；其它设备 frida 操作都经
  `_frida_auth` 的开放态检查把关，唯独 hook.template 直接从元数据取 pid，于是一次迟到的调用会
  把脚本注入一个已消失会话的设备进程。现在设备分支也拒绝 CLOSING/CLOSED/FAILED 状态（本地 PE
  分支本就被 `_require_debuggee_pid` 挡住）。

### 修复（jadx 部分反编译失败不再伪装成完整源码树）

- `apk.export_sources` / `apk.decompile` 走 jadx，而 jadx 常在某几个类反编译失败时以非零退出收场，
  却仍为其余类写出可用的源码树——后端因此保留输出而非直接失败(只有磁盘上一个 `.java` 都没落时才抛)。
  但此前回包与一次整包成功长得一模一样:既无退出码也无 stderr,调用者无从区分「jadx 反编译了整个 APK」
  与「jadx 呛了若干类、这些只是幸存下来的」。无人值守的 agent 会把缺类的树读成完整反编译。
- 现在只要 jadx 非零退出但仍写出了树,`apk.export_sources` 的回包附带 `exit_code`、`tool_failed=true`
  与截断到 8000 字节的 `stderr`;`apk.decompile`(内部先跑整包 export)把这三个字段一并透传到单类结果上——
  所点名的类可能自身反编译干净,但整包判决要让调用者看到,免得把部分树当成完整的。`tool_failed` 与源码的
  `truncated` 语义分明:后者只表示「Java 在内联上限处被截」,前者表示「jadx 自己报了失败,树可能因某个
  这里看不到的原因缺类」。退出码为 0 时这些字段一概不出现;「非零退出且磁盘无源码」仍照旧抛 `backend_error`。
- 新增回归:非零退出带部分树时各字段齐备并经 export→decompile 透传、干净退出无失败字段、非零且无输出仍抛错、
  surfaced 的 stderr 受 `_MAX_STDERR` 约束,以及两个工具的描述都点名 `exit_code` / `tool_failed`。

### 修复（frida 设备解析卡死不再永占 worker）

- **`_resolve_device` 与 `add_remote_device` 里对 frida 的设备查找此前不带可由本侧兜底的截止时间。**
  `frida.get_local_device()`、`get_usb_device(timeout=5)`、`get_device(..., timeout=5)`、
  device manager 的 `get_device(..., timeout=1)` 与 `add_remote_device(...)` 都被直接调用——实测
  一个睡 8s 的查找即便带 `timeout=5` 也要到 8.000s 才返回，frida 的 `timeout=` 形参并不是本侧能
  强制的截止时间。`spawn` / `applications` / `java.*` 都在各自 deadline 起算之前先解析设备，于是一个
  永不返回的 USB 或 host:port 查找会把 worker 一直占住，直到进程被杀。
- 现在每个查找都像枚举那几个操作(`enumerate_devices` 等)一样跑在守护线程上并共用 `_PROBE_TIMEOUT_S`
  (30s)截止：卡死的查找抛 `timeout`，worker 立即释放，仍在后台的守护线程不会阻止进程退出。remote
  路径上「先复用已注册设备」的最佳努力查找若超时/报错，照旧退化到 `add_remote_device`(同样有界)。
- 新增回归：卡死的 USB 解析与卡死的 host:port `add_remote_device` 都在截止时间内抛 `timeout`
  而非空等(把 `_PROBE_TIMEOUT_S` 打小后计时断言)。

### 修复（js/wasm 工具非零退出不再伪装成干净结果）

- `js.deobfuscate` / `js.beautify` / `js.unpack_bundle` / `wasm.wat` / `wasm.info` 走的是「工具死了也把
  已产出的东西交回去」这一路径——webcrack 对半途去混淆常以非零退出收场却仍吐出可用代码,wasm-objdump
  也可能先打印若干段再在后面某段翻车。但此前只要有任何输出,非零退出码与 stderr 就被**整段吞掉**:回包
  与一次干净成功长得一模一样,无人值守的 agent 会把「因为工具中途挂了而被截断」的结果读成成品。
- 现在只要子进程非零退出且仍有输出,回包附带 `exit_code`、`tool_failed=true` 与截断到 8000 字节的
  `stderr`。`tool_failed` 与既有的 `truncated` 语义分明:`truncated` 只表示「我们在内联上限处截了文本」,
  `tool_failed` 表示「子进程自己报了失败,输出可能因某个我们看不到的原因不完整」。退出码为 0 时这些字段
  一概不出现,干净路径不添噪声;「非零退出且毫无输出」仍照旧抛 `backend_error`(带 `exit_code`)。
- 新增回归:非零退出带部分代码/文件/文本时各字段齐备、干净退出无失败字段、非零且无输出仍抛错、
  surfaced 的 stderr 受 `_MAX_STDERR` 约束,以及五个工具的描述都点名 `exit_code` / `tool_failed`。

### 修复（apk 列表分页越界）

- **`apk.classes` / `apk.methods` / `apk.strings` 现在在后端自身钳制分页窗口,不再只依赖工具
  schema**。这三个工具的 schema 已声明 `offset >= 0` 与有界 `limit`(见
  `test_apk_offset_schema.py`),但只有 MCP 传输会跑那层 pydantic 校验;Agent 与 OpenAI 桥接
  经 `CommandCatalog.invoke` 直接 `spec.handler(**arguments)` 调用,越界页会原样抵达后端。
  实测越界前:十个类时 `classes(offset=-1, limit=10)` 变成 `names[-1:9]`——一个**空页却仍报
  `has_more=True`**;`limit=-5` 变成 `names[0:-5]`,十个类被当成五个读。现新增 `_clamp_page`
  把 `offset` 钳到 `>=0`、`limit` 钳到 `1..schema 上限`,与 web / proxy / jsre 列表后端既有做法
  一致;`apk.xrefs` 本就把 `limit` 钳到 `>=1`,现补上同一上限。越界前后行为、上限对齐 schema 的
  漂移护栏均有回归测试(`test_apk_page_clamp.py`)。

### 修复（签名口令上进程表）

- `apk.sign` 过去以 `--ks-pass pass:<口令>` 把 keystore 口令明文放进 apksigner 的命令行。
  argv 对本机所有进程可见（Linux `/proc/<pid>/cmdline`、Windows 进程列表），签名 JVM 跑多久
  就暴露多久——SECURITY.md 把签名口令进入任何可观测通道列为漏洞。现改走 apksigner 原生的
  `env:` 口令源：口令放进仅子进程可见的复制环境，argv 里只剩变量名；stderr 抹除照旧保留作
  纵深防御。回归测试断言 sign 与 verify 两次调用的每个参数都不含口令、口令只出现在注入的
  环境里。
### 修复（mitmproxy 12 停止代理后监听端口不再泄漏）

- **`proxy.stop` 只发 `master.shutdown()`，在 mitmproxy 12 上端口停不下来。**
  mitmproxy 在走向 12.x 的路上让 `Master.done()` 不再收拾 proxyserver 的监听 server——
  mitmdump 从没察觉，因为 `run()` 一返回整个进程就退了。而本服务是长驻进程内嵌：stop()
  报 "stopped"、线程干净退出，OS 监听 socket 却一直 accept 到进程死，端口再也绑不回来，
  现场 gate（`test_proxy_start_means_listening_and_stop_releases_the_port` /
  `test_close_all_releases_every_running_capture`）在真 mitmproxy 12.2.3 上双双失败。
  现 stop() 在发 shutdown 前先在代理 loop 上 drain `Servers.update([])`（官方停监听方式，
  会 await 每个 listener 关闭）；线程已死时跳过 drain 不空等。补 fake 单测钉住
  drain-先于-shutdown 的接线与旧版 mitmproxy 无 Servers API 时的退化路径；真 gate 在装了
  mitmproxy 的机器上验证端口确实释放。

### 修复（`dotnet.il` 长分支与常量操作数按无符号解码）

- `_disassemble_il` 只把 1 字节短分支(`br.s`/`brfalse.s`/`brtrue.s`)当有符号读,4 字节
  长分支(`br`/`brfalse`/`brtrue`)与 `ldc.i4` 常量却按无符号解码。按 ECMA-335 这些都是
  有符号 int32,于是一次向后跳转 `-10` 打成 `4294967286`、`ldc.i4 -1` 打成 `4294967295`——
  agent 读来判断循环走向的正是这个补码位型而非真实偏移。现把有符号操作数集中到
  `_SIGNED_OPERANDS`(两种宽度的分支 + `ldc.i4`),元数据 token(`call`/`ldstr` 等)仍按
  无符号。新增直测:对长分支、常量、短分支与 token 混合的 IL 断言各自解出正确符号。

### 修复（frida.memory.read 在 frida 17 上因用了被删的全局 API 而失效）

- **`frida.memory.read` 的注入脚本用 `Memory.readByteArray(ptr(address), size)` 读内存。**
  frida 17 删掉了 `Memory.read*` 这批全局自由函数，于是这句在现代 runtime 上抛
  `TypeError: not a function`，`frida.memory.read` 在整条动态分析线上直接坏掉——真机复现：
  frida 17.17 attach 本地进程，`attach` / `modules` / `exports` 都正常，唯独 `memory.read`
  报错。改用 NativePointer 方法 `ptr(address).readByteArray(size)`（frida 12 起就有，覆盖
  `android` extra 声明的 `>=16.5` 全区间）。真机验证：修复后读模块基址前 4 字节返回 ELF 魔数
  `7f454c46`。frida 原生 runtime 在 CI 跑不了，故按仓库既有做法（见 hook-template schema 测试）
  以源码静态断言钉住脚本用的是指针方法、不再出现被删的全局名。

### 修复（PE 扫描每次读取都吃满 256 MiB 预算）

- `scan_pe` 的 `_read_pe_bytes` 过去以 `stream.read(max_file_size + 1)` 一次性把整份输入读进
  内存。这一步刻意不信 `stat()`（文件可能在检查与读取之间变大）并把读取封顶在预算内，但
  Python 带缓冲的 `read(n)` 会先按 `n` 预分配再收缩——于是默认 256 MiB 上限下，**每一次扫描
  无论文件多大都瞬时吃掉 256 MiB 堆**（实测一个 4 KiB 文件峰值 256 MiB）。scan_pe 在每个二进制、
  每个会话上都跑，`inspect_dotnet` 与 `.NET` 枚举里的 `_load_metadata_context` 还会各自再读一遍，
  并发会话下这类瞬时尖峰是真实的 OOM/RSS 风险。现改为分块读到 `max_file_size + 1`：常规文件
  短读即 EOF，仍是一次「读满预算」的 `read`（I/O 边界不变，超限照样拒绝、文件增长照样封顶），
  只有大到填满一个分块的文件才多读，且绝不超过实际存在的字节。实测同一个 4 KiB 文件峰值降到
  约 1 MiB。回归测试断言小文件在默认 256 MiB 上限下的分配与文件大小成比例，而非与上限成比例。

### 修复（内存版仓库时间线无界增长）

- `InMemoryAnalysisRepository`（与 SQLite 端口同契约、供自定义组合使用的生产模块）的
  审计日志裁到 `AUDIT_RETAINED_ROWS`、知识表裁到 `KNOWLEDGE_RETAINED_PER_SESSION`、
  关闭会话裁到 `CLOSED_SESSION_RETAINED`，唯独时间线只 `append` 不裁：每个生命周期
  事件与工具备注都往该会话的 Python list 里加一条，长驻进程用这个端口跑一夜就攒一夜。
  文件版时间线自身有 10,000 行 / 8 MB 的裁剪上限，现新增
  `TIMELINE_RETAINED_PER_SESSION`（10,000，与文件版行数上限一致）在 `append_timeline`
  里同样只留最新条目。新增回归：把保留数调小后断言旧条目被裁、无关会话不受影响。

### 修复（合并回归：成功路径残留进程与 UI 捕获错误码）

- die/exeinfope/upx 的 `_capture_process` 重新在**成功**退出后清点并回收启动器遗留的
  detached helper（`terminate_leftover_process_tree`：ppid 遍历 + 会话组扫描,按各自
  `pgrp` 逐个击杀,避免组长 pid 复用误伤）。该行为随「Reap helpers after successful CLI
  launches」引入,但在与 `_capture_process` 读者自闭管道范式收敛的合并中被覆盖丢失,
  只有 de4dot 保留了等效逻辑;本次按现行 process_tree API 重建并接回三处。
- 上述清扫在 Linux 上现在**确定性**收尾:进程启动即启用 `PR_SET_CHILD_SUBREAPER`
  收养启动器遗弃的孤儿,清扫返回前用有界 `waitpid` 轮询把每个被杀 pid 真正回收
  (`ECHILD` 时按 `/proc` 存在性区分「已被收尸」与「尚未过继」,已结束的 pid 不再
  空转到截止)。此前 helper 死没死取决于内核处理 SIGKILL 的时机——测试在快机器上
  碰巧能过,这正是上次合并把回收链整个丢掉却没有一个测试变红的原因。新增 Linux
  专用测试直接钉住机制本身(subreaper 标志已设、被杀子进程不留僵尸、清扫返回时
  孤儿的 `/proc` 条目已消失),机制再被丢弃必然变红,不再靠调度运气。
- `ui.screenshot` / `ui.ocr` 对路径穿越型 session id 现在在**任何平台**都返回
  `invalid_request`:输入校验挪到 Windows 平台门之前,Linux 上不再把敌意输入报成
  `unsupported_on_platform`。

### 修复（`proxy.flow.get` 头部无界回传）

- `proxy.flow.get` 一直把响应体按 200000 字节内联/溢写严格设界,却用 `dict(req.headers)` /
  `dict(resp.headers)` 把头部整包倒进返回——而 mitmproxy 在保留的 flow 上留着完整头部,一个
  多话或恶意的服务端(成千上万个头、几 KB 的 `Set-Cookie`)因此能把一坨无界数据塞进工具返回,
  与本后端其余处处设界的作风相悖。现新增 `_bounded_headers`,按条数(100)、单值(4 KiB)与总量
  (64 KiB)三重设界(重复名沿用旧的 `dict` 语义折叠为最后一个),被裁时在对应 `request` /
  `response` 上打 `metadata_truncated`;`url`、`method` 也一并按既有上限设界。文档串同步说明,
  并新增单值/条数/总量三种裁剪与正常放行的回归测试。
### 修复（`web.network.get` 取不到响应体时仍保持形状）

- `web.network.get` 的文档串承诺回 `body`、`base64_encoded`、`body_truncated`,但当 CDP
  对某个请求没有响应体时(重定向,或响应体已被其缓存淘汰,`Network.getResponseBody` 抛
  「No resource with given identifier found」),失败分支只回 `{**entry, body_error}`——恰恰在
  这条路径上把承诺的三个字段全丢了,读 `result["body"]` 的调用方直接缺键。现失败分支补齐
  `body=""`、`base64_encoded=false`、`body_truncated=false` 与 `body_error`(说明原因),成功
  与失败两条路径形状一致;空体不落盘。文档串补上 `body_error`,并新增该失败路径的回归测试。
### 修复（mitmproxy 出错的流不再被整条丢弃）

- proxy 会话此前只挂了 mitmproxy 的 `response` 钩子,没挂 `error`:一条 mitmproxy 无法完成的流
  (TLS 握手被拒、上游不可达、请求中途连接重置)于是根本不进抓包——而逆向一个 app 时,「这个域拒绝了
  握手」往往正是结论本身,却被静默扔掉。
- 现在挂上 `error` 钩子:出错的流像正常流一样被记录,条目标记 `error=true` 与 `error_msg`(如
  `net::ERR_CONNECTION_REFUSED`),`status` 为 `null`——完成的流一定带数字 `status` 且无 `error` 字段,
  据此区分。`error_msg` 与既有 url/method 一样先经 `_bounded_metadata` 收进上限,超限置 `metadata_truncated`;
  mitmproxy 没给消息时回退成 `flow error`。出错流照样存进 raw 存储(与摘要环严格同步),
  故 `proxy.flow.get` 不会 404 一条列表已登记的流。
- 实现上把 `response` 主体抽成共享的 `_record`,`response` 与 `error` 都走它,保证保留字节记账、
  溢出省略与环淘汰逻辑对两条路径完全一致;顺带把请求字段取值改为 `getattr` 兜底,请求缺失也不炸。
- 新增回归:出错流被捕获并标记、与完成流可区分、错误消息受上限约束、无消息时回退、出错流可经 raw 取回
  (环不变量成立)、完成响应路径不带 error 字段,以及 `proxy.flows` 描述点名 `error` / `error_msg`。
### 修复（device.install 先验证输入是有效 APK（zip），再向设备推送）

- `device.install`（adb install）此前只检查本地路径存在（`is_file`）就把文件交给 adbutils 推送到设备
  再跑 `pm install`。APK 本质是 zip：一个被截断的下载、指错的路径，或某个被当成重打包产物的解码资源
  一旦不是 zip，只能在整份传输之后失败，而 `pm` 报的是一段晦涩的设备错误，而非其实是「参数错」。现在
  在推送前先用 `zipfile.is_zipfile` 判定输入确是 zip（只读归档尾部、不解压，故校验本身没有 zip 炸弹
  暴露面），不是就回精确的 `invalid_params`，设备侧一次都不碰——与 `apk.decode` / `apk.sign` 在开 JVM
  前先验证输入是 zip 属同一快速失败范式。相应新增直测：非 APK 输入在设备传输前即被拒；`_apk_package_name`
  被打桩的两条 install 单测改用真实（极小）zip 作输入。

### 修复（device.pull 写不出文件时不再报成 size 0 的成功）

- `device.pull` 过去在 adb sync“干净返回却没写出本地文件”时（远端路径不存在，较旧 adbutils 不抛异常，
  前置 stat 探测又是尽力而为）会走到 `capped_file_size`——它对不存在的文件返回 0——于是回一个
  `size: 0` 的成功，调用方会当成一个可打开的空文件。现在拉取后若本地文件确实不存在，即报
  `not_found`（远端路径可能不存在）。这个判定与 adbutils 版本无关：拉取成功的普通文件必然落地，
  空的合法远端文件仍会作为 0 字节正常返回。

### 修复（`frida.java.methods` 分不清「类没加载」与「类无自有方法」)

- `frida.java.methods` 此前只回一个方法名数组。脚本里 `Java.use(className)` 对未加载的类会抛异常,
  异常冒出 `Java.perform` 后被 Python 的通用 `except` 兜成 `backend_error`;而**加载了但没有自有方法**
  (方法全继承自父类)的类则正常回空数组。于是「类名写错/没加载」既可能变成一条泛化后端错误、
  也可能——取决于版本与时序——与「类在、但自有方法为空」的空数组无从分辨。无人值守的 agent 据此
  会把一个根本没加载的类读成「这个类没有方法」。
- 现在与兄弟接口 `frida.exports` 的 `found` 一致:脚本侧 `methods` 改为回 `{found, methods}`,
  `Java.use` 失败即 `found=false`、`methods=[]`;成功则 `found=true`。据此,`found=false`+空列表明确
  读作「类未加载/类名不解析」,`found=true`+空列表读作「类在,但不声明自有方法」。分页 `has_more` 行为不变。
- Python 侧解析与 `modules` 同款:优先按 `{found, methods}` 字典解读,同时容忍旧的裸数组形状
  (裸数组按 `found=true` 处理),脚本与 Python 版本错配时不炸。
- 新增回归:未加载类回 `found=false`/空列表、已加载有方法类 `found=true` 且满页 `has_more=true`、
  已加载无自有方法类 `found=true`+空列表,以及裸数组形状仍被容忍并报 `found=true`。
  `frida.java.methods` 描述点名 `found`。

### 修复（WASM 输入校验）

- `wasm.wat` / `wasm.info` 现在在派生 `wasm2wat` / `wasm-objdump` 之前先核对四字节
  `\0asm` 魔数:非 WASM 文件（误传的 PE、文本、抓包下来的 HTML 响应等）过去会把子进程
  拉起来,再以晦涩的工具报错收场——白跑一趟。现直接返回 `invalid_params`,与既有
  `too_large` 守卫同一思路:超限先拦（顺序上魔数检查在体积检查之后,超大的非模块仍报
  `too_large` 而非误判为坏魔数），不合规的输入根本不交给子进程。
### 修复（监控台回环护栏）

- 非回环连接现在真的收到承诺的 `403 loopback_only`。此前回环守卫在中间件里抛
  `HTTPException`,而 FastAPI 的异常处理器只包住路由层,拒绝会变成 `500 internal_error`,
  且每个非本机探测都往事故日志写一条记录(可被扫描器刷爆)。现改为中间件内直接返回 403。

### 修复（`..` 绕过产物归属守卫）

- 全仓沿用 `not session_id or Path(session_id).name != session_id` 作「单路径段」判据,但
  `Path("..").name == ".."`,故 `..` 能溜过。用在 `_session_artifact_roots` 时后果最重:每个
  归属根 `<category>/<id>` 会坍缩成 `<category>/..`,即 artifact 根本身,于是 `session_id=".."`
  的调用者被判定「拥有」**所有**其它会话的产物——而 `unpack.*`/`apk.*`/`dotnet.*` 正是靠
  `_session_owns_artifact_path` 判定客户端传入的磁盘 `path` 是否属于本会话才放行读写。
  (`_session_work_dir` 因另有 `relative_to` 二次围栏而幸免,`..` 在那里已 fail-closed。)
  新增 `_is_safe_session_segment` 显式拒绝 `.`/`..`/空/含分隔符,并让 `_session_artifact_roots`
  与三个 detection 产物写入函数统一走它。新增契约测试直测归属守卫:自有子树/归属根为真、
  他会话子树与根外路径为假、非单段 id(含 `..`)一律不拥有、符号链接无法把路径偷带出树,
  并对 `..` 越权单列回归。
- 产物归属守卫此前零直接测试,本次补齐。

### 修复（时间线 session_id 路径穿越）

- `session.timeline` 把客户端传入的 `session_id` 原样交给 `session_timeline_path`,后者只是
  裸拼接 `artifact_root/sessions/<session_id>/timeline.jsonl`。真实 id 恒为 uuid,但只要跑过
  任何 session,`sessions` 目录就存在,于是 `session_id="../../outside"` 解析成 artifact 根**之外**
  一个真实的 `timeline.jsonl`——被 `timeline.list` 读出内容,也被关闭会话清理逻辑 `unlink`
  (该 unlink 路径此前无守卫,虽下方的 debug-events 删除早有单组件守卫)。现在 `session_timeline_path`
  fail-closed:解析后若逃出 `sessions` 根即抛 `ValueError`(经信封映射为 `invalid_request`),
  合法 uuid 与根内嵌套 id(从不逃根)照常;清理逻辑加同款单组件守卫,uuid 之外的 id 直接跳过。
  回归测试端到端验证越根读取被拒且不泄露文件内容、清理不会删根外文件,并参数化钉住多种穿越形态。

### 修复（`proxy.flow.get` 返回请求体，二进制体不再糊成文本）

- `proxy.flow.get` 此前只回响应体、丢掉请求体：逆向一个 API 最想看的恰是「实际 POST 了什么」，
  而调用者拿不到。现在请求与响应对称返回各自的 `size` 与体：文本(≤200000 字节、可按 UTF-8 严格
  解码)走 `body`，其余走 `body_path`。
- 小体此前用 `decode("utf-8", errors="replace")` 强解：一张 200KB 以内的 PNG、一段 protobuf 会被
  替换字符糊成看似文本的乱码 `body` 交回，agent 无从分辨真伪。现在严格解码，失败即判定二进制并
  落盘成 `.bin` 制品、回 `body_path` 并附 `spill_reason`（`too_large` 或 `binary`），与既有的
  >200KB 溢出路径同款，绝不再把乱码当文本。请求侧同样处理。
- 溢出的请求/响应体各自登记为制品（`proxy_flow_request_body` / `proxy_flow_response_body`），
  `artifact_id` 挂在所属的 `request`/`response` 下而非顶层，两者的 id 不会互相覆盖，落盘体也像其它
  capture 一样可被保留清理回收、可经 `artifacts.describe`/`artifacts.read` 重新读回。
- 补齐后端与 service 两层回归：请求体文本、请求体二进制落盘、响应体二进制落盘（校验字节完全一致、
  请求与响应溢出落在不同文件），以及 service 层把溢出体登记为制品且 id 挂在对应侧。

### 修复（`web.network.get` 的二进制响应体不再以 base64 文本落盘）

- CDP `Network.getResponseBody` 对二进制体(图片、字体、wasm 等)返回 `base64Encoded=true`、
  `body` 为 base64 字符串。此前代码把这段 base64 **文本**直接喂给面向文本的溢出逻辑：大体积二进制
  于是把 base64 文本写进 `.bin` 制品——打开 `body_path` 拿到的并不是调用者以为的原始字节；且容量上限
  按比真实字节大约 33% 的 base64 长度来判定,一个解码后本可放下的体可能被误判 `too_large`。
- 现在二进制体先解码一次:容量上限按真实字节数判定,原始字节写入 `body_path`(`.bin` 名副其实)。
  二进制体不再内联、也不再把 base64 当文本写盘——`body` 为空、`body_truncated` 为 `false`、
  `body_bytes` 是解码后大小、`base64_encoded` 标记源为二进制。文本体(`base64Encoded=false`)行为不变。
- 标记为 base64 却无法解码的体不再被当作字节静默落盘,而是回 `body_error`。
- 新增回归:二进制体解码后字节与落盘文件逐字节一致、返回字段齐备,以及非法 base64 走 `body_error`。

### 修复（损坏的 web token 文件不再卡死启动）

- `web_token.json` 写入不是原子的:进程在写到一半时崩溃会留下截断的 JSON,而加载器此前把它
  直接喂给 `json.loads`(或对非 dict 调 `.get`)并抛异常,控制台从此启动失败,直到有人手工
  删掉该文件。`config.json` 的同类损坏早已是「替换而非致命」;现在 token 文件同样处理——损坏
  即重新生成强随机 token 并以 0600 权限落盘。重新生成是安全的:这是服务器自己的凭据,新值只
  会让旧会话失效。回归测试参数化覆盖截断 JSON、纯垃圾、裸字符串与列表四种损坏形态。

### 修复（监控台只读写请求返回 500）

- **只读部署（`local_full_access=false`）下监控台的写请求回 `500` 而非承诺的 `403`**。
  `/api/write` 的 Web 适配器直接调 service 方法、绕过按处理器的 `write_disabled` 守卫,改以共享
  catalog 的 `write_allowed` 标志兜底:只读时抛 `PermissionError`。但路由只 catch 了
  `KeyError`/`ValueError`,这个 `PermissionError` 会漏成 `500 internal_error`。现在路由捕获它
  并返回承诺的 `403 write_disabled`。
  说明:写面本身并未被写穿——`create_app` 一定会经 `register_agent_routes` 调 `bind_all_tools`,
  后者已从 `local_full_access` 设好 `write_allowed`,所以只读部署的写请求确实被拒,只是拒的
  方式此前是 500 而非承诺的 403。另外 `create_app` 现在也显式从设置写 `write_allowed`,与 MCP
  server 对齐——这是防御性的,让 composition root 成为权威来源,不再依赖"agent 路由注册顺带设
  了它"这一副作用。补只读拒绝(403)、完全访问仍放行、白名单/confirm 门仍先答的回归测试。

### 修复（生成 MCP 配置的秘密清洗）

- **`config generate` 的秘密词表补齐到与脱敏模块一致**：`_SECRET_KEYS`(精确键匹配,刻意如此以
  免误删 `token_count` 这类近似键)此前缺 `authorization`/`credential`/`passwd`/`private_key`/
  `access_key`——而 `agent/redaction` 把这些都当秘密。若某 doctor 探针 detail 以这些命名,系统别处
  都会脱敏、唯独这份被用户复制粘贴的配置漏出。现补齐(含无分隔符拼写,与 api_key/apikey 一致),
  并补测试钉住它们被剥且近似键 `credentials_checked` 仍存活。
- **`config generate` 会把嵌入的 doctor 快照里的秘密原样带进用户复制粘贴的 MCP 配置**。
  `_strip_secrets` 只递归 dict 值、不进 list,而 doctor 探针是以 `probes` 列表承载的,
  于是探针 `details` 里任何秘密命名的键(`api_key`/`token`/…)从未被清掉——恰恰是这个清洗
  器要防的东西。改为同样递归进 list;并给 `doctor_not_ready` 的提前返回也补上清洗(此前那条
  分支直接返回未清洗的 doctor 报告)。补 ready / not-ready 两条路径的回归测试、`_strip_secrets`
  的递归与大小写直测,以及 `_SETTINGS_ENV_MAP` 只引用真实 `Settings` 字段的漂移护栏(否则改名
  会让某个 `HEADLESS_RE_*` 路径从生成配置里悄悄消失)。

### 修复（adb forward 端口越界未在边界拦截）

- `device.forward` 的 local/remote 端点校验用 `tcp:\d{1,5}` 匹配，会放过 `tcp:70000` 这类五位数
  “端口”——而 `connect` 早已拒绝 1..65535 之外的端口。这类越界值原样交给 adb，只能换回一条含糊的
  `backend_error`。现抽出 `_check_forward_spec` 统一校验：tcp 端口须在 1..65535，越界即报
  `invalid_params` 并把越界值放进 details；`localabstract:` 与仅限 remote 侧的 `jdwp:` 原样保留。
  `tcp:0` 在两侧都被拒绝：local 侧 adb 会自动分配空闲端口，但 adbutils 丢弃了应答里带回的端口号，
  调用方只能拿到 `{"local": "tcp:0"}`、无从得知该连哪里；而 `release_forwards` 按请求时的 spec 删除，
  永远匹配不上 adb 实际以真实端口注册的监听——每次 `tcp:0` 都泄漏一个 adb server 监听，且删除失败
  会把追踪槽重新钉回，32 次后 forward 上限在进程生命期内永久锁死。remote 侧的 0 则根本不可连接。
  校验在解析设备之前完成,坏参数不占用任何 forward 槽。新增回归测试覆盖
  越界端口(local/remote)、`tcp:0` 两侧拒绝、边界 `1`/`65535`、`localabstract`/`jdwp`、jdwp 只在 remote 有效、以及
  畸形规格一律拒绝。

### 修复（apk 包名读取会整体解压 manifest）

- `device.install` 回读 APK 包名做校验时,`_apk_package_name` 用
  `archive.read("AndroidManifest.xml")[:65536]`——`read()` 会把整条 manifest 条目解压进内存后才切片。
  一份压缩炸弹式的 AndroidManifest.xml(盘上几 KiB、解压后数 GiB)因此会在切片前吃满内存。现改为
  `archive.open(name).read(_MAX_MANIFEST_BYTES)` 流式读取,只解压所需的前 64 KiB;对正常 manifest
  结果完全一致。新增回归测试用 tracemalloc 证明:面对解压后 32 MiB 的 manifest,峰值内存 <8 MiB
  (旧写法实测约 77 MiB),包名仍被正确解析;并覆盖前缀边界与缺失 manifest 的情形。

### 修复（托管质量门）

- 单测挂起不再吞掉全部日志：Windows quality job 曾在单测步骤挂满 30 分钟作业上限，
  runner 被强杀后连已完成步骤的日志都没有上传，挂在哪个测试无从查起。现在两个单测
  步骤各带步骤级超时（Windows 25 分钟 / Linux 20 分钟；步骤失败但日志保留、覆盖率
  照常上传），Linux 步骤补齐 `--timeout=120` 逐测试上限，并在 pytest 配置里加
  `faulthandler_timeout = 300` + `faulthandler_exit_on_timeout`：pytest-timeout 的
  thread 模式需要 GIL，卡死在 C 调用里的测试它拦不住，而 faulthandler 的 C 层看门狗
  会先转储所有线程栈、点名卡住的测试再退出。`faulthandler_exit_on_timeout` 是
  pytest 9.0 才有的选项，test extra 的 pytest 下限随之从 8.3 抬到 9.0——在 8.x 上
  它只是一条 unknown-option 警告，退出兜底会静默失效。
- 关闭挂起的最后一个盲区：pytest-timeout 与 faulthandler 兜底都按测试武装、测试后
  解除，谁都不覆盖**最后一个测试结束之后**的解释器关闭阶段。多个并发压力测试用非
  守护线程驱动产品代码（Windows 共享冲突下的时间线并发追加、artifact 探针、proxy/web
  后端启动、workflow 导航），其中数处 join 带超时且不查存活——线程一旦卡住，套件照常
  通过、摘要照常打印，然后 `threading._shutdown` 永久等待，正是挂满 30 分钟、无输出
  可查的形态。测试工作线程现全部为守护线程，原先无存活断言的定时 join 补上断言，
  卡住的工作线程在自己的测试里具名失败，而不是在套件通过后拖垮整个 job。
- 托管 quality job 只装 `.[test,dev,web]`：没有 PySide6 / winsdk 时 mypy 仍能过；导入
  `native_app.bootstrap` 不再顺带加载 Qt GUI；没有编好的 PE 夹具时单元测试也能收集完。
  监控台 `webui/src/agent/state.ts` 的改动已重新打进提交的 SPA。
- UPX / XVLKC / Scylla / VMPDump / de4dot 在会话不是 PE 时先报 `target_mismatch`，不再因为
  本机没装 CLI 就说成 `capability_unavailable`。

### 新增（会话目标类型）

- 会话不再只认 PE。`Session` 增加 `target`（`pe|apk|web`）与 `locator`，`architecture`、
  `binary`、`sha256` 改为可选；`session.create` 按扩展名与魔数自动判定目标类型
  （MZ→PE、含 `AndroidManifest.xml` 的 zip→APK、`http(s)`/`.js`/`.wasm`→Web），也可显式传
  `target`。PE 专属工具对非 PE 会话返回结构化 `target_mismatch`，而不是深入后端才失败。

### 新增（Android）

- **静态**：`apk.*` 12 个工具，androguard 进程内解析 manifest/权限/证书/组件/DEX 类与方法/
  字符串/xrefs，jadx CLI 负责 `apk.decompile` 与 `apk.export_sources`。
- **改包**：`apk.decode/repack/sign`，apktool 解包回编 + apksigner 重签，缺省用 Android
  debug keystore；签名失败时 stderr 里的口令会被抹掉再进错误信封。
- **设备**：`device.*` 15 个工具（adbutils），覆盖模拟器/真机连接、装包卸包、启动停止、
  logcat、截图、push/pull、端口转发。**刻意不提供 `device.shell`**——与既有「无
  `dynamic.command`」同一条原则；序列号与包名按严格正则校验，杜绝参数注入。
- **动态**：Frida 后端从「只能本机、只能一个 pid」推广到设备维度（USB/模拟器/远程），
  新增 `frida.devices/device.connect/server.ensure/applications/spawn/java.classes/java.methods`。
  原来的单 pid 校验是**替换而不是移除**：设备操作改用按会话的「设备 + 已授权 pid 集合」，
  会话必须先连设备、pid 必须由本会话 spawn 得到；PE 会话的本机单 pid 行为逐字未变。
  Android hook 模板并入现有 `frida.hook.template`，仍不接受调用方自带脚本。

### 新增（Web）

- **静态**：`js.deobfuscate/beautify/unpack_bundle`（webcrack）、`wasm.info/wat`（wabt）。
  WASM 反编译复用现有 `ghidra.*` 加 ghidra-wasm-plugin——wabt 的 `wasm-decompile` 已于
  2026-06 被上游删除，不再作为路径。
- **动态**：`web.*` 12 个工具，Playwright 驱动 CDP，采集网络请求、console、已解析脚本与
  WASM 模块、DOM 快照、截图与 HAR。大响应体（响应正文、脚本源码）落盘为产物并回引用，
  不撑爆上下文。**刻意不提供 `web.evaluate`**——它是浏览器侧的 `dynamic.command`。
- **抓包**：`proxy.*` 8 个工具，mitmproxy 以 addon 形式跑在独立线程，Web 与 Android 共用，
  含 `proxy.ca.install_android`。

### 修复（HAR 导出规范与边界）

- `web.har.export` 与 `proxy.export_har` 过去各自手搓一份 `{"request":{method,url},
  "response":{status,content:{mimeType}}}` 结构，缺了 HAR 1.2 规定每条 entry 必带的
  `startedDateTime`、`time`、若干 request/response 成员、`cache` 与 `timings`，所以标准
  消费端（Chrome DevTools「导入 HAR」、Firefox、har-validator）一律拒绝加载——抓下来的
  东西只有本项目自己读得懂。现在两者统一走新的 `backends/common/har.py`：产出可被上述工具
  直接打开的合规 HAR 1.2（未采集的头/体/分段耗时按规范以空数组、`-1`、未知 timings 占位，
  entry 上以 `comment` 如实说明），并带 `creator.version`。
- `proxy.export_har` 此前**完全没有大小上限**：flow 环最多 2000 条、单条 URL 可达 16 KiB，
  一夜无人值守的抓包会把一份多兆字节的产物直接写进会话目录，而 retention 从未为它预留额度。
  现与 `web.har.export` 一样按采集上限 `UNREGISTERED_CAPTURE_MAX_BYTES` 逐步丢弃**最旧** entry
  直到落在阈值内，超限即 `truncated=true`；连空 HAR 都放不下时按 `too_large` 拒绝。两个工具
  的返回都新增 `truncated`（并保留 `size`），文档串同步说明。
- HAR 超限截断方向改为丢最旧、保最新。此前 `serialize_har` 从**最新**一端丢弃，与两个采集环
  的淘汰方向（满了淘汰最旧、保留最新）相反：一旦 HAR 超出字节上限，留下的反而是最老的 flow，
  而分析者在某个操作后打开 HAR 想看的正是最近的请求。现从最旧一端丢弃，保留放得下的最新
  条目，与采集环一致；`entry_count`/`truncated`/`size` 语义不变。
- HAR entry 从占位向真数据补齐：`request.queryString` 现由 URL 直接解析（`parse_qsl`
  保留重复键与空值，上限 256 个参数防单条膨胀），HAR 查看器的「Query String Parameters」
  面板因此不再空白，也不必依赖消费端自己再切一遍 URL。`proxy` 侧还在 `response()` 落表时
  记下解码后的响应体字节数（此时 flow 尚未因保留额度被丢体，故 body 被省略的 flow 也留得住
  这个数），导出时填进 HAR 的 `content.size` 与 `response.bodySize`，取代 `-1`；该数值同时
  作为 `response_size` 出现在 `proxy.flows` 每行（无响应体记 0）。`web` 侧采集阶段拿不到响应体
  长度，仍如实以 `-1` 占位。

### 新增（工作方向）

- `workspace_profile`（`full|pe|android|web`）把工具面裁剪到单一场景，默认 `full` 不裁剪。
  裁剪在完整 catalog 注册之后执行，所以 catalog 仍是唯一权威，`full` 恒为任意 profile 的超集。
  同时作用于 MCP 客户端与监控台 Agent 的工具面（后者按 run 读取，改了不必重建 orchestrator）。
- 监控台增加开屏页，让用户在「本地 PE / Web / Android / 全部」之间选择方向，选择经
  `GET`/`POST /api/workspace/mode` 持久化到用户配置；也可用 `workspace.mode.get/set` 工具。

### 依赖

- 新增三个可选 extras：`android`（adbutils / androguard / frida）、`browser`（Playwright）、
  `proxy`（mitmproxy）。jadx、apktool、apksigner、webcrack、wabt 一律用户自备，走
  `HEADLESS_RE_*` 路径设置加 doctor 探针，缺失只降级不阻塞 `ready`——与既有 UPX/DIE 一致。

### 修复（长期无人值守）

上面这批新后端是长生命周期的，下列缺陷都只在连续跑数小时后才显形，因此单独列出。

- **`js.unpack_bundle` 的分页 offset 是工具面里唯一漏标下界的**。仓库早先统一把「负数 offset
  在 schema 层就拒绝」铺到所有分页工具（apk.*/web.*/proxy.flows 的 offset 都带 `minimum: 0`），
  唯独这一个 webcrack 拆包工具漏了。webcrack 客户端用 `start = max(0, int(offset))` 兜底、再把钳
  过的 start 原样回填，于是 `offset=-1` 被悄悄当成第 0 页作答、请求被低报——要负页的调用方以为
  翻到了别处，其实是又读了一遍首屏模块。现在与其余分页工具一致，在 schema 上标 `minimum: 0`，
  负数在边界即被拒绝。
- **抓包停不掉，端口永不释放**。`proxy.stop()` 会立刻返回且线程确实退出，但事件循环是在
  mitmproxy 的 accept 任务仍挂起时被直接关闭的，监听 socket 因此从未关闭：端口一直被占，
  下一次抓包再也起不来。现在先取消并等待所有挂起任务、再 `shutdown_asyncgens`，最后才关闭
  循环。`tests/integration/test_proxy_lifecycle_gate.py` 会真实起停并断言端口确实被释放。
- **抓包缓冲无界**。摘要环是有界的，但保存完整 flow 对象（含报文体）的那份是普通 dict，
  永不淘汰——一夜的抓包足以把宿主机内存吃光。现在两者同步淘汰，取不到的 flow 会明确告知
  已被环形缓冲淘汰，而不是假装不存在。
- **抓包记录器跨线程无锁**。它由 mitmproxy 的事件循环线程写、由 MCP 工作线程读，序号自增与
  双容器更新都没有保护。现在全部走同一把锁，并提供 `snapshot()`/`raw()` 只读入口。
- **`proxy.start` 会为一个根本没起来的代理报成功**。就绪信号在端口绑定之前就置位，端口被占时
  错误只落在后台线程里没人读。现在启动前先拒绝已被占用的端口，启动后轮询到端口真的接受连接
  才返回。
- **浏览器已解析脚本表无界**。`Debugger.scriptParsed` 对每个脚本都累积，长开的页面会一直涨；
  现在与请求、console 一样有界。
- **Frida 授权 pid 用 `sorted()` 保存**，于是「最近一次 spawn」实际取到的是 pid 数值最大的那个：
  先起 A（pid 5000）再起 B（pid 3000），Java 枚举会打到 A 上。改为按时间顺序保留且有上限。
- **web / proxy 后端惰性创建存在竞态**。工具在 16 线程池上执行，两个并发的首次调用会各建一个
  后端，落败者持有的浏览器或已绑定端口就此无人追踪、永远关不掉。改由 `AnalysisService` 在
  构造时统一持有。
- **APK 解析缓存在会话关闭后不释放**。上限 4 份，但每份完整 DEX 分析可达数百 MB，空闲进程会
  一直占着。会话关闭时按路径显式回收。
- Frida 远程设备不再每次调用都重新 `add_remote_device`，改为先复用已注册设备。
- **Watchdog 字段名对不上，每次巡检都会崩**。代码读 `_reported_disconnected`（set），
  字段却声明成 `_disconnected_streak`。未捕获时整次巡检变成 `watchdog_failed`。
- **杀进程树被 UI 页大小卡住**。`collect_descendants` 要 64 个，直接子进程枚举硬封 16，
  Chromium 会留下渲染进程。杀路径改用同一上限。
- **隔离命令在 Windows 上拆不出 argv**。POSIX `shlex` 吃掉反斜杠，配置还按逗号切；
  `C:\Program Files\vm\revert.ps1` 整行变成一个参数。现在按命令行拆并保住路径。
- **jadx / apktool / ghidra 写入后 prune 共享父目录会删掉其它会话**。关闭时只清自己的
  工作树。Ghidra 的 `export_*.json` 已登记为产物，关会话不再一并 `rmtree`。
- **`doctor` 的 radare2 探针只看 PATH，无视配置的 `HEADLESS_RE_R2`**。它用的是只查
  `shutil.which` 的 `probe_command`，而 `r2.*` 工具跑的是 `R2Client(settings.r2)`，直接用
  配置路径。于是操作者把 `HEADLESS_RE_R2` 指到不在 PATH 上的 r2 时，doctor 报 radare2
  缺失、工具却能用——与 webcrack 解析修复同一类 doctor/工具不一致（这次是 doctor 假阴性）。
  改用 `probe_optional_tool("radare2", …, "r2", ("r2","rizin"))`，与 adb / jadx / apktool /
  webcrack / wabt 一致：先认配置路径，再回落 PATH。
- **Ghidra headless 会把操作者的 `JAVA_TOOL_OPTIONS` 直接覆盖掉**。`_run_headless`
  过去 `env["JAVA_TOOL_OPTIONS"] = f"-Xmx{max_heap}"`，把操作者为代理、编码或 JDK 17+
  Ghidra 所需的 `--add-opens` 设的值整个抹掉，在那些机器上悄悄让 analyzeHeadless 跑不起来。
  现在把 `-Xmx` 前置拼进已有值：堆上限作为默认仍生效，而操作者显式的 `-Xmx`（JVM 取最后一个）
  仍然胜出，其余选项一并保留。未设置该变量时结果与之前完全相同（`-Xmx2G`）。
- **`close_session` 在服务锁里关浏览器/代理**。拆到锁外；`web.close` 失败也不跳过
  调试器 worker。x64dbg 的 `debug-events/<session>/events.sqlite3` 关连接后删除。
- **jadx 同名类返回错文件**。`rglob("Main.java")` 不再取树上第一个。
- **PE 专属工具对 APK 会话不会返回 `target_mismatch`**。`detect` / `dotnet` / `unpack`
  入口改用 `require_pe()`。
- **内存仓库的回收/裁剪和 SQLite 不一致**。InMemory GC 会删掉刚登记的那份、裁剪关闭
  会话时不丢掉 RAM 里的 timeline。两边现在同一条规矩。
- **健康监控 `stop` 超时后再 `start` 可能再也起不来**。旧巡检线程还活着时 `start`
  直接返回；它退出后没有人补一条。现在记下重启请求，旧线程收尾后再拉起来。
- **`parse_r2_json` 会把带括号的 opcode 当成 JSON 起点**。`rfind("[")` 切到
  `mov eax, dword [rbp+0x10]` 里，整表解析失败后只留下最后一个对象。现在从第一个
  `[`/`{` 做 `raw_decode`。
- **`doctor` 把源码树和 MSVC 当成必选项**。二进制包部署没有它们也会报 NOT READY。
  必选探针只剩 `python` / `ida_idalib` / `x64dbg_headless_binaries`。
- **resume/step 在事件环溢出时会报成功**。`wait_for_state` 把 `dropped > 0` 当成
  过渡事件，目标其实还停着。现在只认点名的 event kind。
- **对 APK/Web 会话误开 PE 后端会把会话打成 FAILED**。`target_mismatch` 现在退回
  `CREATED`，同一会话还能继续用对口工具。
- **`web.open` 用共享哨兵占位，close 后再 open 会装错浏览器**。每次 open 用独立
  token；close 掉第一次后，第一次启动完成不能覆盖第二次的预约。
- **`workflow.cancel` 拿不到导航等待时的锁**。等待 `events.read` 时放下 runtime
  锁；回来后若已取消就不再往已结束的 navigation 里灌事件。
- **`run_bounded` 会把成功退出的隔离/doctor 助手杀掉**。启动器 exit 0 后只排空
  管道，不再杀残留子进程。de4dot 的 `_capture_process` 则相反：父进程走了还挂着
  子进程时必须收掉。
- **Frida `spawn` 把包名当成 argv 列表，也接受路径**。现在只接受 Android 包名，
  并按字符串交给 `device.spawn`。
- **`apk.repack` / `apk.sign` / `unpack.verify` 吃会话外的主机路径**。必须落在
  当前会话产物树里。`note_verified` 也不能再从 `OEP_CANDIDATE` 直接跳到
  `VERIFIED`。
- **IAT 重建只写新的 `.himps`，代码还在读原来的 IAT**。有确认的 `iat_va` 时按
  RVA 原地打补丁，并把 FirstThunk / IAT 目录指回去。
- **取消的 mission 仍会再开一轮、再写一次工具**。调度器只把状态翻成 CANCELLED，
  编排器还在等审批或卡在 worker 线程里。现在 claim / 审批 / 工具调用都会看
  `cancel_requested`，超时等待也会去取消那条 asyncio 任务。
- **超长 objective 先建空 inbox 再拒绝**。空 thread 不会被 trim，重试会把库撑大。
  现在先 `validate_mission`，过了才建 thread。
- **完成一条较旧的 mission/run 会把它自己删掉再崩**。终态保留裁剪按 `created_at DESC`
  只留每线程最新 N 条；当同线程里较新的先完成、较旧的后完成时，那条刚完成的旧记录恰是
  「最旧的终态行」而被裁掉——可 `set_mission_status` / `cancel_mission` / `transition`
  紧接着 `get_mission` / `get_run` 读回并 `assert ... is not None`,于是操作本身以
  `AssertionError` 崩溃(对无人值守调用者表现为 `internal_error`),而不是返回它刚写下的
  状态。裁剪改按 `updated_at DESC`(即完成时间)排序:刚完成的记录必是最新的一条,永远落在
  保留窗口内,保留条数仍恰为 N。新增三条回归测试(mission 完成 / mission 取消 / run 转终态,
  均为「旧记录后完成」)以严格递增时钟钉住顺序。
- **压缩后的请求仍会超过自己报的预算**。8,000 字符上限选出的尾巴，再加上系统提示
  和压缩通知，线上变成 8,115。现在先给这两条留位置再选尾巴。
- **`cdb -c` 只看第一个 token**。`lm; !process` 和 `k\n.shell` 能穿过白名单。
  现在分号、换行、管道和 `&` 一律拒绝。
- **命名管道取消后无限等**。`CancelIoEx` 失败时 `WaitForSingleObject` 用
  `INFINITE`，请求锁就锁到进程退出。现在最多等两秒。
- **Frida attach / spawn 能永远卡住**，而 `hook.template` 在 `detach` 之后仍报
  钩子还在。现在有 30 秒上限，回复里写明脚本已随 session 销毁。
- **`unpack.verify` 在 APK 会话上仍会解析产物树里的 PE**。先 `require_pe()`。
- **敌意 `NumberOfSections=0xFFFF` 会按节数分配重建头**。超过 96 节直接拒绝。
  导入名按描述符 + ILT（原地 IAT 时不再加上一份 IAT 长度）落盘。
- **工作流导航在等的时候，第二次 `events.read` 会把游标拆开**，再被映射成会拆掉
  x64dbg 的 `rpc_protocol_error`。导航等待时只读持久日志；游标不一致改报
  `event_cursor_inconsistent`。
- **MCP 卸载不认 catalog 超时**。断开能回来，超时还是占着 limiter。现在
  `fail_after` 用工具自己的 timeout，超时回 `tool_timeout`。
- **healthz 的 `urlopen` 超时是按 recv 重置的**。监听方一字节一字节滴，启动器
  和拉起它的 supervisor 会一直等到滴完。每个 recv 共用同一条 deadline。
- **`js.unpack_bundle` 的文件列表停在 2000 且没有页**。2500 个模块会报
  `file_count=2500` 却只给 2000 个名字。现在按 offset/limit 翻页，并返回
  `total` / `has_more`。
- **超时杀进程树在 Linux 上只杀到启动器**。`/proc/<pid>/task/<pid>/children`
  没有走，doctor / isolation / r2 的子进程会留下。现在 POSIX 也走同一套
  descendants。
- **`web.scripts` 的 `has_more` 曾表示环形缓冲淘汰**。翻页之后 `has_more` 只
  表示这一页，淘汰数在 `dropped`。
- **Scylla 探针超时仍报 READY**。GUI 起得来但从不退出，doctor 会把可选工具
  标成可用。超时现在是 `timeout_after_start` 且 `ok=False`。
- **`proxy.ca.install_android` 在会话关闭后仍会 push 证书**。开关会话前后都检查状态。
- **`frida.spawn` 在会话关闭到一半时仍报成功并写回 pid**。`frida.device.connect` 与
  `frida.server.ensure` 触碰设备后都会复查会话状态，唯独 spawn 少了这一步：一次 spawn 中途
  关闭会话，仍会把刚 spawn 出来的 pid 写进（已关闭的）会话元数据并返回 ok=True，让一个已死
  会话被记成持有一个活着的设备进程。现在 spawn/resume 之后也复查状态，关闭时改报 invalid_state
  且不落 `frida_authorized`（设备侧进程无论如何已经起来，这里只保证不把它记到死会话名下）。

同一轮审计在核心侧（与本次新后端无关，早已存在）查出三处同类问题：

- **产物配额只在会话关闭时才生效**。回收器挂在 `close_session` 上，可无人值守跑法恰恰是
  一个会话开着好几天、循环里不停 dump 模块与落 trace——真正会撑爆磁盘的形态，正是配额从不
  介入的那一种。现在注册产物时也做一次回收检查（回收器自带 60 秒节流，成批落盘不会每份都
  去走一遍产物表）。同时回收不再删除**最新**的那一份：单个 dump 大于总配额时，原实现会把
  调用方正准备返回路径的那个文件直接删掉。
- **关闭会话不释放 trace 状态**。workflow、unpack、debuggee 三个 owner 都在关闭时清理，
  只有 `_trace_owner` 漏了，于是每个开过 trace 的会话都会永久留下一份状态。清理放在产物
  落库之后——先由现有的 `_finalize_trace_after_worker_loss` 把 trace 文件注册成产物，再清，
  证据不会因此丢失。
- **关闭会话不忘记后端阶段**。`pop_session` 把每个 `(会话, 后端)` 标成 CLOSED 后永久保留，
  而 `phase()` 全项目只被读来找**待恢复的 FAILED 后端**，CLOSED 残留对谁都没有意义：一台
  整天开关会话的服务器会记住它关过的每一个会话。现在整会话一并忘掉。
- 新增反射式回归护栏：创建并关闭若干会话后，遍历服务上（及下一层）所有字典，断言没有任何一个
  仍以已关闭的会话 id 为键。上面两处是手工翻出来的，第三处不该再靠手工。

随后用压缩时间的 soak 实测（600 轮会话生命周期、20 轮抓包起停、15 轮浏览器开关，以及成千次
失败调用）复核上述结论，成功路径全部零增长，但**失败路径**又暴露出一处：

- **抓包启动失败会在根 logger 上留下僵尸日志 handler**。mitmproxy 在 `Master.__init__` 里就把
  handler 装到根 logger，只有 `run()` 正常收尾走到 `done()` 才卸载——启动失败永远到不了那里。
  留下的不只是一个泄漏对象：handler 仍挂在根 logger 上，钉住整个 master、它的 addon 和已抓到的
  报文，此后**进程内任何一条日志**都会被投递进一个已关闭的事件循环并抛异常。实测 40 次失败启动
  留下 45 MB、75 个句柄和满屏 `Event loop is closed`。现在启动线程收尾与 `stop()` 都会按 master
  身份、以及按事件循环身份（构造函数装完 handler 后才失败时，master 已无人能引用）摘除它。
- **端口占用探测问的是错的问题**。原来只用「连得上吗」判断端口是否被占，可一个 bind 了却不
  accept、或 backlog 已满的持有者，在这个探测下等同于「空闲」，于是照样去启动 mitmproxy，再花
  满 15 秒就绪超时才失败——上面那 40 次失败因此耗了 10 分钟。现在追加一次真实 bind 探测（按平台
  对齐 asyncio 的 `SO_REUSEADDR` 行为，避免误拒），占用则立刻拒绝。同一场景现在 17 秒跑完，
  内存、句柄、handler 增长均为 0。
- **浏览器只能在打开它的那个线程上驱动，而工具调用来自共享线程池**。Playwright 同步 API 基于
  greenlet，对象有线程亲和性：换个线程碰它就从 playwright 内部抛
  `Cannot switch to a different thread`。工具在 16 线程池上执行，`web.open` 与后续 `web.*`
  落在哪个线程毫无关联；线程池会复用空闲线程，所以低负载下「碰巧能用」，一旦并发铺开就开始
  随机失败——最难查的那种。现在每个 web 会话独占一个线程，所有 Playwright 调用都排到它上面执行。
- **抓下来的东西是死路一条**。`web.screenshot` / `web.har.export` / `proxy.export_har`，以及
  超限溢出的响应体与脚本源码，都只把文件写到磁盘再回一个裸路径：工具面上没有任何工具能打开裸
  路径，所以 agent 读不回自己刚抓的东西；而回收只处理登记过的产物，所以一次长跑的浏览器会话
  会在产物目录里堆下永远回收不掉的截图和 HAR。现在这五条路径统一登记为产物并回 `artifact_id`
  （与静态溢出走同一个 `_record_artifact`）。登记失败不影响抓取本身——文件还在，原因放进
  `artifact_error` 字段。
- **UI 截图是其中最大的一处**。`ui.screenshot` 与 `ui.ocr` 每次调用都按新 uuid 写一张**未压缩
  BMP**（整窗可达数 MB），同样不登记。UI 驱动循环因此会在产物目录里堆下按 GB 计的位图，而配额
  连数都数不到它们，agent 也读不回来。现在两条路径都登记；固定文件名、每次覆盖的虚拟桌面抓图
  不在此列（它本来就不增长）。
- **`doctor` 自己也会被同一个坑挂死**。它的探针跑的正是使用者配置的路径，而配置成
  `jadx.bat` 这类启动器很常见；探针虽然都带了 `timeout`，但那是 `subprocess.run` 的超时——
  杀掉启动器之后的排空在 Windows 上没有超时。于是"机器出问题时用来诊断的那条命令"会挂住。
  四处探针改走同一个有界执行器。
- 这些 CLI 工具同时接入了调试器 worker 已有的那张网：spawn 后加入进程作业对象
  （`KILL_ON_JOB_CLOSE`）。超时能收掉它们，但**强杀本服务不会执行任何清理**——而"服务被停掉"
  正是计划任务停止时发生的事，留下一个还在分析样本的 JVM 不是可以接受的收尾。仓库卫生检查里
  那条"长生命周期后端必须分组"的断言，现在也覆盖这个统一执行器。
- OCR 的两条路径（Windows OCR 子进程与 tesseract）也一并改为有界执行。UI 驱动循环会不停调用
  `ui.ocr`，是这批工具里调用频率最高的一个。
- WinDbg（cdb）的两条路径同样改为有界执行。它比其它工具更需要这条：`cdb -pv -p <pid>` 附着的是
  一个活着的进程，只杀到启动器意味着留下一个仍然挂着目标的调试器。
- 同一条规矩也铺到了另外四个外部工具（DIE、Exeinfo PE、UPX、de4dot / NETReactorSlayer）：它们
  通常是可执行文件本身、不经启动器，但路径由使用者配置，包一层批处理是很自然的做法，而那样
  一来超时就又只杀到包装脚本。它们的终止逻辑改为同一个进程树终止。
- **`sessions.unclean` 是工具面里唯一不分页的列表**。没有任何路径会清掉这些行，而每次带着 N 个
  打开的会话被强杀就会新增 N 行，于是它随部署时长单调增长——偏偏它正是崩溃之后最先被调用的
  那个工具。实测 3000 个未清理会话时，单次回包 **993 KiB**。现在与相邻的 `artifacts.list` /
  `audit.list` 一样分页（默认 100，回 `total` / `offset` / `has_more`），同一场景 33 KiB；
  就绪探针也改成只取一行——它要确认的是"存储答不答话"，不是"有多少话要说"。
- **CLI 后端超时只杀启动器，工具本身留下来继续跑**。jadx、apktool、apksigner 与 Ghidra 的
  `analyzeHeadless` 都是启动 JVM 的脚本，webcrack 启动的是 node，而
  `subprocess.run(timeout=...)` 只杀它直接生出来的那个进程。本机实测：杀掉启动器之后，它启动的
  进程照常存活。于是一次超时的分析把 `timeout` 交给调用方，同时把一个没人等待的 JVM 留在机器
  上——占着一个核、锁着样本文件，直到服务进程结束。现在这四个后端改走统一的有界执行：超时先按
  进程树枚举后代（先枚举再杀，因为父进程一死关系就查不到了；广度与深度都有上限）、连同启动器
  一并终止，并把被杀的 pid 放进错误详情。
  并排实测还暴露出第二个、更重的症状：孤儿继承了 stdout/stderr 管道句柄，所以杀掉启动器之后
  **排空会一直读不到 EOF**——而 CPython 的 `subprocess.run` 在 Windows 上超时杀进程后调用的
  `communicate()` **不带超时**。也就是说这不仅漏掉一个进程，它可以让那次工具调用的工作线程
  永久阻塞。新的有界执行器先杀整棵树再排空，因此管道会关闭；同一场景现在 1.0 秒返回、
  两个 pid 都确实终止。
- **一个会说话的页面会让进程的句柄一直涨**。浏览器采集里只有 console 走的是高层
  `page.on("console")`，其余事件都走 CDP。高层事件递过来的 `ConsoleMessage` 带着一组远程
  `JSHandle` 包装对象，没有人释放它们：在一个每次输出 60 行日志的页面上实测，**每次导航泄漏
  120 个 OS 句柄**，60 次导航后 +7200 且仍在线性增长，只有关闭浏览器才会归还——正好是"一个采集
  会话开一整夜"的形态。同为对照：裸 Playwright 同样导航 0 增长，关掉事件接线后也是 0 增长，
  所以是我们这一处。改成和其余事件一样取 `Runtime.consoleAPICalled` 的纯数据后，同一压力下
  每次导航 0 句柄、内存增长从 12 MB 降到 1 MB，console 内容照常采集。
- **任何 `KeyError` 都会被报成"会话不存在"**。结果映射把 `KeyError` 一律当作
  `session_not_found`，于是解析后端回包时少一个键、或一次缓存淘汰竞态，都会告诉调用方"你的会话
  没了"——而对此最合理的反应（重建会话、重跑分析）恰恰是内部瞬时故障最不该得到的回应。现在只有
  会话注册表抛出的 `SessionNotFound` 才映射到该码，其余 `KeyError` 老实报 `internal_error` 并带
  事件 id。`SessionNotFound` 继承自 `KeyError`，代码库里既有的 `except KeyError` 一律照旧生效。
- **APK 解析缓存跨线程无锁**。它是进程级的，而工具调用跑在工作池上、会话关闭又会对同一批字典
  调用 `release()`。把解释器的线程切换间隔压到最小后稳定复现：`release()` 一边遍历缓存、另一
  线程一边插入，抛 `OrderedDict mutated during iteration`；`move_to_end` 与淘汰竞争抛 `KeyError`
  ——而 `KeyError` 会被结果映射成 `session_not_found`，于是一次缓存竞态被报成"会话不存在"。现在
  所有缓存改动走同一把类级锁，解析本身留在锁外，不同 APK 仍可并行分析。同一压力下不再出错。
- **停在上限的列表看起来和"到此为止"完全一样**。四处：r2 载荷最多保留 4096 个条目、
  `apk.xrefs` 最多收集 `limit` 个调用点、`frida.exports` 与 `frida.java.classes/methods` 各自
  按 limit 截断，全都只回 `count`，不说还有没有被丢下的。agent 据此得出"这就是全部 xref /
  全部导出"时，它是在一个切片上下结论。现在 r2 回 `items_truncated` / `items_total` / `items_limit`，
  其余三处回 `has_more`——frida 那几个改为向脚本多要一条，因而不必数完全部就能区分"没有了"和
  "只给了这一页"；恰好填满一页而后面确实没有了的情况不会被误标为不完整。r2 原始输出的截断早已
  如实披露，这几处只是补齐同一条规矩。
- **过大的 finding 会被静默改成另一个东西**。`knowledge.record` 的 value 以 JSON 文本存储、
  在 8000 字符处截断——截断后它不再是合法 JSON，于是读回来的是一段**字符串碎片**而不是写进去的
  对象，而写入时返回的是 ok=True。findings 正是无人值守运行跨会话的记忆，后续判断因此建立在
  调用方无从察觉已被改写的数据上。现在按邻近 kind/key 校验的同一风格如实拒绝，并在错误里给出
  实际长度、上限，以及"大块内容请落成产物、这里只留引用"的去处。
- **重建一份过大的转储不是调用失败，而是进程死亡**。`unpack.pe_rebuild` / `unpack.iat_rebuild`
  会同时持有转储、重建后的映像和中间副本：实测 64 MB 转储峰值为 3.0 倍、256 MB 为 4.0 倍
  （峰值 1055 MB）。之前对转储大小没有任何检查，几 GB 的转储会把整个进程带走，无人值守时连同
  所有打开的会话一起丢失。现在在分配之前先估算峰值，并与**当前真正空闲的物理内存**比较后拒绝
  （`dump_too_large`，附估算值与可用值）——按可用内存而不是固定上限，大内存机器不会被误伤；
  取不到内存数字时放行，因为"因未知而拒绝"正是把限制变成故障的方式。
- **每次 r2 调用都为了一个头部字段读完整个目标**。`pe_preferred_base` 用来取 PE 的 ImageBase，
  而六个 `r2.*` 工具的每一次调用都会走它。在 200 MB 的目标上实测：六次调用 0.41 秒、峰值内存
  +200 MB。改为只读前缀（64 KiB 窗口，遇到超长 DOS stub 最多再补读两次、硬上限 1 MiB）后，
  同样六次调用 0.00 秒、内存增长 0.1 MB，解析结果不变。
- **`artifacts.read` 每翻一页都把整个产物读进内存**。这里的产物是进程转储和 trace，不是文档。
  在一份 200 MB 的转储上实测：20 次 256 KiB 的分页读耗时 1.44 秒、峰值内存冲到 243 MB
  （基线 42 MB）、为了给出 5 MB 数据触碰了 4 GB——因为每一页都从头读一遍整个文件。2 GB 的转储
  则根本放不下。改为 `seek` 后同样的读取 0.03 秒、内存增长不到 1 MB。
- **一个被占用的文件会让回收永久停摆**。Windows 上句柄未关的文件无法删除，而这在这里是常态：
  调试器还在写的 trace、正在被复制的 dump、被扫描器捏住的截图。回收总是从**最旧**的产物开始，
  所以异常抛出的后果不是"漏掉一个"，而是它后面的每一个都再也收不掉——配额从此不再生效，
  而 `maybe_collect` 会把这个异常吞掉，没有任何人被告知。另一个后果同样隐蔽：抛出前已经删掉的
  文件，其数据库行随事务一起回滚，于是留下一批指向空路径、却仍在占配额的行。现在按文件跳过并
  在返回里报告 `skipped`：被占用的产物保留行（仍可读、下次再收），其余照收不误。
- **回收拿回了文件，却拿不回目录**。实测 150 个会话各产出一张截图：回收释放了文件，留下
  **142 个空的按会话目录**（每会话 0.95 个），此后每次磁盘用量遍历都要走一遍——按每天数百个
  会话计，一个月就是上万个只代表"什么都没有"的目录项。现在删掉产物文件后顺手 `rmdir` 它的父
  目录：`rmdir` 本身拒绝非空目录，正好是需要的保护，产物根与数据库目录额外显式排除，而所有
  写入方都会先建目录，所以被清掉的目录用到时自会回来。同一场景空目录降为 0，遍历条目 462→320。
- **库损坏时，恰恰是用来查问题的那几个工具会抛异常**。`artifacts.list` / `audit.list` /
  `sessions.unclean` / `artifacts.describe` / `artifacts.read` / `artifacts.gc` 这批读路径没有
  任何异常保护——它们假设存储不会出错。库被崩溃截断、被替换或被隔离时，异常**穿过工具边界**
  抛出，而这正是调用方想弄清出了什么事的时刻。现在它们和其它工具一样返回信封。
- **存储故障不再笼统地报 `internal_error`**。新增 `storage_unavailable`：库不可达、只读或损坏
  说明的是实例的状态，与请求本身无关；`OperationalError`（多为锁竞争、只读）标记为可重试，
  `DatabaseError`（损坏）标记为不可重试。无人值守的调用方据此能区分"该退避重试"和"别再问了"。
- **只读的产物库会被判定为健康**。就绪探针对存储只做一次读（`list_unclean_sessions`），而一个
  变成只读的库文件——杀软隔离、权限变更、卷以只读重新挂载——**查询照答不误，写入全部丢失**。
  这正是 `probe_artifact_root` 早就为目录写下的理由（"存在但只读的目录能通过一切更便宜的检查"），
  只是没被用到目录存在的意义、也就是那个文件上。现在探针也证明可写；实测发现显而易见的
  `BEGIN IMMEDIATE` **探不出来**（SQLite 把拒绝推迟到真正写页时），改为在事务里建表再回滚，
  能触发且回滚后 schema 原样不变。同一场景下就绪状态从 `ready=True (readable)` 变为
  `ready=False`，并带上真实原因。
- **记账失败既不能让操作失败，也不能被悄悄吞掉**。上一条修复把异常挡住之后，只读库上的
  `session.create` / `close` 会返回 ok=True 而持久化其实全废——调用方对着一条已经停止的审计
  轨迹继续工作。现在失败会写进 `meta.persisted=False` 与 `meta.persist_error`：结果不变，
  但当场可见。
- **产物目录在运行中消失后，服务再也起不来，而且关闭会话会直接抛异常**。磁盘清理、杀软隔离、
  卷重新挂载都会让它消失（今天就真发生过一次）。此后每次调用都因为 `unable to open database
  file` 失败到进程结束，没有任何代码会把目录建回来；更糟的是 `close_session` 之后的记账写库
  在保护块之外，异常**穿过工具边界抛了出去**——会话其实已经关了，调用方拿到的却是 traceback，
  而会话永远停在 CLOSING。现在：记账失败只记录不改变结果（与既有的"时间线写失败不拖垮被记录的
  工作"同一条原则），存储连接失败时重建目录与表结构再重试一次。实测删除产物根之后，所有工具
  照常返回、目录自动重建、无异常逃逸。
- **光把产物登记上还管不住磁盘：回收节流只看时间**。回收器最多每 60 秒跑一次，而生产者可以跑
  得比它快得多——实测 8 MB 配额、每张 1 MB 的截图循环，**0.4 秒内堆到 60 MB（7.5 倍配额）且一次
  都没回收**，因为全部落在同一个节流窗口里。现在字节量本身也是触发条件：自上次回收以来新登记
  的产物超过半个配额就立刻回收，超额因此被限制在阈值上而不是"生产者一分钟能写多少"。同一循环
  现在稳定在 9–11 MB（1.4 倍），写入 60 MB、留存 11 MB。
- 同一轮里补齐的还有：`report.generate` 的 Markdown、`detect.scan` 落盘的 DIE / Exeinfo 原始
  JSON、`pe.headers.runtime` 的头部转储（它旁边的 `modules.dump` 一直是登记的，只有它不是）。
  登记与否按一条线划分：**能便宜地重新生成的派生物**（截图、HAR、报告、扫描器原始输出）登记，
  从而可读可回收；**无法再现的证据**（活进程转储、脱壳产物、de4dot/Scylla 的输出）继续不登记，
  因为登记就等于允许回收器在分析中途删掉唯一的一份。`device.*` 的截图与 pull 暂时留在外面：
  设备工具按 serial 而非会话寻址，而产物表要求 session_id，那是模型问题，不在本次范围内。
- **`frida.hook.template` 报告 `loaded: True`，而钩子在调用返回前就没了**。这里每个操作都在
  `finally` 里 detach，正是这一点保证失败的调用不会把 agent 常驻在别人进程里；但对钩子而言，
  detach 会销毁会话连同其中的脚本。实测 frida 16.5.9：`script.load()` 后 `is_destroyed` 为
  False，`session.detach()` 之后立刻变 True。无人值守的 agent 会据此以为钩子装上了，然后等一个
  永远不会来的输出。现在回包按同文件里 `frida.attach` 已有的惯例如实说明：`persisted: False`
  加一句"探针式注入，detach 后目标进程里不留任何钩子"。
- **浏览器进程被杀后，调用会永久阻塞**。Playwright 的超时是在 node 驱动进程里执行的，驱动一死
  就跟着消失，于是 `web.navigate` 不是报错而是挂死，无人值守的 agent 就此永久停在那一步（实测
  杀掉浏览器后 navigate 挂了 4 分钟仍未返回，只能强杀进程）。现在调用在服务侧有界等待，超时
  返回结构化 `timeout`，并把该会话标记为不可用：后续调用立刻失败而不是排在死调用后面，
  `web.close` 仍能回收会话，重新 `web.open` 可正常恢复。实测同一场景 40 秒有界返回、
  0.25 秒回收、3 秒重开，无残留浏览器进程。
- **超时的工具调用会把线程一直堆下去**。Python 取消不掉已经在跑的线程：`wait_for` 超时后
  limiter 令牌立刻归还，调用方得到 `tool_timeout`，但那个线程还在等后端。任务循环对卡住的
  后端重试时，实测六十次超时留下六十条活线程，下一批六十次没有任何东西拦住。现在进行中的
  调用（含调用方已经放弃的）单独计数；到 32 条仍未返回时，新调用立刻以 `tool_workers_stuck`
  拒绝并写进 run 事件，而不是再开一条。计数跟着线程走、不跟着调用方走：后端一旦真正回来，
  计数就降，新调用可以继续。
- **卡住的浏览器会话关不掉 Chromium**。`web.close` 在 runner 已 wedged 时不再调用
  Playwright（对象有线程亲和性），于是 node 驱动和它拉起的浏览器一直活到进程退出。
  现在打开时记下驱动 PID，关闭时从当前线程杀整棵进程树。
- **`device.forward` 建完就忘**。转发活在 adb server 上，关会话不会拆掉；长跑的 agent
  反复给 frida 或调试端口做转发，最终绑不上新端口。现在由服务持有的 AdbBackend 记住
  `(serial, local)`，`close_all` 时按记录拆除。
- **设备截图 / pull 和 jsre unpack 目录不进产物表**。它们按 serial 或一次性 uuid 落盘，
  回收器看不见，目录随调用次数单调增长。写入后按条数和字节量淘汰最旧的，刚写入的那份保留。
- **Scylla / XVLKC / VMP dumper / de4dot / NETReactorSlayer 的 doctor 探针仍走 `subprocess.run`**。
  Scylla 在超时后把「启动过」当成可用，却不杀进程，GUI 探针会把窗口留在机器上；其余超时在
  Windows 上可能让 `communicate()` 永不返回。全部改走同一个有界执行器。
- **apktool / jadx / ghidra 按会话落盘的树不进产物表**。解码、导出源码和分析工程会留下
  整棵目录，关会话也不删。写入后按会话目录数和体积淘汰最旧的（刚写入的那份保留）。
- **样本间隔离步骤仍走 `subprocess.run`**。无人值守的入口正是这里：配置的命令通常是
  拉起 hypervisor 工具的脚本，超时只杀到脚本，子进程继承管道后 Windows 上的排空没有
  截止时间，工作线程就停在那次轮换上，而虚拟机还是脏的。改走同一个有界执行器。
- **`device.packages` 一次回完整包列表，`device.properties` 截断却不说**。忙碌的模拟器
  轻轻松松超过一次工具回包该装下的量；停在上限的列表和「到此为止」看起来一样。两者都
  带回 `has_more`，包列表默认 500、硬上限 2000。`apk.native_libs` 同样封顶并披露。
- **ADB 调用在设备卡住时没有截止时间**。adbutils 的 `shell` / `install` / `sync` 默认
  一直等到设备应答；一个假死的模拟器就能永久占住一条工具线程。能传 `timeout` 的路径
  都带上截止（探测 8 秒、shell 30 秒、传输 120 秒），老版本 adbutils 不认该参数时回退。
- **APK 组件/权限列表和 manifest 截断不说话**。加壳样本可以塞进几千个空组件；manifest
  超过 200k 字符时只切一刀、回包仍像完整 XML。组件与权限封顶并回 `has_more`，manifest
  回 `truncated`。
- **`apk.open` 对读不出包名的 zip 仍回 `{opened: True, package: None}`**。一个不是 APK
  的普通 zip（androguard 的 `get_package()` 返回 None）会被无人值守的 agent 当成已打开的
  包继续分析。现在空包名记为 `backend_error`（`opened: False`），而不是一个没有身份的
  成功结果。
- **jadx 导出源码列表和 webcrack unpack 文件列表同样切到 2000 条却不说**。旁边虽有
  `java_file_count` / `file_count` 是全量，只看列表的调用方仍会当成完整目录。补上
  `has_more`。
- **`web.console` 默认只回最后 200 行，不说前面还有**。缓冲区本身有界，这一页再切一刀
  之后看起来就像「页面只打了这些日志」。回 `has_more`。证书列表同样封顶并披露。
- **Ghidra 导出的函数/符号/xref 列表停在 limit 上不说话**，反编译 C 超过 200k 字符也只
  切一刀。脚本补上 `has_more` / `truncated`。
- **`analyzeHeadless` 退出非零却留下空 `{}` 时被当成空成功**。脚本失败后遗留的空导出会让
  `ghidra.functions/symbols/xrefs` 回 `items=[]`、`ghidra.decompile` 回空 C，无人值守的
  导出据此把失败的运行读成「这个二进制没有函数」。现在非零退出且导出无内容记为
  `backend_error`；`analyzeHeadless` 常在真正写出 postScript 结果后仍退出 1，这种带内容的
  非零退出仍算成功。
- **`proxy.ca.install_android` 和 `frida.server.ensure` 每次新建一个 AdbBackend**。
  那个实例记不住本进程建过的转发，`close_all` 拆不掉它们。改为走服务持有的那一个。
- **`frida.applications` / `frida.modules` 以及 apk 的 classes/methods/strings 分页
  只有 total，没有 `has_more`**。total 能算出来，但和相邻工具的字段不一致，只读 count
  的调用方仍会当成完整一页。一律补上。
- **`apk.strings` 会为了给出 total 把 DEX 里每一条字符串都装进一个集合再排序**。加壳
  样本可以有上百万条，一次调用就能把进程打满。采集上限 5000 条唯一值，超出回
  `has_more`，不再为了计数去物化全集。
- **拆转发失败后就把记录扔掉**。`release_forwards` 先清空再逐条拆除；设备当时掉线，
  adb server 上的转发还在，而本进程已经忘了，以后的 `close_all` 再也不会去拆。失败
  的项重新挂回跟踪列表。
- **`frida.server.ensure` 在 su 命令返回后就报 `running: True`**，并不再看 ps。启动器
  成功而 frida-server 立刻退出时，调用方会以为钩子已经能连上。启动后再查一次进程表，
  看不见就如实回 `running: False`。
- **`frida.server.ensure` 把 frida-server 绑到 `0.0.0.0`**，于是每次启动都把这条 root 级
  控制通道（无鉴权）暴露给设备能路由到的所有接口——同网段任何主机都能连上做插桩。改为
  默认绑回环 `127.0.0.1`：USB/adb 传输与 `adb forward` 照常可达（本机模拟器、USB 真机就是
  这么驱动的），仅靠网络路由到设备的主机则连不上。确需按设备 IP 远程连接时显式传
  `bind_host="0.0.0.0"` 才放开。该值会进入 `su -c '…'` 命令行，写进去前按严格主机字符集
  校验，带冒号、空格或 shell 元字符一律拒绝而不是照跑。
- **并发的 `proxy.start` / `web.open` 会各起一份实例**。检查「已经有了」和写入跟踪表
  不在同一把锁里，两个工作线程会各自绑定端口或拉起 Chromium，后写入的那份把先起来的
  弄丢，泄漏到进程退出。现在先在表里占位再启动，失败或中途被关则清掉占位并回收。
- **`apk.classes` 同样为了 total 把全部类名排序进一份列表**。加壳样本可以有几十万个
  类。采集上限 10000，超出回 `has_more`。单个类的 methods 采集上限 2000。
- **`web.scripts` 缓冲区满了也不说**。脚本表有上限，旧的被挤掉之后回包看起来仍像
  「页面只解析了这些」。满员且确有淘汰时回 `has_more`。网络请求与抓包 flows 回
  `dropped`（被环挤掉的条数），分页另回 `has_more`。console 同样记 `dropped`。
  `web.wasm.list` / `web.scripts(wasm_only=True)` 原先把 `has_more` 硬写成 False，
  共享环淘汰后 WASM 列表仍像完整。两种模式现在都披露淘汰。
- **`frida.device.connect` 在 USB/本机路径上丢掉已解析的设备**。远程分支回
  `id`/`name`/`type`，USB 分支只回调用方传入的别名（`{"id": "usb"}`）。现在两边
  都回真实设备信息，授权记录也钉在解析后的 id 上。
- **Frida `spawn` 成功而 `resume` 失败时，暂停的进程被留下，错误里也不带 pid**。
  无人值守循环会在设备上堆暂停的应用。现在 resume 失败会杀掉该 pid，并把 pid 放进
  错误详情。
- **`device.launch` 在 monkey 返回后就报 `launched: True`**，不管应用有没有到前台。
  启动后再读一次当前 activity，对不上就如实回 `launched: False` 并带上 `foreground`。
- **`device.install` / `uninstall` / `force_stop` 同样把 adb 返回当成成功**。装包不查
  `pm path`、卸包不看包是否还在、强停不看 pidof，无人值守循环会以为应用已经装上、卸掉或
  停掉。现在对照设备侧状态回 `installed` / `uninstalled` / `stopped`（核不上就 `null`）。
- **`device.current_activity` 在 `app_current()` 返回 None 时仍回 `{package: None,
  activity: None}`**。dumpsys 读失败被无人值守的 agent 当成「前台没有应用」这一事实，而不是
  一次失败的读取。现在读不出包名记为 `backend_error`，真实的包名/activity 组合行为不变。
- **`device.list` 对每个设备再调一次 `get_state`**。adbutils 的 `open_transport` 默认等
  600 秒，假死的 adb server 会把工作线程占满十分钟；而且 `device_list()` 只回在线设备，
  offline 看起来像「没有这台设备」。改为一次 `host:devices`（带 socket 超时），offline 也
  列出来，并给 `open_transport` 换上 120 秒的挂起上限。
- **`device.packages` 仍会为了排序把完整包列表装进内存**。采集停在 limit 上。jadx / webcrack
  的文件列表同样不再为了 `file_count` 物化全部路径。
- **`device.pull` 会把整棵目录拷到宿主机**。adbutils 在远端是目录时递归拉取，没有体积上限；
  一次 `/sdcard` 就能把磁盘写满，而产物表看不见这些文件。目录和超过捕获上限的文件在拷贝前
  拒绝。`device.push` 同样拒绝超过上限的本地文件。
- **`device.install` / `device.push` 先连设备、后查本地文件**。「文件在不在、多大」是廉价的本地
  事实，也是最常见的手误，而 `_device` 要够到 adb server。把本地检查排在后面，意味着写错的路径
  要白搭一次设备往返，而当 adb server 恰好连不上时，真正的问题（文件不存在/超限）还会被设备
  错误盖掉。改为先判本地文件：路径不存在回 `not_found`、`push` 的超限文件回 `too_large`，都在
  连设备之前当场返回，合法输入才去连设备（与 `frida.spawn` 先判包名同一处理）。
- **`proxy.replay` 把命令排进代理线程就算成功**。循环已死或命令稍后失败时，调用方仍拿到
  `replayed: True`。现在等到 mitmproxy 真正执行完（15 秒上限）才回成功。
- **`frida.java.classes` 会在设备上把已加载类全部列一遍**。`enumerateLoadedClassesSync`
  先物化全集再截断；加壳应用可以有十几万个类，这一次 RPC 就能把目标拖死。改为边枚举边停。
- **jadx 反编译会把整个 .java 读进内存再切**。生成器吐出的单文件可以到几十 MB。按上限读。
- **有界执行器仍会把工具的全部 stdout/stderr 读进内存**。Ghidra / jadx 的进度输出可以到
  上百 MB，调用方只用其中几 KB。现在每个流最多保留 8 MB，多出的丢弃以免撑满管道。
- **Ghidra 导出 JSON 没有体积检查**。postScript 写出的文件被整份 `read_text`；脚本自己的
  列表上限挡不住一份被写爆的导出。超过 2 MB 拒绝，而不是把进程读满。
- **截图可以单独超过捕获目录的字节上限**。淘汰从不删最新的那一份，于是一张超大的
  `device.screenshot` / `web.screenshot`（尤其是 full_page）会永远留在磁盘上。写入后若超限
  则删掉并拒绝。
- **抓包环形缓冲按条数封顶，但每条仍可带着整份报文体**。两千条各几十 MB 的响应照样能把
  内存吃光。超过 2 MB 的请求/响应体不再留在 `_raw` 里，列表上回 `body_omitted`，取正文或
  重放会如实报 `too_large`。
- **`web.network.get` / `web.script.source` 会把 CDP 送来的整份正文写进产物目录**。超过
  内联上限就落盘，没有捕获上限；一条媒体响应就能在 retention 跑起来之前把磁盘写满。超过
  捕获上限改为拒绝，不写文件。console 单行同样封顶，超长回 `text_truncated`。
- **`apk.sign` 只看 apksigner 退出码就报 `signed: True`**。写出文件但签名无效时，调用方会
  把未签名包当已签名去装。签名后再跑 `apksigner verify`，核不上就报错。
- **`device.forward` 的跟踪表没有上限**。转发记在 adb server 上，单次 `close_session` 拆
  不掉；无人值守循环每轮换一个本地端口，表和 server 一起涨。满 32 条后拒绝新的转发。
- **`frida.modules` 会把目标进程的全部模块序列化进这一次 RPC**。Python 侧再截断。改为在
  脚本里按 limit 停，并带回 `total`。

### 新增（项目文档）

- 补充 `SECURITY.md`（围绕受限工具面界定漏洞范围与私密上报流程）与 `CONTRIBUTING.md`
  （质量门命令、测试目录与命名契约、加新工具的硬规矩）。
- `SECURITY.md` 增加「安全开关速查」：把 `local_full_access` 与三个 autonomy 配置键
  （`agent_auto_approve_effects` / `agent_auto_approve_tools` / `agent_never_auto_approve`）
  连同环境变量与效果列成表，并写明未配置=packed-analysis 预设、显式空列表=fail-closed
  两条易踩坑规则。
- 修正文档口径：README 里「敌意输入下全部返回信封」的工具数从过时的 262 改为 264（=全部
  265 个 MCP 工具减去会真删数据的 `artifacts.gc`），并改述为「绑定工具数 − 1」的不变式，
  跟 `test_tool_fault_contract.py` 的断言一致，避免再随目录增长漂移。
- `CONTRIBUTING.md` 补上平台差异说明：CI 的 quality job 跑在 windows-latest，`python -m mypy`
  的权威零错误门在 Windows；在 Linux/macOS 直接跑 mypy 会报若干 Windows 专属 stdlib 属性
  （`msvcrt`/`ctypes.windll` 等）的假阳性，属环境差异而非真错误。

### 测试（契约护栏）

- **会话层对敌意与降级输入的 fail-closed 契约成套固定**（`core/session.py` 85%→99%）：
  崩溃残留的 SQLite 行——带路径分隔符的 id(遍历企图)、空 locator、未知 state 列、
  非法 architecture、天真/垃圾时间戳、`resolve()` 抛 OSError 的死挂载——一律安静跳过或
  归一化恢复而不是让 hydration 崩掉;store 源本身抛异常或返回非 Mapping 行时启动照常。
  注册表护栏直测:同态迁移是无副作用的 no-op(不更新 `updated_at`)、CLOSING/CLOSED
  会话拒绝挂 backend、`remove_closed` 拒删活会话、重启后 adopt 进来的 closed 行可被
  正常退休。目标分类直面伪造文件:PK 魔数但 zip 损坏回落 PE、无扩展名时按 wasm/带
  manifest 的 zip 魔数识别、`.apk` 非 zip 或缺 `AndroidManifest.xml` 报结构化 ValueError、
  伪造 MZ/PE 头与不支持的 machine 各自 fail-closed;本地 `.js` 资产建会话时哈希入册,
  远程 URL 不碰磁盘。
- **外部工具发现与校验的护栏成套固定**（`config.py` 82%→100%）：idalib/x64dbg 的发现逻辑
  决定服务器会加载并执行哪个外部二进制,现在在临时目录里把宿主平台钉住后跨平台直测:
  Windows 注册表指向的 IDA 目录若缺 idalib 运行时(GUI-only 安装)不会被交给加载器、
  注册文件损坏安静回落文件系统扫描、Program Files 双根去重、POSIX 家目录扫描跳过
  消失的根;`validate_ida_home` 四种结构化裁决(空路径/非目录/缺 idalib/可用)各自直测,
  缺件裁决必须说出期望的文件名。x64dbg headless 只认 x86/x64 且大小写空白宽容;
  已有 config.json 读不动时 `update_config_values` 报错并保证不覆写原文件。
  `_as_int`/`_as_float` 对垃圾值回退而非炸掉启动,负值一律钳到 0;`_as_command`
  的 env 覆盖默认、字符串默认按操作员写法切 argv、数组默认丢弃空片段。
- **只读部署的写拦截由全工具面契约固定**：每个写工具在 `local_full_access=false` 时返回
  `write_disabled` 并短路、读工具不受影响、被 guard 包裹的集合恒等于按 `tools/catalog.py`
  分级判定的写集合——分级与执行不再各走各的（此前只在一个合成探针上验证机制）。
- **工具面边界契约**：禁止 `dynamic.command` / `device.shell` / `web.evaluate` 等自由命令 /
  eval 工具重现，每个工具须带非空描述与对象型 input_schema，读写分级唯一且互斥。
- **四个复制的 `_capture_process` 由共享契约固定**（DIE / Exeinfo PE / UPX /
  de4dot+NETReactorSlayer）：headless 启动（Windows 上 `CREATE_NO_WINDOW`、不继承 stdin）与
  缺执行文件时的结构化 `executable_not_found`，一处修好不会漏掉其它三处。
- **OpenAI 导出**：断言每个 MCP 工具都被导出且 `write_tools` 映射回来恰好等于 catalog 的写
  集合，桥接方的审批清单不会与写策略护栏漂移。
- **packed-analysis 自动批准的排除名单钉死到真实 catalog**：`_EXCLUDED_AUTO_FILE_WRITES`
  里的每个名字都必须是真实存在的 `file_write` 工具，预设 = agent 文件写工具减去该名单——
  改名会让排除项变成死字符串、悄悄放开某个敏感写(打补丁 / APK 重签 / 产物 GC)，新增文件写
  工具也会被这条断言逮到而不是默认随预设自动批准；并用真实 spec 验证 patches / apk 改包 /
  `artifacts.gc` / `web.screenshot` 等仍留人工，而代表性的 `dynamic.stealth.set` 照常自动跑。
- **敏感信息脱敏覆盖整个关键字与分隔符矩阵**：错误信封与事故日志共用一条 secret 正则，
  过去只验过 `token=` 一种形态；现补齐 `api_key`/`api-key`/`apikey`/`token`/`secret`/`password`、
  `:` 与 `=` 两种分隔符、`Authorization: Bearer` 头与大小写不敏感，并断言普通诊断文本不被误抹、
  运行期 bearer 口令在信封与事故日志里都被抹成 `[REDACTED]`。
- **监控台认证边界成套固定**：错 token 与缺 token 同样 401 且不发放 bootstrap cookie，
  服务端从未签发过的伪造 bootstrap cookie 也不被提升为授权；
  公网源地址即使带对 token 也被 403(含 `/readyz`);`/healthz` 是唯一的非回环例外且不含
  任何秘密;IPv6 回环(`::1`)照常通过主机守卫;被截短/篡改的 token 文件会被强 token 顶替
  并保持 0600 权限。正是这批测试暴露了上面「回环护栏 500」的缺陷。`?token%3D…` 的编码
  修复也补齐了边界:无标记原样透传、标记在中段、尾随参数保留、大小写不敏感。
- **产物下载路径逃逸守卫**：`/api/artifacts/{id}/file` 无论 DB 行指向哪里,凡解析后越出
  产物根(含 `根/../外部` 这类回爬)一律 `403 artifact_outside_root`;未知 id → 404、
  根内真实文件 → 200、文件已被删 → 404。
- **`run_cli_safely` CLI 边界**：成功透传退出码、Ctrl-C 归 130、崩溃归 1 并在 stderr 打
  一行脱敏的机器可读信封(不吐 traceback、不漏口令)。
- **apksigner 口令抹除双路径固定**：签名与校验两条失败路径都把 `--ks-pass pass:…` 里的
  口令从 stderr 抹成 `***` 再进错误信封(`SECURITY.md` 明文承诺,此前无测试)。
- **会话目标守卫直测**：`Session.require_pe/require_target/require_binary/require_architecture/
  require_locator` 各自要求哪种 `target`、错目标抛携带 `target_mismatch` 码与 expected/actual
  详情的 `TargetMismatch`(此前只在 service 层间接验过两个工具)。
- **只读开关解析固定**：`local_full_access` 的 env/JSON 解析——未配置=完全访问、falsy
  (`0/false/no/off`,大小写与空格不敏感)=只读、truthy=完全访问、JSON 可选只读且 env 覆盖
  JSON——写守卫读的 `catalog.write_allowed` 正来自它,解析错就会悄悄重开写面。
- **错误信封尺寸钳制**：`RpcError` 把调用方可控的 message 钳在 2048 字符、字符串型 details
  钳在 1024(恰好放限长边界值原样透传、int/嵌套 dict 不动),并断言 `ok=False` 无 error 的
  Result 被拒——防止超长 session id 之类把信封撑到几百 KB,也防失败被当成功。
- **OpenAI 桥接 CLI 三形态**：默认输出完整导出(count==tools==name_map)、`--names-only`
  只剩 `{name_map,count}`、`--output` 把完整 JSON 写到(自动创建的)路径并在 stdout 报告而不
  把工具体打到屏幕(CI 只 smoke 了 `--names-only`)。
- **全表面资源策略有界**：全部 265 个工具的 `resource_policy` 都有有限且为正的超时与为正的
  输出上限——防止 0/负/非有限超时混入导致无人值守跑挂。
- **ScyllaHide 画像映射纯函数直测**：别名/节名规范化与其 fail-closed 拒绝(空串或未知名会连
  同白名单一起报出)、3 字符短 token(`vmp`/`tmd`)只按词边界匹配以免命中别的词内部、非壳类
  category 被忽略、更长的检测 token 胜出、按架构的白名单与 section 往返(armadillo 仅 x86)、
  以及 `stealth_hint_profile` 对缺失/非法元数据返回 None(此前仅经 service 端到端间接覆盖)。
- **两条媒体路由的产物根逃逸守卫**：`web/preview` 的 PNG 与 `virtual-desktop/frame` 的帧和产物
  下载走同一套「文件必须落在产物根内」判定却此前无测试;这批打桩 service 采集使其在 Linux 可跑,
  断言越根路径分别 404(`preview_not_found`/`capture_not_found`)、根内真实文件 200 且字节正确、
  采集失败回 409。
- **能力目录钉死到真实工具与探针**：`_CORE_CAPABILITIES` 用字符串字面量硬编码每个能力暴露的
  工具名与状态探针名,此前无任何东西把它们与现实绑定——一旦 `tools/catalog.py` 或 `doctor.py`
  改名,能力就会宣传一个不存在的工具或永远解析不到的探针,而 `list_capabilities` 只会默默把它
  报成 `missing` 且不报错。新增契约断言每个宣传的工具名都是真实 MCP 工具、每个 `status_probe`
  都是真实 doctor 探针、id 唯一且形状完整,并用打桩 doctor 验证状态映射(ready/missing、无探针恒
  ready、缺失探针回退 missing)与 backend/status 两个过滤器。
- **asyncio 异常钩子首次落测**：进程/线程/unraisable 三个钩子早有测试,唯独 asyncio 的
  没有——没人 await 的任务失败经 loop 异常处理器上报,我们的处理器必须把事故写进 incident 日志
  (走同一个脱敏器,`api_key=...` 不落盘)、loop 交来无异常对象的上下文(回调错误就是这样)时
  从 message 合成 RuntimeError 而非丢弃报告;在无运行中 loop 时安装必须静默返回(
  `install_global_exception_hooks` 恰在任何 loop 存在前运行)。
- **workflow 取消/超时/重置的不幸路径**：happy path(start→事件→match)已充分测试,但目标
  卡死时 service 求助的那三条转移没有——`timeout_workflow_navigation` 零测试、cancel 只测过
  无导航空转、样本间清场的 `prepare_workflow_reset`(解除所有断点武装+停止监听)零测试。
  钉住:cancel/timeout 把 WAITING 导航置为对应终态且恰好请求一次 ENSURE_PAUSED;对已了结的
  导航幂等、不再发第二个暂停命令;reset 禁用全部 intent 并规划物理 REMOVE、取消导航,空闲态
  reset 不规划任何工作。
- **`_failure` 异常→错误码映射直测(信封契约)**：每个 service 方法的 except 块都汇入 `_failure`,
  无人值守调用者据结果的 `code` 与 `retryable` 分支——存储故障可重试、`invalid_request` 不可。
  该映射是有序 isinstance 链,重排或漏一条会静默改变调用者看到的码,此前无直接测试。钉住承重行:
  `SessionNotFound`→`session_not_found`(不可重试)、`InvalidStateTransition`/`ValueError`→
  `invalid_request`、`FileNotFoundError`→`file_not_found`、`TimeoutError`→`workflow_timeout`
  (可重试)、`sqlite3.OperationalError`→`storage_unavailable`(可重试)而 `DatabaseError`→同码但
  不可重试、`TargetMismatch`/`AddressSyncError` 保留自有码与 details;并验证兜底 `internal_error`
  归档 incident 且消息脱敏(`api_key=...` 不入信封也不落日志)。
- **`_read_capped` 直测(bounded 子进程的输出上限)**：`run_bounded` 在线程上经它读取子进程
  stdout/stderr,是阻止失控或敌意工具用海量输出撑爆内存的那道字节天花板。子进程管道要真实进程,
  但上限算术与截断标志是纯逻辑、此前未单测。用脚本化假流钉住:限内全留不截断、恰好等于 cap 不
  截断(填满即结束是完整读取)、单块超限切到 cap 并置位、满后续块不再增长缓冲但保持置位、空流
  返回空且不截断、中途管道损坏(ValueError/OSError)吞掉异常返回已读部分而非上抛。
- **`_loaded_string_tuple` 三路解析直测(自治默认的 fail-closed 语义)**：`agent_auto_approve_*`
  经它解析,须区分「显式空」与「未设置」——env 覆盖一切(含 env 设空即「什么都不自动批准」且不
  回落 preset);config 文件里键存在(哪怕是 `[]`)是显式选择,一律 fail-closed、绝不被 packed
  分析 preset 悄悄顶替(否则用户主动关闭自动批准会被静默重新打开);唯有键完全缺席才用 preset。
  用会抛异常的哨兵 preset 证明它只在缺席时被调用。
- **`_as_bool` / `_as_tuple` 环境解析直测(安全设置入口)**：`_as_bool` 决定 `local_full_access`
  ——整个写面的开关——故「关」的词集必须恰为 `{0,false,no,off}`(去空白、大小写无关),其余非空
  值一律为真,`None`(未设置)才回落默认;空串是「已设置」且不在关词集,故读作真(显式钉住是有意
  行为)。`_as_tuple` 解析 `agent_never_auto_approve` 等名单:逗号分割、去空白、丢空片段、按序
  去重(重复规则不该看起来像两条,尾逗号的空片段不该变成规则),env/默认串/默认列表三种来源同规,
  无来源回空而非崩。
- **`encode_knowledge_value` 直测(超限拒绝而非截断)**：knowledge 列存的是序列化后的发现,
  截断到限长会写出不再是合法 JSON 的字符串,令后续每次查询都在读取端抛错。钉住:限内值往返
  保真且 `ensure_ascii=False` 保留中文可读;恰好等于 `KNOWLEDGE_VALUE_MAX_CHARS` 的值接受且
  可解析;超限整体拒绝并提示「把大块作为 artifact、这里只留引用」。
- **`normalize_base_url` 直测(provider 端点规范化)**：base_url 决定 api key 发往何处,却无
  直接测试。钉住:裸 host 追加 `/v1`、已有 `/v1` 不重复、去尾斜杠、子路径追加 `/v1`、首尾
  空白与 scheme 大小写归一;并显式验证 query 与 fragment 被丢弃(base_url 是前缀而非请求,
  混进 `?token=...` 会随每次调用外泄/落日志);非绝对 http(s)(空、`ftp`、`file`、缺 scheme、
  缺 host)一律拒绝;`ProviderProfile` 构造时即规范化,调用者无法绕过。
- **workflow 运行台账首次落测**：`workflows/runtime.py` 是 service 每次调试器操作都推进、
  监控台直接渲染的状态台账,status 与 failure 必须步调一致(FAILED 必带结构化 failure、
  非 FAILED 不得残留 failure),此前无直接测试。钉住:新建台账 IDLE 且 id 唯一;四条
  `__post_init__` 不变量逐一拒绝;`advance` 计数、拒绝已失败台账、也不能借 status=FAILED
  偷渡失败转移;`fail` 记录结构化失败、零进度声明被拒、未给 state 时保留最后好状态;
  `to_dict` 输出 ISO 时间戳与 modules/breakpoints/navigation 的完整 JSON 形状。
- **workflow 执行器首次落测**：engine/navigation/lifecycle/breakpoints 都是纯函数且已充分测试,
  但把计划变成有序调试器端口调用的 `workflows/executor.py`(暂停→设断→刷新模块→再对账→恢复)
  此前零测试。用记录型假端口钉住:非正超时先拒绝且不碰端口;SET 计划到端口恰一次且返回态无残留;
  效果顺序恒为 pause 先、resume 尾;中途失败时 `WorkflowExecutionError.execution` 如实报告已
  完成的操作数(部分态重新规划恰剩一个 SET);模块刷新按新基址 REMOVE+SET 重绑;引用未跟踪模块
  的刷新 fail-closed、不会静默只刷子集。
- **SPA 兜底路由的双重契约**：catch-all 路由必须像路由器、不能像通配符——刷新客户端深链
  (`/threads/x`)要回 SPA 壳,否则所有书签 404;但同一 catch-all 排在 API 路由之后,*未知*的
  `/api/...` 落进它时若回 HTML,打错字的 API 客户端会把控制台页面当 JSON 解析。此前该路由
  (`web/routes/spa.py`)没有任何直接测试。补测:带 token 深链回壳、未认证深链 401、未知
  `/api/...` 与过期 `/assets/...` 哈希一律 404 且不含 HTML 壳。
- **README 头版本号钉死到 pyproject 与 build_info**：版本升级必须同步移动 README 头部横幅
  (全角括号里的 `（v0.2.1）`),而非只改 pyproject;下文的 Release 标签 URL `v0.1.0-deps` 不是
  版本声明、须保持不动。新增护栏把横幅版本钉到 pyproject 的 `version` 与运行期 `build_info()`
  三者同步。
- **审批哈希的 key 顺序无关性**：审批门比较两个独立算出的哈希——orchestrator 哈希它提议的参数,
  监控台哈希它为批准而重建的参数,两边都走 `canonical_args_sha256`。此前只比过同一 dict,没钉住
  它必须依赖参数*值*而非序列化器碰巧用的 key 顺序:否则重排但等价的负载会过不了 mismatch 检查、
  卡住合法批准。补测试:顶层与嵌套 key 重排哈希相同、值不同则哈希不同,并端到端验证按重排参数
  重算的哈希仍能 `decide`+`consume` 该调用。
- **`bounded_tool_result` 直测(含 untrusted 标记)**：两个 transport 都经它把工具输出交给模型;
  超限回复被替换为摘要并打上 `untrusted_tool_output`——告诉模型这段被截断的工具输出不可当指令服从
  的防注入标记。此前只经 `apply_result_budget` 间接测,自身边缘(非 dict 包装、精确等长边界、
  摘要按 `max_bytes//2` 截断、以及那枚 untrusted 标记)从未钉住。补直测:小 dict 原样透传、
  非 dict 包成 `{"value": …}`、超限→带 `untrusted_tool_output=True`/`original_bytes`/摘要且再编码不超预算、
  等长不截断、超一字节即截断。
- **超限成功的工具结果被 `bounded_tool_result` 截断后当成失败**。每条工具结果都是 `{"ok": bool, …}`
  信封,但截断摘要丢掉了 `ok`;orchestrator 用 `bounded.get("ok", False)` 读判定,于是一次**成功**
  但体积超预算的调用(如大反编译、大字符串导出)在监控台和审计里显示成失败的工具调用——只因为它大。
  两个 transport(Agent 的 orchestrator 与 MCP 的 `apply_result_budget`)都经它。现在摘要保留信封原本的
  `ok`(单个 bool,不撑破预算):截断的成功仍报成功、截断的失败仍报失败。补测:截断的成功/失败各自保留
  `ok`、非信封负载不无中生有出 `ok`、orchestrator 的 `tool.completed` 对超限成功记 `ok=True`,并把 MCP
  预算测里那条精确字节断言更新到 16494。
- **Cursor 下划线别名解析 + 全表面无碰撞**：Cursor 以 `static_functions` 调用而 catalog 注册的是
  `static.functions`,`install_cursor_underscore_aliases` 在 `get_tool` 处解析且不新增 ListTools 项。
  它用普通 dict 建下划线→点名映射,两个折叠成同一下划线形的点名会互相静默覆盖(OpenAI 桥接对这类
  碰撞有守卫,这条路径没有)。catalog 存在多段点名(`breakpoints.condition.set`),碰撞并非假想。
  新增契约:钉住出厂全表面 265 个 MCP 名折叠后无碰撞,并直测别名解析(点名/下划线/多段名都命中同一
  工具、无点名工具与未知名不受影响、无点名时 `get_tool` 保持原样不被闭包替换)。
- **MCP server 的 `write_allowed` 接线回归**：`create_server` 从 `local_full_access` 读入共享
  catalog 的 `write_allowed`;该处的常驻注释记着它曾一度没被读、只读部署照拿全写面。此前没有任何
  测试钉住这条接线,一次重构把它删掉就会重开那个洞。补参数化回归:只读/完全访问两向都断言
  `create_server` 后 `COMMAND_CATALOG.write_allowed` 与设置一致(并在结束时还原全局标志)。
- **Web 写适配器 `invoke_write` 契约直测**：`/api/write` 白名单+confirm 后交给 `WebCommandAdapter`,
  真正的分级判定在这里:非 WEB 写一律 `KeyError`、会话级写缺 `session_id` 抛
  `ValueError("session_id_required")`(路由渲染 400)、`artifacts.gc` 走字节预算而非 session、
  只读时先抛 `PermissionError` 不碰 service。此前只在路由层间接测过,`session_id_required` 一路
  完全没测。补直测:含缺 session 时 service 一次都不被调、读工具即便存在也不能当写触达、
  read-only fail-closed。
- **Web 异常边界的 500 响应脱敏端到端**：工具级信封已验过运行期口令被抹,但 FastAPI 边界虽然
  走同一条 `exception_envelope` 路径,此前无测试断言 HTTP 500 响应体本身被脱敏。新增测试:一个
  处理器抛出把 `Authorization: Bearer <运行期 secret>` 插进消息的异常,断言该 secret 既不出现在
  500 响应体、消息里出现 `REDACTED`,也不落进事故日志。
- **`capped_file_size` 直测**：`prune_capped_dir` 会保留最新一项(即使它单个就超预算),
  `capped_file_size` 是写入方用来当场删掉「刚写下却单个爆表」的那一项的配套原语——越界磁盘
  兜底。前者有直测,后者此前只经一个 monkeypatch 上限的截图测试间接触到。补三态直测:
  超上限→删文件并回 `(size, True)`、等于/低于上限→保留(边界严格:`==cap` 不算越界)、
  文件不存在→`(0, False)`(没落地的采集不得被读成越界失败)。
- **Prometheus 标签转义防伪造行**：`/metrics` 暴露把工具名放进标签值,`_LABEL_ESCAPES` 定义了
  反斜杠/双引号/换行三种转义但此前只验过双引号。未转义的换行不只是弄脏一个值——它会提前结束
  该行、余下部分被当成新样本解析,于是工具名成了可被(潜在)敌意字符串伪造出一条时间序列的位置。
  新增测试钉住三种转义都生效,且没有任何物理换行漏进标签值(逐行断言 `{` 至多一个)。
- **依赖清单快照的许可与接线契约**：`build_deps_snapshot`(撑 `/api/deps` 与上手清单)是 README
  反复重申的许可红线的机器可读形态——x64dbg headless 树可随包、IDA 永不。此前无测试钉住这套
  逐项 `packable`/`never_bundle` 标志,且每项还硬编码一个 `Settings` 属性与一个 `HEADLESS_RE_*`
  变量。新增护栏:钉住 IDA `never_bundle=true / packable=false`、x64dbg 可打包、
  `claims_universal_unpack=false` 与 policy 块一致;present 检测对文件/目录/None 三态正确、
  必需但缺失者进 `missing_core`;counts 内部自洽;每个 `id` 都是真实 `Settings` 字段、每个 env
  都被 `config.py` 读取——改名或翻转标志会在此炸,而不是让 IDA 被悄悄重划为可打包。
- **CONTRIBUTING 质量门钉死到 CI**：CONTRIBUTING 让贡献者本地照跑 CI 那套门;若 CI 改了某步
  命令,文档会与真正卡 PR 的门漂移——照文档跑通了、CI 仍拒。新增护栏解析 CONTRIBUTING「质量门」
  代码块里的每条命令(剥掉注释)并断言它们逐条字面出现在 `ci.yml`,外加安装 extra
  (`.[test,dev,web]`)两处一致。
- **SECURITY.md 开关表钉死到实现**：安全开关速查表把配置键映射到环境变量并承诺行为;
  `Settings` 字段或 env 管道一旦改名,安全文档就会指着一个拧不动的旋钮。新增护栏解析表格行,
  断言每个配置键都是真实 `Settings` 字段、每个 `HEADLESS_RE_*` 变量确实被 `config.py` 读取;
  并检查三份文档(SECURITY/README/CONTRIBUTING)引用的每个 `tests/...` 契约测试文件都真实存在,
  防止「由某测试强制」的说辞指向一个已被挪走的守卫。
- **自治授权的重启往返**：`PUT /api/agent/autonomy` 经 `update_config_values` 落盘,下个进程
  经 `Settings.load` → `AutonomyPolicy.from_settings` 读回——写读两侧各自独立拼写 `agent_*`
  三个键名,任何一侧改名都会让「记住的批准」在重启后无声消失。新增真实文件往返测试
  (仅把配置路径重定向出用户主目录),并钉住授权时落盘的显式空 effects 列表在重载后保持
  fail-closed、不被 packed-analysis 预设回填。
- **`update_config_values` 直测**：它是用户 config.json 的唯一写入方(「记住此次批准」的
  自治授权与依赖包安装器的工具路径都经它落盘),此前只被调用方 mock 从未直测。钉住:合并保留
  无关键、`None` 删键(删不存在的键安静通过)、`Path` 值序列化为字符串、已损坏的旧文件被替换
  而非让之后每次保存都崩、POSIX 上落盘 0600(config.json 可能携带自治授权,同机其他用户无权改)。
- **README 工具算术钉死到 catalog**：README 陈述了三处具体数字(MCP 工具总数、148/117 的
  读写拆分、敌意输入覆盖数=总数−1 个刻意排除),此前无任何东西重算它们——加一个工具或改一次
  读写归类,首页就悄悄变成小说。新增护栏用各自独特的句式定位三处声明并与
  `tools/catalog.py` 实时对账;句式被改写时按「恰好一处匹配」的断言吵着失败,而不是护栏静默失明。
- **Provider 秘密面成套固定**：`providers.json` 是部署里唯一合法明文存 API key 的文件,
  此前无测试钉住它的两条命脉——文件本身在 POSIX 上必须 0600(目录 0700)且 key 确实写进去了
  (否则「私有文件」保护的是空气);而一切对外形态(`public()` / `list_public()` /
  Zerofall 导入预览)只许出现掩码(`sk…89`),原始 key 与 `providerApiKeys` 里的每个值都不得
  出现。另钉 `masked_secret` 短 key(≤8)只回 `********` 不泄长度、未配置档案报
  `configured=false` 且不编造掩码、`HEADLESS_RE_PROVIDER_API_KEY` 环境覆盖生效时 key 既不进
  文件也不进公开列表。
- **全路由未认证扫描**：认证是逐路由手写的(`_require_token`/`authorize` 50+ 处调用点),
  没有任何结构性机制阻止新路由漏掉这一行。新增契约测试遍历注册在 app 上的全部 85 个路由,
  未带 token(回环源)逐一请求并要求 401——必填 query 参数导致的 422 会被自动补参重试,
  使判定落在认证而非 schema 上;同时钉死三个刻意的未认证例外(`/healthz` 活性、
  `/readyz`/`/metrics` 监督探针,设计上免 token 以免把控制台 token 交给 supervisor),
  并断言三者的响应体都不含 token。

### 变更（Android 后端清理）

- 移除 apktool 客户端 `_run` 里从未被任何调用方传入、且函数体立即丢弃的 `redact_from`
  死参数(口令抹除实际由调用处的 `stderr.replace` 完成,行为不变)。
- 移除 adb 客户端里编译后从未被引用的 `_COMPONENT_RE` 死常量(组件名从未成为任何工具的
  输入面,该校验从未接线)。

## [0.2.1] - 2026-08-12

0.2.0 的安装包无法使用，这个版本修掉它，并带上一轮代码审计发现的自愈缺陷。

### 修复（安装包）

- **MSI 装出来是个空壳**。它只有 740 KB，因为里面只有源码：没有任何第三方依赖，
  也没有 Python 运行时。在一台干净机器上装完，`python -m headless_re_mcp` 会直接
  `ModuleNotFoundError: No module named 'pydantic'`。现在运行时和依赖随包发布
  （33 MB，3261 个文件），安装后不依赖机器上装没装 Python。因为 `pydantic-core`
  只提供 cp312 专用轮子而非 abi3，内置解释器版本是锁定的——这也正是必须连解释器
  一起打包、而不能只放依赖的原因。
- **验证脚本存在盲区，正是它让空壳通过了检查**。它用系统 Python 加 `PYTHONPATH`
  去导入安装出来的副本，依赖其实来自开发机的 site-packages，所以只证明了"目录完整"，
  没证明"装完能用"。现在它会清空 PATH 里的所有解释器、只允许自带运行时应答，
  并额外校验 web 栈（fastapi/uvicorn/httpx/mcp）确实存在。
- 字节码改为构建时预编译并随包安装（因而卸载时被一并移除），启动器加 `-B` 禁止
  运行时再写。此前依赖 `util:RemoveFolderEx` 清理，在 3000 多个文件的规模下会漏掉
  71 个 `.pyc`。

### 修复（代码审计发现）

- **传输故障会先把被调试进程杀掉**，重连根本没机会介入。`rpc_transport_error` 被列在
  `_FATAL_WORKER_ERRORS` 里，约 15 处调用点据此调用 `_fail_runtime`，后者会
  `terminate()` 掉 x64dbg 连同它持有的被调试进程，并把会话置为 FAILED。但客户端只在
  确认 worker **仍然存活**时才抛这个码（进程死了抛的是 `worker_exited`），所以它按构造
  就等于"连接断了、后端还在"。结果是：自愈只在空闲会话上生效（drain pump 会吞掉异常），
  在有请求的会话上反而摧毁现场。此前的集成测试直接把 `_transport` 置空，恰好绕开了
  这条路径，所以一直是绿的；新增的 gate 让故障从真实请求里发生。
- **单步失败会被伪装成成功**。`_absorb_redundant_run_control` 原本对任何带 `wait_for`
  的方法生效，而 step/resume 在原生端是 `requirePaused=true`，被拒时目标必然处于
  `paused`——那既是失败后的状态也是执行前的状态，状态永远无法证明单步发生过。配合
  `wait_for_state` 在事件环溢出（`dropped > 0`）时会放行，失败的单步就会带着未移动的
  指令指针返回成功。现在只对 `pause` 生效。
- **健康监控会去动已被关闭的后端**。快照在锁外使用，`close_session` 可能已经把 runtime
  摘走；此时重连会占着请求锁最长 30 秒，而 `close_session` 正在等同一把锁。现在重连前
  会用 `is_current` 复核。`_fail_runtime` 也补上了健康记录清理，否则死掉的后端会被
  永久报成不健康。
- **停止超时后重启会留下两条巡检线程**。`stop()` 的 join 只等 2 秒，而一次巡检可能卡在
  重连里 30 秒；随后的 `start()` 清掉停止信号，等于把上一条线程也复活了。
- **只读模式只在 MCP 一条通路上生效**。Web 控制台的 agent 路由和 OpenAI 桥接走的是
  `bind_all_tools`，绑的是未包装的原始 handler；`WebCommandAdapter.invoke_write` 更是
  直接调用服务方法。守卫已下沉到 `CommandCatalog.bind_mcp` 这个唯一收口，Web 直连路径
  单独补了检查。
- 健康巡检间隔解析失败时不再静默归零（等于关掉自愈），而是回退到默认的 5 秒；
  `session.health` 在没有任何后端时返回 `healthy: null` 而非 `true`。
- **工具线程可能耗尽 anyio 的公共线程池**。把工具挪到工作线程本身是对的，但用的是默认
  池：几个卡住的调试调用就能饿死所有其它需要线程的任务，包括框架自身的。现在使用独立
  限流器（16 条），到顶后新调用排队，是诚实的背压而非无声饥饿；并且开启
  `abandon_on_cancel`，客户端中途断开不必再等调试器把 60 秒超时走完。
- 重连的三处健壮性缺口：覆盖 `_transport` 前未关闭旧句柄；`hello` 返回的 capabilities
  不是数组时静默沿用旧能力集（会把降级的 worker 当成完好的）；能力检查排在重连之后，
  导致一个后端根本不支持的调用要先白等 30 秒重连再被拒。
- `terminate()` 不加锁修改客户端状态，与后台重连并发时可能把新连接挂到正在拆除的对象上。
- 逐个关闭会话（不走 `close_all`）时巡检线程不会停止，会比它服务的所有后端都活得久。

### 修复

- **一次耗时调用会卡住整个 MCP 服务**。FastMCP 对同步工具是直接在事件循环里调用的
  （`call_fn_with_arg_validation` 里 `fn_is_async` 为假时直接 `return fn(...)`），而本项目
  所有 handler 都是同步且可能阻塞数十秒（`dynamic.launch` 默认超时 60 秒、IDA 反编译等）。
  这期间同一连接上的其它请求全部排队，包括用来问"出什么事了"的那些。现在工具在工作线程
  上执行，事件循环保持空闲。
- **`local_full_access` 是个不起作用的开关**。它由安装流程写入、被 `Settings` 读入，
  但代码中从无任何地方消费它——设成 `false` 得到的是虚假的安全感。现在它真正生效：
  只读部署下所有 STATE_CHANGE / FILE_WRITE 工具返回 `write_disabled` 错误信封，
  只读工具不受影响。工具仍然可见，调用方得到的是可理解的拒绝而不是工具凭空消失。

### 新增

- 全工具面契约测试：198 个工具在每次运行时都被喂入敌意参数，必须返回错误信封而非抛出。
  此前这条性质只被手工测量过一次，没有任何机制阻止新工具打破它。

## [0.2.0] - 2026-08-12

第一个自愈能力经过真机验证的版本。198 个工具扩到 199 个，全部工具在敌意输入下均返回结构化错误信封。

### 新增

- **动静结合的复合工作流**：`dynamic.analyze_function` 从静态地址一步跟到运行时断点；
  `dynamic.trace_api_arguments` 在断点处按调用约定取参（x64 走寄存器，x86 走栈）。
- **智能地址换算** `sync.resolve_runtime_address`：静态地址、RVA、运行时地址之间自动换算，
  调用方不必关心 ASLR 下的 ImageBase。`dynamic.breakpoint_set` 新增 `address_space`
  参数，可直接下静态地址断点。
- **后台健康监控与自愈**：连接掉线会被自动重建，无需任何人察觉。`session.health`
  按需检查后端存活与连接状态。死掉的 worker 只上报不自动重启，因为重启后的调试器
  不再附着于任何进程。
- **分析知识持久化** `knowledge.record` / `knowledge.query`：按会话幂等记录函数、API、
  结构体等分析结论，多轮对话之间不再丢失上下文。
- **分析报告** `report.generate`：把会话结论渲染成 Markdown。
- **可观测性** `meta.metrics`：每次工具调用的耗时与成败以结构化 JSON 记录并聚合。
- **崩溃恢复** `session.recover`：重开死掉的后端；会话已进入终态时改为重建。
- **批量分析** `batch.analyze`：多样本并行，单个样本失败不影响整批。
- **OpenAI 桥接** `openai_bridge.py`：把工具导出为 function-calling 格式，
  同时兼容 Claude 与 OpenAI 生态。
- **隐藏桌面**：在独立的 Win32 桌面上启动被调试程序，其窗口不出现在交互桌面上；
  WebUI 可截图观察，并对 GPU 窗口的黑屏截图做降级检测。
- **隔离部署检查**：`doctor` 新增提权与虚拟机/隔离环境探测，并按必需与可选分组输出。

### 修复

- **一次 RPC 超时会永久废掉会话**。transport 在任何读写故障后被关闭清空，而它只在启动时
  赋值过，因此之后每次调用都返回 `rpc_unavailable`，即便 worker 仍在运行、仍持有被调试进程。
  `session.recover` 也救不了：它看到后端仍注册，报 `kept` 然后什么都不做。现在连接会被重建，
  失败的那次调用不会被重放（避免状态变更类操作执行两次）。
- **WinDbg 后端会返回无法启动的路径**。`_discover_cdb` 可能返回 Microsoft Store 的
  `cdb.exe`，该路径 `is_file()` 为真却无法通过 `CreateProcess` 启动，导致 `WinError 5`。
  现在这类路径被一致地排除，并给出可操作的错误。
- **CI 每天产生一次被取消的运行**。真机 gate 工作流按日调度却需要一个不存在的自托管
  runner，每次排队到 24 小时上限被 GitHub 取消，看起来像有夜间覆盖，实际什么都没跑。
- 修复 `XdbgClient` 在部分构造下访问 `_desktop` 抛 `AttributeError`。

### 变更

- CI 新增前端作业（typecheck、单测、构建）以及**产物过时门禁**：Vite 用哈希文件名编码内容，
  资源增删即说明提交的产物与源码不一致。
- 发布流水线：打 `v*` 标签会构建 MSI、做一次装-跑-卸往返验证，然后连同 SHA256 一起发布。
- MSI 卸载不再残留。Python 运行时写在安装目录旁的 `__pycache__` 不被安装器追踪，
  实测一次往返会留下 122 个文件；现在通过 `util:RemoveFolderEx` 清空。
- 打包时校验 `pyproject.toml` 与 `Product.wxs` 的版本一致，避免安装器声明过期版本
  而使 `MajorUpgrade` 失效。
- 启用 ruff E303：填充空行曾把一个 gate 文件撑到 2052 行、其中 85% 是空行而无人察觉。

### 验证

- 507 个单元测试；61 个集成 gate 对真实 IDA + x64dbg 通过（跳过的均为未配置的可选后端）。
- 197 个工具在敌意输入下 100% 返回结构化错误信封，零抛出。
- MSI 装-跑-卸往返零残留。

## [0.1.0] - 2026-07-28

首个公开快照：IDA 与 x64dbg 双后端、MCP 工具面、WebUI 工作台、会话与产物持久化。

[Unreleased]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.2.1
[0.2.0]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0
