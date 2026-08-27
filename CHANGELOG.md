# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

## [Unreleased]

本轮在既有 PE 逆向能力之外新增 Android 与 Web 两个目标域，并把监控台重做成对话居中的
Agent 工作台。工具面从 199 增至 **276（159 只读 / 117 写）**；读写分级在
`tools/catalog.py` 里逐个显式声明（如 `memory.protection`、`workflow.breakpoint.put` /
`disable` 计入写，`static.search.text`、`patches.list` 计入读）。以下按类别列出。

新增 Linux x86_64 核心支持：wheel/sdist 与 `scripts/install-linux.sh` 可安装，`doctor --strict` 以平台动态必需项判断就绪，`serve` / `serve-web`、会话、制品和可移植后端可在 Linux 加载。doctor 与 `/readyz` 现在报告 `full`（Windows）或 `core`（Linux）支持级别。

x64dbg、WinDbg/cdb、Win32 UI/UIA/SendInput/Windows OCR、hidden desktop、MSI/WiX 及现有 Windows 专用 unpacker 适配在 Linux 明确报告 `unsupported_on_platform`，不再伪装 ready，也不阻塞 Linux 核心就绪。Windows 的原有 required 探针与 MSI/PowerShell 路径保留；IDA 探测同时识别 Windows `idalib.dll` 与 Linux `libidalib.so`。

CI 增加 Ubuntu/Python 3.11、3.12 的 lint、mypy、unit、doctor、核心服务与 wheel/sdist 构建；真实 Windows 后端 gate 继续留在 Windows job，Linux 收集时给 Windows-only 集成测试明确 skip 原因。

托管 quality job 只装 `.[test,dev,web]`：没有 PySide6 / winsdk 时 mypy 仍能过；导入 `native_app.bootstrap` 不再顺带加载 Qt GUI；没有编好的 PE 夹具时单元测试也能收集完。监控台 `webui/src/agent/state.ts` 的改动已重新打进提交的 SPA。UPX/XVLKC/Scylla/VMPDump/de4dot 在会话不是 PE 时先报 `target_mismatch`，不再因为本机没装 CLI 就说成 `capability_unavailable`。

CLI 工具超时不再可能卡死或漏杀孤儿进程。`run_bounded` 过去在 `with subprocess.Popen(...)` 里跑工具，其 `__exit__` 会在调用线程上关闭 stdout/stderr——当被启动进程派生的孙进程继承了这对管道并存活时，读取线程仍阻塞在 `read()` 上持有缓冲区锁，`close()` 便永久阻塞，有界超时变成永久挂起。现不再用上下文管理器：每个读取线程自持其流并在 `read()` 返回后关闭，主线程只回收进程、绝不碰管道。POSIX 下还让工具独立成会话，超时/取消时按进程组整体发信号（限组长，避免误杀服务自身的进程组），从而杀掉 ppid 遍历看不到、已被 init 收养的孙进程（如残留的 JVM/helper）。

die/exeinfope/upx/de4dot 各自的 `_capture_process` 采用同一范式收敛：读取线程自持自闭管道、捕获线程只在读取线程已结束时才关句柄，POSIX 下工具独立成会话。de4dot（及复用它的 NETReactorSlayer）正常退出后遗留的 runner 子进程（JVM/dotnet，常被 init 收养）以前 ppid 遍历看不到而泄漏；新增 `collect_process_group` / `terminate_process_group` 按会话组枚举并逐个按各自 `pgrp` 击杀，避免组长 pid 复用误伤无关进程组。

调用方取消（`BoundedCancelled`）在各适配器间统一为“取消不是失败”：NETReactorSlayer 适配器过去把取消重映射成 `process_failed`，与 scylla/vmp_dumper/xvlkc 等兄弟适配器不一致，现改为原样上抛；`unpack.auto` 的 UPX 阶段（`unpack_upx_test` / `unpack_upx_unpack`）过去把取消经通用 `except BaseException` 吞成 `internal_error` 事故与假的 `upx_test_failed`，现先行捕获并重抛给 `unpack.auto` 的取消处理器，最终干净地记为 `unpack_cancelled`。此外 `unpack.xvlkc/vmp/scylla` 各 CLI dump 在进入取消作用域前会像 `unpack.auto` 一样先 `_reset_unpack_cancel`，避免上一次 `unpack.cancel` 遗留的取消闩让后续同会话 dump 一进来就自我取消。

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

### 修复（托管质量门）

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

- **抓包停不掉，端口永不释放**。`proxy.stop()` 会立刻返回且线程确实退出，但事件循环是在
  mitmproxy 的 accept 任务仍挂起时被直接关闭的，监听 socket 因此从未关闭：端口一直被占，
  下一次抓包再也起不来。现在先取消并等待所有挂起任务、再 `shutdown_asyncgens`，最后才关闭
  循环。但仅取消 task 在 mitmproxy 12 上还不够：`proxyserver` addon 在 `done()` 里并不停
  自己的 server（CLI 靠进程退出释放端口），它持有的 `ServerInstance` 监听 socket 也不挂在
  任何可取消的 task 上，于是 `stop()` 报成功而端口仍被占、下一次抓包永远绑不上。收尾现在先
  逐个 `await ServerInstance.stop()` 显式关掉监听 socket，再走上面的任务取消与循环关闭。
  `tests/integration/test_proxy_lifecycle_gate.py` 会真实起停并断言端口确实被释放；
  `tests/unit/test_proxy_server_teardown.py` 不依赖装上 mitmproxy 也能钉住这条收尾。
- **并发起两个抓包会伪报「mitmproxy failed to start」**。mitmproxy 把 addon 上下文存在进程级模块
  全局里(`Master.__init__` 做 `mitmproxy.ctx.options = self.options`),所以后一个 master 一构造就
  把这个全局改指向自己那份尚未 `load()` 完的 options,而前一个 master 启动阶段的 `running` 钩子
  正好读 `ctx.options.rfile`——`ReadFile.load()` 还没注册 `rfile`,抛 `AttributeError`。它被
  mitmproxy 的 `safecall` 吞掉却仍被**记进日志**,再被 `errorcheck` addon 升级成致命退出,于是另一路
  毫不相干的 `proxy.start` 就以「mitmproxy failed to start: 1」失败。而 `proxyserver` 是在
  `running` 之前的 `setup_servers` 里绑好端口的,所以「端口可连」早于 `running` 发生、不足以判定启动
  完成。现新增进程级 `_STARTUP_LOCK`,把「构造→listening→`running` 跑完」这段对 ctx 敏感的启动窗口
  串行化:额外挂一个排在最后的 `_ready` addon,其 `running` 钩子置事件,`start()` 等到该事件置位且端口
  可连才释放锁。抓包起来之后彼此不再共享 ctx,故多路抓包仍可并发运行。4 路 barrier 压测下,修复前
  ~9/24 起动会中招,修复后 0/24;`tests/integration/test_proxy_lifecycle_gate.py` 新增并发起动 gate 钉住。
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
- **jadx 导出源码列表和 webcrack unpack 文件列表同样切到 2000 条却不说**。旁边虽有
  `java_file_count` / `file_count` 是全量，只看列表的调用方仍会当成完整目录。补上
  `has_more`。
- **`web.console` 默认只回最后 200 行，不说前面还有**。缓冲区本身有界，这一页再切一刀
  之后看起来就像「页面只打了这些日志」。回 `has_more`。证书列表同样封顶并披露。
- **Ghidra 导出的函数/符号/xref 列表停在 limit 上不说话**，反编译 C 超过 200k 字符也只
  切一刀。脚本补上 `has_more` / `truncated`。
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
- **`device.list` 对每个设备再调一次 `get_state`**。adbutils 的 `open_transport` 默认等
  600 秒，假死的 adb server 会把工作线程占满十分钟；而且 `device_list()` 只回在线设备，
  offline 看起来像「没有这台设备」。改为一次 `host:devices`（带 socket 超时），offline 也
  列出来，并给 `open_transport` 换上 120 秒的挂起上限。
- **`device.packages` 仍会为了排序把完整包列表装进内存**。采集停在 limit 上。jadx / webcrack
  的文件列表同样不再为了 `file_count` 物化全部路径。
- **`device.pull` 会把整棵目录拷到宿主机**。adbutils 在远端是目录时递归拉取，没有体积上限；
  一次 `/sdcard` 就能把磁盘写满，而产物表看不见这些文件。目录和超过捕获上限的文件在拷贝前
  拒绝。`device.push` 同样拒绝超过上限的本地文件。
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
- **Agent 浏览器工作台 gate 修复为可移植且与 SPA 同步**:该端到端 gate 写死了 Windows Chrome
  的绝对路径(`C:\Program Files\Google\Chrome\Application\chrome.exe`)且驱动的是早已被本地化成
  中文的旧英文 SPA——在非 Windows 上启动即崩、在 Windows 上也会因找不到英文控件而失败(CI 从不
  跑集成 gate,所以一直没人发现它其实各平台皆红)。现在:Windows 路径存在时才用真 Chrome、否则回落
  到 Playwright 自带 Chromium,两者都起不来则如实 skip(skip≠pass),与其余 web gate 一致;全部定位
  子改到现网 SPA(开屏/工作台标题、消息框与发送、模型设置弹窗字段与保存、批准卡片按钮、检查器下按
  tab 隐藏的事件表);保存不再自动关弹窗,故显式关闭;并把自治强制为 fail-closed 的「请求批准」——
  否则 `Settings.load()` 填入的加壳分析预设会自动批准 `workflow.cancel`(state_change),根本不会
  出现批准卡片。刷新后再批准这一段改为钉住 `/approve` 回包与恢复的 SSE 游标(reload 会丢掉内存里的
  对话记录直到重新选中会话,完成气泡只作为流式文本一闪而过,钉它会 flaky)。这条 gate 现在在 Linux
  上真实起浏览器跑通,而不再只是崩溃或跳过。
- **`apk.open` 对「能打开但清单解析不了」的 APK 不再谎报 `internal_error`**。androguard 打开一个
  ZIP 合法、但 `AndroidManifest.xml` 不是有效 AXML（混淆/截断/故意损坏,野外常见）的 APK 时,多数
  取值器会吞掉解析失败返回 `None`/`[]`,唯独 `get_androidversion_name`/`get_androidversion_code`
  抛 `KeyError('Name')`/`KeyError('Code')`。`open()` 里这两个调用没有包裹,裸 `KeyError` 逃出
  后端,被服务层兜底的 `except BaseException` 记成 `internal_error` 事故——把一次「输入畸形」
  误报成「我们的代码崩了」,还顺手抹掉了本可解析出的字段（包名、native ABI、权限数）。现在这两个
  取值器像 androguard 对其兄弟取值器一样容错降级为 `None`,并加一层结构化兜底,任何其他 androguard
  异常也回结构化 `backend_error` 而非 `internal_error`（`apk.manifest` 早已如此,`open` 是唯一漏网的）。
  `tests/unit/test_apk_open_fields.py` 不装 androguard 也能钉住这条降级；
  `tests/integration/test_android_re_gate.py` 在装了 androguard 时真实断言 `apk.open` 对合成 APK
  返回 ok、native ABI 正确、`version_name` 为 None（修复前是 ok=False / `internal_error`）。
- **`apk.classes/methods/strings/xrefs` 首次拿到真实 DEX 的端到端覆盖**。这四个 DEX 分析工具此前
  只有用假对象打桩的单元测试,集成 gate 里的合成 APK 又只带占位 `classes.dex`——androguard 的
  完整分析在那儿只走到干净失败分支,从没真正解析过一个 DEX。运行机上没有 Android SDK(无 d8/dx),
  故 gate 现在按 DEX 格式手工汇编出一个最小但合法的 `classes.dex`（一个 `LCrackme;` 类、一个
  `public static secret()V` 方法、方法体 `const-string v0, "s3cr3t"; return-void`,含正确的
  adler32/SHA1、map_list 与 4 字节对齐）,装了 androguard 时真实断言:类名、方法的
  descriptor(`()V`)与 access、smali 与点分两种类名都能解析、字符串字面量 `s3cr3t` 在结果里、
  无人调用的方法回结构化空 `callers`（而非 not_found）、不存在的类回 `not_found`。这正是假对象钉不住、
  一旦 androguard 改了 `get_classes`/`get_methods`/`get_strings`/`get_xref_from` 就会露馅的那部分。
- **`apk.export_sources` / `apk.decompile` 首次有真实 jadx 的端到端覆盖**。jadx 是用户自备的 CLI
  (需 JRE),故这条 gate 像 webcrack/wabt 一样未配置即 skip(skip≠pass);配了就用真 jadx 反编上面那个
  手工 DEX,断言:源码树列出该类、按简单类名取回的 Java 里出现方法名、jadx 从未产出的类回 `not_found`
  而非崩溃或空源码。  jadx 会把无包名的类丢进 `defpackage/`,所以点分路径 `Crackme.java` 在源码根不存在、
  正好命中客户端「同名唯一匹配」的回退分支——这条路径此前也没有集成覆盖。
- **Frida live gate 改为可移植,不再在 Linux/macOS 上一律 skip**。它此前写死要 `gui_fixture.exe`
  这个 PE 夹具、并断言模块里有 `kernel32.dll`/`ntdll.dll`,还被 conftest 的 `_WINDOWS_ONLY_MODULES`
  强制在非 Windows 上跳过——于是 frida 这条可移植后端在 Linux 上从没被真正验证过。现在 POSIX 上直接
  attach 一个睡眠中的 Python 解释器(任何进程都会载入 C 运行时),断言同一套契约:未授权 pid 回
  `permission_denied`、attach 成功、模块枚举里能找到 `libc.so`/`ld` 这类系统库、该库导出非空、`noop`
  模板能加载;并从 `_WINDOWS_ONLY_MODULES` 移除该文件。frida 缺失或 OS 禁止本地 attach
  (Linux 的 ptrace_scope、macOS 未签名解释器)时诚实 skip(skip≠pass),Windows 路径与断言不变。
- **r2 live gate 改为可移植,在 Linux 上真跑 radare2**。它此前只认 `headless_fixture.exe` 这个 PE
  夹具、非 Windows 上因夹具缺失而 skip,于是 radare2 这条被点名的可移植后端从没在 Linux 上验证过地址
  映射。现在 POSIX 上用本机 C 工具链(`cc`/`gcc`/`clang`)现编一个带几个真实函数的小 ELF,跑
  `open` + `aa`/`aflj`,断言解析出函数且每项都带统一 `Address`。映射对 PIE ELF 诚实降级:没有 PE
  ImageBase 就没有 module 相对的 RVA,地址保留绝对 VA——正是断言所验证的;PE 仍走 RVA/module 分支。
  r2 缺失或没有 C 编译器时 skip(skip≠pass)。该 gate 本就未被 conftest 的 `_WINDOWS_ONLY_MODULES`
  拦截,只是缺夹具而空跑,现补上 Linux 侧的真实覆盖。
- **`r2.xrefs` 在现代 radare2 上根本取不到交叉引用**。它跑的是 `axj @ addr`,而现代 r2 的 `axj` 是
  写命令(「add jmp reference」)、不是列举——`ax?` 明确写着 `axj = add jmp reference`,列举用的是
  `axlj`(全量)或按地址的 `axtj`/`axfj`。于是 `axj @ addr` 什么也不吐,`parse_r2_json` 拿到空串、
  `enrich` 报 `parsed: False`、`items` 为空,无论目标地址有没有引用都一样——这个工具对任何近代 r2
  都是废的。现改为按地址分别取「引用到」(`axtj`)与「引用自」(`axfj`)两个方向、合并成统一的
  `{from,to,type}`(`axtj` 只给源,目标即所查地址,故补上 `to`),再走原有 `enrich` 映射出
  `from_address`/`to_address`。命令白名单相应从 `axj @ addr` 收敛为 `ax[tf]j @ addr`;裸 `axj` 不再
  接受(实测已验证 `main→helper` 的 CALL 边能被正确解析)。`run()` 拆出 `_exec()` 以便一次 xrefs 里
  跑两趟分析而各自独立解析(空的一侧保持空列表,不被另一侧输出吞掉)。
  `tests/integration/test_m11_r2_live_gate.py` 新增对真实 CALL 边的断言钉住。
  (补记:上面「裸 `axj` 不再接受」当初只落到了注释和本条描述里——`axj` 其实仍误留在允许集 `_ALLOWED`
  中,与该策略相悖;虽然没有任何工具会构造裸 `axj`、无实际暴露,但为让白名单名副其实,现已把它从允许集移除,
  并在 `test_r2_command_whitelist.py` 补一条断言钉住裸 `axj` 被拒,防其回潜。)
- **Ghidra 在 Linux/macOS 上选错启动器,装对了也一个工具都跑不起来**。Ghidra 发行版里
  `support/analyzeHeadless`(Unix 脚本)与 `support/analyzeHeadless.bat`(Windows 批处理)并排都在,
  而 `_find_analyze_headless` 把 `.bat` 排在最前——POSIX 上永远选中不可执行的批处理,spawn 即
  `PermissionError`,`ghidra.analyze`/`functions`/`decompile`/`symbols`/`xrefs` 全军覆没。现按本 OS
  排序(Windows 先 `.bat`,其余先 Unix 脚本),只有单个启动器时仍回退到另一个(假 home 的单测夹具
  不受影响)。新增单测钉住两个 OS 的选择;新增可移植 live gate
  `tests/integration/test_m11_ghidra_live_gate.py`:POSIX 现编小 ELF、经
  `HEADLESS_RE_GHIDRA_HOME` 跑真实 headless 导入+分析,断言选中 Unix 启动器、输出含成功报告、
  `-deleteProject` 未留下 `.gpr`/`.rep`;未配置 Ghidra/缺编译器时 skip(skip≠pass)。已在 Linux 对
  真实 Ghidra 12.1.3 验证通过。
- **`ghidra.functions`/`symbols`/`xrefs`/`decompile` 在现代 Ghidra 上全部空手而归**。导出 postScript
  `ExportJson.py` 标着 `@runtime Jython`,而 Ghidra 11.3 起移除了自带 Jython 改用 PyGhidra——在 11.3+
  (含当前发行的 12.x)上,分析本身成功,但脚本阶段直接报「Ghidra was not started with PyGhidra.
  Python is not available」,于是四个导出工具对任何近代 Ghidra 都取不到结果。现把 postScript 重写为
  原生 `ExportJson.java`(Ghidra 的一等脚本语言,headless 下自动编译、无需任何额外运行时,且各版本通用),
  保持原有 `mode/out_path/limit/address` 入参与 `{mode,items,count,has_more}`(decompile 另加
  `function/entry/decompiled/truncated`)输出契约不变;JSON 手写转义,不依赖 Ghidra classpath 上是否有
  JSON 库。客户端 `_EXPORT_SCRIPT` 相应改为 `ExportJson.java`,旧 Jython 脚本删除,pyproject 对应的
  ruff/mypy 例外一并移除。`test_m11_ghidra_live_gate.py` 新增 export gate:对现编 ELF 跑
  functions/symbols/xrefs/decompile,断言取到带 entry/body_size 的具名函数、带 type 的符号、
  `main→helper` 的真实 CALL 边、以及点名被调者 `secret` 的反编译 C。已在 Linux 对真实 Ghidra 12.1.3
  验证四个工具全部返回。
- **本地 Frida 读取(`modules`/`exports`/`memory.read`)把后端故障报成 internal_error 事故**。这三条
  本地读取 attach 之后加载枚举脚本、跑 RPC,却没有任何错误映射:目标进程中途死掉、页不可读、
  `script.load()` 被拒时抛出的原始 frida 异常一路穿到服务信封,被记成 `internal_error` 加一条事故日志
  ——正是 r2/apk 适配器早已修掉的反模式,也与 Frida 自己的设备侧读取(`java_enumerate`/
  `hook_template_device` 映射成 `backend_error`)不一致。现三条本地读取统一走
  `_read_with_script` 辅助:attach 之后的 frida 故障映射为 `backend_error`(看着像超时的映射为
  `timeout`),且始终 detach 探针;attach 本身的失败仍由 `_attach_local` 提前抛出结构化 FridaError。
  另外 `memory.read` 现按 r2 `disasm`/`xrefs` 的约定先行校验地址为非负整数——工具面把 address 标成 int
  却没设下界,负地址此前会一路到 agent 里的 `ptr(address)` 再回成 internal_error 事故,而非干净的
  `invalid_params`。新增单测钉住:后端故障映射为 `backend_error` 且探针已 detach、负地址回 `invalid_params`。
- **r2 的 `strings`/`imports`/`exports`/`disasm` 补上真实 live 覆盖**。单测都 mock r2 的 JSON,结构上
  抓不到「某命令在新版 r2 上不再吐列举」这类漂移——正是 `axj` 回归藏身之处:live 工具在现代 r2 上什么
  都不返回,而所有 mock 单测照过。r2 live gate 现对现编 ELF 真跑 `izj`/`iij`/`iEj`/`aflj`/`pdj`,断言各自
  解析出应有内容(格式串、`printf` 导入、至少一个导出、映射出地址的反汇编)。夹具的格式串加长到超过
  r2 字符串扫描的 4 字节下限,`izj` 才会报它。已在 radare2 6.2.0 验证通过。
- **`frida.memory.read` 在近代 frida 上根本读不了**。枚举脚本的 `read` RPC 调的是
  `Memory.readByteArray(ptr(address), size)`——这个全局读快捷方式在近代 frida 已被移除(frida 17.x 上
  直接抛 `TypeError: not a function`),于是 `memory.read` 对任何当前 frida 都是废的,而 `modules`/
  `exports` 仍好使,问题一直没被发现。改用 NativePointer 方法 `ptr(address).readByteArray(size)`(存在了
  很多个大版本,新旧通吃);页不可读时 `readByteArray` 返回 null,`Uint8Array(null)` 会抛,故 null 读
  报成空字节而非异常。这个 bug 是把可移植 Frida live gate 扩到覆盖 `memory.read`(它此前唯一没覆盖的本地
  读取)时抓到的:gate 现对某系统库的 module base 读 4 字节,断言真实字节就是该平台可执行文件魔数(POSIX
  的 ELF `7f454c46`、Windows PE 的 MZ `4d5a`),错地址或坏读取都伪造不出来。已在 frida 17.17.0 attach 一个
  睡眠解释器验证通过。上一条的 `_read_with_script` 映射也在此得到印证:这个「移除的 API」故障是以干净的
  `backend_error` 冒出来的,而非 internal_error 事故。另加一条静态单测钉住枚举脚本用 NativePointer 读法、
  不含被移除的 `Memory.readByteArray` 全局,让没装 frida 的 CI 也能挡住回归。
- **`frida.java.classes`/`frida.java.methods` 在近代 frida 上取回空列表**。这两个 Java 枚举 RPC 在
  `Java.perform`/`enumerateLoadedClasses` 之后同步 `return out`。frida 17 起捆绑的 frida-java-bridge 7.x
  把 `enumerateLoadedClasses` 改成异步回调,于是同步返回在任何当前 frida 上都拿回空(或残缺)列表,而
  frida 16 仍好使——与 `memory.read` 同属版本漂移。现两个 RPC 都改为返回 Promise:`classes` 从
  `onComplete` resolve(命中上限时经 `finish()` 提前 resolve,取代现代 bridge 不再支持的抛「哨兵字符串」
  提前跳出),`methods` 在走完 `getDeclaredMethods()` 后 resolve。这在 frida 16(Promise 在 executor 返回
  前就 resolve)与 17(稍后 resolve)上读起来都对,`exports_sync` 两者都会 await,Python 侧不变。已在
  frida 17.17.0 实测 `exports_sync` 确会 await 一个返回 Promise 的 RPC(延时 `setTimeout` resolve 的值原样
  取回);ART 上 `enumerateLoadedClasses` 的异步时序本身需要真实 Android 设备,故此处未跑(skip≠pass),
  修法依据 frida 17 迁移说明与一份吻合的上游报告(frida-mcp)。另加静态单测钉住 Promise/onComplete 形态与
  哨兵抛出的移除,让没有设备的 CI 也能挡住回归。
- **proxy live gate 补上真实抓包覆盖**。原 lifecycle gate 只证明「start 即在监听、stop 即释放端口」,却从没
  真的把请求穿过代理,于是抓包主链路——mitmproxy 在每个响应上回调 recorder addon、`flows`/`flow_get`/
  `export_har` 再把它读回来——在装着的 mitmproxy 版本上从未验证过,而这正是版本漂移的藏身处(客户端注释
  自己也点明 addon/flow API 各版本有别)。新增抓包 gate:起一个一次性的本地 HTTP 源站,经代理 GET 它(纯
  HTTP,不需要 TLS/CA 信任),断言这条 flow 以正确的 method/url/status/host 被记录、`flow_get` 取回真实的
  请求/响应体、`export_har` 至少产出一条。已在 mitmproxy 12.2.3 实测通过。
- **Web CDP gate 只证明浏览器起得来、DOM 读得到,却没验证抓包与 console 采集这两条最会漂的 CDP 主链路**。
  原 gate 用一个 `data:` URL 开浏览器,断言 `web.scripts` 回了个 list、`web.console` 调用 ok、DOM 快照标题含
  `gate`——但 `web.console` 在**空缓冲**上一样 ok,而 `data:` URL 不发任何网络请求,于是 `_wire_events` 里那几个
  `cdp.on(...)`(`Runtime.consoleAPICalled` 采 console、`Network.requestWillBeSent`/`responseReceived` 采请求)以及
  `network_get` 走的 `Network.getResponseBody` 在真实 Chromium 上从没被断言过采到过东西,而这正是 Playwright/CDP
  版本漂移最容易断的地方。现把 gate 补实:①原 `data:` 夹具本就 `console.log('gate-ready')`,改为轮询 `web.console`
  直到真出现该行(空缓冲会失败,不再放行);②新增一条抓包 gate,起一次性本地 HTTP 源站发一个拉子资源(带
  `NETWORK_GATE_MARKER`)的页面,断言 `network_list` 采到该子资源、状态被 `responseReceived` 填成 200、MIME 是
  javascript,再用 `network_get` 经 `Network.getResponseBody` 把响应体读回、body 里含该 marker——空缓冲或坏掉的
  getResponseBody 都伪造不出。已在 Playwright 1.62 + Chromium(headless)实测通过,缺 Playwright/浏览器时干净
  skip(skip≠pass)。
- **jsre 的 WASM 路径(wabt)补上真实 live 覆盖**。`wasm.wat`/`wasm.info` 的单测都 mock 掉
  `wasm2wat`/`wasm-objdump` 的输出,结构上抓不到「装着的 wabt 吐出客户端处理不了的东西」这类
  漂移——而 wabt 是本工程里唯一在 Linux 上能真跑、却从没被 live gate 碰过的具名后端。新增 WASM
  gate:把一个极小模块(导出 `add` 函数外加一段 memory)的 wasm 字节内嵌进测试(只依赖
  `wasm2wat`/`wasm-objdump`,不需要 `wat2wasm`),对它真跑两条工具,断言 `wasm2wat` 的 WAT
  回环里带着 `(module`、`export "add"`、`i32.add`,`wasm-objdump -h -x` 列出 Type/Export/Code
  段与 `add` 符号(证明是段遍历解析成功,而非只读了文件头)。gate 像服务一样从 settings/PATH
  解析 wabt,缺失时干净 skip(skip≠pass)。已在 wabt 1.0.41 实测通过,并确认未配置 wabt 时按预期
  skip。
- **`js.unpack_bundle` 在近代 webcrack 上根本写不出东西**。客户端先 `out_dir.mkdir(exist_ok=True)`
  建好输出目录,再不带 `--force` 地跑 `webcrack <file> -o <out_dir>`;而 webcrack 的 `-o` 处理是
  `if (force || !existsSync(output)) rm(output); else error("output directory already exists")`
  ——目录已存在且没给 `--force` 时直接报错退出、什么都不写。由于客户端总是先建目录(服务层每次还发一个
  全新的唯一路径),于是每次解包都非零退出、产物为空,`js.unpack_bundle` 在任何带这道「已存在即拒写」
  防护的 webcrack 上都是死的。单测都 mock 掉 `_run`,从不跑真实的「already exists」判断,漂移一直没被
  发现——与 r2 `axj`、Ghidra Jython、Frida 被删 API 同属版本漂移。现补上 `--force`,让 webcrack 清掉
  并重写它自己拥有的这个目录;该 flag 与那道防护同在一个处理器里,凡会触发防护的 webcrack 必然也认
  `--force`。已在 webcrack 2.16.0(Node 22)先复现故障、再验证修复。web RE gate 也顺势补强:原
  `js.deobfuscate` gate 只断言「回了若干字节」,echo 或半路 bail 的 webcrack 照样能过;现夹具把密文藏成
  转义串 `\x48\x33...`(解码后是 `H3adl3ss`,源码里从不以明文出现),断言输出里出现 `H3adl3ss`——echo
  或坏 pass 伪造不出来;并新增 `js.unpack_bundle` 的端到端 gate,断言 webcrack 确实写出了
  `deobfuscated.js`(正是 `--force` 修复的 live 守卫)。另加静态单测钉住解包命令必带 `--force`,让没装
  webcrack 的 CI 也能挡住回归。
- **jadx 反编译路径补上真实 live 覆盖**。`apk.export_sources`/`apk.decompile` 此前无 live 覆盖——Android
  RE gate 只造一个合成 APK、断言结构化降级,于是「jadx 改了输出布局」这类漂移抓不到:客户端从
  `<out>/sources/...` 读反编译出的 Java,并把类名映射成 `sources/<包>/<类>.java`,两处都是只有真跑才验证得了
  的布局约定。jadx 除 Dalvik 外也吃 JVM 字节码,故新增 gate 用 javac 编一个极小的 `com.example.Sample`、打成
  jar 后交给 jadx:`export_sources` 必须列出 `sources/com/example/Sample.java`,`decompile("com.example.Sample")`
  必须回出该类源码(含一个原样保留的标记串,选错文件或空读都伪造不出来,顺带钉住类名→路径映射)。gate 像
  服务一样从 settings/PATH 解析 jadx,缺 jadx 或缺 JDK 时干净 skip(skip≠pass)。已在 jadx 1.5.6 + JDK 21 实测
  通过,`sources/` 布局成立,故客户端无需改动。
- **androguard 的 `apk.*` 面与 apktool decode 补上真实 live 覆盖**。`apk.open`/`classes`/`methods`/`strings`/
  `xrefs` 的单测要么 mock 掉 androguard(monkeypatch `_parsed`)、要么只断言结构化降级,于是「androguard 4.x
  API 漂了」这类问题抓不到——3→4 大改重塑了 `get_classes`/`is_external`/`get_xref_from`/`get_strings`,一旦
  漂移,真实工具什么有用的都不吐,而整套单测照过;apktool decode 同理无 live 覆盖。新增一个极小的committed
  APK 夹具(`fixtures/android/sample.apk`:单个 `com.example.gate.Sample`,其 `caller` 调 `callee`、后者
  返回标记串 `APK_GATE_MARKER_STRING`;清单声明 `INTERNET` 权限,随包带一个 `lib/arm64-v8a/libgate.so`
  原生库,整包再用自签 `CN=HeadlessRE Gate` 做 v1(JAR)签名,好让 manifest 侧的读法有真东西可查),对它真跑
  两个后端:androguard 必须列出该类、其方法、标记串,解出 caller→callee 的 xref,从二进制 AXML 读出包名与
  `com.example.gate.MainActivity` 组件、读出声明的权限、枚举出原生 ABI、把签名证书读回成可读 DN
  (manifest/components/permissions/native_libs/certificates 走的是与 DEX 分析不同的另一套 4.x API);apktool 必须把它
  decode 回一棵含该类的 manifest+smali 树。两个能力各自独立 skip(skip≠pass)。夹具的 smali 由 apktool 3.0.3
  汇成 `classes.dex`、manifest 由 aapt2 链接 android framework 编成二进制 AXML(apktool 自带的 aapt2 步在本环境
  不传 framework `-I`、解不出 `android:` 属性,故 manifest 单独编好后连同一个极小 `resources.arsc` 与占位
  `.so`(合成、不可加载,只会被按名列出)一起打进 APK zip、最后经 jarsigner 用 keytool 生成的一次性 RSA key 签名
  ——committed 的 `.apk` 即产物,keystore 不留),可读的 smali/manifest 源一并committed 在旁。已在
  androguard 4.1.4 + apktool 3.0.3(JDK 21)实测通过,三面(DEX/清单/签名)都解得出。
- **androguard 的 loguru DEBUG 洪流灌爆无人值守服务的日志**。androguard 默认经 loguru 在 DEBUG 级输出——
  实测一个只含单类的 1KB APK,每次 `AnalyzeAPK` 就吐约 150 行(每个 basic block 一行),真实应用则成千上万。
  代码树里没有任何 androguard 日志配置,于是 `apk.classes`/`methods`/`strings`/`xrefs` 每调一次都把这堆
  DEBUG 灌到 stderr,把服务自己的日志埋掉。分析问题本就以结构化结果上报,故 `ApkClient` 现在构造时一次性用
  `loguru.disable("androguard")` 关掉 androguard 的日志记录——这是嵌入方该用的做法:只按包名过滤掉 androguard
  的记录,不动任何 handler、不碰宿主 app 自己的日志;而 `androguard.util.set_log` 会 `logger.remove(0)` 删掉
  loguru 默认 handler 再全局加一个 stderr handler(等于重配整个 logger,不只是 androguard)。实测一次
  `classes()` 的 androguard stderr 行数 155→0。新增单测钉住这次 disable 调用(只需 loguru、不需真 APK),live
  gate 也加断言:真跑一次 `AnalyzeAPK` 不产生任何 androguard 记录;gate 里旧的、会全局重配的 `set_log` 辅助已移除。
- **`apk.certificates` 把证书主体/签发者当对象 repr 吐出来,而不是可读的 DN**。androguard 4.x 回的是
  asn1crypto `x509` 证书,其 `subject`/`issuer` 是 `x509.Name` 对象,`str(name)` 是
  `<asn1crypto.x509.Name 0x.. b'0<1\x0b0\t..'>` 这种对象 repr;而客户端此前正是 `str(getattr(cert, "subject"))`,
  于是「这个 APK 是谁签的」——证书读取存在的唯一意义——回来的是一坨没法看的 repr。改用 `Name.human_friendly`
  渲染成可读 DN(`Common Name: .., Organization: ..`),对没有该属性的证书形态(更老的 androguard、或本就是字符串)
  回退到 `str`,并把「属性访问抛异常」当作没有、以免一个古怪证书把整个字段清空。顺带把 `sha256` 也 `str()` 兜住:
  整个证书 payload 会跨 MCP 边界做 JSON 序列化,而 asn1crypto 的兄弟属性 `sha256`(非 `sha256_fingerprint`)是原始
  bytes——某个证书对象在这里给出 bytes(或任何非标量)不会让采集循环失败、却会在下游序列化时崩,故每个证书字段
  (subject/issuer/serial/sha256)都在源头钉成字符串。新增静态单测(用替身对象钉住可读路径与两条回退、并断言含
  Name 主体与 bytes sha256 的 payload 能 `json.dumps`,不需 androguard、不需真 APK);详见下方 gate 条目的 live 覆盖。
- **`apk.export_sources`/`apk.decompile` 对 jadx 的部分失败守口如瓶,把不完整的树当成功回**。jadx 在
  无法反编译某些类时以非零码退出,但仍会写出能编出来的那些、并给编不出的类留一份带 `// jadx failed to decompile`
  注释的桩;客户端 `_run` 只在**一个 .java 都没落盘**时才硬失败,故意走「拿到什么给什么」的路子。问题是 `export_sources`
  拿到 `_run` 返回的退出码后**整条丢弃**——它自己的注释都写着 jadx「部分失败仍写可用源码」,却把这个码扔了,于是一次
  部分失败(树里缺类、或某个类体其实是 jadx 的失败桩)与一次干净跑回来的结果一模一样,agent 会把缺了类的树读成反编译
  已完成。现 `export_sources` 在 jadx 非零退出时补 `tool_failed`/`exit_code`/`stderr`(仍照常列出已写出的源码);`decompile`
  把这个标志一路带出来——请求的类文件在、可回,但它可能正是那份 `// jadx failed to decompile` 桩,故调用方不能因为
  「回了个文件」就当它是干净输出。新增单测用 mock 的 `_run` 钉住两条路径(部分退出补齐三字段、干净跑不带标志),jadx
  live gate 也加断言:干净跑一次 `export_sources`/`decompile` 都不得带 `tool_failed`(不需真 jadx、由单测覆盖部分失败路径)。
  同源问题也在 jsre/wabt 上修掉,见下条。
- **jsre(webcrack)与 wabt(wasm2wat/wasm-objdump)对自己的非零退出同样守口如瓶**。四个走「拿到什么给什么」的入口
  ——`js.deobfuscate`/`js.unpack_bundle`、`wasm.wat`/`wasm.info`——的 `_run` 守卫都只在「非零退出**且**什么都没回」时才
  硬失败;可一旦工具非零退出却仍打印了东西(webcrack 半路解包仍吐出已处理的部分;wasm2wat/wasm-objdump 可能写完前
  几段后在某段上 bail),这些入口就把它当干净结果原样返回,agent 会把截断的 WAT、短了的 objdump、半成品的 deob 读成
  完整产物。此前 jadx 那条也误称 jsre/wabt「已经」抬了这个标志——其实都没有。现补齐:新增 `_note_nonzero_exit`,四个入口
  在子进程非零退出时补 `tool_failed`/`exit_code`/`stderr`(输出照常返回),与 jadx 的语义对齐。WASM live gate 里原本就写着
  「干净模块不得带 `tool_failed`」的断言此前是空的(键根本不存在),现在这条断言真正生效;另加单测用 mock 的 `_run` 钉住
  四个入口的部分退出与干净路径(不需真 webcrack/wabt)。
- **`proxy.flow.get` 把二进制响应体解成乱码,还装作是正文**。它对不大于 200000 字节的 body 一律
  `body.decode("utf-8", errors="replace")`——对文本(JSON/HTML)没问题,但响应体同样常是二进制(图片、protobuf、
  mitmproxy 没解压的载荷),`errors="replace"` 会把这些字节替换成 `�` 后当作 `response.body` 回出:读起来像真正文、
  却没有任何标记说明它已被改写,agent 分不清「这是被 replace 毁掉的解码」还是「这就是原始内容」,且原始字节不可恢复。
  兄弟工具 `web.network.get` 早已用 `base64_encoded` 标记把 CDP 回的二进制体如实标出,`proxy.flow.get` 却没有。现改为
  先做**严格** utf-8 解码:成功即照旧回文本、`base64_encoded` 为 false;失败(即二进制)则把原始字节 base64 后放进
  `response.body`、`base64_encoded` 置 true,body 可解回精确字节、调用方也知道它不是文本(与 `web.network.get` 对齐)。
  阈值从「原始 200000 字节」改成「内联串 200000 字符」并卡在 256KiB 工具结果上限之内——base64 体积是原始的 4/3,若按
  原始字节判定,近 200KB 的二进制体 base64 后约 267KB 会顶破结果上限;超过内联上限者(文本或二进制皆然)照旧把**原始
  字节**落盘到 `response.body_path`(读回精确 body,不是截断或再编码的)。文本体行为完全不变(200001 全 `x` 仍走落盘,
  proxy live gate 里 `mitm-capture-ok` 仍原样回文本)。新增单测钉住二进制体 base64 可解回原字节、文本体 `base64_encoded`
  为 false(不需 mitmproxy);proxy live gate 的真实抓包读回照常通过(mitmproxy 12.2.3)。
- **jsre 与 jadx 的大输出会被传输层整条丢弃、换回一份 16KiB 摘要**。工具结果在过 MCP/agent 边界前会被 JSON 序列化,两条
  传输(`agent.context.bounded_tool_result`、`mcp.adapter.apply_result_budget`)一旦编码后的信封超过
  `ResourcePolicy.max_result_bytes`(262144),就把**整个**结果替换成一份约 16KiB 的摘要——每个有用字段一并丢掉,只剩
  `summary`。可 `js.deobfuscate`/`js.beautify`、`wasm.wat`/`wasm.info` 的 `_bounded_output` 与 `apk.decompile` 的取源都按
  **原始字节数** 截断到 `400_000`,而这个上限**高于**传输预算:一个 400KB 的 `code`/`source` 字段 JSON 编码后有 500+KB
  (实测 526378),必然顶破 262144、必然被换成摘要,于是 agent 拿到的不是干净截断的源码、而是一段 JSON 转义了一半的 16KiB
  片段。根因是「客户端按原始字节截、传输层按编码字节算」这对错配——JSON 转义(`\"`、`\\`、`\n`、控制字符→`\uXXXX`)会把编码
  体积撑大,故任何原始字节上限都保证不了编码后能过。兄弟 `web.network.get`/`_spill_text` 早已用 200000 的较低上限来「压在
  预算之下」,jsre/jadx 的 400000 是与之相悖的那个、且必然触网。新增共享助手
  `backends/common/json_budget.fit_json_text`:按**编码后**体积把文本裁到「预算−字段余量」以内(余量 64KiB 兜住其余字段——
  含最坏情况 8000 字符全 `\uXXXX` 的 stderr——与 JSON 结构),二分找出编码后能过的最长前缀、绝不切断多字节字符,并把裁前的
  真实字节数照常报在 `bytes`。`_bounded_output` 与 `apk.decompile` 改用它;jadx 取源也只读「编码预算+1」字节(编码体永不小于
  原始体,读更多也留不住),据此判 `truncated`。这样一份大输出回来的是干净截断的 ~192KB 有用文本(带 `truncated: true`),而不是
  16KiB 摘要;小输出原样不变。`RESULT_BUDGET_BYTES` 以常量镜像 `ResourcePolicy.max_result_bytes` 并由单测钉死防漂移;另加
  单测喂 1MiB 输出、断言过 `bounded_tool_result` 后仍带 `code`、不带 `summary`(修前 400KB 必被摘要),原「按原始字节截」的
  单测改成按编码体积断言。已在 wabt 1.0.36 上跑通 WASM live gate(干净小输出照旧原样回)。
- **`web.network.get`/`web.script.source`/`web.dom.snapshot` 的内联字段也栽在同一处、且更值得担心——这些正文是页面(可能是恶意页)
  自己控制的**。上一条曾说 web 的 `_spill_text` 用 200000 的较低上限「压在预算之下」——其实没有:200000 **原始字节** 的正文一样能
  编码到 262144 以上(实测 200000 字符+适量转义即 263220),更别提它旁边还挂着一个可达 16KiB 的 `url`;一旦触网,连指向落盘副本的
  `body_path`/`source_path` 都随整条结果一起被摘要吞掉,agent 既拿不到正文、也找不到那份文件。`dom.snapshot` 更糟:`html` 只按
  字符截到 200000、根本不落盘,超预算就是整条没了。现三处都过 `fit_json_text` 按编码体积再兜一层(web 侧余量取 32KiB,够容下
  16KiB 的 url 加其余标量,不像 jsre 那样需要为 stderr 留 64KiB)。`_spill_text` 的语义收紧为「只要内联被裁——无论是原始上限还是
  编码上限——就必落盘」,于是 `truncated` 永远伴随一个 `*_path` 指向完整正文;干净的小正文照旧整条内联、不落盘(200000 全 `x` 编码
  仅 200002<预算,行为不变)。新增单测:①编码上限单独触发时也落盘并裁内联;②一条带 16KiB url 的大 `network_get` 结果过
  `bounded_tool_result` 后仍带 `body_path`、不被摘要;③`dom.snapshot` 的 `html` 按编码体积裁并置 `truncated`。既有 spill/字段单测
  全绿(原始上限作为第一道界不变)。

- **`apk.export_sources` 与 `js.unpack_bundle` 的文件清单也栽在同一处——单个路径短、整条数组却能顶破预算。** 上两条只兜住了
  单个大文本字段(`source`/`code`/`wat`、正文 body、`html`),没管**数组**。这两个工具各回一份至多 2000 条的相对路径清单
  (`java_files` / `files`),每条路径本身很短,但对一个类爆炸的大 APK 或深层 bundle,2000 条深包名路径 JSON 编码后轻松过 200KB
  ——`java_file_count`/`output_dir`/分页游标全挂在同一条结果里,一旦编码体越过 262144,传输层照旧把**整条**换成约 16KiB 摘要:
  agent 既拿不到任何一条路径、也拿不到落盘目录去自己遍历。原有的**条数**上限 `_MAX_LISTED_FILES`(2000)防不住这个——顶破预算的是
  每条路径的**长度**、不是条数。新增 `fit_json_text` 的数组姊妹 `backends/common/json_budget.fit_json_list`:按编码后的**整个数组**
  体积二分裁出「能过预算」的最长前缀、保序丢弃末尾若干条,并如实回报丢了多少。`export_sources` 用它裁 `java_files`,把丢弃折进
  既有的 `has_more`(其语义本就是「清单不完整」);`unpack_bundle` 在算 `has_more` **之前**裁 `window`,于是被预算裁过的一页仍报
  `has_more: true`、调用方可照常翻页取余下部分,`listing_truncated` 也随之置真。两处余量都取默认 64KiB(足够容下 `_note_*` 追加的
  至多 8000 字符 stderr、`output_dir` 与各计数标量)。清单小的照旧整条原样回(默认 `limit=100` 与典型小 APK 都走快路径、不触裁剪)。
  `fit_json_list` 有独立单测(裁到编码预算、保序、可把只有一条却超限的数组裁空);另加客户端级单测:把预算调小、喂 60 个文件的
  mock 树,断言 `export_sources`/`unpack_bundle` 都把清单裁短、`has_more` 置真、裁后数组编码体确实落在预算内(无需真 jadx/webcrack)。
  顺带修一处上一轮遗留的陈旧单测——`apk.decompile` 早已改用 `fit_json_text`、`_MAX_SOURCE_BYTES` 常量已删,该测仍 import 它并断言
  硬编码的 400000 上限;现改为按编码预算断言(`source` 短于原文件且 JSON 编码体不超 `RESULT_BUDGET_BYTES`)。r2 的分项清单
  (`_MAX_ITEMS`=4096 条 dict)是同一类的下一个、且更常触网(真实二进制动辄数千函数/字符串),但它同时挂着一份可能很大的原始
  `raw` 字段、需要连带处理,留作独立一轮。

- **r2 的 `functions`/`strings`/`imports`/`exports`/`disasm`/`xrefs` 几乎必被传输层整条丢弃——它把同一份数据装了两遍、还都没按预算裁。**
  接上一条留的那轮:r2 的这几条工具走 `enrich_r2_payload`,而它 `out = dict(data)` 会把原始 r2 输出 `raw`(在 `client.run` 里
  按**原始字节**截到 `_MAX_OUTPUT`=1_000_000)原样带进结果,同时又把这份 `raw` 解析成 `items`(至多 `_MAX_ITEMS`=4096 条、每条还
  补了 `address` 地址映射)——**同一个列表既以未解析的 JSON 文本躺在 `raw`、又以解析后的 dict 躺在 `items`**,近乎翻倍。两个上限
  (`raw` 的 1MB、`items` 的 4096 条)都不是按编码字节算的,而 `raw` 那 1MB 本身就是 262144 传输预算的近 4 倍:真实二进制随便
  几千个函数/字符串,`raw`+`items` 合起来轻松几百 KB 到 1MB+,`agent.context.bounded_tool_result` 照旧把**整条**换成约 16KiB 摘要——
  地址映射、计数、`items_truncated` 全没了,agent 拿到的不是「干净截断的前若干条」而是一段摘要。根因是这份 `raw` 对已解析成 `items`
  的列表**纯属冗余**:能解析成 list 就说明 `raw` 不是那截在 1MB 的残片(截断的 JSON 解不出来),它和 `items` 是同一份数据。现在:
  **①解析出 list 时直接丢掉 `raw`**(列表类工具的 catalog 描述本就只承诺 `items`/`count`/`items_*`、从没提 `raw`),再用
  `fit_json_list` 按编码体积把 `items` 裁进「预算−16KiB 余量」(4096 条计数上限保留在前面,只为挡住把上百万条都 enrich 一遍的
  活儿);`count` 报实际返回数、`items_total` 报解析出的总数、`items_truncated` 在 `count<总数` 时置真(计数上限或字节预算任一触发
  都算)、`items_limit` 仍是 4096 硬计数天花板(字节先到时 `count` 会低于它)。**②没有 list 时**(`r2.info` 的 `i` 身份文本,或某个
  `*j` 输出超 1MB 截断后解不出的残片)`raw` 才是正文——保留,但用 `fit_json_text` 按编码预算兜一层,`raw` 被裁则 `truncated` 置真、
  `output_bytes` 用 `setdefault` 保住 run() 记下的真实产出大小、`returned_bytes` 改报实际返回字节。只有 `client.open` 读 `raw`,走的
  是 `i`(非 list 分支),不受影响;没有别的调用方读 list 分支的 `raw`。**连带修一处双重 enrich 的隐性依赖**:`disasm` 过去先调
  `run()`(已 enrich)、再把结果 `enrich_r2_payload` 一遍以补上请求地址映射,靠的正是第一遍 enrich 把 `raw` 留着好让第二遍重解析;
  现在第一遍会丢 `raw`,第二遍便无从解析、把已建好的 `items` 误报成 `parsed=False`。改法是拆出 `_run_raw`(只跑命令、产原始 payload、
  不 enrich):`run` = `enrich(_run_raw(...))`,`disasm` 则 `_run_raw` 后补 `address`/`count` 再 enrich 一次;`xrefs` 本就用 `_exec`
  自行合并 axtj/axfj 后只 enrich 一次,不受影响。真实 r2(radare2 5.5.0)的 live gate——functions 地址映射、`disasm`/`izj`/`iij`/`iEj`
  在本机 r2 上解析、`disasm` 干净不带 `tool_failed`——三条全过。六条工具的 catalog 描述同步更新:注明「不返回 raw」「`count`
  可能因结果预算低于上限」。裁剪余量取 16KiB(丢掉 `raw` 后余下 module/architecture/address/commands/计数等标量都很小)。单测:原来
  钉「4096 条计数上限」的 says-when-cut 系列(strings/imports/exports/xrefs)改成喂 4099 条中等行、断言字节预算把 `count` 裁到 4096
  以下、`items_total`=4099、`items_limit`=4096、`raw` 不在、且整条 JSON 编码体不超 `RESULT_BUDGET_BYTES`;另加一条端到端断言——
  4099 条 xref 过 `bounded_tool_result` 后仍带 `items`、不被换成摘要(修前必被摘要);再补一条「行足够小时 4096 计数上限仍生效」证明
  计数上限没被字节预算完全取代;`r2.info` 截断测从「`raw` 恰好 1MB」改成「短于 1MB 且编码体不超预算、`returned_bytes` 与之一致、
  `output_bytes` 仍为真实产出」;空 list(`"[]"`)测断言 `raw` 已被丢、`count`=0。地址映射与各 address_fields 测(小列表)不受影响。

- **`apk.classes`/`methods`/`strings`/`xrefs` 与 `proxy.flows` 的分页结果同样会被传输层整条丢弃——每条工具只按行数封顶,没按编码字节裁。**
  接上一条 r2 的思路推到 Android 与 Web 域:这几条工具都返回一个按 offset/limit 切出的窗口,而**每行的体积是变量**——`apk.strings`
  每个字符串封到 2000 字符,默认 `limit`=200 时一页就 ~400KB;`proxy.flows` 每行的 `url` 封到 16KiB,`limit`=1000 时一个窗口能到几 MB。
  行数上限(`limit` / `_MAX_*`)拦不住这种溢出,溢出来自长度:一旦编码体超过 262144 传输预算,`bounded_tool_result` 照旧把**整条**回复
  ——行、`count`/`total`/`offset`、`has_more` 分页游标全都——换成约 16KiB 摘要,agent 拿到的不是「前若干行」而是一段摘要。现在每条在算
  `has_more` **之前**用 `fit_json_list` 把窗口按编码体积裁进「预算−16KiB 余量」:裁过的一页 `count` 会低于请求的 `limit`,但 `has_more`
  仍为真(`offset+len(window)<total`),调用方据此翻页即可越过被裁的部分,不会把半页读成全集。`apk.xrefs` 没有 offset 可翻页,故其字节裁剪
  直接并入 `has_more`(被裁只意味着省略了其余 caller)。五条工具的 catalog 描述同步更新:读 `count`、别读 `limit`,凭 `has_more` 翻页。
  裁剪余量取 16KiB(窗口之外的 `count`/`total`/`offset`/`has_more`/`scan_capped`/`dropped` 等标量都很小)。单测(`test_list_budget.py`)
  用真实的超量数据跑真实预算:1500 个 ~300 字符类名的 `classes`、1200 个长签名方法的 `methods`、默认 200 行即溢出的 `strings`、800 个长
  类名 caller 且**未触行数上限**故 `has_more` 只能来自字节裁剪的 `xrefs`、300 行长 url 的 `flows`——各断言 `0<count<limit`、`has_more` 为真、
  且整条 JSON 编码体不超 `RESULT_BUDGET_BYTES`;另有一条小页面用例断言合身时不裁、`has_more` 不误报。

- **`web.network.list`/`web.console`/`web.scripts` 的分页结果同样会被传输层整条丢弃——只按行数封顶,没按编码字节裁。**
  Web 动态侧和 apk/proxy 是同一类:每行的**逐字段**元数据早已按上限兜住(`url` 封 `_MAX_URL_BYTES`=16KiB、console 每条文本封
  `_MAX_CONSOLE_TEXT`=8KiB),但**整页列表**从未按编码体积裁——1000 行 network、2000 行 console、2000 条 scripts 各自能到几 MB。
  `web.scripts` 的 catalog 描述自己就记着「整份列表 441 KiB」,早已越过 262144 传输预算:一旦编码体超预算,`bounded_tool_result` 照旧把
  **整条**回复(行、`count`/`total`/`offset`、`has_more`、`dropped`)换成约 16KiB 摘要,行数上限拦不住,溢出来自长度。现在每条在算
  `has_more` **之前**用 `fit_json_list` 把窗口按编码体积裁进「预算−16KiB 余量」。`network.list` 与 `scripts` 是 offset/limit 向前翻页,保留
  前缀即可;`console` 是「最近 N 条」视图、没有 offset,故**反向**裁剪(`fit_json_list` 取前导段→喂进倒序页→再倒回)以留住最新、丢掉最旧,
  并把裁剪并入 `has_more`,免得半页被读成整个近期缓冲。三条工具描述同步更新:读 `count`、别读 `limit`,凭 `has_more` 翻页;console 注明留新弃旧。
  单测(`test_web_list_budget.py`)用真实超量捕获跑真实预算:300 行 ~16KiB url 的 network、300 条 ~16KiB url 的 scripts——各断言 `0<count<limit`、
  `has_more` 为真、编码体不超预算;`console` 用 200 条 ~8KiB 文本且 `limit`=2000(**不触行数上限**故 `has_more` 只能来自字节裁剪)、并断言留下的
  末行是最新的一条(#199)、首行不是最旧(#0);另有一条小页面用例断言合身时不裁、`has_more` 不误报。

- **`apk.manifest`/`device.logcat`/`device.packages` 也会被传输层整条丢弃——它们只按原始字符数或行数封顶,没按编码字节裁。**
  把同一条编码预算收敛推到 Android 剩下的原始文本/计数封顶输出:①`apk.manifest` 过去 `xml[:200000]` 按**字符**切。AndroidManifest 满是属性引号,
  每个 `"` 编码成 `\"`(2 字节),200k 字符的切片编码后能越过 262144 预算,`bounded_tool_result` 照旧把整份 manifest 连 package 一起换成约 16KiB
  摘要。改用 `fit_json_text` 按编码体积兜底(留 8KiB 给 package/truncated),`truncated` 无论字符上限还是编码上限触发都如实置真。②`device.logcat`
  过去从 200k 字符切片里取最多 5000 行返回;行内的引号/反斜杠/控制字符编码后膨胀,数组自身的引号与逗号再叠加,字符上限单独拦不住。改用 `fit_json_list`
  按编码体积裁,且这是「最近 N 行」视图,故**反向**裁剪留住最新、丢掉最旧,裁剪并入 `truncated`。③`device.packages` 过去列最多 2000 个包名,而
  Android 包名可长达 255 字符,整份列表能越过预算;改用 `fit_json_list` 裁,无 offset 故裁剪并入 `has_more`。`apk.properties`(getprop 短值字典)风险低
  且字典不便裁,保持原样。三条工具描述同步更新:读 `count`/`truncated`、别把页面当全集;logcat 注明留新弃旧。单测(`test_android_budget.py`)用真实
  超量输出跑真实预算:全引号 manifest 断言 `manifest_xml` 被裁到字符上限**以下**、`truncated` 真、编码体不超预算;1900 行 ~100 字符引号密集的 logcat
  (**内容短于字符上限**故裁剪只能来自字节预算)断言末行是最新(#1899)、首行不是最旧(#0)、编码体不超预算;1500 个 255 字符包名、`limit`=2000
  (**不触行数上限**)断言 `0<count<1500`、`has_more` 真、编码体不超预算。

- **`frida.memory.read` 大读几乎必被传输层整条丢弃,`frida` 的枚举列表也会——输出随输入放大却只按原始大小或行数封顶。**
  把编码预算收敛推到动态插桩面。①`memory.read` 是最确凿的一个:`size` 上限 256KiB,而 `data.hex()` 把字节数翻倍成最多约 512KiB 的十六进制串
  ——接近整个 262144 预算的两倍,任何超过约 128KiB 的读取编码后必然越界,`bounded_tool_result` 把**整条**结果(连 `data`、`address` 一起)换成
  约 16KiB 摘要,即大读实际什么可用数据都拿不到。现按「编码后十六进制能装下多少就返回多少」裁(十六进制无需 JSON 转义,可读预算恰好减半),新增
  `returned`(`data` 实际字节数)与 `truncated`,调用方据此从 `address+returned` 续读。②`modules`/`exports`/`applications` 与 java `classes`/
  `methods` 只按行数封顶:模块 `path` 长度无上限(Android 深层 data 路径)、C++ 修饰导出名可达数百字符、包名可长达 255、大应用有数千个长类名,任何
  一整页都可能越过预算被整条丢弃。各用 `fit_json_list` 按编码体积裁,`has_more`(由裁后长度重算,或与裁剪标志相或)仍如实报告「还有更多」。六条
  工具描述同步更新:读 `count`/`returned`、别读 `limit`/`size`,凭 `has_more` 翻页。`enumerate_devices`(设备数天然很少)保持原样。单测
  (`test_frida_budget.py`):200000 字节的 `memory.read` 断言 `truncated` 真、`0<returned<size`、`len(data)==returned*2`、编码体不超预算,另有
  16 字节小读断言整块返回不裁;256 个 ~2000 字符 path 的 `modules`、512 个 ~1000 字符修饰名的 `exports`(**不触行数上限**故 `has_more` 只能来自
  字节裁剪)、2000 个长类名/方法名的 java `classes`/`methods`、1000 个 255 字符包名的 `applications`,各断言 `0<count<上限`、`has_more` 真、编码体
  不超预算。

- **`proxy.flow.get` 的响应体只按原始字符数决定是否落盘,文本体会被传输层整条丢弃。**
  `flow_get` 过去在 `len(inline) <= 200000` 时内联响应体。这道闸是给 base64 体设计的(无 JSON 特殊字符,原始长度≈编码长度),但 UTF-8**文本**
  体里的引号/反斜杠/控制字符编码后会膨胀——一个 18 万字符、引号密集的文本体编码后约 360KB,越过 262144 预算,`bounded_tool_result` 便把**整条**
  `flow_get`(连 headers、size、body)换成约 16KiB 摘要。`web.network_get` 早已用 `_spill_text` 按编码体积兜底;现在 `flow_get` 对齐:当内联体的
  **编码形态**会越界时,把精确的原始字节落到 `body_path`(而非内联一份被截断或重编码的),不再只看字符数。顺带用 `_bounded_metadata` 把请求 `url`
  按 `_MAX_URL_BYTES`=16KiB 兜住(此前在 `flow_get` 里无上限,会侵蚀留给编码检查的余量,`flows()` 早已这么兜)。既有 flow_get 测试不变(20 万字符
  落盘、小文本/二进制内联路径行为如常)。新测(`test_proxy_flow_get_budget.py`):18 万全引号文本体(**短于字符上限**故只能靠编码闸)断言 `body`
  不在、`body_path` 存在且落盘字节与原文一致、`size`=180000、整条编码体不超预算。

- **`proxy.flow.get` 的请求/响应头原样返回,既不强制类型也不限体积。**
  接上一条 `flow_get` 正文的收敛:头部之前是 `dict(req.headers)`/`dict(resp.headers)` 直出。头部键值由对端控制,既没类型强制也没体积上限——恶意
  服务器可发几 MB 头部(即便正文已落盘,也足以把回复顶过 262144 预算被整条丢弃),且某些 mitmproxy 版本给的是原始 `bytes`,JSON 序列化器根本编码
  不了(直接崩成 `internal_error`)。新增 `_bounded_headers`:每个键/值都强制成 `str`(`bytes` 按 UTF-8 解码),单值封到 4KiB,整张头表按 JSON 编码
  体积裁进各自 16KiB 的配额——两张头表加上已兜住的 `url` 正好落在正文编码检查为「非正文字段」预留的余量内。头表被裁时在对应的 request/response 上置
  `headers_truncated`。既有 flow_get 测试不变(小头表照常直出)。新测:200 个 ~4000 字符的响应头(约 800KB)断言头表被裁到 200 条以下、
  `headers_truncated` 真、整条编码体不超预算;一个 `bytes` 头值断言回来是 `str` 且 `json.dumps` 不抛。

- **`apk.certificates` 只报 v1(JAR)签名,无法区分「未签名」与「只用 v2/v3 方案签名」。** 过去 payload 仅有
  `v1_signed`(由 `get_signature_names()` 推出)。面向 API 24+/30+ 的现代 APK 常常**只**用 APK Signature Scheme v2/v3
  签名、根本不带 META-INF 里的 v1 JAR 文件——这类包 `v1_signed` 为假,分析者若只看这一个字段就会把签好的包误读成未签名。反过来,一个现代
  目标若**只**有 v1 签名,正是 CVE-2017-13156(Janus)可利用的可疑形态,值得单独标出。现新增 `v2_signed`、`v3_signed` 与总体 `signed`
  三个标志,经新助手 `_sig_scheme` 调 androguard 的 `is_signed_v2`/`is_signed_v3`/`is_signed`:方案判定干净作答时给 `True`/`False`,方法
  缺失(更老的 androguard)或解析签名块抛异常时给 `None`——`null` 表示「测不出」,不与「没用该方案签」(`False`)混为一谈。`v1_signed`
  维持 `bool(names)` 原样不动。工具描述同步说明四个签名标志及 `null` 语义、并点出 v1-only 的 Janus 风险。单测(`test_apk_certificates_fields.py`):
  v2/v3-only 假 APK(`v1_signed` 假但 `signed` 真)、抛异常的方案判定(回 `None` 而非 `False`)、缺失方法的老 androguard(全部降级为 `None`)各一例;
  实机 gate(`test_m11_android_apk_live_gate.py`)对 jarsigner v1-only 夹具补断言 `signed` 真、`v2_signed`/`v3_signed` 均为 `False`(而非 `None`)。

- **`apk.certificates` 不报证书有效期,而过期或有效期离谱的签名证书本身就是信号。** 每条证书之前只有 subject/issuer/serial/sha256。androguard 4.x
  的证书是 asn1crypto `x509.Certificate`,其 `not_valid_before`/`not_valid_after` 是**带时区的 `datetime`**——MCP 的 JSON 序列化器根本编不了,
  必须在源头渲染成字符串。现每条证书新增 `not_before`/`not_after`,经新助手 `_cert_datetime` 取到有效期边界并 `isoformat()` 成 ISO-8601 字符串;
  没有该属性的证书形态(更老的 androguard、或本就是字符串)或抛异常的属性降级为 `None`,以免一个古怪证书把周边字段清空、或把 `datetime` 漏进序列化器
  崩成 `internal_error`。工具描述补上这两字段及其 `null` 语义。单测(`test_apk_certificates_fields.py`):用 `cryptography` 现造一张自签证书、按
  androguard 的路径经 asn1crypto 载入,断言 `not_before`/`not_after` 回来是预期 ISO 串且 `json.dumps` 不因 `datetime` 抛;另一例断言缺属性时两界均为 `None`
  且整条 payload 可序列化。实机 gate 对真实夹具证书补断言两界均可被 `datetime.fromisoformat` 解析、且 `not_after` 严格晚于 `not_before`(断言时序而非固定
  时间戳,重造夹具的一次性密钥不会打断 gate)。

- **`apk.manifest` 只回 XML 文本,不抽取 `<application>` 的安全标志,而 `debuggable`/`allowBackup` 是 Android 安全审查最靠前的两条。** 之前
  `manifest()` 只有 `package`/`manifest_xml`/`truncated`,分析者要自己在 XML 里翻这两个属性。现新增 `debuggable`、`allow_backup` 两个布尔字段,
  经新助手 `_manifest_flag` 调 androguard 的 `get_attribute_value('application', attr)` 取声明值并映射:`"true"`→`True`、`"false"`→`False`、
  未声明(或属性缺失/访问抛异常)→`None`。关键是**不把「未声明」塌成 `False`**:`allowBackup` 不声明时在 Android 12 之前仍默认开启备份,若伪造成
  `False` 会被读成清单从未做过的显式拒绝——`None` 保留「从未钉死」这一真相。工具描述补上两字段及其 `null` 语义。单测(`test_apk_fields.py`):
  声明 `debuggable=true`/`allowBackup=false` 的假清单断言映射成真/假布尔;空清单断言两者均为 `None` 而非 `False`。实机 gate 对真实夹具(其
  `<application>` 两标志都没声明)补断言两者均为 `None`,走的正是 `get_attribute_value` 对缺失属性返回 `None` 的真实路径。

- **`web.network.get` 不回响应头,而 `Set-Cookie`/CSP/CORS/重定向 `Location`/HSTS 恰是正文答不了、Web 逆向最想看的安全元数据。** 之前
  `on_response` 只从 CDP 的 `Network.responseReceived` 取了 `status`/`mimeType`,响应头整个丢掉;`network_get` 因此只能回正文,分析者看不到任何头部。
  现 `on_response` 额外抓 `response.headers`,`network_get` 新增 `response_headers`(str→str)与 `headers_truncated` 两字段。头由服务器控制,
  照搬会出两种事故:恶意源站可发几 MB 头把整条回复顶过 262144 预算被丢成摘要,某些取值又可能不是 `str` 直接崩序列化——故新增 `_bounded_headers`
  (镜像 `proxy.flow_get` 的同名处理):每个键/值强制成 `str`(`bytes` 按 UTF-8 解码)、单值封到 4KiB、整张头表按 JSON 编码体积裁进 16KiB。抓到的头
  存在**独立于请求条目**的 `response_headers` 环(键为 requestId、按 `_MAX_REQUESTS` 淘汰),使 `network_list` 的分页行保持精简(其行早已按 url 体积
  兜),只有 `network_get` 才逐条取回。没有对应响应的请求返回空头表 + `headers_truncated` 假,而非缺键或抛错。工具描述补上两字段。单测
  (`test_web_network_get_fields.py`):经桩件断言取回 `set-cookie`/CSP;无响应条目返回空表;`_bounded_headers` 直测——`bytes` 键值被强制成 `str`
  且 `json.dumps` 不抛、超大单值被封顶、400 条大头被按编码体积裁到不超 16KiB 且 `truncated` 真。`test_web_fields.py` 经真实 `_wire_events` 布线断言超大
  响应头在入环前就被封顶、`headers_truncated` 真。实机 gate(`test_web_re_gate.py`)对真实浏览器抓到的 `/app.js` 响应补断言 `response_headers` 里
  (键名大小写归一后)`content-type` 含 `javascript`,证明 responseReceived→捕获→取回这条链路端到端可用。

- **`web.network.get` 只回响应头,不回请求头,而客户端发出的 `Cookie`/`Authorization`/自定义 `X-` 头/`User-Agent` 同样是 Web 逆向的核心事实。** 接上一条
  响应头的补齐:请求头分散在两个 CDP 事件里——`requestWillBeSent` 带页面/脚本设置的头,`requestWillBeSentExtraInfo` 带网络栈追加的头(尤其 `Cookie`)。
  只抓前者会让分析者误以为「没发 Cookie」,故新增 `_accumulate_headers` 把两个事件的头按 requestId 合并进同一桶(dict 按名去重,重定向复用 id 也不会无界增长),
  每个值即时强制成 `str` 并封到 4KiB;`network_get` 在读取时对合并后的桶再按 JSON 编码体积兜一次(经 `_bounded_headers`),返回 `request_headers`(str→str)
  与 `request_headers_truncated`。请求头同样存在独立于请求条目的桶(按 `_MAX_REQUESTS` 淘汰),保持 `network_list` 分页行精简。工具描述补上两字段并说明
  ExtraInfo 合并。单测(`test_web_network_get_fields.py`):经桩件断言取回 `user-agent`/`cookie`、`request_headers_truncated` 假;无请求头时返回空表。
  `test_web_fields.py` 经真实 `_wire_events` 布线断言 `requestWillBeSent`(User-Agent)与 `requestWillBeSentExtraInfo`(Cookie)合并进同一请求、超大头值入桶前被封顶。
  实机 gate(`test_web_re_gate.py`)对真实浏览器抓到的 `/app.js` 请求补断言 `request_headers`(键名归一后)含 `user-agent`,证明 requestWillBeSent(+ExtraInfo)→
  合并→取回端到端可用。

- **`web.network.get` 能回响应体却回不了请求体,而 API 调用发出的 POST/PUT 载荷(JSON/表单)正是分析者最想看的。** 至此 `network_get` 已有请求/响应头、
  响应体,唯独缺请求体。请求体像响应体一样**按需取**而非入环缓存(否则 3000 条请求各存一份会吃光内存):`on_request` 只在条目上记一个 `has_post_data`
  布尔(由 `hasPostData`/内联 `postData` 推出),`network_get` 仅当其为真时调 `Network.getRequestPostData` 取回,经 `_spill_text` 兜底(大体落 `request_body_path`、
  截断标 `request_body_truncated`),返回 `request_body`。浏览器若已丢弃该数据,则以 `request_body_error` 记录而非让整条读取失败(响应体照常返回);
  `_spill_text` 抛的 `too_large`(超采集上限的上传)照旧上抛,与响应体一致。工具描述补上 `has_post_data`/`request_body` 及错误/落盘语义。单测
  (`test_web_network_get_fields.py`):`has_post_data` 为真的请求断言经 `getRequestPostData` 取回 `{"user":"admin"}`;getRequestPostData 抛错时断言响应体仍在、
  `request_body` 不在、`request_body_error` 记录到位。`test_web_fields.py` 布线断言 GET 的 `has_post_data` 为假。实机 gate 对真实 `/app.js`(GET)补断言
  `has_post_data` 为假,钉住这条「按需取」的开关端到端接线。

- **`proxy.flow.get` 能回响应体却回不了请求体,与 `web.network.get` 补齐后的形态不对称。** mitmproxy 的 `flow.request` 和 `flow.response` 一样带
  `raw_content`,故请求体用与响应体完全相同的方式处理:诚实解码(utf-8,否则 base64 精确字节并标 `base64_encoded`),超长(原始字符或 JSON 编码体积)则
  落 `request.body_path`,否则内联 `request.body`;并新增 `request.size`。关键在预算:`flow_get` 现在可能同时内联请求体与响应体,若不核算,两个大体加起来会
  越过 262144 预算把整条回复丢成摘要——故请求体一旦内联,其编码字节数会计入响应体那次编码兜底(`fit_json_text`)的 reserve,逼响应体在两者都大时改走落盘。
  工具描述改为「请求/响应各自带 body/body_path/base64_encoded」。单测(`test_proxy_flow_get_budget.py`):POST 请求体内联取回 `{"user":"admin"}`、二进制请求体走
  base64、超大请求体落盘、以及「100KB 请求体内联 + 180KB 响应体」这组断言响应体因预算核算而落盘、整条不超预算。实机 gate(`test_proxy_lifecycle_gate.py`)
  给 origin 加 `do_POST`、经代理发一条 JSON POST,断言 `flow_get` 从真实 mitmproxy flow 的 `request.raw_content` 读回请求体(size 与正文都对得上)。

- **`apk.components` 只列四类组件名,却不标哪些被导出,而「导出组件」正是一个 App 对外的攻击面——Android 静态审查最先要问的一件事。** 过去 payload 只有
  `activities`/`services`/`receivers`/`providers`(全部组件名)、`main_activity` 与 `has_more`,分析者无法从中区分「仅内部可达」与「任何其他 App 都能拉起」。
  androguard 没有逐组件的导出判定 getter,故新增 `exported` 字段:按类别(同样四组)给出被导出组件的 FQN 子集,判定直接读解码后的清单树
  (`get_android_manifest_xml`)——显式 `android:exported="true"` 记为导出;未声明该属性但带 `intent-filter` 也记为导出(Android 12 之前的隐式导出规则,
  与 MobSF/drozer 一致);`android:exported="false"` 一律不导出(显式优先于隐式)。未声明+无 filter 不导出。清单名按 Android 规则解析成 FQN,与扁平列表对齐;
  整条端到端 `try` 兜底——清单解析不了则退化为四组空列表而非让 `components()` 失败。唯一不推断的边角是「`targetSdk < 17` 的未声明 provider 默认导出」这一遗留默认,
  已在工具描述里注明可能少报。单测(`test_apk_exported_components.py`)用手工构造的 lxml 清单覆盖:显式 true、隐式(filter)、`false` 压过 filter、未声明+无 filter 不导出、
  按类别分组、`exported` 恒为扁平列表子集、清单抛错时退化空组,以及名字解析与判定规则本身。实机 gate(`test_m11_android_apk_live_gate.py`)对真实夹具断言 MainActivity(无
  filter、无 `android:exported`)不在任何导出组里、四组皆空——证明该判定跑在真实 androguard 解码的清单上,而非只在 mock 里。

- **`apk.permissions` 只回权限名,不报保护级别,而「申请了哪些 dangerous 权限」是 Android 权限审查最先要问的。** 过去 payload 仅有 `permissions`/
  `requested_permissions`(均为 uses-permission 名)、`count`、`has_more`,分析者无法从名字区分 `INTERNET`(normal)与 `READ_CONTACTS`(dangerous)。
  androguard 的 `get_details_permissions` 能把每条申请权限映射到 `[protectionLevel, label, description]`(平台 AOSP 权限,及 APK 自声明的带数值
  protectionLevel 的自定义权限),故新增三个字段:`protection_levels` 把每条能解析的申请权限映射到其基础保护级别(`normal|instant` 取基础 token → `normal`;
  其余如 `dangerous`/`signature` 原样),`dangerous` 是其中保护级别含 `dangerous` token 的子集(运行时授权攻击面:通讯录/定位/短信/麦克风…),
  `custom_permissions` 则来自 `get_declared_permissions`——App 用 `<permission>` 自己定义的权限,与它申请的权限是两个面。级别取值只保留基础 token 并小写;
  解析不到的权限(自定义或本版 DB 不识别)不进 `protection_levels`(缺席不等于安全),也不进 `dangerous`。`protection_levels`/`dangerous` 限定在已封顶的申请集内、
  整条 `try` 兜底——本版无 AOSP DB 时退化为空级别而非让 `permissions()` 失败。工具描述改为点名 `protection_levels`/`dangerous`/`custom_permissions` 三字段及其语义。
  单测(`test_apk_permission_levels.py`)覆盖:基础级别抽取、`dangerous` 子集、解析不到的权限缺席而非误报 normal、`custom_permissions` 独立列出、老字段不变、
  DB 缺失退化空、以及辅助函数按名字集限定+token 归一化。实机 gate(`test_m11_android_apk_live_gate.py`)用真实 androguard AOSP DB 断言 INTERNET 解析为 `normal`、
  不在 dangerous、且夹具无自定义权限——证明级别来自真实权限库而非 mock。

- **Web 域缺 cookie 读取能力,而 cookie 的安全标志(HttpOnly/Secure/SameSite)是 Web 会话/鉴权逆向最核心的一类事实。** 之前 web.* 有网络、控制台、脚本、
  DOM、HAR,却没有任何看 cookie 的工具:分析者无法回答「会话 cookie 是否 HttpOnly(能否被页面脚本/XSS 读取)、是否 Secure(会不会走明文 HTTP)、SameSite 是否为
  None(CSRF 面)」。新增只读工具 `web.cookies`:经 CDP `Network.getAllCookies` 读取浏览器会话持有的全部 cookie(含 `document.cookie` 看不到的 HttpOnly 项),每条
  归一化为 JSON 安全标量——`name`/`value`/`domain`/`path`、布尔 `secure`/`http_only`/`session`/字符串 `same_site`(站点未设则为空),以及 `expires`(会话 cookie 的
  -1 归一化为 null 而非伪造的史前时间戳)。`value` 按 4KiB 上限封顶、超出置 `value_truncated`;整份集合按 JSON 编码体积 `fit_json_list` 裁剪,`total`/`has_more` 让被裁
  的一页不被当成全部。工具计入只读面(266,149 只读 / 117 写);catalog 计数不变式、README 三处工具算术、`test_tool_catalog_agent`/`test_workspace_profiles`/
  `test_mcp_server` 的工具集与计数断言同步更新。单测(`test_web_cookies_fields.py`)用假 CDP 覆盖:安全标志、value 封顶+flag、空/畸形回复退化、大量大 cookie 按预算裁剪且
  不超 262144、`_normalize_cookie` 默认值与 expires 归一化、以及描述点名 http_only/secure/same_site。实机 gate(`test_web_re_gate.py`)让 origin 在首页下发一个
  `HttpOnly` cookie,经真实 chromium 用 `web.cookies` 读回其值与 `http_only=true`——CDP 能拿到 HttpOnly cookie 正是 `document.cookie` 永远做不到的,以此证明走的是 CDP 而非页面脚本捷径。

- **`apk.manifest` 报了 debuggable/allowBackup,却漏了同样属于最靠前一档的明文流量姿态——`usesCleartextTraffic` 与 `networkSecurityConfig`。** 允许明文 HTTP 是
  Android 安全审查的常见高危项,而 Network Security Config 又能重新放开明文或改动 CA 信任,二者一起才说得清网络传输面。补上两个字段:`uses_cleartext_traffic` 用既有
  `_manifest_flag` 读成布尔(未声明为 null——不是 False:目标 API 28 以下未声明默认允许明文,谎报 False 会读成从未有过的显式禁止);`network_security_config` 用新增
  `_manifest_attr` 保留声明的资源引用字符串(如 `@xml/network_security_config`,未声明为 null),其存在本身即信号——说明明文/信任由该配置治理,从而修饰 cleartext 的解读。
  与既有安全标志共用同一「null≠False」的诚实退化:方法缺失/访问抛错/未解析清单都退化为 null 而非崩掉或伪造。`_manifest_attr` 对取值封 512 字符上限,防敌意值撑大回复。
  工具描述补齐三项 `<application>` 安全标志加 `network_security_config` 的语义与各自默认值。单测(`test_apk_fields.py`)在既有两条清单标志用例上扩断言:显式 cleartext=true+NSC
  引用取回、未声明时两者皆 null。实机 gate(`test_m11_android_apk_live_gate.py`)对真实夹具断言两者皆 null——夹具既未声明 usesCleartextTraffic 也无 NSC,证明走的是真实
  `get_attribute_value`(缺失返回 None)而非 mock。

- **Web 域能读 cookie 却读不到 DOM 存储,而 localStorage/sessionStorage 恰是 cookie 读不到的那半个客户端凭据库——JWT、刷新令牌、会话态常存于此。** 接上一条 `web.cookies`,
  新增只读工具 `web.storage`:经 CDP `DOMStorage.getDOMStorageItems` 读取当前页面安全源的 localStorage 与 sessionStorage(不跑任何页面脚本,因而无需 `web.evaluate` 那类
  任意 JS——与本项目「不开放任意 JS 求值」的立场一致)。返回 `origin` 加两个 str->str 映射 `local_storage`/`session_storage`;安全源由页面 URL 推出(`scheme://host[:port]`),
  opaque 源(`about:blank`/`data:` URL)无按源存储,回空 `origin` 且两映射为空、不去打扰 CDP。每个值按 8KiB 上限封顶(足够容下 JWT/令牌),每张映射按 JSON 编码体积各自设 96KiB 上限,
  两张加总不超 262144 结果预算;被封顶的值或被裁的映射置 `local_storage_truncated`/`session_storage_truncated`。工具计入只读面(267,150 只读 / 117 写);catalog 计数不变式、
  README 三处工具算术、`test_tool_catalog_agent`/`test_workspace_profiles`/`test_mcp_server` 的工具集与计数断言同步更新。单测(`test_web_storage_fields.py`)用假 CDP 覆盖:
  local/session 分别取回、opaque 源回空且不触碰 CDP、大值封顶+flag、大量条目按预算裁剪且不超 262144、`_security_origin` 抽取与 `_bounded_storage` 归一化/跳过畸形对、描述点名两库。
  实机 gate(`test_web_re_gate.py`)让 app.js 在真实 http 源写入 localStorage/sessionStorage,经真实 chromium 用 `web.storage` 读回两枚令牌并按 http 源归类——opaque 源的 data: URL
  永远做不到,以此证明走的是真实 DOMStorage 路径。

- **`proxy.export_har` 导出的 HAR 只有请求行与状态码,漏了头、体、时序——对任何 HAR 消费方几乎没用。** 之前每条 entry 仅 `request{method,url}` 与
  `response{status,content{mimeType}}`,既没有请求/响应头,也没有 body,更缺 HAR 1.2 必需的 `startedDateTime`/`timings`/`httpVersion`/`cookies`/`queryString` 等字段,
  导出的文件无法被浏览器或 Charles 等工具重新加载分析。改为从 recorder 仍保留的完整 flow 对象(与 `flow_get` 同源)重建每条 entry:请求/响应头(`items(multi=True)` 保留重复
  头如多条 Set-Cookie)、`queryString`、请求体(`postData.text`,二进制走 base64 且标 `encoding`)、响应体(`content.text`+`size`+`mimeType`,二进制同样 base64)、状态与
  `statusText`/`httpVersion`、`startedDateTime`(由 `timestamp_start` 转 ISO-8601 UTC)、`time` 与 `timings`(把总耗时记入 receive,使 timings 之和等于 time,符合规范)。
  因写的是文件、不受 262144 结果预算约束,故 body 完整导出(体量本就由 recorder 的保留上限 `_MAX_RETAINED_BYTES` 兜住)。body 被逐出或超保留上限的 flow 没有原始对象,则回退成
  一条带 `comment`(头/体未保留)的精简但合规 entry,绝不静默丢弃任何已捕获 flow。工具描述改述 HAR 为完整记录并说明精简回退。单测(`test_proxy_har_export.py`):头/体/时序齐全、
  POST 的 postData 与二进制响应体 base64 往返、queryString 解析、body 未保留时两条精简 entry 不丢流。实机 gate(`test_proxy_lifecycle_gate.py`)对真实 mitmproxy 捕获的 POST
  读回 HAR,断言其请求头、postData 正文与源站响应体都在——证明富 HAR 来自真实 flow 而非摘要。

- **`proxy.flows` 只能按 offset/limit 翻页,无法在一次繁忙抓包里挑出关心的那几条,分诊全靠把整个环翻一遍。** 现给 `proxy.flows` 增加四类可选过滤(彼此 AND):
  `method`(大小写不敏感精确匹配,如 POST)、`host_contains`/`url_contains`(大小写不敏感子串)、`status_min`/`status_max`(闭区间状态码,均 100..599——故 `status_min` 400 单用即所有
  错误响应,`status_min` 404 配 `status_max` 404 即精确 404)。状态区间会排除没有响应的 flow(status 为 None):既然按状态过滤,它就没有状态可比。空白过滤串按「无过滤」处理,既不匹配
  全部也不匹配空。过滤在整段抓包上先做、再对命中集分页,故 `total` 变为命中数、`has_more` 针对命中集翻页;此外新增 `filtered`(为真)与 `captured`(过滤前环内条数),让「命中数」与
  「抓到多少」不被混为一谈。`dropped` 仍是抓包环已淘汰的条数(抓包属性,与过滤无关)。工具描述补上这些过滤与 `filtered`/`captured` 语义。单测(`test_proxy_flow_filters.py`):method
  精确/大小写、host/url 子串、状态区间选错误与精确码、状态区间排除无响应流、多过滤 AND、空白串忽略、命中集分页与 `dropped` 不受过滤影响。实机 gate(`test_proxy_lifecycle_gate.py`)对真实
  mitmproxy 捕获的 GET/POST 用各过滤读回,证明过滤读的正是真实抓包的摘要字段。

- **`apk.xrefs` 只能列某方法的调用者(xref-from),回答不了「这个方法又调了谁」(xref-to)——而数据流追踪两个方向都要。** androguard 的 `MethodAnalysis` 同时提供
  `get_xref_from`(调用者)与 `get_xref_to`(被调者),二者返回同样的 `(class, ref, offset)` 三元组,故用一个 `direction` 开关同时驱动:`direction="callers"`(默认,行为不变)列
  调用 `method_name` 的方法,放在 `callers` 字段;`direction="callees"` 列 `method_name` 自身调用的方法,列字段改名为 `callees`(而非 `callers`),两者互不混用。payload 回显 `direction`,
  使 callees 回复不会被误读成 callers;每行仍是 `{class, method}` 且 `has_more` 语义(行数上限或字节预算裁剪)不变。非 callers/callees 的取值按 `invalid_params` 拒绝,不静默回退默认。
  工具描述补上 `direction` 与 `callees` 字段。单测(`test_apk_fields.py`):同一方法 2 个调用者 / 3 个被调者——callees 走 `get_xref_to` 得 3 且落 `callees` 字段无 `callers` 键、默认走
  `get_xref_from` 得 2 且落 `callers` 无 `callees`(2≠3 证明取的是正确那一侧),以及未知 direction 报 `invalid_params`。实机 gate(`test_m11_android_apk_live_gate.py`)对真实 dex 里
  `caller→callee` 这条 invoke 边两个方向都读回:callers of `callee` 含 `caller`,callees of `caller` 含 `callee`,证明真实 androguard 的 `get_xref_to` 路径可用而非仅 mock。

- **新增 `wasm.imports` / `wasm.exports`:结构化读出一个 `.wasm` 模块的宿主边界——它依赖哪些宿主函数/全局/内存/表,又向宿主暴露哪些入口。** 此前 WASM 域只有 `wasm.wat`/`wasm.info`
  回原始 wabt 文本,agent 想知道 import/export 面只能自己去 parse `wasm-objdump -x` 的输出——既繁琐又随 wabt 版本漂移。两条新工具直接读模块的二进制 Import/Export 段,故**不需要装 wabt**
  (本环境正是没有 wabt 的情形)、也不会随 wabt 版本变化。`wasm.imports` 每行含 `module`/`name`/`kind`;func 导入附 `type_index` 及(当 Type 段能解析时)`params`/`results`(valtype 名);
  memory/table 导入附 `limits`(`min`,有上界则含 `max`);global 导入附 `value_type` 与 `mutable`。`wasm.exports` 每行含 `name`/`kind`/`index`。两者都回 `count`/`total`/`offset`/`declared`/
  `has_more`/`incomplete`:`total` 是实际解析出的条数(可分页),`declared` 是段头声明的条数,二者因模块被截断或触达条目上限而不一致时 `incomplete` 为真,故短列表不会被误读成完整边界;
  `count` 可能因结果预算裁剪而低于 `limit`,按 `has_more` 翻页。解析器对敌意输入全程有界:每次切片都核对缓冲区边界、LEB128 按位宽封顶(连续 continuation 字节不会空转)、向量与名字长度设上限,
  非法/截断模块给出「部分但带 `incomplete` 标记」的结果而非越界读或崩溃;只有根本不是 WebAssembly 模块的输入才硬报错。工具面 267→**269**(150→**152** 只读,写不变)。单测
  (`test_wasm_imports_exports.py`):func 签名解析、memory/table/global 各类型、export 名/类型/索引、无段的空模块、非模块硬报错、截断段置 `incomplete`、失控 LEB128 被位宽封顶不空转、
  WasmClient 无 wabt 也能分页读盘上文件、缺文件报 `not_found`。实机测试(`test_m11_wasm_live_gate.py`,因不需 wabt 故不 skip)对真实 wat2wasm 产物与一枚带 Import 段的模块两端读回。

- **新增 `wasm.names`:读出 `.wasm` 模块自定义 "name" 段里的函数索引→名字符号表——把「剥符号但带调试名」的模块符号化。** 承接 `wasm.imports`/`exports` 的二进制读取思路:导出给出有名的入口,
  但模块内部函数在没有 name 段时只是索引;`wasm.names` 解析自定义 "name" 段(子段 0 模块名、子段 1 函数名映射),这是可读性的最大单项提升。同样**不需要 wabt**、不随其版本漂移。关键在于:
  自定义段都用 id 0,若沿用 `wasm.imports` 那套「按 id 取最后一个」会把 `producers`/`.debug_*` 等其它自定义段错当成 name 段——故新增 `_find_custom_section`,遍历时读每个 id 0 段自带的段名、只取名为
  "name" 的那个。回 `present`(模块是否带 name 段——剥符号模块为假,区别于「带 name 段但没有函数名」)、`module_name`(或 null)、`function_names`(每行 `{index, name}` 按 index 排序)及
  `count`/`total`/`offset`/`has_more`/`incomplete`。解析器沿用同一有界读:名字映射子段被截断或触达条目上限置 `incomplete`,越界不读、非模块才硬报错。工具面 269→**270**(152→**153** 只读)。单测
  (`test_wasm_imports_exports.py`):模块名+函数名解析、`producers` 段不被误当 name 段(`present` 假)、截断映射置 `incomplete`、WasmClient 无 wabt 分页读盘、剥符号模块 `present` 假。实机测试
  (`test_m11_wasm_live_gate.py`)对一枚带 name 段的模块读回 `gate` 模块名与 `add`/`run` 函数名,并确认真实 wat2wasm 产物(无 name 段)`present` 为假。

- **新增 `apk.string_xrefs`:回答「这个字符串常量在哪被用到」——把 `apk.strings` 只能证明「存在」的一条字符串定位到读取它的方法。** 追踪硬编码的 URL/密钥/命令时,光有字符串列表不够,
  还要知道谁引用它;androguard 的 `StringAnalysis` 与方法一样携带 xref-from 边,`get_xref_from()` 给出 `(ClassAnalysis, MethodAnalysis)` 对,取其方法端即得引用者。默认 `value` 精确匹配
  (`match="exact"`);置 `contains=true` 则匹配任何含该子串的字符串(`match="contains"`),此时可能命中多条不同字符串,每行的 `string` 标明本条边属于哪一条,使子串命中可归因。回 `xrefs`
  (每行 `{class, method, string}`)、`value`、`match`、`strings_matched`(命中的不同字符串条数)、`count`(返回的引用行数)、`has_more`(行数上限或字节预算裁剪;无 offset,故裁剪即省略其余)、
  `scan_capped`(字符串扫描在遍历完整个 DEX 前触达上限,故空/短结果不被读成「别处再无引用」)。空 `value` 按 `invalid_params` 拒绝(否则 contains 模式会匹配全部字符串)。工具面 270→**271**
  (153→**154** 只读,写不变)。单测(`test_apk_fields.py`):精确匹配列出两个引用方法且不含无关串、contains 命中多条并逐行标注所属串而精确同串命中零、`limit` 截断置 `has_more`、空 `value` 报
  `invalid_params`。实机 gate(`test_m11_android_apk_live_gate.py`)对真实 dex:`APK_GATE_MARKER_STRING` 由 `callee` 引用,精确查询命中 `callee`,`MARKER` 子串查询经 contains 命中同一条边——
  读的是真实 androguard 的 `StringAnalysis.get_xref_from`(区别于方法 xref-from/xref-to),而非 mock。

- **`web.network.list` 只能按 offset/limit 翻页,一次繁忙抓包(几十上百条请求)只能整页翻,挑不出关心的那几条——与已加过滤的 `proxy.flows` 一边繁一边简。** 现把同一套过滤镜像到
  `web.network.list`(彼此 AND):`method`(大小写不敏感精确匹配,如 GET)、`resource_type`(对 CDP resourceType 大小写不敏感精确匹配——Document/Script/XHR/Fetch/Image/Stylesheet 等固定词表,是 Web
  分诊最自然的一维)、`url_contains`(大小写不敏感子串)、`status_min`/`status_max`(闭区间状态码,均 100..599——故 `status_min` 400 单用即所有错误响应,`status_min` 404 配 `status_max` 404 即精确 404)。
  状态区间会排除还没拿到响应的请求(status 为 None):既然按状态过滤,它就没有状态可比。空白过滤串按「无过滤」处理,既不匹配全部也不匹配空。过滤在整段抓包上先做、再对命中集分页,故 `total` 变为命中数、
  `has_more` 针对命中集翻页;此外新增 `filtered`(为真)与 `captured`(过滤前环内条数),让「命中数」与「抓到多少」不被混为一谈。`dropped` 仍是抓包环已淘汰的条数(抓包属性,与过滤无关)。工具描述
  补上这些过滤与 `filtered`/`captured` 语义(保留原有 `requests`/`resourceType`/`dropped` 等字段说明)。这是修改既有工具而非新增,工具面计数不变。单测(`test_web_network_filters.py`,复用 `proxy.flows`
  过滤测试的形制):method 精确/大小写、resource_type 精确/大小写、url 子串、状态区间选错误与精确码、状态区间排除无响应请求、多过滤 AND、空白串忽略、命中集分页与 `dropped` 不受过滤影响。实机 gate
  (`test_web_re_gate.py`)对真实 Chrome 抓到的 `/index.html`(Document)与 `/app.js`(Script):`url_contains="app.js"` 命中子资源且置 `filtered`/`captured`、`resource_type="Script"` 只留脚本请求、
  `method="GET"` 配 2xx 区间仍留住它、无意义子串给出空的已过滤视图(`total` 0)而非整环。

- **`web.console` 只能取最近 N 条,一页嘈杂的控制台(几百条 debug/log 里夹着那一条 error)只能全量翻,挑不出关心的那几条——与已加过滤的 `web.network.list`/`proxy.flows` 一边繁一边简。**
  现把同一套过滤镜像到 `web.console`(彼此 AND,然后仍取命中集里最近的 N 条):`level`(对消息 `type` 大小写不敏感精确匹配——CDP consoleAPICalled 词表 log/info/warning/error/debug/trace 等,故 `level`
  error 只留错误、不含警告)、`text_contains`(消息文本大小写不敏感子串;文本在抓取时已按每条上限裁剪,故子串比对的是裁剪后的形态)。空白过滤串按「无过滤」处理,既不匹配全部也不匹配空。命中后新增
  `filtered`(为真)与 `captured`(过滤前缓冲区条数),`has_more` 转为对命中集的最近 N 视图翻页;`dropped` 仍是控制台环已淘汰的条数(抓包属性,与过滤无关)。工具描述补上这些过滤与 `filtered`/`captured`
  语义并点明每行有 `type`/`text`(保留原有「最近 N 视图」「预算裁剪保留最新」「`text_truncated`」说明)。这是修改既有工具而非新增,工具面计数不变。单测(`test_web_console_filters.py`,复用
  `web.network.list` 过滤测试的形制):level 精确/大小写、text 子串、多过滤 AND、空白串忽略、命中集的最近 N 视图翻页与 `has_more`、`dropped` 不受过滤影响。实机 gate(`test_web_re_gate.py`)对真实 Chrome
  抓到的 `console.log('gate-ready')`:`text_contains="gate-ready"` 与 `level="log"` 都留住它并置 `filtered`/`captured`,不匹配子串给出空的已过滤视图、`level="error"` 不含该条——端到端走真实 `_console_matches`
  而非仅单测 fake。

- **`apk.classes`/`apk.strings` 只能按 offset/limit 翻页,面对一个几万类、几千串的真实 App,想找到关心的那个类或那条串只能整页翻——与已加过滤的抓包面(`web.network.list`/`web.console`/`proxy.flows`)
  一样繁。** 现给两者各加一个 `contains`(大小写不敏感子串)过滤,与那几个面同源:`apk.classes(contains="crypto")` 直接列出所有 crypto 类、`apk.strings(contains="http")` 直接列出所有 URL,不必翻遍整个 DEX。
  过滤在扫描时施加(上限计的是「已检视数」而非「命中数」,故有无过滤时走的是同一段 `_MAX_CLASSES_COLLECT`/`_MAX_STRINGS_COLLECT` 检视窗口,无过滤时行为逐字节不变);类名按点分/smali 名比对,字符串按
  完整常量比对(与 `apk.string_xrefs` 一致,故 contains 查询在两个工具间吻合)。命中后 `total` 只计匹配数并新增 `filtered`(为真);`scan_capped` 语义不变——带过滤且为真时意味「检视窗口之外可能还有匹配」,
  故过滤落空不被读成「无此类/无此串」。空白过滤串按「无过滤」处理,既不匹配全部也不匹配空。这是修改既有工具而非新增,工具面计数不变。单测(`test_apk_fields.py`):类名 contains 精确/大小写、落空给出空的已过滤列表、
  空白串忽略且外部类仍排除;字符串 contains 大小写、子串在常量中部命中(证明是子串非前缀)、空白串忽略。实机 gate(`test_m11_android_apk_live_gate.py`)对真实 dex:`classes(contains="sample")` 留住 Sample 类并置
  `filtered`、无意义串给出空的已过滤列表;`strings(contains="MARKER")` 留住标记串并置 `filtered`——走真实 androguard 扫描而非 mock。

- **`apk.classes`/`apk.strings` 加过滤后,`apk.methods` 成了 DEX 列表面里最后一个还只能按 offset/limit 翻页的——一个上千方法的 God-Activity 或生成的 binder,想挑出关心的那几个方法只能整页翻。** 现给它补上
  同源的 `contains`(大小写不敏感子串)过滤,与 `apk.classes`/`apk.strings` 逐字段对齐:`apk.methods(class_name=..., contains="crypt")` 直接列出该类里所有 crypt* 方法,不必翻遍整个类。过滤在扫描时施加(上限计
  「已检视数」而非「命中数」,故有无过滤走同一段 `_MAX_METHODS_COLLECT` 检视窗口,无过滤时行为逐字节不变);比对的是方法名而非描述符,故 `contains="()V"` 不会因每个方法的描述符恰好是 `()V` 而误命中。命中后
  `total` 只计匹配数并新增 `filtered`(为真);`scan_capped` 语义不变——带过滤且为真时意味「检视窗口之外可能还有匹配」。空白过滤串按「无过滤」处理,既不匹配全部也不匹配空。这是修改既有工具而非新增,工具面
  计数不变。单测(`test_apk_fields.py`):方法名 contains 大小写(encryptPayload/Encrypt 命中而 decrypt 不含 "encrypt")、只按名不按描述符命中、落空给出空的已过滤列表、空白串忽略、无过滤仍列全部。实机 gate
  (`test_m11_android_apk_live_gate.py`)对真实 dex:`methods(contains="CALL")` 留住 callee/caller 两个方法并置 `filtered`、排除 `<init>`,无意义串给出空的已过滤列表——走真实 androguard 扫描而非 mock。

- **`web.scripts` 只有 `wasm_only` 与 offset/limit,一页解析了几百个脚本时想按 URL 挑出关心的那个(如 app.js)只能整页翻——是 Web 列表面里最后一个还没有子串过滤的。** 现加一个 `url_contains`
  (大小写不敏感的 URL 子串)过滤,与 `web.network.list` 同源,并与 `wasm_only` 相 AND:`url_contains="app.js"` 直接定位那个脚本。命中后 `total` 只计匹配数并新增 `filtered`(为真)与 `captured`
  (过滤前环内条数),`has_more` 针对命中集翻页;`dropped` 仍是脚本环已淘汰数(与过滤无关)。刻意只让新的 `url_contains` 触发 `filtered`/`captured`:`wasm_only` 单用时保持原有无标记形态,故复用同一
  代码路径的 `web.wasm.list` 回复逐字节不变。空白过滤串按「无过滤」处理。这是修改既有工具而非新增,工具面计数不变。单测(`test_web_scripts_fields.py`):url 子串大小写、落空给出空的已过滤列表、
  与 `wasm_only` 相 AND 且 `captured` 为整环、空白串忽略、`wasm_only` 单用形态不变。实机 gate(`test_web_re_gate.py`)对真实 Chrome 解析出的 `app.js`:`url_contains="app.js"` 留住它并置 `filtered`、
  无意义子串给出空的已过滤视图——端到端走真实 CDP 脚本捕获而非单测 fake。

- **新增 `apk.disassemble`:直接从 androguard 读出某方法的 Dalvik 字节码指令,回答 `apk.xrefs` 只能指到而答不出的「这个方法到底做了什么」。** 现有反编译 `apk.decompile`(jadx,需 Java/JRE)与
  `apk.decode`(apktool 的 baksmali)都依赖外部工具,本机没装就用不了;本工具走 androguard 的 `EncodedMethod.get_instructions`,**不需要 jadx/JRE 或 apktool**,与 WASM 那套无依赖二进制读取同一思路。
  按 `class_name`+`method_name` 定位(类名接受点分 `com.example.X` 或 smali `Lcom/example/X;` 两种形式);方法名有重载时,`overloads` 列出该名下所有描述符、默认按描述符排序取第一个,传 `descriptor`
  可指定某一个。每行含 `idx`、`addr`(代码单元偏移,故分支目标可对齐)、`mnemonic`(Dalvik 操作码,如 const-string/invoke-virtual)、`operands`。另回 `class_name`/`method_name`/`descriptor`/`access`/
  `count`/`total`/`offset`/`has_more`/`scan_capped`/`overloads`:`total` 是收集到的指令数(上限 20000,超出置 `scan_capped`),`count` 可能因结果预算裁剪(单条 const-string 操作数可达 2000 字符)低于
  `limit`,按 `has_more` 翻页。未知类/方法报 `not_found`,空 `class_name`/`method_name` 报 `invalid_params`。抽象/native 等无代码方法给出空指令列表而非崩溃。工具面 271→**272**(154→**155** 只读,写不变)。
  单测(`test_apk_fields.py`):callee 的两条指令带正确代码单元偏移与 marker 操作数、点分类名解析到 smali 类、重载列全并由 `descriptor` 选定、未知方法 `not_found`、空参 `invalid_params`、长方法分页。
  实机 gate(`test_m11_android_apk_live_gate.py`)对真实 dex:`callee` 反汇编含 `const-string` 且操作数带 `APK_GATE_MARKER_STRING`、首指令 `addr` 为 0、`overloads` 恰一条;`caller` 反汇编含 `invoke` 且操作数
  指向 `callee`——读的是真实 `EncodedMethod.get_instructions` 路径,而非 mock。

- **新增 `apk.intent_filters`:列出各组件声明的 intent-filter——Android 的深链接/IPC 入口面,即 `apk.components` 只回答「谁被导出」之外的「怎么被触达」。** 深链接劫持与导出组件是 Android 最典型的攻击面,
  但此前只能拿到导出组件名,拿不到到达它们的 action/scheme/host/path。androguard 无结构化 intent-filter getter,故沿用 `_exported_components` 那套:从解码后的清单树(`get_android_manifest_xml`)遍历每个
  声明了 `<intent-filter>` 的组件,记录组件 FQN、类别(activities/services/receivers/providers)、是否导出(有 filter 即导出,除非显式 `android:exported="false"`——显式属性优先),以及每条 filter 的 `actions`、
  `categories`、`data`(每个 `<data>` 元素声明的 android:* 属性:scheme/host/port/path/pathPrefix/pathPattern/mimeType/ssp 等,原样按元素报出而不猜测 Android 的跨元素合并,故调用方看到的是清单真正声明的
  scheme/host,而非拼出的可能错误的 scheme://host)。每条 filter 另带 `deep_link`:当它是典型可浏览 Web 入口(VIEW action + BROWSABLE category + 带 scheme 的 data)时为真——最该先看的劫持面。仅列出至少有
  一条 filter 的组件;回 `components`/`count`/`total`/`offset`/`has_more`/`scan_capped`,`total` 上限 256(超出置 `scan_capped`),`count` 可能因结果预算裁剪低于 `limit`,按 `has_more` 翻页。清单不可解析时降级为
  空列表而非抛错;抽象等无关组件不出现。这是纯清单读取(不触 DEX),用 `_apk` 轻量对象。工具面 272→**273**(155→**156** 只读,写不变)。单测(`test_apk_intent_filters.py`,复用导出组件测试的
  真·lxml 清单树形制):只列有 filter 的组件、深链接 flag 与 data 属性读出、MAIN/LAUNCHER 不算深链接、`exported="false"` 压过 filter 但 filter 仍报出且 `deep_link` 仍为真、receiver 归到 receivers、无 filter
  清单为空、清单抛错降级为空。实机 gate(`test_m11_android_apk_live_gate.py`)对真实 AXML:本夹具 MainActivity 无 intent-filter,故读回空组件列表与 `total` 0——证明遍历在真实解码路径上跑通且诚实降级
  (空而非崩),与上面导出检查同一层级;填充形态由 crafted 清单单测覆盖。

- **新增 `wasm.sections`:结构化列出一个 `.wasm` 模块的段布局——即模块的二进制骨架,是逆向一枚 WASM 时最先要看的「地图」。** 此前段布局只有 `wasm.info` 能给,而它回的是 `wasm-objdump -h -x`
  的原始文本、且**需要装 wabt**(本环境正是没有的情形);想按 id/大小/条数分流只能自己 parse 那段文本。新工具承接 `wasm.imports`/`exports`/`names` 的二进制读取思路,直接走模块顶层段、**不需要
  wabt**、不随其版本漂移。每行含 `id`、`name`(well-known 段名:`type`/`import`/`function`/`table`/`memory`/`global`/`export`/`start`/`element`/`code`/`data`/`data_count`/`custom`,未知 id 以十六进制字节
  可见而非丢弃)、`size`(段体声明的字节长度)、`offset`(段体在文件中的起始偏移)。自定义段(id 0)另带 `custom_name`——因所有自定义段共用 id 0,只能靠各自开头自带的段名区分是 `name`/`producers`/`.debug_*`
  中的哪一个。带向量计数的段(type/import/function/table/memory/global/export/element/code/data)与 data_count 段另带 `count`,即段头声明的条目数,只从段体开头那个整数廉价读出而不解码整段(注意此每行
  `count` 是段内条目数,区别于顶层 `count` 即本页行数)。回 `sections`/`count`/`total`/`offset`/`has_more`/`incomplete`:某段声明的大小越过缓冲区或触达段数上限时 `incomplete` 为真,故部分地图不被读成完整布局;
  读段自身开头的 name/count 隔离在该段体内(已被切片边界核查),故某段谎报内部长度只会让该行省略 `custom_name`/`count`,不污染顶层遍历。工具面 273→**274**(156→**157** 只读,写不变)。单测
  (`test_wasm_imports_exports.py`):type+import+export 三段地图带正确 id/name/count 与偏移不越界、自定义 `name`/`producers` 段按 `custom_name` 区分且不带 `count`、data_count 段读出其单一计数、未知 id 以
  十六进制呈现、段越界置 `incomplete` 且只保留已成功走完的段、非模块硬报错、WasmClient 无 wabt 也能分页读盘、缺文件报 `not_found`。实机测试(`test_m11_wasm_live_gate.py`,因不需 wabt 故不 skip)对真实
  wat2wasm 产物读回 type/export/code 段与各自条数、段按文件序升序且不越界,并对带 name 段的模块经 `custom_name` 认出自定义 "name" 段。

- **新增 `wasm.strings`:从一个 `.wasm` 模块的 Data 段抽取可打印字符串——即模块内嵌的字面量池(URL、API 路径、格式串、错误文本),是 `pe.strings` 的 WASM 版。** 此前 WASM 域看不到这层:`wasm.info` 只给段头
  文本、`wasm.imports`/`exports` 只给宿主边界,字面量池无从查。新工具承接 `wasm.imports`/`exports`/`names`/`sections` 的二进制读取思路,直接走 Data 段各数据段(active/passive、MVP 与 bulk-memory 两种编码都
  认)、跳过 active 段的 offset 初始化表达式,再从段字节里抽出长度不小于 `min_length`(默认 4)的极大可打印 ASCII 串——同样**不需要 wabt**、不随其版本漂移。回 `strings`(去重且排序)/`count`/`total`/`offset`/
  `min_length`/`data_segments`/`has_more`/`incomplete`;`contains` 只保留含该(大小写不敏感)子串的串并置 `filtered`(空过滤忽略),`total` 为过滤后的可分页条数,`data_segments` 为扫过的段数。防敌意:单串超
  256 字符即切分(不让一个巨大 run 独吞成一条)、去重串数触顶即停并置 `incomplete`;offset 初始化表达式只「跳过」不求值,遇不认识的段 flag 或无法跳过的 opcode 便停并置 `incomplete`——绝不猜段字节起点而把随后的
  向量长度误读成数据。工具面 274→**275**(157→**158** 只读,写不变)。单测(`test_wasm_imports_exports.py`):可打印 run 抽取与 min_len 下限、单串切分不超上限、去重触顶置 incomplete、active/passive/带 memidx 三种段
  flag 均解、global.get 的 offset 表达式可跳过、未知 offset opcode 停并置 incomplete、段越界置 incomplete、无 Data 段为空而非报错、非模块硬报错、WasmClient 无 wabt 也能过滤分页读盘且 `min_length` 下限被夹到 1、
  缺文件报 `not_found`。实机测试(`test_m11_wasm_live_gate.py`,因不需 wabt 故不 skip)对含内存+一 active 数据段的真实模块读回两个字面串、按 `min_length` 抬高下限筛除短串、按大小写不敏感子串过滤。

- **新增 `wasm.functions`:列出一个 `.wasm` 模块自己*定义*的函数表——每个函数的绝对索引、类型索引、解析出的签名与(带 name 段时的)调试名。** 此前 `wasm.imports`/`exports` 给的是宿主边界、`wasm.names` 给的是
  名字映射,但「这个模块定义了哪些函数、各是什么签名」——逆向一枚 WASM 时用来导航的函数表——没有一个工具直接给出;没有它,内部函数只是一串没有签名也没有名字的索引。新工具直接读 Function 段(id 3,
  每个已定义函数一个类型索引),并就地对齐 Type 段(解析 `params`/`results`)、Import 段(数出被导入的函数数,作为索引偏移)与自定义 name 段(补 `name`),故与 `wasm.imports`/`sections`/`names` 同为**纯 Python
  读二进制、免 wabt、不随其版本漂移**;输入超 16 MiB 按 `too_large` 拒绝。每行含 `index`(绝对函数索引——WASM 的函数索引是「先导入后定义」,故已定义函数的绝对索引 = 被导入函数数 + 它在 Function 段里的位次,
  这也正是 name 段与 call 指令用的编号)、`type_index`,以及(当 Type 段能解析该索引时)`params`/`results`(valtype 名),带 name 段时另有 `name`。**只列已定义函数**——被导入的函数属于 `wasm.imports` 而不进此表。
  回 `functions`/`count`/`total`/`offset`/`declared`/`has_more`/`incomplete`:`total` 是实际解析出的可分页条数、`declared` 是段头声明的条数,二者因截断或触达条目上限而背离时 `incomplete` 为真,故短列表不被读成完整函数表;
  预算裁剪落到 `has_more`,可继续翻页。工具面 275→**276**(158→**159** 只读,写不变)。单测(`test_wasm_imports_exports.py`):两个已定义函数带签名与绝对索引、索引在被导入函数之后偏移(一个 func 导入 + 一个 memory 导入,
  已定义函数落在绝对索引 1)、name 段补名、未知类型索引只留 index/type_index 而不臆造签名、无 Function 段为空而非报错、段截断置 incomplete、非模块硬报错、WasmClient 无 wabt 也能分页读盘且列表字段名为 functions、
  缺文件报 `not_found`。实机测试(`test_m11_wasm_live_gate.py`,因不需 wabt 故不 skip)对真实 wat2wasm 产物读回其唯一定义函数(绝对索引 0、类型 0、签名 (i32,i32)->i32),并对带一个 func 导入但无 Function 段的模块确认
  已定义函数数为 0(证明被导入函数不进此表)。

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
