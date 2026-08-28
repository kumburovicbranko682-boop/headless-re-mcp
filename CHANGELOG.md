# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

## [Unreleased]

本轮在既有 PE 逆向能力之外新增 Android 与 Web 两个目标域，并把监控台重做成对话居中的
Agent 工作台。工具面从 199 增至 **284（166 只读 / 118 写）**；读写分级在
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

### 修复（合并回归：成功路径残留进程与 UI 捕获错误码）

- die/exeinfope/upx 的 `_capture_process` 重新在**成功**退出后清点并回收启动器遗留的
  detached helper（`terminate_leftover_process_tree`：ppid 遍历 + 会话组扫描,按各自
  `pgrp` 逐个击杀,避免组长 pid 复用误伤）。该行为随「Reap helpers after successful CLI
  launches」引入,但在与 `_capture_process` 读者自闭管道范式收敛的合并中被覆盖丢失,
  只有 de4dot 保留了等效逻辑;本次按现行 process_tree API 重建并接回三处。
- `ui.screenshot` / `ui.ocr` 对路径穿越型 session id 现在在**任何平台**都返回
  `invalid_request`:输入校验挪到 Windows 平台门之前,Linux 上不再把敌意输入报成
  `unsupported_on_platform`。

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
- **`frida.modules`/`exports`/`imports`/`memory.read` 只认本机 PE 调试对象，绑了设备也读不到目标进程**。
  这四个原生读一律走本机 `frida.attach(pid)`（PE debuggee 那条路径），所以会话一旦
  `frida.device.connect` + `frida.spawn` 绑到 USB/模拟器/远程、拿到设备侧 pid，想枚举某个
  `.so` 的模块/导出/导入（例如在 `libssl.so` 里定位 `SSL_write` 去 hook）或读设备内存，
  要么无从下手、要么静默 attach 到本机同名进程——这恰是 Android 原生逆向的第一步。现在这四个
  工具与 `frida.hook.template` 走同一条双路径路由：会话元数据 `frida_authorized` 里有已授权 pid
  时，针对该设备进程的最近授权 pid 执行；否则回落到本机 debuggee。新增的设备侧
  `modules_device`/`exports_device`/`imports_device`/`memory_read_device` 把 attach/load/RPC
  整体交给 `_run_deadline` 有界（与 `java_enumerate` 一致），卡死或暂停的目标进程不再占住 worker；
  pid 必须落在本会话已授权集合内，否则在解析设备之前就 `permission_denied`。分页、`name_filter`、
  `has_more` 与 `address` 校验（`[0, 2**64)`、非法值 attach 前即拒）经 `_run_enum` 由本机/设备两路
  共用，回包字段与本机路径逐字一致；本机 PE 路径行为未变。

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
  循环。`tests/integration/test_proxy_lifecycle_gate.py` 会真实起停并断言端口确实被释放。
- **抓包缓冲无界**。摘要环是有界的，但保存完整 flow 对象（含报文体）的那份是普通 dict，
  永不淘汰——一夜的抓包足以把宿主机内存吃光。现在两者同步淘汰，取不到的 flow 会明确告知
  已被环形缓冲淘汰，而不是假装不存在。
- **`proxy.export_har` 落盘无界**。摘要环有界，但每条摘要可带 16 KiB 的 URL，跑满的 2000 条
  一次序列化就是几十 MiB；`_register_capture` 只登记不设自己的字节上限，于是一个无人值守的
  `proxy.export_har` 每调一次就往产物根加那么多。`web.har_export` 早就按 `UNREGISTERED_CAPTURE_
  MAX_BYTES` 丢条目收敛，proxy 这条一直没有。现在与它对齐：丢到装得下为止、回 `truncated` 与
  `size`，落盘的仍是完整合法的 HAR（不是被字节截断的碎片），装不下最小 HAR 时回 `too_large`。
- **APK 分页在 Agent 传输上不受约束**。`apk.classes/methods/strings/xrefs` 的 `offset`/`limit`
  边界只写在 MCP 输入 schema（`offset>=0`、`limit<=cap`）里；但 Agent 编排器经
  `catalog.invoke` → `handler(**arguments)` 直接调用处理器，不跑 pydantic 值校验，模型给的负
  `offset` 会把 `names[offset:offset+limit]` 变成尾部切片、悄悄把列表末尾当第零页返回，超额
  `limit` 则无视页上限（`apk.xrefs` 更是完全没有上限）。web/proxy/frida/adb 后端早就无论走哪条
  传输都自行 clamp；APK 这条没有。现在后端统一 clamp（`offset` 归零下限、`limit` 收到与 schema
  一致的页上限），两条传输行为一致。
- **子进程后端的 `timeout` 上限只写在 schema 里**。`apk.decompile/export_sources/decode/repack/sign`
  与 `js.deobfuscate/beautify/unpack_bundle`、`wasm.wat/info` 的 `timeout` 上界（`le=600/1200/1800`）
  只在 MCP 输入 schema 里；但 Agent 编排器经 `catalog.invoke` → `handler(**arguments)` 直接调用，
  不跑 pydantic 值校验，模型给的超大 `timeout` 会原样流进 `run_bounded`，一个无人值守的
  jadx/apktool/webcrack 就能远超 schema 上限地占着一个核（和样本文件锁）。Frida 后端早有
  `_bound_timeout` 收敛，这三条子进程后端没有。现在各自按对应工具的 schema `le` 在后端 clamp，
  两条传输行为一致。
- **`web.open`/`web.navigate` 的 `timeout` 只在 schema 里有界**。上界 `le=120.0` 只写在 MCP 输入
  schema；Agent 编排器经 `catalog.invoke` → `handler(**arguments)` 直接调用，不跑 pydantic 值校验，
  于是模型给的超大 `timeout` 会让 `page.goto` 等 `timeout*1000` 毫秒、`_Runner` future 等
  `timeout+30` 秒——一次导航到卡死页面就能把浏览器工作线程占到远超上限。更糟的是 `gt=0` 下界同样
  被绕过：非正 `timeout` 传到 `page.goto` 就是 `timeout=0`，Playwright 读作「永不超时」，成了无界等待。
  现在后端按 schema 上限 clamp、非正值回落到 schema 缺省（30s），与 Frida/子进程后端一致。
- **`web.scripts` 无法只看运行时生成脚本，也不能按 URL 定位**。给它加上 `dynamic_only` 与 `url_filter`：前者只留
  `dynamic=True` 的脚本（`eval`/`new Function`/注入 `<script>`，其 url 通常为空，正是加壳器解包后 payload 的落点，url 过滤够不着），
  后者对 url 做大小写不敏感子串匹配；二者都在分页前应用，于是 `total` 即匹配数——在解析了成百上千脚本的页面上直接锁定目标。
- **`frida.applications` 是唯一没有名字过滤的 frida 枚举器**。`frida.modules`/`exports`/`imports`/`java.classes`/`java.methods`
  早都有 `name_filter`，但列设备已装应用的这个只有 `limit`——满是应用的真机上，目标 app 落在前 `limit` 个之后就够不着了。补上
  `name_filter`：对 `identifier` 或显示 `name` 做大小写不敏感子串匹配、在 cap 之前应用，于是排在后面的目标也能捞出、`total` 即
  匹配数。与 `device.packages` 一样是进程内过滤（非在 agent 内 JS 过滤）。
- **`device.packages` 只能分页翻，装了几百个包时定位目标全靠运气**。它原来只有 `third_party_only` 和 `limit`，没有名字过滤——
  在包很多的真机上，要找的包（`com.evil…`）可能落在 `limit` 之后就够不着了。加上 `name_filter`：对包名做大小写不敏感子串匹配、
  在 cap 之前应用，于是目标包即便排在前 `limit` 个之后也能捞出来，与 `apk.classes`/`apk.strings` 及 web/proxy 列表过滤同一套路。
  过滤在进程内做，**不**拼进设备端的 `pm` 命令（`dev.shell` 会走设备 `sh`），所以不可能注入 shell token，延续「无 `adb shell` 透传」的约束。
- **`apk.native_libs` 只给裸路径，看不出哪个 `.so` 是加壳后的大 payload**。它原来把每个原生库当成一个字符串路径返回，是整个
  apk 面里唯一没用富对象的列表（`certificates`/`components` 早已是带字段的对象）。现把每个条目改成 `{path, abi, size}`：`abi`
  取 `lib/<abi>/` 目录（直接挂在 `lib/` 下的散文件为空），`size` 是从 zip 中央目录读到的**未压缩**字节数——不解压、不读内容即可
  凭元数据把体积异常的 payload `.so` 标出来（元数据读不到时才省略 `size`）。`abis` 仍是去重排序的 ABI 集合，`count`/`has_more`
  不变。
- **`web.cookies` 缺席：浏览器的 cookie jar 只能从抓包的 Set-Cookie 头里零散拼**。抓包里的 Set-Cookie 只是某一次响应的片段，
  而 web RE 真正要的是当前完整的 jar——JS 通过 `document.cookie` 写入的、跨若干次重定向（其请求早被环形缓冲淘汰）累积的、以及
  页面自身脚本读不到的 HttpOnly cookie（会话/鉴权令牌往往正是这类）。新增只读工具 `web.cookies`，走 CDP `Network.getAllCookies`
  一次性读出整个 jar：返回 `name`、`value`（按上限裁剪并标 `value_truncated`）、`domain`、`path`、`http_only`、`secure`、
  `session`，以及浏览器给出的 `expires`/`size`/`same_site`；先按 `_MAX_COOKIES` 限制采集面（jar 更大时置 `collection_truncated`），
  `domain_filter` 对域名做大小写不敏感子串匹配、在分页前应用，把应用自身 cookie 从第三方追踪里择出来。工具总数 267→268。
- **`web.storage` 缺席：令牌的另一半藏在 localStorage 里却读不到**。`web.cookies` 补齐了 cookie jar，但现代 SPA 的 JWT/刷新令牌
  和应用配置往往存在 `localStorage`/`sessionStorage`，而非 cookie——抓包的 Set-Cookie 够不着，页面自身的 `document.cookie` 也读不到。
  既然设计上不开放任意 JS（无 `web.evaluate`），就沿用 `web.dom.snapshot` 已在用的**定长内嵌脚本**范式（调用方只选 area，永远不提供代码），
  新增只读工具 `web.storage`：`kind` 选 `local`（默认，跨标签页/重启持久）或 `session`（单标签页），其它值 `invalid_params`；只读顶层文档
  所属源（跨源 iframe 的存储不含在内）。返回 `storage`（每项 `{key, value}`，`value` 超限裁剪并标 `value_truncated`）、`kind`、`origin`
  （条目所属源）、`count`/`total`/`offset`/`has_more`，以及 store 条目数超采集上限时的 `collection_truncated`；`key_filter` 对键做大小写
  不敏感子串匹配、在分页前应用，故 `total` 为匹配数。计数与单值都在浏览器内先行设限（`_MAX_STORAGE_ITEMS`/`_MAX_STORAGE_VALUE`），
  百万键或数 MB 的值都不会整体序列化进本进程。`data:`/`about:blank` 这类不透明源没有存储，返回 `invalid_state`（提示先导航到 http(s) 页面）
  而非伪装成空 jar。只读，工具总数 272→273（155 只读 / 118 写）。
- **`web.cookies`/`web.storage` 只读顶层文档所属源，页面里嵌的 iframe 及其独立源根本看不见，动态 web 线缺一张"页面由哪些框架组成"的图**。
  `web.cookies`、`web.storage` 明说只覆盖顶层源，`web.dom.snapshot` 也只是顶层文档的 HTML——而现代页面把登录/支付/验证码/广告放进
  跨源 iframe，这些框架的源、存储、cookie 都是另一条边界，此前没有工具能把它们列出来。新增只读工具 `web.frames`：走 CDP
  `Page.getFrameTree` 把框架树按广度优先摊平成每帧一行。答复带 `frames`、`count`、`total`、`offset`、`has_more`，页面嵌套超
  1024 上限时置 `frames_truncated`。每行 `{frame_id, url, security_origin, depth, is_main}`，浏览器给出时再带 `parent_id`
  （外层帧 id，主帧没有）、`name`（iframe 的 name 属性）与 `mime_type`；主帧 `depth` 为 0、`is_main` 为真居首，子帧紧随其父，
  故从扁平表经 `parent_id` 即可重建嵌套。`url_filter` 对帧 url 做大小写不敏感子串匹配、在分页前应用，故 `total` 为匹配数——在
  一堆第三方追踪帧里定位某个内嵌源的办法。于是 `web.frames` 补上了 `web.cookies`/`web.storage`/`web.dom.snapshot` 看不到的那部分
  页面，某个跨源 iframe 的 `security_origin` 成为下一步的支点。树用带上限的队列摊平（而非递归），病态深嵌套也压不爆栈。只读，
  工具总数 280→281（163 只读 / 118 写）。
- **`proxy.start` 同样不限并发实例，跨会话可无界累积线程与抓包缓冲**。每个活的代理都占一个事件循环线程、一个绑定端口，并可
  保留至多 `_MAX_RETAINED_BYTES`（64 MiB）的抓包体；单会话有「一会话一代理」和端口占用检查约束，但总数无界——一个在多会话
  间反复 `proxy.start` 的调用方能攒下 N 个线程和 N×64 MiB。仿照刚给 web 加的并发上限，加上 `_MAX_PROXIES`（8）：持锁、在
  绑定端口/启动线程之前校验，超限返回 `invalid_state`（附 `cap`/`held`），提示先 `proxy.stop`。被拒的 start 绝不绑定端口或泄漏预留。
- **`web.open` 不限并发，浏览器会话可无界堆叠拖垮宿主**。每个 `web.open` 都持有一个活的 Chromium（独立进程树、数百 MB
  内存），但后端从不限制同时打开的会话数——一个忘记 `web.close` 的调用方或跑飞的 agent 循环能一直 fork 浏览器直到宿主被
  耗尽。仿照 adb 后端限制并发端口转发的做法，加上 `_MAX_WEB_SESSIONS`（8）：在持锁、且在 import playwright、启动浏览器
  之前就校验，超限的 `open` 返回 `invalid_state`（附 `cap`/`held`），提示先 `web.close` 一个，而不是启动第九个浏览器再崩。
  被拒的 open 绝不会占用槽位或泄漏预留。
- **`frida.imports` 缺席：能列一个原生模块导出什么，却看不到它调用什么**。`frida.exports` 回答"这个 `.so` 提供哪些符号"，
  但拿到一个陌生原生库时，分析者的第一问往往是反过来的——"它依赖什么"：`dlopen`/`JNI_OnLoad` 说明它在动态加载或桥接 Java，
  `system`/`ptrace` 是行为线索。新增 `frida.imports`，用 `Module.enumerateImports` 完整镜像 exports 那条路径：同样的
  在 agent 内先按子串过滤再取上限（`limit+1` 分页、无 offset），返回 `found`/`module`/`base` 与 `imports`（`name`、`type`、
  提供方 `module`、绑定后的 `address`），以及 `count`/`has_more`，只作用于 debuggee pid。工具总数 266→267。
- **`apk.callees` 缺席：能查一个 DEX 方法被谁调用，却看不到它调用了什么**。`apk.xrefs` 用 androguard 的
  `MethodAnalysis.get_xref_from()` 回答"谁调用了这个方法"，但拿到一个混淆过的方法时，分析者的第一问往往是反过来的——
  "它做了什么"：它触及的框架/库 API（`Cipher.doFinal`、`Runtime.exec`、`HttpURLConnection`、某个 JNI native）就是不反编译也能
  看清方法意图的最快读法，正如 `frida.imports` 之于 `frida.exports`。新增 `apk.callees`，用 `get_xref_to()` 镜像出这条出边方向：
  同样的可选 `class_name` 声明类限定（点分或 `Lsmali/` 形式，避免在混淆 app 里把同名方法的调用目标混作一团并撑爆采集上限）、
  同样的 `offset`/`limit` 分页、`total`/`has_more`/`scan_capped`。每行是 `{class, method, descriptor, external}`，其中
  `external` 为真标记不在本 app 内定义的框架/库目标——正是 JNI/加密/exec/网络这些一眼要找的调用面。与 `apk.xrefs` 逐调用点
  列出不同，`apk.callees` 按 `class+method+descriptor` 去重、只列去重后的目标集合，因为这里的价值是"触及了哪些 API"而非"各调用几次"。
  只读，工具总数 269→270（153 只读 / 117 写）。
- **Frida 原生线只能按已知 needle 搜内存，无法发现未知字符串**：`frida.memory.scan` 要你先知道要找什么，而 r2.strings /
  apk.strings 那种"把所有可打印字符串抓出来"的发现步骤在活进程上没有——偏偏运行时才解密的 C2 URL、密钥料、脱混淆
  日志行只存在于活内存里，静态扫壳后的二进制只看得到密文。新增只读工具 `frida.strings`：按 protection 掩码遍历内存段，
  逐段（有每段字节上限）抓取可打印 ASCII 串。返回 strings（每项 {address（串起始处，可直接喂给 frida.memory.read）、
  value（可打印串，超 512 字符截断并置 value_truncated）}）加 count、scanned_ranges、truncated（命中串数/段数/每段字节
  上限，可能还有更多）。min_length 丢弃过短串（默认 4，即 strings(1) 下限；调高降噪）；protection 同 frida.memory.ranges
  的 r/w/x 掩码（默认 'r--' 抓可读段，'rw-' 收窄到解密数据常驻的可写段）；name_filter 在封顶前于 agent 内按子串过滤
  （目标 token 可直达）；无 offset。目标为本会话已授权设备 pid（frida.device.connect + frida.spawn），否则本地被调试
  进程。是 frida.memory.scan（已知 needle）之外的发现步骤，也是每条静态线都有的 strings 提取在活进程上的对应物。
  只读，工具总数 316→317（197 只读 / 120 写）。
- **Frida Java 线读不到无实例的静态常量**：`frida.java.instances` 需要堆上存在活实例才能反射字段，而应用常把硬编码
  API key、base URL、加密密钥、功能开关放在从不实例化的工具/配置/加密类的 static final 字段里——这类类 instances
  够不到。新增只读工具 `frida.java.static_fields`：直接在 Class 上反射静态字段（`f.get(null)`），无需实例。返回 fields
  （每项 {name、type、value——字段 toString，超 512 字符截断并置 value_truncated；反射被拒为 '<unreadable>'、null
  字段为 'null'、is_final 标记常量}）加 class_name、count、has_more。只读本类声明的静态字段、不含继承字段（实例字段
  走 frida.java.instances）；byte[]/对象字段显示其 Java toString 而非内容；name_filter 在封顶前按字段名子串过滤
  （KEY/URL/TOKEN 之类可直达）；无 offset；class_name 必须是精确已加载类名，未知类为 backend_error。目标为本会话已
  授权设备 pid（frida.device.connect + frida.spawn），否则本地被调试进程；仅 ART。往往是静态 apk 线只能看到混淆值的
  硬编码密钥最快的一击。只读，工具总数 315→316（196 只读 / 120 写）。
- **Frida Java 线只能枚举类与方法，读不到运行时对象**：`frida.java.classes` / `frida.java.methods` 能告诉你某个类已
  加载、声明了哪些方法，却无法看到堆上此刻真实存在的实例及其字段值——而运行时的配置/会话/加密对象里正装着 base
  URL、bearer token、解密后的密钥、功能开关，是静态 apk 线够不到的答案。新增只读工具 `frida.java.instances`：用
  `Java.choose` 遍历目标进程堆上某个类的存活实例，对每个实例反射 `getDeclaredFields` 快照字段。返回 instances（每项
  {fields（每个 {name、type、value——字段 toString，超 512 字符截断并置 value_truncated；反射被拒时为 '<unreadable>'、
  null 字段为 'null'}）、field_count（过滤后、逐实例封顶前的声明字段数）、fields_truncated}）加 class_name、count、
  has_more。只读本类声明的字段、不含继承字段（与 frida.java.methods 一致）；name_filter 在 max_fields 封顶前按字段名
  子串过滤（token/key/url 之类可直达而非被埋）；max_fields 界定每实例字段数、limit 界定实例数（无 offset，用 name_filter
  收窄）；class_name 必须是精确的已加载类名，未知类为 backend_error。目标为本会话已授权的设备 pid（frida.device.connect
  + frida.spawn），否则本地被调试进程；仅 ART。只读，工具总数 314→315（195 只读 / 120 写）。
- **Ghidra 线补齐 strings→endpoints→secrets 三件套（与 r2/dotnet 对齐），并把原生线的聚合抽成共享层**：`ghidra.strings`
  之上新增两个只读工具，跑在 Ghidra 已定义的字符串数据上、复用共享的 `endpoint_scan.py` / `secret_scan.py`。`ghidra.endpoints`
  抽取 URL/host/请求路径，返回 endpoints（每项 {value、kind(url|path)、scheme、host、source（所在字符串）、address（Ghidra
  地址串，正是 ghidra.xrefs 需要的形式，可直接回溯到引用它的代码再 ghidra.decompile）、count}）加 hosts 去重集/hosts_truncated、
  offset/limit/total/has_more、scan_capped（已定义字符串多于 scan_limit）；include_paths 可关掉相对路径只留 URL。`ghidra.secrets`
  用同一套高精度检测器（外加 include_generic 高熵兜底）找硬编码凭据，返回 secrets（每项 {detector、value、source、address、
  count}）加 detectors、scan_capped。两者都支持 name_filter（分页前子串过滤、total 即命中数）与分页，scan_limit 界定扫描的已
  定义字符串数（Ghidra 自身上限 1024）；都一次性重导入二进制、需要 HEADLESS_RE_GHIDRA_HOME。同时把 r2/Ghidra 两条原生线
  重复的“去重/计数/挂引用/host 汇总/过滤/分页/封顶”聚合逻辑抽成 `backends/common/finding_aggregate.py`（`aggregate_endpoints`
  / `aggregate_secrets`，输入 `(text, ref)` 对，ref 按行合并进每条命中），r2 的适配器改为委托它、输出逐字段不变。都只读，
  工具总数 312→314（194 只读 / 120 写）。
- **原生二进制线（radare2）只有裸 strings，缺 endpoints/secrets**：js/apk/wasm/dotnet/web/proxy 都已有端点/凭据
  三件套，唯独原生线（ELF/Mach-O/PE）还要人肉 grep `r2.strings`。新增两个只读工具，都在 r2 恢复出的同一批字符串
  （radare2 `izj`，即 r2.strings 列出的那批）上复用共享的 `endpoint_scan.py` / `secret_scan.py`。`r2.endpoints`
  抽取 URL/host/请求路径，返回 endpoints（每项 {value、kind(url|path)、scheme、host、source（所在字符串）、count，
  以及 r2 给出的 vaddr 与 address(va/rva/module)，可直接喂给 r2.xrefs / r2.disasm 回溯到引用它的代码}）加 hosts 去重集/
  hosts_truncated、offset/limit/total/has_more、scan_capped（r2 返回超过 4096 条字符串、底层已被截断）；include_paths
  可关掉相对路径只留 URL。`r2.secrets` 用同一套高精度检测器（外加 include_generic 高熵兜底）找硬编码凭据，返回
  secrets（每项 {detector、value、source、count、vaddr、address}）加 detectors、scan_capped。两者都支持 name_filter
  （分页前子串过滤、total 即命中数）与分页；都一次性重开二进制、需要 PATH 上的 radare2 或 HEADLESS_RE_R2。都只读，
  工具总数 310→312（192 只读 / 120 写）。
- **.NET 静态线补齐 strings→endpoints→secrets 三件套（与 js/apk/wasm 对齐）**：在 `dotnet.strings` 之上新增两个
  只读工具，都跑在同一批 #US ldstr 字面量上、复用共享的 `endpoint_scan.py` / `secret_scan.py`。`dotnet.endpoints`
  抽取 URL/host/请求路径（回答「这个程序集与哪些后端通信」），返回 endpoints（每项 {value、kind(url|path)、
  scheme、host、source（所在字面量）、token（0x70xxxxxx 用户字符串 token，可经 dotnet.il 回溯到加载它的方法）、
  count}）加 hosts 去重集/hosts_truncated、offset/limit/total/has_more、scan_capped、has_us_heap；include_paths
  可关掉相对路径只留 URL。`dotnet.secrets` 用同一套高精度检测器（AWS/Google/GitHub/Slack/Stripe/JWT/私钥/
  basic-auth-URL，外加 include_generic 开启的高熵兜底）在这些字面量上找硬编码凭据，返回 secrets（每项
  {detector、value、source、token、count}）加 detectors、scan_capped、has_us_heap。两者都支持 name_filter（分页前
  子串过滤、total 即命中数）与分页；无 #US 堆时 has_us_heap=false、列表为空（这是答案而非报错），非 .NET 为
  not_dotnet/clr_unverified。都只读，工具总数 308→310（190 只读 / 120 写）。
- **.NET 这条线（inspect/enumerate/il/xrefs/deobfuscate）没有真正的「字符串」能力**：`dotnet.enumerate
  kind="strings"` 走的是 #Strings 堆（元数据标识符——类型/方法/字段名），而程序真正用 `ldstr` 加载的字符串常量
  （URL、端点、提示语、格式串、内嵌密钥）存在另一个 #US 用户字符串堆里，无工具可读。新增只读工具 `dotnet.strings`：
  纯 Python 从 CLR 元数据解码 #US 堆（UTF-16LE），是 apk.strings / js.strings / wasm.strings 的 .NET 对应物。
  返回 items（每项 {offset（在 #US 堆内的字节偏移）、token（`ldstr` 操作数携带的 0x70xxxxxx 用户字符串 token，
  故此处的字面量可经 dotnet.il 回溯到加载它的方法）、value（解码后按 4096 字符裁剪，超出置 truncated）、
  char_length}），外加 offset/limit/total/truncated/scan_capped（堆内条目超过 20000 收集上限）/has_us_heap，以及
  capability/backend/not_ida_idalib/claims_universal_unpack=false。`name_filter` 分页前按子串（大小写不敏感）过滤、
  total 即命中数；`min_length` 丢弃过短串。无 #US 堆时 has_us_heap=false、items 为空——这是答案而非报错；非 .NET
  输入为 not_dotnet/clr_unverified。只读，工具总数 307→308（188 只读 / 120 写）。
- **js.sourcemap 需要 `.map` 在磁盘上，但线上 SPA 的 map 通常是「服务出来的」而非落盘**。新增只读工具
  `web.script.sourcemap`：js.sourcemap 的动态对应物。它经 CDP 取到某个已解析脚本的源码，读末尾的
  `//# sourceMappingURL=`；内联 data: URI 直接解码，外部引用则在页面自身上下文里 `fetch`（`credentials: 'include'`，
  故同源或 CORS 放行、甚至带鉴权的 map 也能取到），再用共享的 source-map 解析器还原压缩前的原始源码。
  从 web.scripts 选 script_id。扁平 map 与索引 map（sections）都支持。两种模式与 js.sourcemap 一致：`extract` 为空
  时列出原始源（`sources`/`count`/`total`/`offset`/`has_more`/`sources_total`/`with_content`/`map`/`origin`，
  origin 为 inline|external:<url>），`name_filter` 分页前按名字子串过滤；`extract` 非空时返回该源原文（截断 2 MiB，
  附 `content_truncated`）。每次答复都带 `script_id`、`script_url`、`has_source_map` 及（若有）`source_map_url`。
  脚本没有 sourceMappingURL 时返回 `has_source_map: False` 空列表而非报错，方便廉价扫过 web.scripts；页面从未解析过
  的 script id 为 not_found；相对 map 但脚本无 URL 可解析为 invalid_state；浏览器取不到 map 为 backend_error 并带 url。
  只读，工具总数 306→307（187 只读 / 120 写）。
- **JS 这条线有 deobfuscate/beautify（只能把压缩代码重新排版），却没有 source map 支持——而真正的
  「反压缩」是拿回原始源码**。新增只读工具 `js.sourcemap`：一个 bundle 的 `.map` 在 `sourcesContent` 里带着
  压缩前的源码文本（原始标识符、模块结构、注释），把它捞回来远胜过给压缩代码重新排版。依赖无关（不走
  Node/webcrack），文件可读就能用。`path` 可以是 `.map` 本身，也可以是末尾带 `//# sourceMappingURL=` 的 `.js`
  ——内联 data: URI 或相邻 `.map` 文件都能解析；远程（http/协议相对）URL 不抓取，而是以 capability_unavailable
  连同 url 返回，因为该后端不做网络 I/O。扁平 map 与索引 map（`sections`）都支持。两种模式：`extract` 为空（默认）
  时列出原始源，答复 `sources`（每项 `{source（应用 sourceRoot 后的名字）, has_content（map 是否内嵌其文本）,
  length（该文本字符数）}`）、`count`、`total`、`offset`、`has_more`、`sources_total`、`with_content`（多少源带了文本）、
  `map`（`{version, file, source_root, index_map}`）与 `origin`（file|inline|external:<url>）；`name_filter` 按名字子串
  过滤、分页前应用故 `total` 是命中数。`extract` 非空时返回该源的原始文本：`matched`（先精确名匹配、再首个子串匹配），
  命中则给 `source`、`content`（截断到 2 MiB，附 `content_truncated`）、`length` 与 `has_content`。列表字段是 `sources`。
  缺文件 not_found；超 16 MiB too_large；`.js` 里没有 sourceMappingURL 且自身也不是 map 则 not_found。
  只读，工具总数 305→306（186 只读 / 120 写）。
- **Ghidra 这条线有 functions/symbols/xrefs/decompile，却没有字符串——于是「找到一个字符串→查谁引用它→
  反编译引用函数」这条链在 Ghidra 内部走不通，因为没法在 Ghidra 里发现字符串地址**。新增只读工具
  `ghidra.strings`：r2.strings 在 Ghidra 线上的对应物，列出程序里 Ghidra 分析标记为字符串的已定义数据，
  且用的是 Ghidra 自己的地址空间——拿到某字符串的 `address` 就能直接喂给 ghidra.xrefs 找引用者、再
  ghidra.decompile 那个函数，把这条链补齐。答复 `items`——每项带 `address`（Ghidra 地址串，正是 ghidra.xrefs
  要的形式）、`value`（字符串，截断到 2048 字符）、`type`（Ghidra 数据类型，如 string/unicode）与 `length`
  （该数据的字节长度），另带 `count` 与 `has_more`（填满 limit 的一页不会被误读成全部）。只列 Ghidra 已定义的
  字符串；恰好可打印的未定义字节不列（要原始扫描用 r2.strings）。和其他 ghidra 工具一样在 -deleteProject 下重新
  导入二进制，大文件耗时若干分钟，需要 HEADLESS_RE_GHIDRA_HOME。只读，工具总数 304→305（185 只读 / 120 写）。
- **r2.imports 只列从其他库拉来的重定位、r2.exports 只列动态导出表，两者都看不到非 strip 二进制里带名字的
  本地/内部符号**。新增只读工具 `r2.symbols`（走白名单命令 `isj`）：完整符号表，是 imports/exports 的超集。
  在非 strip 的 ELF/Mach-O 上它还能暴露那两者看不到的本地函数、数据对象、调试符号——当分析派生的
  r2.functions（aflj）只给出一堆无名块时，这就是要伸手去拿的「函数/名字清单」。答复 `items`——每项带 `name`
  （r2 反修饰成功时另带 `realname`）、`type`（FUNC/OBJ/SECTION/...）、`bind`（GLOBAL/LOCAL/WEAK）、`size`、
  `is_imported`、`vaddr` 与 `address`（va/rva/module），另带 `count`；无整数地址字段。列表触及 4096 上限时置
  `items_truncated`/`items_total`/`items_limit`；无 `symbols`/`truncated`/`has_more` 字段。只读，一次性重开二进制。
  工具总数 303→304（184 只读 / 120 写）。
- **radare2 这条跨平台二进制逆向线（ELF/Mach-O 等非 PE）有 info/functions/strings/imports/exports/disasm/xrefs，
  却缺最基础的一层：段/节表**。新增只读工具 `r2.sections`（走白名单命令 `iSj`）：frida.memory.ranges（映射活进程）
  的静态对应物，也是 PE 节表在 ELF/Mach-O 上的等价物。答复 `items`——每项带 `name`、`size`（虚拟大小）、`vsize`、
  `paddr`（文件偏移）、`vaddr`、`perm`（rwx 权限串）与 `address`（va/rva/module），另带 `count`；无整数地址字段。
  列表触及 4096 上限时置 `items_truncated`/`items_total`/`items_limit`；无 `sections`/`truncated`/`has_more` 字段。
  据此可判断某地址落在哪个段、代码段（r-x）到哪结束、某字符串/符号住在哪个节里。像其他 r2 工具一样一次性重开二进制。
  只读，工具总数 302→303（183 只读 / 120 写）。
- **`proxy.hosts` 把抓包按 host 汇总（太粗，看不出调了哪个 API），`proxy.flows` 每个请求一行（太细，繁忙抓包里翻不完），中间缺一层逆向真正想要的「API 清单」：
  这个 app 到底打了哪些 method+path 端点、各多少次、返回什么状态**。新增只读工具 `proxy.endpoints`：js/apk/wasm/web.endpoints（从静态代码抽端点）的动态对应物。
  它把留存的 flow 按 (method, host, 请求路径) 聚成一行，默认把路径里易变的段——纯数字 id、UUID、长 hex 块——折叠成占位符，故 /users/123 与 /users/456 合并成
  一条 `POST users/{num}`；`normalize=False` 则按精确路径分组。每行 `{method, host, path, flows（请求数）, failed（无响应数）, content_types（去重响应 MIME）,
  statuses（{状态码: 次数} 映射）}`，另带 `example_url`（一个带 query 的具体实例）与 `first_flow`（可丢给 proxy.flow.get / proxy.replay 的 flow id），
  该行自身的类型/状态集合溢出上限时置 `truncated`。答复还带 `total`（name_filter 后的去重端点数）、`total_flows`、`dropped`（环形逐出）与 `endpoints_truncated`
  （去重端点总数触及 5000 上限）。按 flows 降序（最忙端点在前）再 host、path、method 排序。`content_type_filter` 先收窄参与聚合的 flow——传 'json' 就把 API 面
  从 image/script/css 噪声里拎出来；`name_filter` 再对 method/host/path 做大小写不敏感子串匹配、分页前应用，故 `total` 是命中数。列表字段是 `endpoints`。
  只读，工具总数 301→302（182 只读 / 120 写）。
- **有了 `frida.memory.ranges` 能看内存图、`frida.memory.read` 能按地址读，却仍缺最关键的一步：在运行进程里「找」东西**。新增只读工具 `frida.memory.scan`：
  短命探针注入，按 protection 掩码枚举内存段并对每段跑 `Memory.scanSync`，把运行时才解密出来、只存在于活进程内存里的密钥/令牌/结构体特征变成一个地址，
  可直接丢给 `frida.memory.read` 读上下文。`pattern` 支持两种解读：`pattern_type='text'`（默认）把字符串按 utf-8 编成字节模式（找已知令牌或错误串），
  `'hex'` 接受 Frida 匹配模式——空格分隔的字节对加 `??` 通配（如 'de ad ?? ef'，找 magic/签名）；全通配或格式错误的 hex 是 invalid_params。`protection`
  与 ranges 同为三位 r/w/x 掩码：默认 'r--' 扫可读段，'rw-' 收窄到可写段（运行时解密密钥的落脚处，通常正是要找的地方）。答复带 `matches`（每个 `address`、
  `size`、`protection`、`file`（映射路径或匿名 ''））、`count`、`scanned_ranges`（访问了多少段）与 `truncated`（命中数、段数或单段字节任一上限被触及，可能还有更多——
  收窄 pattern/protection 或把 limit 提到上限 1024）。没有 offset：扫描是一次性有界操作，不分页；即使本地路径（无探针 deadline）也被「最多 1024 命中 / 4096 段 /
  单段 128 MiB」硬上限约束，不会失控。目标与其它 frida 探针一致：会话已连设备时用其授权 pid，否则用本地被调试进程。列表字段是 `matches`，与 ranges/read 一起
  构成「看图→扫描→读取」的运行时内存取证闭环。只读（读内存、不写），工具总数 297→298（180 只读 / 118 写）。
- **Frida 线能 `frida.memory.read` 从一个地址读字节，却没有任何工具告诉你「哪些地址是映射的、可读还是可写、背后是哪个模块」——而运行时解密出来的密钥/令牌恰恰
  落在可写匿名区里，你得先看到内存图才知道去读哪儿**。新增只读工具 `frida.memory.ranges`：短命探针注入 `Process.enumerateRanges`，列出目标进程的映射内存段。
  答复带 `ranges`（每段 `base`、`size`、`protection`（如 'rw-'、'r-x'）、`file`（映射文件路径，匿名段为 ''））、`count`、`total` 与 `has_more`，故填满一页
  不会被当成整张图。`protection` 是三位 r/w/x 掩码（'-' 为通配），直接传给枚举器：默认 'r--' 列出 read 能碰的可读段，'rw-' 收窄到可写段（运行时解密密钥落脚处），
  '--x' 到可执行代码，'---' 到全部。`name_filter` 再对映射文件路径做大小写敏感子串匹配、在截断前应用，故某个库的映射（如 libssl）可达而非被埋在上限之外——没有
  offset。目标与其它 frida 探针一致：会话已连设备（frida.device.connect + frida.spawn）时用其授权 pid，否则用本地被调试进程；整套 attach/枚举/detach 受探针
  deadline 约束，故卡死的进程不会占住 worker。列表字段是 `ranges`，配合 `frida.memory.read` 构成「看图→读段」工作流。只读，工具总数 296→297（179 只读 / 118 写）。
- **`web.network.list` 只能告诉你页面「实际打过」哪些请求，但逆向真正想问的是「这页 JS 里配置了哪些后端」——那些被 feature flag / 角色门控、只在管理台或
  懒加载 chunk 里出现、正常会话根本不会触发的端点，网络日志里永远看不到**。新增只读工具 `web.endpoints`：`js.endpoints` 的动态页对应物、`web.network.list`
  的静态补充。它抓取页面已解析的每个脚本源码——包括壳/加载器在内存里 eval 出来、从不落盘的运行时脚本——用共享 JS 词法器（`\x`/`\u` 转义 URL 先解码、注释与
  正则里的引号不误判）提取带协议的 URL（http/https/ws/wss/ftp）以及（`include_paths` 时）请求路径（`/api/...`）。按 value 跨脚本去重，每行
  `{value, kind（url|path）, scheme, host, count（整页出现次数）, first_script（{script_id, url}，可直接丢给 web.script.source 的脚本）}`，按 count 降序再
  value 排序。答复另带 `hosts`（URL 端点的去重 host 集，过多置 hosts_truncated）、`scanned_scripts`、`scripts_dropped`（已解析脚本表环形逐出）与 `scan_capped`
  （脚本数、单源字节、总扫描字节或去重端点数任一触及上限——上限与 web.secrets 相同：最多 200 脚本、单源 4 MiB、总 64 MiB）。`url_filter`/`dynamic_only`
  先收窄扫哪些脚本（`dynamic_only` 专挑 eval/壳载荷）；WASM 脚本跳过。`include_paths=False` 只留绝对 URL、滤掉相对路径噪声。`name_filter` 再对 value 或 host
  做大小写不敏感子串匹配、在 host 汇总与分页前应用，故 `total` 是命中数。列表字段是 `endpoints`。只读，工具总数 295→296（178 只读 / 118 写）。
- **`js.secrets` 扫的是磁盘上的文件，但一个跑起来的页面里最值钱的一问是「这页 JS 里到底写死了哪些凭据」——尤其是壳/加载器在内存里 eval 出来、从不落盘的那些脚本，
  静态分析根本看不到**。新增只读工具 `web.secrets`：把 `js.secrets` 用的同一套检测（共享的 JS 词法器 + 共享 `secret_scan.py` 探测器，故 `\x`/`\u` 转义的 key
  先解码、注释与正则里的引号不误判）跑在页面已解析的每个脚本源码上——包括 `dynamic=True` 的运行时脚本（eval / new Function / document.write 注入的壳载荷）。
  按 `(detector, value)` 跨脚本去重，每行 `{detector, value（命中的凭据，过长置 value_truncated）, count（整页出现次数）, first_script（{script_id, url}，
  可直接丢给 web.script.source 的那个脚本）}`，按 detector 再 count 再 value 排序。答复另带 `detectors`（命中的探测器种类集合）、`scanned_scripts`（实际抓取并
  扫描的脚本数）、`scripts_dropped`（已解析脚本表的环形逐出）与 `scan_capped`（脚本数、单源字节、总扫描字节或去重命中数任一触及上限）。每层都设了界：最多抓 200 个
  脚本、单源最多 4 MiB、总扫描 64 MiB，故再大的页面也不会撑爆本进程；整批在一次 runner 调用里跑，故给了比单次 CDP 读更宽的超时。`url_filter`/`dynamic_only`
  先收窄扫哪些脚本（`dynamic_only` 专挑没有 url 的 eval/壳载荷）；WASM 脚本跳过（那是 `wasm.secrets` 的活，先用 web.wasm.get 拉出模块）。`name_filter` 再对 detector
  或 value 做大小写不敏感子串匹配、分页前应用，故 `total` 是命中数。`include_generic` 对没被具体探测器认领的字面量补一个高熵兜底。列表字段是 `secrets`；要完整读某个命中
  脚本用 `web.script.source` 加该行的 `first_script.script_id`。只读，工具总数 294→295（177 只读 / 118 写）。
- **Web 动态分析原来只有 `web.cookies` 和 `web.storage`（local/session）两处取数，但现代 SPA 越来越多地把 auth token、缓存的 API 响应、用户数据放进
  IndexedDB——Set-Cookie 抓包、`document.cookie`、Web Storage 都够不到它**。新增只读工具 `web.indexed_db`：沿用 `web.storage` 的做法（页面内固定
  片段、不接受任意 JS），只针对顶层文档 origin 读 IndexedDB。返回两块：`databases` 是结构——每个库一行 `{name, version, stores（对象存储名）}`，某库被截断或打不开时带
  `stores_truncated`/`error`；`records` 是扁平、分页的数据，每行 `{database, store, key, value}`，value 在浏览器里 JSON 序列化（ArrayBuffer/Blob/
  TypedArray/Date 渲染成 `[Blob 1234]` 这样的短占位符而不是丢弃或变成 `{}`）并裁剪、过长置 value_truncated。答复另带 `count`/`total`/`offset`/`has_more`
  与 `collection_truncated`（打开的库数、扫描的存储数、读取的记录数任一触及页面内上限时为真）。每一层都在浏览器里设了界（库、跨库存储数、每存储与总记录数、单值字节），
  故再大或再深的库也不会整个序列化进本进程。`database_filter`/`store_filter`/`key_filter` 分别对 record 的库/存储/键做大小写不敏感子串匹配、分页前应用，
  故 `total` 是命中数；`databases` 结构图不受这些过滤影响。`data:`/`about:blank` 这种不透明 origin（或浏览器不暴露 `indexedDB.databases`）没有 IndexedDB，
  报 `invalid_state` 而不是空结果。列表字段是 `records`，结构总览是 `databases`。只读：没有 put/delete。只读，工具总数 293→294（176 只读 / 118 写）。
- **`wasm.strings`/`wasm.endpoints` 补齐后，WASM 这条线离 JS/APK 的三件套只差最后一件「这个模块把哪些凭据编进去了」**。新增只读工具
  `wasm.secrets`：复用 `wasm.strings` 的同一段 data 段解析（进程内、免 wabt）拿到 rodata 的可打印串，再把 `js.secrets`/`apk.secrets` 共用的那套
  高精度凭据探测器（共享模块 `backends/common/secret_scan.py`，现在 JS/APK/代理/WASM 四条线共用一份规则）跑在每条串上——于是一个由 Rust/Go/C++
  编出来、把 AWS/Google/GitHub key、Slack/Stripe token、JWT 或 PEM 私钥头写死进去的 wasm 模块，不必 `wasm2wat` 出一屏文本再翻，就能一次交出这些凭据。
  按 `(detector, value)` 去重，每行 `{detector, value（命中的凭据，过长置 value_truncated）, count（出现次数）, first_offset（最早出现的那条 run 的
  模块绝对字节偏移）}`，按 detector 再 count 再 value 排序。答复另带 `detectors`（命中的探测器种类集合）、`has_data_section`（模块没有 data 段时为 false、
  `secrets` 为空——是答案不是错误），以及命中数超上限时的 `scan_capped`。探测器均加锚以压低误报，故普通长随机串不会被报，除非置 `include_generic`（对整条即为
  高熵 base64/hex 的 run 补一个 `generic_high_entropy`，仅对没被具体探测器命中的 run 生效）。`name_filter` 对 detector 或 value 做大小写不敏感子串
  匹配、分页前应用，故 `total` 是命中数。列表字段是 `secrets`；原始串用 `wasm.strings`，网络面用 `wasm.endpoints`。只读，工具总数 292→293（175 只读 / 118 写）。
- **WASM 这条线有了 `wasm.summary`（结构）/`wasm.names`（符号）/`wasm.strings`（内容），但和 JS/APK 比还差最高价值的一问「这个模块到底连哪些后端」**。
  新增只读工具 `wasm.endpoints`：复用 `wasm.strings` 的同一段 data 段解析（进程内、免 wabt）拿到 rodata 的可打印串，再把 `js.endpoints`/`apk.endpoints`
  共用的那套 URL/路径识别（共享模块 `backends/common/endpoint_scan.py`，现在 JS/APK/WASM 三条线共用一份规则）跑在每条串上——于是一个由 Rust/Go/C++
  编出来的 wasm 模块，不必 `wasm2wat` 出一屏文本再 grep，就能一次交出它触及的 fetch host 与 api 路径。按 value 去重，每行 `{value, kind（url|path）,
  scheme, host, count（出现次数）, first_offset（最早出现的那条 run 的模块绝对字节偏移）}`，路径行 scheme/host 为空，按 count 再 value 排序。答复另带
  `hosts`（URL 端点的去重 host 集合——「这模块跟谁说话」的答案）、`hosts_truncated`、`has_data_section`（模块没有 data 段时为 false、`endpoints` 为空——
  是答案不是错误），以及命中数超上限或串扫描封顶时的 `scan_capped`。`include_paths` 置假则只留带协议的 URL；`name_filter` 对 value 或 host 做大小写不敏感
  子串匹配、在 host 汇总与分页前应用，故 `total` 是命中数。列表字段是 `endpoints`；原始串仍用 `wasm.strings`。只读，工具总数 291→292（174 只读 / 118 写）。
- **`js.secrets`/`apk.secrets` 扫的是静止文件，但凭据泄漏最要命的一处是「运行时到底有哪些 key/token 真的过了线」——`Authorization`/`Cookie` 头、
  跟着重定向 url 走的 OAuth token、被 JSON 响应回显的 api key——这些是运行时现签发的，静态 bundle 里根本没有**。新增只读工具 `proxy.secrets`：把
  `js.secrets`/`apk.secrets` 用的同一套高精度凭据探测器（共享模块 `backends/common/secret_scan.py`，现在 JS/APK/代理三条线共用一份规则）跑在环形
  缓冲里保留的每一条流上——url、请求/响应头、以及解码后（gzip/deflate/zstd，边界与 `proxy.search` 一致）的请求/响应体。按 `(detector, value)` 去重，
  每行 `{detector, value（命中的凭据，过长置 value_truncated）, count（整份 capture 里的出现次数）, where（去重后的命中位置：url、request_headers、
  response_headers、request_body、response_body——命中在 request_headers 读作客户端在发它、在 response_body 读作服务端在漏它）, first_flow（{id, seq,
  url, where}，可直接丢给 proxy.flow.get 的那条流）}`，按 detector 再 count 再 value 排序。答复另带 `detectors`（命中的探测器种类集合）、`dropped`
  （环形缓冲的整体逐出计数，同 `proxy.flows`）与 `scan_capped`（命中数上限或与 `proxy.search` 共享的解码字节预算耗尽）。`url_filter`/`content_type_filter`
  先收窄扫哪些流（大小写不敏感子串、AND 组合，界定解码开销，同 `proxy.search`）；`name_filter` 再对 detector 或 value 做大小写不敏感子串匹配、分页前应用，
  故 `total` 是命中数。`include_generic` 对没被具体探测器认领的值补一个高熵 base64/hex 兜底（默认关，牺牲召回换精度）。列表字段是 `secrets`；要完整读某条
  命中流用 `proxy.flow.get` 加该行的 `first_flow.id`。只读，工具总数 290→291（173 只读 / 118 写）。
- **移动逆向最先要问的另一问是「这个 app 到底连哪些后端」——host、URL、api 路径；`apk.strings` 能倒出整个 DEX 字符串池，但得自己从上千条里挑**。
  新增只读工具 `apk.endpoints`：把 `js.endpoints` 用的同一套 URL/路径识别（现已抽到共享模块 `backends/common/endpoint_scan.py`，JS 与 APK 两条线
  共用一份规则）跑在每一条 DEX 字符串常量上，抽出带协议的 URL（http/https/ws/wss/ftp）以及（`include_paths` 为真时）整条即路径的请求路径
  （`/api/...`、`/v1/users`、任意两段路径），去重并按出现次数聚合。答复带 `endpoints`（每行 `{value（过长置 value_truncated）, kind（url|path）,
  scheme, host, source（命中所在的 DEX 常量，过长置 source_truncated——丢进 apk.string_xrefs 即可定位用法）, count（含它的不同常量数）}`，按 count
  再 value 排序）、`count`/`total`/`offset`/`has_more`、`hosts`（URL 端点的去重 host 集合，超上限置 `hosts_truncated`），以及命中数超上限或扫描
  预算耗尽时的 `scan_capped`。路径端点的 scheme/host 为空。`name_filter` 对 value 或 host 做大小写不敏感子串匹配、在 host 汇总与分页前应用，故
  `total` 是命中数；`include_paths` 置假则只留外部 URL。列表字段是 `endpoints`；原始池用 `apk.strings`，硬编码 key 用 `apk.secrets`，定位用法用
  `apk.string_xrefs`。只读，工具总数 289→290（172 只读 / 118 写）。
- **移动逆向和前端一样，最先要问的两问之一是「这个 app 把哪些凭据写死进去了」；`apk.strings` 能倒出整个 DEX 字符串池，但要不要肉眼在成千上万条里挑
  key**。新增只读工具 `apk.secrets`：把 `js.secrets` 用的同一套高精度凭据探测器（现已抽到共享模块 `backends/common/secret_scan.py`，JS 与 APK
  两条线共用一份规则）跑在每一条 DEX 字符串常量上，只返回命中——AWS access-key id、Google API key 与 OAuth token、GitHub token（classic 与
  fine-grained）、Slack token 与 webhook、Stripe secret key、Twilio SID/key、SendGrid 与 Mailgun key、npm token、JWT、PEM 私钥头、带
  `user:pass@` 的 URL。答复带 `secrets`（每行 `{detector, value（命中的凭据，过长置 value_truncated）, source（命中所在的 DEX 常量，过长置
  source_truncated——把它丢进 apk.string_xrefs 就能定位到用它的代码）, count（含它的不同常量数）}`，按 detector 再 count 再 value 排序）、
  `count`/`total`/`offset`/`has_more`、`detectors`（命中的探测器种类集合），以及命中数超上限或扫描预算耗尽时的 `scan_capped`。探测器均加锚以压低
  误报，故普通长随机串不会被报，除非置 `include_generic`（对整条即为高熵 base64/hex 的常量补一个 `generic_high_entropy`，仅对没被具体探测器命中的
  常量生效）。`name_filter` 对 detector 或 value 做大小写不敏感子串匹配、分页前应用，故 `total` 是命中数。列表字段是 `secrets`；原始池仍用
  `apk.strings`，定位用法用 `apk.string_xrefs`。只读，工具总数 288→289（171 只读 / 118 写）。
- **`js.strings` 倒出全部字面量、`js.endpoints` 给出网络面，但静态 bundle 分析价值最高的一问是「前端到底把哪些凭据写死进去了」——AWS/Google/GitHub
  key、JWT、私钥……以前得肉眼在字面量里翻**。新增只读工具 `js.secrets`：复用 `js.strings`/`js.endpoints` 的同一词法器（故注释与正则里的引号不误判、
  `\x`/`\u` 转义的 key 先解码再匹配），对字符串字面量跑一组高精度凭据探测器——AWS access-key id、Google API key 与 OAuth token、GitHub token
  （classic 与 fine-grained）、Slack token 与 webhook、Stripe secret key、Twilio SID/key、SendGrid 与 Mailgun key、npm token、JWT、PEM 私钥头，
  以及带 `user:pass@` 的 URL。答复带 `secrets`（每行 `{detector, value（命中的凭据，过长时置 value_truncated 截断）, count（全文件出现次数）,
  first_offset（首个来源字面量的字符下标）}`，按 detector 再按 count 再按 value 排序）、`count`/`total`/`offset`/`has_more`、`detectors`
  （命中的探测器种类集合——一眼看清「泄了哪几类」），以及不同命中数超采集上限时的 `scan_capped`。探测器均加锚以压低误报，故一条普通的长随机串不会
  被报出，除非置 `include_generic`——它对整条即为高熵 base64/hex token 的字面量补一个 `generic_high_entropy` 探测器（仅对没有被具体探测器命中的
  字面量生效）。`name_filter` 对 detector 或 value 做大小写不敏感子串匹配、在分页前应用，故 `total` 是命中数——只看 aws 或 jwt 命中的办法。列表
  字段是 `secrets`；与 `js.strings`/`endpoints` 一致只扫字符串字面量，故藏在注释里的凭据不报。缺文件 `not_found`、超 16 MiB `too_large`。只读，
  工具总数 287→288（170 只读 / 118 写）。
- **`js.strings` 把所有字面量都倒出来，但 JS/移动逆向最先要问的是「这份 bundle 到底连哪些后端」——URL、host、api 路径，得自己从上千条
  字符串里挑**。新增只读工具 `js.endpoints`：复用 `js.strings` 的同一词法器（故 `\x`/`\u` 转义的 URL 会被解码还原、注释与正则里的引号
  不会误判），从字符串字面量里抽出带协议的 URL（http/https/ws/wss/ftp）以及（`include_paths` 为真时）整条即路径的请求路径（`/api/...`、
  `/v1/users`、任意两段路径），去重并按出现次数聚合。答复带 `endpoints`（每行 `{value, kind（url|path）, scheme, host, count（全文件出现
  次数）, first_offset（首个来源字面量的字符下标）}`，按 count 再按 value 排序）、`count`/`total`/`offset`/`has_more`、`hosts`（URL 端点的
  去重 host 集合——一眼看清连了哪些域，超上限置 `hosts_truncated`），以及不同端点数超采集上限时的 `scan_capped`。路径端点的 scheme/host
  为空。`name_filter` 对 value 或 host 做大小写不敏感子串匹配、在 host 汇总与分页之前应用，故 `total` 是命中数——在众多 host 里锁定某个
  api 域的办法；`include_paths` 置假则只留外部 URL。列表字段是 `endpoints`；要看全部原始字面量（不止网络相关）仍用 `js.strings`。缺文件
  `not_found`、超 16 MiB `too_large`。只读，工具总数 286→287（169 只读 / 118 写）。
- **JS 静态线只有 `js.deobfuscate`/`js.beautify`/`js.unpack_bundle` 三把，且都要 webcrack（Node），没装则整条线 `capability_unavailable`；
  想从一份 bundle 里捞 URL、api 端点、报错文案、内嵌 key，只能先反混淆再对着满屏代码翻**。新增只读工具 `js.strings`：在进程内读源码、
  用一个小词法器抽字符串字面量（不调 webcrack，故 Node 没装也能用——正是 `wasm.summary`/`names`/`strings` 三件套免 wabt 的同一思路）。
  是词法器而非正则扫街：注释里、正则字面量里的引号不会被误当成字符串（正则/除法用标准的「前一个有意义 token」启发式判别）；且 `\x`/`\u`
  转义会**解码**——这正是把混淆器写成 `"\x68\x74\x74\x70"` 的 URL 还原出来的关键。答复带 `strings`（每行 `{offset（字面量的字符下标）,
  text（已解码）, size（解码后长度）, kind（single|double|template）}`，单条超文本上限时置 `text_truncated`）、`count`/`total`/`offset`/
  `has_more`，以及字面量数超采集上限时的 `scan_capped`。`min_length` 默认 3（丢掉 minified 代码里成堆的空串与一两字符串）；调高可在大
  bundle 上进一步降噪。`name_filter` 对文本做大小写不敏感子串匹配（是文案/URL 而非符号）、在分页前应用，故 `total` 是命中数——在上千条里
  找 "http" 或某 api host 的办法。模板 `...` 的静态段按段抽取（`${...}` 空洞把它切开），`${...}` 里的表达式不单独抽。整段文本仍用
  `js.beautify`、拆 bundle 仍用 `js.unpack_bundle`。缺文件 `not_found`、超 16 MiB `too_large`。只读，工具总数 285→286（168 只读 / 118 写）。
- **`wasm.summary` 给结构、`wasm.names` 给符号，唯独读不到模块的内容——rodata 里的 URL、报错文案、格式串、内嵌 key 没有工具能捞**。
  这些常量字符串是 wasm 逆向 triage 最先 grep 的东西，都住在 data 段，但此前要么装 wabt 跑 `wasm.wat` 在满屏文本里翻、要么无从下手。
  新增只读工具 `wasm.strings`：同样在进程内解析（不调 wabt），把 data（id 11）段当二进制做 `strings`——扫出 ≥`min_length` 的可打印
  ASCII（0x20–0x7e）连续段，按模块内偏移升序返回。答复带 `strings`（每行 `{offset（模块绝对字节偏移）, text, size}`，单段超文本上限时置
  `text_truncated`）、`count`/`total`/`offset`/`has_more`、`has_data_section`，以及段内字符串超采集上限时的 `scan_capped`。没有 data 段
  的模块 `has_data_section` 为 false、`strings` 为空——这是答案而非报错。`min_length` 默认 4（像 `strings` 一样把二进制噪声滤掉），调高可
  在大模块上进一步降噪。`name_filter` 对文本做大小写不敏感子串匹配（data 字符串是文案/URL 而非符号）、在分页前应用，故 `total` 是命中数——
  在上千条里找 "https" 或某 api host 的办法。于是 `wasm.summary`（结构）/`wasm.names`（符号）/`wasm.strings`（内容）凑齐了免 wabt 的
  三件套。非 wasm 文件 `invalid_params`、超 16 MiB `too_large`。只读，工具总数 283→284（166 只读 / 118 写）。
- **`wasm.summary` 给出的都是裸下标（导出下标 3、`start_function` 3），没有名字，逆向时得对着 WAT 反查**。wasm 模块常带一个
  名为 `name` 的 custom 段，把函数下标映射到可读名字（emscripten `-g`、debug/dev 构建都会保留），这是「func 42」和
  「`_ZN4core...`」之间的差别，也是 wasm 逆向在拿到导入/导出之后最想要的一样东西。新增只读工具 `wasm.names`：同样在进程内解析
  （不调 wabt），解码 `name` 段的模块名子段（id 0）与函数名子段（id 1），把 `{index, name}` 映射结构化分页返回。答复带
  `module_name`、`names`、`count`/`total`/`offset`/`has_more`、`has_name_section`，以及 namemap 超采集上限时的 `scan_capped`。
  被剥掉名字的发布版模块 `has_name_section` 为 false、`names` 为空——这是答案而非报错，说明无名可查。`name_filter` 对名字做大小写
  敏感子串匹配（wasm 名字是符号）、在分页前应用，故 `total` 是命中数——在命名了上千个函数的模块里定位某一个的办法。只解码 0/1
  两个子段，local/label 等其余子段按声明长度跳过；子段/namemap 条目越界即报 `WasmParseError`→`invalid_params`，命中数按整段 vec
  统计而只有列表受采集上限约束。非 wasm 文件 `invalid_params`、超 16 MiB `too_large`。只读，工具总数 276→277（159 只读 / 118 写）。
- **WASM 一条线只有 `wasm.wat`/`wasm.info` 两把「整段文本」工具，且都要装 wabt，没装则整条线 `capability_unavailable`**。
  即便装了，想知道一个模块「依赖宿主的哪些接口、导出哪些入口」也只能去 grep wasm2wat/wasm-objdump 吐出的大段文本。新增只读
  工具 `wasm.summary`：直接在进程内解析模块的二进制分段（不调 wabt、不起子进程，故 wabt 缺席时照样可用），把三样三分类结构化
  返回——`imports`（每条 `{module, name, kind}`，函数导入附 `type_index`：即 `env.*` 的 JS glue、`wasi_snapshot_preview1.*`
  系统调用这类**宿主接口**，直接说明模块能向外调用什么）、`exports`（每条 `{name, kind, index}`：模块的入口点），以及 `version`、
  逐段 `sections`（`{id, name, size}`，custom 段附 `custom_name`）与存在时的 `start_function`。只深读 import/export/start 三段，
  其余段（type/code/data…）按声明长度跳过，故再大的 code 段在这里也不花代价。所有读取都对缓冲区与段边界做校验、LEB128 整数限长、
  分段遍历计数、导出/导入向量按 `max_imports`/`max_exports` 封顶（`*_total` 报声明长度、`*_truncated` 标记一页没盖全），故畸形或
  敌意模块得到结构化 `WasmParseError`→`invalid_params` 而非死循环/超量分配；非 wasm 文件报 `invalid_params`，超 16 MiB 报 `too_large`。
  穷举指令文本仍用 `wasm.wat`、wabt 的段落 dump 仍用 `wasm.info`。只读，工具总数 275→276（158 只读 / 118 写）。
- **`apk.files` 能看见藏在 `assets/` 里的载荷，却没有任何工具能把它取出来做下一步分析**。`apk.files` 标出一个嵌套 apk/zip
  （`kind` 为 `zip`）、一段 ELF（`elf`）或多出来的 `classesN.dex`（`dex`）后，此前想拿到那一个成员只能整树 `apk.decode`/
  `apk.export_sources`（apktool/jadx 子进程，把整包铺开），没有"只取这一个成员"的办法。新增只读工具 `apk.extract`：按 `apk.files`
  给出的精确归档路径（大小写敏感、无通配）把**单个**成员复制到会话制品树下的一个 uuid 文件——绝不用调用方给的名字落盘，故一个
  形如 `../../etc/passwd` 的成员路径无法逃出该目录（zip-slip）；目录成员或不存在的成员分别报 `invalid_params`/`not_found`。
  取出的字节登记为制品，故受保留策略回收、可由 `artifacts.open` 读回；返回 `{member, size, path, sha256（取出字节的哈希，便于
  按 hash/VT 检索）, artifact_id}`，magic 命中时附 `kind`。成员声明的未压缩大小在读取前先对 64 MiB 上限校验、读取本身再多读一
  字节封顶，故一个谎报大小或本身就是解压炸弹的成员会被 `too_large` 拒绝而非撑爆本进程。只读，工具总数 274→275（157 只读 / 118 写）。
- **`apk.native_libs` 只看 `lib/`，assets 里藏的第二段 dex / ELF / 嵌套 apk 全看不见**。恶意样本常把真正的载荷塞进
  `assets/`、`res/raw/` 或多出来的 `classes2.dex`——`apk.native_libs` 只枚举 `lib/*.so`，其余归档成员没有任何工具能列出。
  新增只读工具 `apk.files`，直接读 zip 中央目录列出全部成员（不解压归档）：每行 `{path, size（未压缩）, compressed_size,
  stored（未被 deflate，通常是已压缩的嵌套归档的信号）}`，并在**首字节 magic 命中时**附 `kind`（`dex`/`elf`/`zip`/`axml`/
  `png`/`jpeg`/`pdf`/`class`）——按字节而非扩展名判定，故一个改名成 `.png` 的载荷仍被叫作它本来的样子。`kind` 只对返回页
  的成员嗅探（每个至多读 `_FILE_MAGIC_BYTES` 字节，解压炸弹在这里也撑不起来），故代价至多 `limit` 次短读，而非每个成员一次。
  同样的 `offset`/`limit` 分页与 `total`/`has_more`，成员数超 `_MAX_FILES_COLLECT`（10000）采集上限时置 `scan_capped`；
  `name_filter` 对成员路径做大小写敏感子串匹配、在采集上限前应用，故超上限的 `assets/` 载荷仍可按名找到。加密/损坏的成员
  仍按元数据列出、`kind` 留空。只读，工具总数 273→274（156 只读 / 118 写）。
- **锁定了包/进程，仍不知道"该拉哪个文件"——设备线能列进程、列 APK 路径，却没法浏览设备文件系统**。分析者拿到包
  （`device.package_paths`）或进程后，下一步往往要拉一个具体文件：sqlite 库、shared_prefs 的 xml、令牌缓存、`/sdcard` 或
  `/data/local/tmp` 下的日志，但此前没有工具能列目录，只能靠猜完整路径喂给 `device.pull`。新增只读工具 `device.ls`：走 adb
  文件同步协议的 LIST/STAT 通道（不是设备 shell，故 path 绝不会被当命令解释）列一个目录。答复带 `path`、`is_dir`、`entries`、
  `count`、`total`、`offset`、`has_more`，目录条目超 4096 上限时置 `collection_truncated`。每行 `{name, type（dir/file/symlink/other）,
  size, mode（八进制权限位，如 0644）}`，设备给出 mtime 时再带 `mtime`（epoch 秒）；条目按"目录在前、再按名字"排序。传入文件路径就
  只列该文件自身（等价 `ls <file>`）。adbd 读不到的目录（无 root 的 app 私有 `/data/data/<pkg>`）返回空而非报错——同步协议对此报的
  是"无条目"而非权限故障。于是 `device.package_paths`/`device.processes`→`device.ls`→`device.pull` 把"哪个 app/进程"接到"该拉哪个
  文件"。path 必须绝对；只读，工具总数 282→283（165 只读 / 118 写）。
- **frida 线只能列已安装应用（`frida.applications`），列不出"正在跑的进程"，而 `frida.attach` 要的恰是运行进程的 pid**。
  `frida.applications` 给的是安装清单（运行时才带 pid），但要附加到一个非 app 的进程——系统守护、原生 helper、已 fork 的组件——
  就得有 frida 自己的进程枚举，此前 frida 线没有。新增只读工具 `frida.processes`：走 frida 的 `enumerate_processes` 列出该会话所连
  设备上的每个活进程。答复带 `processes`、`count`、`total`、`has_more`（沿用 `frida.applications` 的"限量+`name_filter`、无 offset"
  惯用式）。每行 `{pid, name}`、按 pid 排序；`name_filter` 对进程名做大小写不敏感子串匹配、在限量前应用，故 `total` 为匹配数。这里的
  pid 是 frida 自己的 pid 空间（该会话所连设备），正是 `frida.attach` 与各 `frida.*_device` hook 直接取用的值——这也是它与
  `device.processes`（读 adb `ps`、仅 Android、adb-serial 的 pid）的区别：一个喂给 frida、一个喂给 apk/pull 线。只读，
  工具总数 281→282（164 只读 / 118 写）。
- **`device.packages` 报的是"装了什么"，拿不到"此刻在跑什么"，装好的包名与可附加的运行目标之间断了一截**。一个 app id 在 zygote
  fork 出进程前并不是可附加的目标，而 `frida.attach`/`frida.spawn` 要的是进程 pid（或进程名），此前设备线没有任何工具能把运行中的
  进程连同 pid 列出来。新增只读工具 `device.processes`：跑 `ps -A`，按表头列名（而非固定列序）定位 PID/USER/PPID/NAME 列，逐行整形成
  `{pid, name, user, ppid}`。答复带 `processes`、`count`、`total`、`offset`、`has_more`，设备报的行数超 8192 上限时置
  `collection_truncated`。app 的进程就是 `name` 等于包名（组件声明了独立进程时为 `包名:进程`）的那一行；行按 pid 排序。`name_filter`
  按名字子串（大小写不敏感）在分页前过滤，故 `total` 是命中数——在跑着数百进程的设备上定位某个 app 进程的办法。于是
  `device.processes`→`frida.attach(pid=…)` 把"装了什么"接到"附加到正在跑的那个"。`ps -A` 不取任何调用方 token，无法注入 shell
  命令。只读，工具总数 279→280（162 只读 / 118 写）。
- **`device.packages` 只报包名，拿不到已装应用在设备上的 APK 路径，动态线与静态线之间断了一截**。分析者在设备上锁定一个包后，
  下一步通常是把它的 APK 拉下来交给 `apk.*` 静态分析，但此前没有工具能给出安装位置，只能靠手头另有一份 APK。新增只读工具
  `device.package_paths`：对给定包名跑 `pm path`，返回其在设备上的 APK 路径——base APK 以及 app bundle 安装时带的每个 split
  （按 density/语言/abi 切分的 config APK）。答复带 `package`、`paths`、`count`、`base_apk`（名为 base.apk 的那个，没有则取第一个）、
  `split`（多于一个路径时为真），路径数超 64 上限时置 `paths_truncated`。于是 `device.package_paths`→`device.pull`→`apk.open` 把
  动态设备线接到静态 apk 线上。包名经 `_check_package` 校验、作为单个 argv 传给 `pm path`（绝不拼进 shell 字符串），无法注入命令；
  未安装的包（`pm path` 无输出）报 `not_found`、非法包名报 `invalid_params`。只读，工具总数 278→279（161 只读 / 118 写）。
- **adb forward 只能建、不能查也不能单删，填满 32 槽后只有 `close_all` 能回收**。`device.forward` 会在 adb server 上占一个
  转发槽（frida 的 `tcp:27042`、某个调试端口），而这些转发不随会话关闭消失；此前唯一的清理是 `close_all` 里的
  `release_forwards` 一次性全删。于是一个跨多个 app、长期运行的 agent 会把 32 槽的表悄悄填满，撞上 `too many adb forwards` 后
  除了拆掉全部会话别无他法，也看不到到底占了哪些。新增两件：只读的 `device.forwards` 把本进程持有的转发表读出来（每条
  `{serial, local, remote}`，附 `count` 与 `cap`；纯内存读取，不取 serial、不碰设备），以及会改状态的 `device.forward_remove`——
  按 `local` 端点（如 `tcp:27042`）单删一条、精确回收一个槽，是 `release_forwards` 的逐条逆操作。`removed` 仅在本进程确实
  持有该转发时为真；删一个本就不存在的转发是幂等空操作而非报错（仍会请求 adb，"not found" 被吞掉），而删一个我们持有、
  但 adb 侧失败的转发会保留表项让下次 `close_all` 重试并回 `backend_error`，与 `release_forwards` 的韧性一致。为此把内部
  转发表从 `list[(serial, local)]` 改为 `dict[(serial, local) -> remote]`，好让列表能报出完整三元组、并在按同一 `local`
  重新转发到新 `remote` 时同步更新。`device.forwards` 只读、`device.forward_remove` 计入写，工具总数 270→272（154 只读 / 118 写）。
- **`device.logcat` 只能拉最后 N 行，噪声设备上错误被淹没**。它一直只按 `-t N` 取尾，等价于 console 加 `type_filter` 之前的样子。
  现给它加上 `min_priority`（`V`/`D`/`I`/`W`/`E`/`F`）：交给 logcat 自己的 `*:<级别>` filterspec 在源头过滤，于是 `-t N` 取到的是
  最后 N 条**匹配**行，而不是先取 N 行再由客户端筛剩下寥寥几条——传 `E` 即可从吵闹的设备里只捞错误。级别在固定集合内校验，
  并作为独立 argv 传入（绝不拼进 shell），未知级别是 `invalid_params`，与既有「无 `device.shell` 透传」的安全约束一致。
- **`web.console` 没有类型过滤，报错淹没在海量 log 里**。延续 `url_filter` 的思路，给 `web.console` 加上 `type_filter`：对条目
  `type` 做大小写不敏感的精确匹配（`error`/`warning`/`log`…），在取尾之前应用，于是能把失败（包括折叠进来的未捕获异常，其
  type 为 error）从被 log 刷屏的控制台里单独拉出来；`has_more` 随之反映更早的匹配项，`dropped` 仍为环形缓冲淘汰计数。
- **`web.network.list` 只能按 URL 过滤，抓包被 Image/Script/Stylesheet 淹没时挑不出 API 流量**。真实页面一次能抓到成百上千
  条请求，绝大多数是静态资源；分析者最常要的下一步是「只看 XHR/Fetch」以聚焦接口调用。行里本就有 `resourceType`，故给
  `web.network.list` 加上 `type_filter`：对 `resourceType` 做大小写不敏感的精确匹配（如 `XHR`/`Fetch`），与 `url_filter` 同处
  分页之前、两者需同时满足，于是能把 API 流量从资源噪声里单独拉出来，`total` 即过滤后的匹配数，`dropped` 仍为环形缓冲淘汰计数。
- **`proxy.flows` 只按摘要（url、类型、失败）过滤，唯独答不出「哪条流*里*有这个字符串」——泄漏的 token、响应里回显的 api key、
  请求体带的某个值——只能一条条 `proxy.flow.get` 翻**。新增只读工具 `proxy.search`：对环形缓冲里保留的每条流，grep 其 url、
  请求/响应头、以及**解码后**的请求/响应体，返回命中的流。响应体按 `proxy.flow.get` 同样的有界方式解码（gzip/deflate/zstd），故压缩
  响应里的命中也找得到。答复带 `query`、`flows`、`count`、`total`（过滤后命中的流数）、`offset`、`has_more`、`dropped`（环形淘汰数，与
  `proxy.flows` 同源）、`scan_capped`（解码字节预算耗尽、后续流未搜时为真）。每行 `{id, seq, method, url, host, status, matches}`，
  流体超保留上限只搜了 url 时另带 `body_omitted`。`matches` 是 `{where, count, snippet}` 列表：`where` 取 `url`/`request_headers`/
  `request_body`/`response_headers`/`response_body`；`count` 是该处出现次数；`snippet` 是首个命中带上下文、从更大的体里裁出时用省略号标记。
  匹配为大小写不敏感子串（不分大小写地找主机或 token）。`url_filter`/`content_type_filter` 在搜体之前先缩小搜哪些流（大小写不敏感
  子串、AND 组合），故繁忙抓包上的定向搜索仍然便宜；`total` 是既过了过滤又命中查询的流数。列表字段是 `flows`、每处命中的字段是
  `matches`；要看某条命中的流全文仍用 `proxy.flow.get` 配其 `id`。空 query 或超 1024 字符报 `invalid_params`。只读，工具总数
  284→285（167 只读 / 118 写）。
- **繁忙抓包里想知道「这个 App 到底连了哪些主机、各连了多少、有没有失败」，只能对着 `proxy.flows` 一页页翻**。`proxy.flows`
  是一行一个请求；判断哪个是 C2/CDN/遥测端点、哪个域名握手全失败，得把整份抓包读一遍。新增只读工具 `proxy.hosts`：把环形缓冲里
  保留的流按 `host` 汇总，一主机一行——`flows`（请求数）、`failed`（从未拿到响应的数）、`methods`（用过的方法，去重排序）、
  `content_types`（响应 MIME 的 `;` 前主类型，去重排序）、`statuses`（`{状态码: 次数}` 映射），以及见到上游 IP 时的 `remote_ips`。
  按 `flows` 降序（最吵的主机在前）、同数再按主机名排，故翻页稳定。答复另带 `count`/`total`（过滤后不同主机数）/`offset`/`has_more`、
  `total_flows`（汇总的流总数，即整份保留抓包）与 `dropped`（环形淘汰数，与 `proxy.flows` 同源）。每主机的四个去重集合都有上限
  （方法 16、类型/状态/IP 各 32），被恶意服务器用无限多样的取值撑爆时丢弃多余值并给该行置 `truncated`。`host_filter` 对主机名做
  大小写不敏感子串匹配、在分页前应用，故 `total` 是命中数；要看某主机下的逐条请求仍用 `proxy.flows` 配 `url_filter`。列表字段是
  `hosts`、每行请求数是 `flows`。只读，工具总数 277→278（160 只读 / 118 写）。
- **`proxy.flows` 只能按 URL 过滤，繁忙抓包里 API 流量与失败连接都挑不出**。`proxy.flows` 此前只有 `url_filter`，而 `error()`
  钩子专门记录连接失败（上游 reset、TLS 握手失败——正是 pinned 移动 App 挂到代理后最常见的证据）却只能靠逐页翻看每行的
  `failed` 字段才找得到，API 流量也埋在 image/script/css 响应里。延续 `web.network.list` 的思路，给 `proxy.flows` 加两个过滤：
  `content_type_filter` 对行上的 `content_type` 做大小写不敏感的**子串**匹配（不同于 `web.network.list` 对 `resourceType` 的精确
  匹配——代理行保留的是原始头 `application/json; charset=utf-8`，故 `json` 才是有用的针），把 JSON/XML/表单等接口流量从静态资源里
  拉出来；`failed_only` 为真时只留 `failed` 为真的流，一步捞出那些握手/重置失败。两者与 `url_filter` 一样在分页之前应用、以 AND
  组合，故 `total` 为过滤后的匹配数，`dropped` 仍是全量环形缓冲淘汰计数。无新增工具，仅 `proxy.flows` 多两个可选参数。
- **`apk.components` 的导出组件不带 intent-filter，看不到具体调用面**。知道某组件被导出后，分析者下一步要问的是"什么 intent
  能触发它"——`BOOT_COMPLETED`（持久化）、`SMS_RECEIVED`（拦截短信）这类 action，或 `BROWSABLE` 这类 category，正是导出组件的
  实际调用面。既然已在遍历清单树，就顺带用新增的 `_intent_filter_names` 收集每个导出组件各 `<intent-filter>` 的
  `<action>`/`<category>` 名称（去重、排序、按组件设上限），并入其条目为 `actions`/`categories`。
- **`web.network.list` 与 `proxy.flows` 没有 URL 过滤，繁忙抓包只能逐页翻找**。二者原来只分页，而 `apk.*`/`frida.*` 列表工具
  早有 `name_filter`。现给两者都加上 `url_filter`：对 url 做大小写不敏感子串匹配，在分页之前应用，于是 `total` 即匹配数，能在
  抓到成百上千请求的页面上直接定位某个端点/主机/`.json`；`dropped`（环形缓冲淘汰计数）仍基于未过滤的全量，不受过滤影响。
- **`apk.open` 的 `security` 不含 `sharedUserId`，共享沙箱信号缺失**。声明了 `android:sharedUserId` 的应用会与同 id、同签名的
  其它应用共享同一 Linux 沙箱，其值本身即信号（`android.uid.system` 是重大红旗）。该属性位于根 `<manifest>` 标签而非
  `<application>`，故新增 `_manifest_root_attr` 从清单树读取，并把 `shared_user_id`（字符串或 null）并入 `security`；
  自 API 29 起虽被弃用但仍生效，因此仍具定级价值。
- **`apk.certificates` 不报签名算法与签名者密钥强度，弱签名无法识别**。原来只给 `hash_algo`（摘要），但 MD5/SHA1 签名或
  1024 位 RSA 密钥是旧工具链/二次打包样本的经典特征。新增 `signature_algo`（如 `rsassa_pkcs1v15`）与 `key_algo`/`key_size`
  （从 asn1crypto 证书的 `public_key.algorithm`/`bit_size` 读取），三者与摘要、有效期并列于定级信息中；读取按证书防御式处理，
  某个 `public_key` 访问抛错时退化为 `("", None)` 而非丢弃整张证书。
- **HAR 导出的 `request.cookies`/`response.cookies` 恒为空**。`cookies` 是 HAR 请求/响应的必填成员，也是分析者最关心的内容
  （页面带的会话令牌、服务端下发的 Cookie 及其安全标志），却一直为空。新增 `request_cookies`（拆分 `Cookie` 头的
  `name=value` 列表）与 `response_cookies`/`_parse_set_cookie`（逐条 `Set-Cookie` 解析出 name/value 及 `path`/`domain`/
  `HttpOnly`/`Secure`——正是会话 Cookie 的定级信号），全部取自 `har_entry` 已收到的头部，web 与 proxy 两侧同时受益；
  `expires` 刻意不输出（Set-Cookie 是 HTTP-date，而 HAR 要 ISO 8601，原样拷贝会让严格查看器拒绝整个日志），数量另有上限。
- **`apk.components` 只列组件名，不标注哪些是导出的（对外攻击面）**。一个 `android:exported="true"`（或属性缺省时按平台
  隐式规则：activity/service/receiver 含 `<intent-filter>`、provider 目标 SDK < 17）且没有 `android:permission` 保护的
  组件，可被任意已安装应用直接拉起，是 Android 恶意样本/安全分析的首要信号。新增 `_exported_components` 直接解析清单 XML 树
  （`get_android_manifest_xml`），据此给出 `exported` 列表（每项 `{type, name, permission}`，无保护时 permission 为 null）
  与 `exported_count`；这是在原四类名单之外的**新增**字段，不改动既有形状，清单无法解析时退化为空列表而非报错。
- **`web.console` 普通条目不带来源位置，无法定位日志出处**。抛出的异常早已附带抛出点 `url`/`line`，但 `console.*` 条目
  只有 `type`/`text`，而 CDP 的 `consoleAPICalled` 事件本就带 `stackTrace`——其栈顶帧正是 `console.*` 的调用点。新增
  `_console_call_site` 从栈顶帧还原 `url`/`line`（0 基，与 `Debugger.scriptParsed` 一致）并附到每条 console 记录上，
  于是一条日志可回溯到发出它的脚本（尤其是 `web.scripts` 现在会标记的匿名/运行时生成脚本）；栈缺失或结构异常时退化为不带
  位置而非中断采集。
- **未捕获异常只记了抛出点，丢了导致它的调用链**。`exceptionThrown` 条目此前只带 `text` 和抛出点 `url`/`line`，但排查一个
  未捕获错误（反调试 throw、混淆代码里炸开的地方）时，最先要看的是「哪条函数链走到了这里」，而 CDP 的
  `exceptionDetails.stackTrace.callFrames` 本就带着这条链。新增 `_stack_frames`，把它整理成有界的 `stack` 列表
  （每项 `{function, url, line}`，行号 0 基、与抛出点及 `Debugger.scriptParsed` 一致），只取栈顶 `_MAX_STACK_FRAMES`（32）
  帧、每个字段有界、匿名帧保留空 `function`、不追异步 `parent` 以保持扁平有界；栈缺失或结构异常时给出空列表而非中断采集。
  于是一个未捕获错误能被定位到代码里的具体调用路径，而不只是有个名字。`console.*` 与既有抛出点字段不变。
- **HAR 导出的 `serverIPAddress` 一直为空，命中的真实服务器 IP 丢失**。该字段按 HAR 规范就是本次请求实际连到的服务器地址——
  一个域名背后真正的 C2/CDN 主机，是做基础设施关联（域前置、快速通量、同 IP 归并）时 URL 给不出的关键旋转点。web 侧 CDP 的
  `Network.responseReceived` 就带 `remoteIPAddress`/`remotePort`，proxy 侧 mitmproxy 的 `server_conn.ip_address` 也记着
  连接建立后解析出的 (host, port)；现在两侧把它接进 `har_entry` 的新增可选参数 `server_ip`，非空时写出 `serverIPAddress`。
  web 抓包在响应到达时把 `remote_ip`/`remote_port` 挂到请求环上，这两项因体量小且信号强，破例保留在精简的 `web.network.list`
  行内（不像响应头那样被剔除），`web.network.get` 亦随之带出；缓存命中与 `data:` 响应从不建连，字段自然缺席而非伪造。
  `proxy.flow.get` 也对称地从 `server_conn` 给出 `remote_ip`/`remote_port`，与 `web.network.get` 保持一致；未建连的流
  （DNS/握手失败）不带这两项。  `proxy.flows` 的摘要行也在 `response()` 采集时挂上 `remote_ip`/`remote_port`，于是列流量时
  就能一眼看到每条命中的上游服务器（与 `web.network.list` 对称），不必逐条 `flow.get`；未建连的流同样缺席这两项。
- **`device.pull` 的体积上限是「先整份拉下来再检查」，stat 失败或设备谎报大小时形同虚设**。早先加的 stat 预检只有在
  stat 成功且设备如实上报时才拦得住；一旦 stat 抛错（部分 ROM/路径不支持）或设备把大小报小，`adbutils.sync.pull` 会把
  整份——可能有好几 GB——的文件先写进产物目录，等 pull 结束后的尺寸检查再删，传输途中就能把宿主磁盘写满。改为用
  `sync.iter_content` 分块流式拉取，边写边累计字节数，一旦跨过捕获上限就**在写入越界分块之前**停手、删掉半成品、报
  `too_large`，于是落盘量恒不超过上限，与 stat 是否可用无关。传输中途出错也删掉半成品，避免留下一份会被当成完整 pull 的
  截断文件；没有 `iter_content` 的旧 adbutils 回退到原「整份+后检」路径。
- **HAR 导出的 `request.bodySize`/`response.bodySize` 恒为 `-1`，请求/响应体大小丢失**。这两个字段按 HAR 规范就是消息体的
  字节数，而发送方自己声明的 `Content-Length` 正是该值——它取自请求头而非我们保留的（可能已被截断的）体副本，因此即使内联体
  被裁剪也不会少报。web 与 proxy 两侧现在都已把头传给 `har_entry`，于是新增 `content_length` 助手从 Content-Length 还原
  `bodySize`（缺失、重复折叠或非数字则退化为 `-1`），两个导出器同时受益；`response.content.size` 仍为 0，因为不解压就无从
  得知未压缩长度，而导出刻意不保留响应体。
- **HAR 导出的 `response.redirectURL` 一直为空，重定向链丢失**。该字段按 HAR 规范就是响应 `Location` 头的跳转目标，
  而 web 与 proxy 两侧现在都已把响应头传给 `har_entry`，于是直接在其中用 `header_value` 从 Location 头还原 redirectURL——
  两个导出器同时受益，OAuth 跳转、追踪器、短链这类重定向链不再在查看器里显示为空白。
- **`apk.open` 不报应用级安全标志**。首轮排查最看重的 `android:debuggable`、`allowBackup`、`usesCleartextTraffic`
  和是否自带 Network Security Config，之前一个都没有。现在新增 `security` 子对象四项一并给出：这些标志挂在唯一的
  `<application>` 标签上，按属性名读取可靠（不像按名字查组件那样会因相对名不匹配而失准），缺失属性回落到应用实际运行的
  平台默认值（debuggable 关、allowBackup 开、cleartext 在 API 28 以下默认允许），访问器缺失时整条设防不影响 apk.open。
- **`apk.permissions` 从不暴露应用自定义声明的权限**。此前只返回 uses-permission（used/requested）两个视图，应用用
  `<permission>` 自己定义的权限完全看不到，而其 protectionLevel 正是权限边界：一个 normal/dangerous 级别的自定义权限
  若守着某个 exported 组件，就是提权面。现在借 androguard 的 `get_declared_permissions_details()`（设防调用，缺失该
  访问器或形状异常即退回空列表）新增 `declared_permissions`，每项为 `{name, protection_level}`，与 requested 列表分开、
  受同一 256 上限约束。
- **`apk.certificates` 只报 v1 签名，且证书信息太少**。`v1_signed` 由 META-INF 签名文件是否存在推得，于是仅用
  v2/v3（APK Signature Scheme）签名的现代应用被读成“未签名”，而只有 v1 签名（v2/v3 皆无）这一 Janus 篡改风险信号也
  无从看出。现在借 androguard 的 `is_signed_v1/v2/v3`（各自设防，缺失或抛错即记为 False）补出 `v2_signed`、
  `v3_signed` 和 `signed`（三者任一），每张证书也补上 `sha1`（威胁情报库检索用的指纹）、`hash_algo` 以及
  `not_before`/`not_after` 有效期（新签发或超长有效期是恶意样本常见特征）——各字段单独设防，某属性缺失不会拖垮整条应答。
- **`web.scripts` 无法区分运行时生成的脚本，而那正是逆向最想看的**。`Debugger.scriptParsed` 对 eval、
  `new Function`、document.write 注入的脚本会附带 `stackTrace`，这类脚本 url 为空，在列表里和其它匿名脚本无从分辨——
  可 packer 解包后的真实载荷恰恰落在这里。`on_script` 现在据 `stackTrace` 是否存在打上 `dynamic: true`，并在引擎给出
  `length` 时一并记录脚本字符数，`web.scripts` 因此能把生成脚本标出来、按大小挑出值得 `web.script.source` 拉取的那一个。
- **修正上一条引入的疏漏：har.export 专用的内联请求体泄漏进了 `web.network.list`/`web.network.get`**。为让
  `har.export` 能写出 `request.postData` 而在 ring 上留的 8 KiB 内联 `post_data`（连同 `post_data_truncated`）本是
  纯内部细节，却既进了本应精简的 `network.list` 索引（每行多带一份 POST 载荷），又进了 `network.get`（与它按需拉取的
  完整 `request_body` 重复）。新增 `_NETWORK_INTERNAL_KEYS`，`network.list` 现在同时剔除头部列表与该内联体，
  `network.get`（含软 `body_error` 分支）也把它剔除，只保留规范的 `request_body`。
- **HAR 导出丢掉了请求体（`request.postData`）**。`proxy.export_har` 和 `web.har.export` 已经把 method/url/
  status、queryString、请求/响应头都补齐成 spec-valid 的 HAR 1.2，但 POST 载荷——JSON body、表单凭据、签名 blob，
  也就是做 API/协议分析时最想看的东西——始终缺失。common `har.py` 新增 `post_data(body, mime_type)` 助手（表单
  `application/x-www-form-urlencoded` 额外拆成 spec 的 `params` 列表，其它按 `text` 原样带上，字节按 utf-8 宽松解码，
  统一裁到 256 KiB）和 `header_value()`，`har_entry` 新增 `request_post_data` 参数在有 body 时写出 `request.postData`。
  web 侧在 `requestWillBeSent` 里把 CDP 对小 body 内联的 `postData` 存一份到 ring（上限 8 KiB，`post_data_truncated`
  标记裁剪；大 body 仍只置 `has_post_data`，靠 `web.network.get` 按需拉全量），`har.export` 据此按请求自身的
  content-type 类型化写出；proxy 侧从保留的原始 flow 的 `request.content` 取体、按其 content-type 类型化（body 被
  omit 或已被 ring 驱逐的 flow 保持为空而非伪造）。
- **`web.console` 把对象/数组参数塌缩成 "Object"，丢掉了记录的载荷**。`console.log({id, token})` 经
  `Runtime.consoleAPICalled` 送来的是没有 primitive `value` 的 RemoteObject，旧逻辑退到 `description`（就是
  "Object"/"Array(3)"），于是逆向最关心的被记录的配置、token 全丢了。CDP 其实在 `preview.properties` 里带着
  成员，现在新增 `_render_console_preview` 把它们折回 DevTools 风格的 `{k: v}` / `[v, ...]`（字符串成员加引号、
  溢出以省略号收尾、成员数上限 50），`_clip_console_text` 的取值顺序变为 value → preview → description → type；
  仍走同一条 per-message 截断，超大对象照样被裁。没有 preview 的对象（如 Promise）退回 description 不变。
- **`frida.memory.read` 只界定了 `size`，`address` 不设防**。`size` 在后端严格校验（1..262144），但
  `address` 直接透传给注入 JS 的 `ptr(address)`；MCP schema 虽标注 int，Agent 传输不跑 pydantic，于是
  负值/浮点/字符串都能到达，非数字还会以 `ValueError` 冒泡成 `internal_error`。现在后端在 attach 之前
  按与 `size` 相同的严格形状校验 `address`（必须是 int，且落在 `[0, 2**64)`，连 bool 一并拒），越界即
  `invalid_params`。另外，读到未映射/受保护地址时 `Memory.readByteArray` 会在 agent 内抛错，过去裸异常
  冒泡成 `internal_error`（读作工具 bug），现改为干净的 `backend_error` 并点名地址——那是调用方给的地址
  不可读，不是内部故障。
- **`web.network.get` 拿不到请求/响应头，而 `proxy.flow.get` 早就有——两条动态分析线不对称**。
  响应头（Set-Cookie/CSP/CORS/Content-Type）与请求头（鉴权、cookie、自定义 API 头）正是 Web 动态分析要看的，
  CDP 在 `requestWillBeSent` / `responseReceived` 事件里就带着，但 ring entry 从不保留、`web.network.get` 也
  从不返回。现在 `on_request` / `on_response` 各自把头存到 entry（新增 `_cdp_headers`：CDP 用换行连接重复名，
  按换行拆开使每个 Set-Cookie 各占一条，数量 100/单条 8 KiB/单侧 16 KiB 有界，防止 header 洪水撑大最多
  _MAX_REQUESTS 条的 ring）；`web.network.get` 随即以 `request_headers` / `response_headers` 返回。为免撑大列表，
  `web.network.list` 把这两个键从每行剔除（改逐行投影），头只在 get/har 里取。附带地，`web.har.export` 也把这
  两侧头喂给 `har_entry`，于是 Web HAR 也有了头部，与 proxy HAR 对齐（上一版说 Web HAR 无头部，现已补上）。
- **`proxy.flow.get` 用 `dict(headers)` 把重复头折叠，Set-Cookie 被折损**。mitmproxy 的
  `Headers` 是多值容器，`dict(...)` 会把同名头合并成一个逗号连接的值——对多数头（RFC 7230 允许逗号合并）
  无妨，但对 `Set-Cookie` 是破坏：RFC 6265 明确禁止逗号合并，而 `Expires` 日期本身就带逗号，于是一个
  下发多个 cookie 的响应回来变成一坨无法解析的字符串，恰好丢掉了 flow.get 最该暴露的会话/鉴权数据。
  现在请求/响应 `headers` 改成按线序排列的 `{name, value}` 列表，逐条保留重复（顺序本身也是指纹信号），
  并复用 `har_headers` 做数量/长度上限；每个 Set-Cookie 各占一条。属 pre-1.0 的输出形状变更（dict → list）。
- **`proxy.export_har` 丢掉了它明明留着的请求/响应头**。导出只用 recorder 的摘要
  （method/url/status/content_type）建 entry，可 recorder 的 raw flow 里完整保留着请求头与响应头——
  Authorization/Cookie/Set-Cookie/Content-Type 这些正是把 HAR 拿去 DevTools 看 Headers 页时最想要的东西，
  `proxy.flow.get` 早就逐条暴露了它们，唯独 HAR 里全空。现在 `har_entry` 新增可选的 `request_headers` /
  `response_headers`（用新加的 `har_headers` 从 mitmproxy `Headers` 或 dict 转成 spec 的 name/value 列表，
  数量上限 200、单条 8 KiB，畸形映射退化成空表），`export_har` 按 flow id 回捞 raw flow 填入两侧头部；
  已被 ring 淘汰或正文被省略（无 raw 对象）的 flow 头部留空而非伪造。web 侧 ring 只存摘要不留头部，
  故 `web.har.export` 仍是空头部，如实反映各自捕获到的东西。
- **HAR 导出的 `request.queryString` 恒为空，明明 URL 里就带着查询参数**。`proxy.export_har` /
  `web.har.export` 走同一套 `har_entry`，每条 entry 的 `queryString` 一律发空数组——可这正是逆向者
  打开 HAR 最想看的请求参数，而数据本就在同一条 entry 的 `url` 里（HAR 是 spec-valid 的，只是这个必填
  成员没填实）。现在 `har_entry` 用新加的 `query_string(url)` 从 URL 的查询段解析出 name/value（`urlsplit`
  分离掉 fragment、`keep_blank_values` 保留 `?a=1&b=&c` 里的空值、百分号解码），两个导出器同样受益；
  解析失败退化成空数组不影响整份导出，参数数量上限 512 防止畸形超密查询撑大单条 entry。数据来自本就
  保留的 URL，不是凭空编造。
  URL 原样交给 `page.goto`：`file:///etc/passwd` 直接读任意磁盘内容、`chrome://` 与 `view-source:` /
  `filesystem:` 暴露浏览器内部页，读到的东西再经 `web.dom.snapshot` / `web.script.source` 就能被 agent
  取回——这条 web 面本就为同一类风险刻意不提供任意 JS `evaluate`，导航目标却没有对应约束。且 Agent
  传输不跑 pydantic 校验，模型给什么 URL 就走什么。现在后端在 `page.goto` 之前按 scheme allowlist 校验：
  只放行 web 目标真正使用的 `http://`/`https://`，外加 `data:`（不透明源的内联内容，够不到本地磁盘或特权
  页，且 hermetic 浏览器测试无需联网即靠它构造），其余（`file:`/`chrome:`/`about:`/`javascript:`/无 scheme
  的裸路径）一律以 `invalid_params` 拒绝；`web.open` 的空 URL 仍表示「开一个空白浏览器」，不受此限。
- **doctor 对 JVM/node 启动器只看文件存在就报 `detected`**。jadx/apktool/apksigner 都是拉起 JVM
  的脚本、webcrack 是拉起 node 的 npm shim，启动器在场不代表能跑；`probe_ghidra` 早就在 `java`
  不在 PATH 时拒绝把 analyzeHeadless 报成可用，这四条却报纯 `detected`，操作者要自己把顶层
  `java` 探针和它们联系起来。现在同样如实：状态仍是 `detected`（可选项从不阻塞就绪），但 summary
  点名缺席的运行时、details 带 `missing_runtime`、remediation 说明装什么。
- **`web.open` 把「浏览器没装」报成 `backend_error`**。`pip install playwright` 从不下载 Chromium，
  模块能导入、`_check_available` 通过，只有 `chromium.launch()` 失败，报文里写着让人去跑
  `playwright install`。可这跟 androguard/jadx/mitmproxy 缺席是同一类——一个没配好的可选能力，
  别处一律用 `capability_unavailable` 表达；web 这条却抛 `backend_error`，无人值守的编排会把「没装
  好」当成「跑坏了」。现在按报文识别这种启动失败，改抛 `capability_unavailable` 并给出
  `playwright install chromium` 的指引，与其余可选后端一致。
- **doctor 把 Playwright 只当普通 Python 模块，导入成功就报 `detected`**。可 `pip install
  playwright` 从不下载 Chromium，模块能导入不代表 `web.open` 能起浏览器——这正是上一条在运行期
  才暴露的「模块在、浏览器不在」。别的可选工具里，JVM 启动器缺 `java`、webcrack 缺 `node` 时
  doctor 已如实点名缺席的运行时；唯独 web 这条主探针只看导入，操作者在装好包却没跑 install 的机器上
  跑 doctor，看到的是干巴巴的「detected」，无从得知还差一步。现在按同一「在场≠可用」原则处理：向
  Playwright 自己问版本/平台正确的 Chromium 可执行路径（在有界子进程里问，驱动卡死也拖不垮
  doctor——那正是机器出问题时有人会跑的命令），落盘不在就仍报 `detected`（可选项从不阻塞就绪）但
  summary 点明浏览器没装、details 带 `chromium_executable`、remediation 给出
  `python -m playwright install chromium`；问不出结果（驱动缺失/超时）就回落到原来的纯 `detected`，
  绝不臆测。
- **doctor 的 wabt 探针与后端对「装没装」各执一词**。`WasmClient` 分别解析 `wasm2wat`（撑
  `wasm.wat`）和 `wasm-objdump`（撑 `wasm.info`），且 `settings.wabt` 可指向单个可执行文件、也可
  指向 wabt 的 bin 目录。可 doctor 走的是通用 `probe_optional_tool`，只认「单个 PATH 命令」加「文件值
  的设置」，还只探 `wasm2wat` 一个：把 wabt 配成目录时它 `Path(dir).is_file()` 为假、`wasm2wat` 又不在
  PATH，于是报 `missing`——而后端能从该目录解析出两个二进制、`wasm.*` 全都能跑；反过来只有 `wasm2wat`
  没有 `wasm-objdump` 时，它又报纯 `detected`，掩盖了 `wasm.info` 其实会 `capability_unavailable`。现在
  doctor 用后端同一个 `_resolve_wabt_tool` 分别解析两个二进制：都缺才 `missing`；缺一个则仍 `detected`
  但点名缺的二进制与随之失效的工具（`wasm2wat`↔`wasm.wat`、`wasm-objdump`↔`wasm.info`）并给出补齐指引；
  两个都在才报「wasm2wat + wasm-objdump」。目录式配置与部分安装从此如实呈现，doctor 与后端不再打架。
- **`apk.sign` 把 keystore 口令放进子进程 argv**。apksigner 的口令过去以 `--ks-pass pass:<口令>` /
  `--key-pass pass:<口令>` 直接写在命令行上——而 argv 在多用户机上人人可读（`ps`、`/proc/<pid>/cmdline`），
  一个自定义 keystore 的口令就这么泄给了同机的其他用户。模块本就承诺「口令绝不进错误详情」（失败时把
  stderr 里的口令抹成 `***`），可 argv 这条更直接的泄露口一直开着。现在口令改经环境变量交给 apksigner
  （`--ks-pass env:` / `--key-pass env:`，`run_bounded` 的 `stdin` 是 `DEVNULL` 故不用 `stdin:` 通道），
  子进程环境在 `os.environ` 基础上只加这一个变量以保留 `PATH`/`JAVA_HOME`；verify 那趟不碰口令。stderr
  抹除作为第二道防线保留。debug keystore 口令是公开的 `android`，本就无所谓；这修的是自定义 keystore。
- **`device.install` 读 APK 清单会被解压炸弹 OOM**。为了不引入 androguard，`_apk_package_name`
  用 `ZipFile.read("AndroidManifest.xml")[:65536]` 手搓解析——可 `read()` 会先把整个成员解压进内存
  再切片，一个把清单做成解压后上 GiB 的恶意 APK，能在切片之前就把进程撑爆；而 `install()` 正是拿
  调用方给的、可能有敌意的 APK 来跑这一步。现在改成 `archive.open(...).read(64 KiB)` 流式只读扫描
  窗口，读满即止，恶意清单再大也只解压这一窗。
- **androguard 进程内解析会被解压炸弹 OOM**。androguard 在解析前先把 `classes*.dex`、`resources.arsc`
  和清单经 zipfile 解压进内存；一个压缩后极小、解压后上 GiB 的成员（解压炸弹）会在那一步就把整个进程
  撑爆，而墙钟上限拦不住——分配发生在超时触发之前。中央目录里声明的未压缩大小是 zipfile 会产出的可靠
  上界（实测：CPython 到点即止并在不符时报错，不会越界解压），因此只读元数据把 androguard 要解压的那几个
  成员的声明未压缩大小加总，超过上限（512 MiB，远高于任何真实应用的 dex+arsc 体量）就在交给 androguard
  之前拒绝，并提示改用 `apk.decode`/`apk.decompile`（有界子进程）。畸形归档仍留给 androguard 报
  `backend_error`，不去猜。
- **androguard 进程内解析没有时间上限**。`apk.decode/decompile/export_sources/repack/sign` 走的是
  jadx/apktool 子进程、都带有界 `timeout`，但 `apk.open/classes/methods/strings/xrefs` 走的是进程内
  androguard（`APK()`/`AnalyzeAPK()`），既没有 `timeout` 参数也没有任何上限：一个恶意或超大的 APK
  丢进来，能把调用它的 MCP 工作线程占到解析跑完为止、还不给一个像样的故障，正是子进程后端早已
  设防的那种无界等待。现在解析放到守护线程上按墙钟上限跑（`Future.result(timeout=)`，与 Frida 后端
  `_run_deadline` 同构）：到点就把调用者放开并回 `timeout`，跑飞的解析在后台自行收尾（纯 C/Python
  无让点、杀不掉，但不再挟持线程池）。上限给得宽（300s），合法大号 multidex 应用仍是秒级到数十秒，
  只有卡死或离谱的解析才会触顶。
- **未登记产物树的字节上限被文件数量绕过**。`apk.decode/decompile/export_sources` 的产物树与
  `js.unpack_bundle` 的解包树都不进产物表，只能靠本地字节上限（`_refuse_oversized_tree` 与
  `prune_capped_dir` 的 `max_bytes=64/256 MiB`）兜底。可这两处都用 `_dir_size` 量体积，而它数满
  4096 个文件就停、只回一个裸 int——一个把大量小文件（一个大号或恶意 APK 经 apktool/jadx 展开出的
  几万个 smali/资源，或 webcrack 解包出的一堆碎片）铺开的树，只统计到头 4096 个就显得很小，字节
  上限于是形同虚设、整棵树留在盘上。现在 `_dir_size` 接受 `budget`：一旦累计越过预算就立即停手，
  并额外回一个 `over` 标志表示「还没数完/文件数超上限，真实体积至少这么大、可能大得多」；两处上限
  执行者都据 `over` 把这种树当作已越界（`prune` 计成至少一字节超预算而淘汰、`_refuse_oversized_tree`
  直接删树报 `too_large`）。文件数安全阀同时抬到 25 万——远高于真实 APK 展开的量级、真正大的树也早
  被字节预算拦下——所以合法的多文件大应用仍被精确量出、不会仅因文件多就被拒。
- **非 PE 后端的 `timeout` 一律报成不可重试**。apk/web/proxy/jsre/frida/device 六条线各自的 `_as_rpc`
  把后端异常裹成 `XdbgRpcError` 时只带 `code`/`message`/`details`，从不设 `retryable`，于是全部默认
  `False`——一个可重试的瞬时 `timeout`（设备卡住、外部工具一时慢），被报得跟永久的 `invalid_params`
  一模一样。可通用 `TimedOut`/`TimeoutError` 路径、DIE/Exeinfo 扫描器、以及 x64dbg/IDA 后端早就把
  超时标成 `retryable=True`；唯独这六条非 PE 线漏了，无人值守、按 `retryable` 决定是否重试的编排器
  于是对一个再调一次就好的停顿彻底放弃。现在六条线共用一个 `backend_error_is_retryable` 判定
  （落在 `core/results.py`，与 `_failure` 同处一个叶子模块）：只有 `timeout` 算可重试，`backend_error`
  作为同时涵盖永久故障（畸形 APK、坏参数）的兜底码仍不可重试，免得编排器在永远不会成功的调用上空转。
  非 PE 的故障契约就此与系统其余部分对齐。
- **`js.unpack_bundle` 的 `offset` 少了下界声明**。同类分页工具（`apk.*`、`web.*`、`proxy.flows`）的
  `offset` 都声明为 `Annotated[int, Field(ge=0)]`，唯独它写成裸 `int`——后端本就 `max(0, offset)` 兜底、
  功能上无碍，但 MCP schema 这份给 Agent/客户端看的契约独此一条没有下界。现在补齐 `ge=0`，与兄弟工具一致。
- **非 PE 后端异常靠每个 except 元组「记得写全」才不被误报成 internal_error**。`_failure` 早就直接认
  x64dbg/IDA 那族结构化异常（`StealthError`/`IdaWorkerError`/`XdbgRpcError`，取 `.code`/`.retryable`），
  但 adb/apk/apktool/frida/jadx/jsre/proxy/web 这八种后端异常不在其中——它们只在服务方法先经各自
  `_as_rpc` 裹成 `XdbgRpcError` 时才被认得。于是整套映射系在约 40 个服务方法各自的 `except (...)` 元组
  把可能抛出的后端异常类型一个不落地列全上；漏一个，一个本可被调用方按 `code`/`retryable` 处理的结构化
  故障就会跌进 `internal_error` 兜底，凭空记一条事故、还把后端精心设好的 `code`/`details`/`retryable` 丢掉——
  正是上面那些分支当初被加进来要杜绝的误判。现在 `_failure` 也直接识别这八种后端异常，并按 `_as_rpc`
  同一套 `backend_error_is_retryable` 推导 `retryable`：漏写 except 元组的方法退化成正确的结构化信封而非
  假事故，两条路径由构造保证给出一致的信封。
- **`apk.xrefs` 没有 `offset`，热点方法的调用点翻不到第一页以后**。`apk.classes/methods/strings` 早就是
  统一的分页形态——把结果收进一个有上限的列表（到 `_MAX_*_COLLECT` 就停并置 `scan_capped`）、`_page_bounds`
  夹 `offset`/`limit`、回 `count`/`total`/`offset`/`has_more`；唯独 `apk.xrefs` 只有 `limit`、收到页大小就停、
  也不回 `total`：一个被大量调用的工具/日志方法，其调用点超过一页的部分根本没有办法翻到，`has_more` 之外
  「这是不是全部调用者」也无从回答。现在 `apk.xrefs` 对齐兄弟工具：调用者收进上限 `_MAX_XREFS_COLLECT`（5000，
  防止畸形 DEX 把某个方法的调用点堆成无界列表）的列表并在触顶时置 `scan_capped`，`_page_bounds` 夹 `offset`
  （负值归零，不再尾切）与 `limit`（`le=1000`），回 `count`/`total`/`offset`/`has_more`/`scan_capped`。热点方法
  的调用点从此可逐页翻完。
- **`web.open`/`web.navigate` 把导航超时报成不可重试的 `backend_error`**。`page.goto` 到点未达等待状态时抛
  Playwright 自己的 `TimeoutError`，可 `open`/`navigate` 的 goto 都裹在一个通用 `except Exception` 里，一律
  转成 `backend_error`——而慢页面是最常见的瞬时状况。`_Runner` 的墙钟兜底早已把超时报成 `timeout`
  （retryable），adb/apk/jsre/jadx/apktool/frida/proxy 各后端的超时也都是 `timeout`；唯独 goto 这条把一个再
  导航一次很可能就成功的停顿标成不可重试，无人值守、按 `retryable` 决定重试的编排器于是干脆放弃。现在
  按类型名 `TimeoutError`（跨 Playwright 版本、措辞改动都稳）加报文兜底识别导航超时，改抛 `timeout`（带
  `url`、retryable），真正的加载错误（DNS、连接被拒）仍是 `backend_error`。`open` 首次导航超时照旧整体
  中止并拆掉会话，但现在标成 `timeout`，编排器会重开重试。
- **`web.network.get` 把「浏览器卡死」吞成一次成功的空 body**。取响应体走 `_runner(handle).call(...)`，
  而 `_Runner.call` 在浏览器超时（并就此把会话标 wedged）、会话已 wedged、或已 close 时抛的都是
  `WebError`——这些是会话级故障，之后每一次调用都会同样失败。可这里一个通用 `except Exception` 把它们
  连同真正的单体错误一起收进 `{**entry, "body_error": ...}` 原样返回：`ok=True`、带齐请求元数据，读起来
  就像一次「拿到了元数据、只是没 body」的成功。于是无人值守的编排器拿着一个再也不会响应的浏览器反复
  取 body，永远不知道该 `web.close` 重开。姊妹工具 `web.script.source` 早就是 `except WebError: raise` +
  只把非 `WebError` 的单体失败兜成 `not_found`；`network.get` 独此一处没对齐。现在它也先 `except WebError:
  raise` 让会话级故障带自己的 `code` 上抛（`timeout` 可重试），只有真正的单体 CDP 失败（资源不存在、body
  已被清出缓冲）才继续留作软 `body_error`、连同 `requestId`/`url` 等元数据一起返回。
- **`proxy.flow.get` 把压缩响应体原样当文本返回，等于给了一坨乱码**。它取的是 `resp.raw_content`——
  报文在链路上的原始字节，而现代 Web 的响应体绝大多数是 gzip/deflate/zstd/brotli 压缩过的；原样
  `decode("utf-8")` 出来的是噪声。于是这个「就为看响应体而存在」的工具，对最常见的情形交回的是垃圾。
  不能简单改调 `.content`（mitmproxy 会整体解压）：抓包环 只约束了**压缩后**的体积，一个敌意服务器
  完全可以回一个几百 KB、解压后上 GiB 的解压炸弹，把整个进程 OOM。现在新增有界解码 `_decode_body`：
  gzip/deflate（`zlib.decompressobj` 带 `max_length`）与 zstd（`zstandard` 流式 reader 带上限读）都在
  `_MAX_DECODED_BODY`（8 MiB）内解，超出即截断并置 `body_truncated`；brotli 在现装的绑定里没法对输出
  设限、其它未知编码同理，一律**不解**、原样返回并标 `body_decoded=False`——是「诚实的、仍是该编码的
  字节」，而不是「压缩数据冒充文本」。响应体被内容编码过时，`response` 现在带 `body_encoding`（编码名）、
  `body_decoded`（是否真解开了）、`encoded_size`（链路上的字节数），而 `size` 报解码后的长度；未编码的
  响应（identity/无该头）行为不变。
- **`proxy.flow.get` 只回响应体，请求体（POST/PUT 载荷）根本拿不到**。而抓包分析多半正是冲着请求
  载荷去的——API 参数、鉴权 token、表单字段。此前 `request` 只有 method/url/headers，一个只看响应的视角
  把最要紧的那半截藏了起来。现在请求体与响应体走同一套有界解码 `_decode_body`（gzip/deflate/zstd 在
  `_MAX_DECODED_BODY` 内解、防解压炸弹，brotli/未知编码原样带回并标 `body_decoded=False`）：≤200000 字节
  内联到 `request.body`，更大则外溢成 `flow-req-*.bin` 落到 `request.body_path`；没有请求体的 GET 则两者
  皆无，不平白塞个空 `body`。服务层 `proxy_flow_get` 现在把请求、响应两边的外溢各自登记入册（请求体的
  artifact id 落在自己的 `request_artifact_id`、不覆盖响应的 `artifact_id`），两个文件都被 retention 认领，
  谁也不会变成没人回收的孤儿。`_register_capture` 为此加了个可选的 `key` 形参（默认 `artifact_id`，其余
  调用方行为不变），让一个会外溢多个文件的工具能把每个 id 放进各自的字段。
- **`proxy.export_har` / `web.har.export` 导出的 HAR 缺了一半必填字段，标准查看器根本打不开**。
  两个导出各自内联拼一个 `{request:{method,url}, response:{status,content:{mimeType}}}` 就当 HAR 交差——
  可 HAR 1.2 的 entry 远不止这些：`startedDateTime`、`time`、`request`/`response` 各自要带
  `httpVersion`/`cookies`/`headers`（请求还要 `queryString`、响应还要 `content`）与 `headersSize`/`bodySize`，
  外加 `cache` 和 `timings`。少了这些，Chrome DevTools、Firefox、各类 HAR 分析器都判为格式非法、拒绝载入——
  一个哪儿都打不开的文件不叫导出。现在两边共用 `backends/common/har.py` 的 `har_entry` / `har_document`：
  每条 entry 都补齐全部必填成员，抓包留下的（method/url/status/mimeType 与起始时间）照实填，没留的
  （各类 header、body 大小）以合法的空数组 / `-1`「未知」哨兵占位而非省略——文件能开，又不谎报没有的数据。
  `startedDateTime` 用真实起始时刻：proxy 取 mitmproxy 的 `flow.request.timestamp_start`、web 取 CDP 的
  `wallTime`（各自记进 flow / network 摘要，`proxy.flows`、`web.network.list` 因此多出一个 `started_at` 纪元时间
  字段），拿不到才退化到当下；缺失时 `iso8601` 退到纪元 `1970-01-01T00:00:00+00:00`，绝不省掉这个必填字段
  让整份 log 被判废。既有的按容量裁剪（`UNREGISTERED_CAPTURE_MAX_BYTES` 内丢 entry）与 `too_large` 上抛照旧。
- **`web.dom.snapshot` 把超过内联上限的 DOM 直接截断丢弃，剩下的再也拿不回来**。姊妹工具
  `web.script.source`、`web.network.get` 对超大载荷都是「内联一段前缀、其余外溢成 artifact」，唯独
  DOM 快照在浏览器里 `slice(0, 200000)` 一刀切掉——一个大型 SPA 的 DOM（内联被逆向常要的正是内联脚本、
  嵌入数据）过了 200 KB 就只剩个头，没有任何补救路径。现在它对齐姊妹工具：浏览器侧改在抓包容量上限
  （`UNREGISTERED_CAPTURE_MAX_BYTES`，而非 200 KB 内联上限）处截断以约束传输，避免超大页整体序列化进内存；
  Python 侧走 `_spill_text` 内联前缀、把完整（至多到容量上限）DOM 落到 `dom_path`，`truncated` 置位，服务层
  `web_dom_snapshot` 把该文件登记为 `web_dom_snapshot` artifact 交给 retention 回收。`_spill_text` 为此加了个
  `truncate` 形参：response body / script source 是调用方要的完整数据、拿不全就该 `too_large` 报错（行为不变），
  而快照是尽力而为的视图、超限时降级成「留住容量上限那份、按字节边界切、标 truncated」而非整调用失败。
  DOM 在内联上限内时行为不变：`html` 就是整份、无 `dom_path`、`truncated=False`。
- **`web.wasm.list` 能列出 WebAssembly 模块，却没有任何工具能把模块取出来分析——分析终点建好了、桥没搭**。
  仓库早有 `wasm.wat`（wasm2wat）/`wasm.info`（wasm-objdump）对 `.wasm` 做反汇编与段信息，但从浏览器里
  拿一个活模块的唯一途径是 `web.script.source` → CDP `Debugger.getScriptSource`，而它对 wasm 返回的是引擎
  的**文本反汇编**、不是二进制字节，喂不进那两个工具。于是 `web.wasm.list` 成了半截路：看得见模块、取不出来。
  新增只读工具 `web.wasm.get(session_id, script_id)`：走 CDP `Debugger.getWasmBytecode` 取原始字节码，base64
  解码后——因是二进制、一律外溢成 `wasm-*.wasm` 制品（不内联），服务层登记为 `web_wasm_module` 交给 retention，
  回 `scriptId`/`url`/`bytes`/`wasm_path`，随后可直接把 `wasm_path` 交给 `wasm.wat`/`wasm.info`。会话级故障
  （浏览器超时/wedged/已关）带自己的 `code` 上抛（与 `web.script.source` 一致，`timeout` 可重试）；模块不存在
  或已被清出记 `not_found`；对着一个 JavaScript scriptId 调用是 `invalid_params`；超过抓包容量上限的模块
  `too_large`。它是 `web.script.source` 的二进制孪生（同样按 scriptId 取单个脚本的内容供分析），故归入只读；
  工具面因此从 265 增至 266（149 只读 / 117 写）。
- **`js.deobfuscate/beautify`、`wasm.wat`、`wasm.info` 过了 400 KB 内联上限就把尾巴丢了，且 `run_bounded` 的
  单流上限处还有一层没人说的静默截断**——`web.dom.snapshot` 早已改成溢出到制品，唯独这几个可移植单文件工具还停在
  「切到 400 KB、置 `truncated`、剩下的没了」。可 WAT 文本天然比 `.wasm` 字节大好几倍（`wasm2wat` 输出常达输入的数倍），
  一个真实模块几乎必然撞上内联上限，于是 `web.wasm.get` → `wasm.wat` 这条刚搭好的桥拿回来的照样是残缺前缀；
  `wasm-objdump -x` 列全部函数/导入/导出时同理。更深一层：`run_bounded` 对每条流有 8 MiB 硬上限（`DEFAULT_MAX_OUTPUT`）
  并回 `stdout_truncated`，但 `_run` 过去把这个标志直接丢掉——子进程真吐超过 8 MiB 时连捕获都被悄悄砍了、无人知晓。
  现在 `_bounded_output` 对齐 DOM 快照的溢出范式：内联仍是 `_MAX_INLINE` 前缀、`truncated` 语义不变，但一旦被切且
  调用方给了 `spill_dir`，就把**完整**载荷写到 `<key>-<uuid>.<ext>`（`code-*.txt` / `wat-*.wat` / `objdump-*.txt`）并回
  `code_path`/`wat_path`/`objdump_path`，尾巴因此可读；服务层把落盘目录设为 jsre 制品根、每次调用后按
  `JSRE_UNPACK_MAX_ENTRIES`/`JSRE_UNPACK_MAX_BYTES` 走 `prune_capped_dir` 有界回收（与 unpack 树同一套，避免这些不进
  artifact 表的溢出文件无限增长）。另加 `capture_truncated`：当子进程输出连 8 MiB 单流上限都撑破时置位，明确告知
  「连这份落盘文件也只是前缀」，而非让调用方把一个静默截断的文件读成完整输出。输出落在内联上限内时行为不变
  （无 `_path`、`truncated=False`、无 `capture_truncated`）。
- **`web.console` 收得到 `console.*`，却漏掉未捕获异常与未处理的 Promise 拒绝——正是逆向最想看的那类失败**。
  控制台环形缓冲只挂了 `Runtime.consoleAPICalled`，而一个逃逸的 `throw`（反篡改检查抛错、混淆代码在某处崩掉）
  或一个 unhandled rejection 走的是 `Runtime.exceptionThrown` 这条独立事件——DevTools 控制台照样显示，我们却
  只字不收。`Runtime.enable` 本就同时发这两个事件，缺的只是处理器。现在新增 `on_exception`：把异常渲染成一条
  控制台行（`text` 头 "Uncaught" / "Uncaught (in promise)" 接 `exception.description` 的完整 "Error: msg\n at …"
  栈，抛原始量则接其 `value`），与其他控制台行共用同一环形写入器和 `_MAX_CONSOLE_TEXT` 逐行上限（一个抛出
  兆字节字符串的页面钉不住缓冲）。落库的 entry 记 `type:"error"` 并置 `uncaught:true`，让调用方能把「抛出的
  失败」与「页面自己 `console.error` 的」区分开，引擎报了抛出点时附上 `url`/`line`。`console.*` 的既有行为不变。
- **`web.network.list` 里被拦截/中断的请求停在 `status:null`，和还在飞的请求长一个样**。网络环形缓冲只挂了
  `Network.requestWillBeSent` 与 `Network.responseReceived`——可一个被 CSP/CORS/混合内容拦下、被 abort、或撞上
  `net::ERR_*` 传输故障的请求根本不会有响应，它走的是 `Network.loadingFailed` 这条独立事件。缺了它，一次失败的
  加载就永远停在 `status:None`，与一个仍在进行中的请求无从区分——而「哪个端点被拦了」恰是逆向最想看的信号。现在
  新增 `on_loading_failed`：就地给对应 entry 打上 `failed:true`，附 `error_text`（如 `net::ERR_BLOCKED_BY_CLIENT`），
  策略拦截再带 `blocked_reason`（如 `csp`）与 `canceled`，字段照 `_MAX_METADATA_BYTES` 有界（超限置
  `metadata_truncated`），与 `on_response` 填 `status` 同一范式。失败事件指向一个已被环形缓冲挤出/从未见过的
  requestId 时直接忽略，不凭空造一条裸 entry。`web.network.list` 原样透出这些字段，成功请求行为不变。
- **`web.network.get` 只取得响应体，请求发出的 POST 体根本拿不到——而逆向 API/协议时请求载荷往往比响应更关键**。
  代理侧 `proxy.flow.get` 早就有 `request.body`，web 侧却只有响应体，两条线不对称。原因：CDP 的
  `Network.requestWillBeSent` 在体较大时不会内联 `postData`，取回它得按需调 `Network.getRequestPostData`。现在
  `on_request` 记录 `hasPostData` → 行上打 `has_post_data`（只在为真时，`web.network.list` 借此告诉调用方哪条有体可取）；
  `web.network.get` 在该行有体时调 `getRequestPostData` 取回请求体，并与响应体同一套 `_spill_text` 有界处理：小体走
  `request_body`、超内联上限溢出到 `request_body_path`（服务层用独立 `key=request_artifact_id` 登记为 `web_request_body`
  制品，不覆盖响应体的 `artifact_id`）、`request_body_truncated` 标记裁剪。会话级故障（runner 超时/wedged/已关）与响应体
  一样上抛（`timeout` 可重试），而每体级故障（CDP 未留存该请求体、或请求体超抓包容量上限）降级成软 `request_body_error`
  以免连已取到的响应体一起丢掉。无 POST 体的请求（GET）行为不变，绝不会触发 `getRequestPostData` 调用。
- **代理侧同一个盲区：连接失败的 flow 根本不进 `proxy.flows`**。`_FlowRecorder` 只实现了 mitmproxy 的
  `response()` 钩子——可一个在拿到响应前就失败的 flow（上游 refuse/reset、DNS 或 TLS 握手失败——把被 pin 的
  移动 App 挂到代理后最常见的正是这个、或超时）走的是 `error()` 钩子。没实现它，`proxy.flows` 就悄悄丢掉每一条
  失败连接，而这恰是架代理最想抓的证据。现在新增 `error()`：把 flow 记成一条 `failed:true` 且带 `error_text`
  （`flow.error.msg`）、`status:null` 的完结 flow；抓取失败请求体的保留走与 `response()` 完全相同的有界路径（抽出
  共用的 `_store_raw_locked` 承载 raw 存储/驱逐，`response()` 行为逐字不变），故 `proxy.flow.get` 仍能取回「当时
  试图发出的请求」（含请求体），其空响应段现在会带上 `failed`/`error_text` 说明缘由，而非被读成一次零长响应的成功
  抓取。`_flow_stored_bytes` / `_content_len` 本就容忍 `response=None`，字段照 `_MAX_METADATA_BYTES` 有界。
- **`frida.modules` 是唯一没有过滤器的枚举器，第 256 个之后的模块无从触达**。`frida.exports` 按 `module_name`
  过滤、`frida.java.classes` 按 `name_filter` 过滤，唯独 `frida.modules` 只有 `limit`（上限 256）、既无 offset 也无
  过滤——一个模块数超过 256 的进程，枚举序靠后的模块在任何页都看不到；而 `frida.exports` 又要求精确的 `module_name`，
  于是「第一页里找不到的模块」连它的导出都查不了。现在 `frida.modules` 加 `name_filter`：agent 端（`_ENUM_SCRIPT`）
  在截断前按子串 `m.name.indexOf(filter) !== -1` 过滤（与 `classes` 同一范式，大小写敏感），返回的 `total` 是匹配数、
  `has_more` 据此计算，故按名字即可把任意模块捞进页内、进而拿到精确名喂给 `frida.exports`。JS 仍最多 push `cap` 条、
  `total` 走计数，不会把整张模块表序列化成一坨 JSON。`frida.modules` 的既有无过滤行为不变（`name_filter` 默认空）。
- **`frida.exports` 同一个坑，只是低一层**：只有 `limit`（上限 512）、无 offset、无导出名过滤，一个大模块
  （libc、libcrypto、带上千符号的混淆 `.so`）里排在 512 之后的导出无从触达——可「拿到某个目标符号（如
  `SSL_write`）的地址去 hook」正是这个工具存在的全部意义。现在 `frida.exports` 加 `name_filter`：agent 端在截断前
  按子串 `e.name.indexOf(filter) !== -1` 过滤（与 `frida.modules` / `classes` 同一范式，大小写敏感），`has_more` 仍
  沿用「多取一条」的探针机制，故目标符号即便埋在 512 之后也能连同地址一并捞出。既有无过滤行为不变
  （`name_filter` 默认空）。至此 frida 的三个枚举器（modules / exports / java.classes）都能按名字收敛，
  `frida.modules(name_filter)` → 精确模块名 → `frida.exports(module, name_filter)` → 精确符号地址这条链彻底打通。
- **`frida.java.methods` 是 Java 侧的同一个缺口**：只有 `limit`（上限 2000）、无 offset、无方法名过滤，一个声明了
  上百方法的类里找目标方法（`doFinal`、`checkLicense`）只能整页拉回来自己扫。现在加 `name_filter`：agent 端
  （`_JAVA_SCRIPT.methods`）在截断前按方法签名子串 `sig.indexOf(filter) !== -1` 过滤（与 `classes` 同一范式，大小写
  敏感），`has_more` 仍走「多取一条」探针。至此 frida 四个枚举器（modules / exports / java.classes / java.methods）
  全部支持按名字收敛，Java 侧 `frida.java.classes(name_filter)` → 精确类名 → `frida.java.methods(class, name_filter)`
  → 目标方法这条链与 native 侧对称打通。既有无过滤行为不变（`name_filter` 默认空）。
- **静态侧同一个可达性死角**：`apk.classes` / `apk.methods` / `apk.strings` 先收集到 `_MAX_*_COLLECT`
  上限（10000 类 / 单类 2000 方法 / 5000 去重字符串）再排序、再分页——一旦命中收集上限（`scan_capped`），
  收集到的只是 `get_classes()`/`get_strings()` 吐出的**任意前缀**，排在收集边界之后的目标（比如捆了一堆 SDK
  的大 App 里某个 `com.target.Crypto`、或某条埋在第 5000 条之后的 URL/密钥片段）任何 offset 都翻不到——文档里
  那句「has_more 只表示还有已收集的行」正是这个坑。三者各加 `name_filter`：在**收集阶段、上限之前**按子串过滤
  （大小写敏感，与 frida 系列同一范式），于是非匹配项不占收集预算，目标即便排在原来的收集边界之后也能被扫进来、
  连同 `total`/`scan_capped` 一并如实反映过滤后的视图。既有无过滤行为不变（`name_filter` 默认空）。
- **`apk.strings` 只能靠已知片段（`name_filter`）收敛，浏览发现时被短噪声淹没**。DEX 字符串池里绝大多数是短噪声——
  `I`/`V` 这类类型描述符、单字母、混淆后的 `a`/`b`/`c` 名——真正有价值的 URL/密钥/命令往往埋在其后，而 5000 条去重
  收集上限一旦被这些噪声填满，长字符串就落在收集边界之外、任何 offset 都翻不到（与上一条同一个可达性死角）。新增
  `min_len` 参数，即 `strings(1)` 的长度下限惯用法：在**收集阶段、上限之前**丢弃短于该长度的字符串（与 `name_filter`
  同处一处、两者需同时满足），于是设个 6~8 的下限就能让埋在 5000 条噪声之后的长字符串真正可达，而不只是让结果更干净。
  既有行为不变（`min_len` 默认 0，即不设下限）。
- **`apk.strings` 找到一条可疑常量后，没法回答「它在哪里被用到」**。`apk.xrefs` 只做方法调用点（谁调了这个方法），
  而分析恶意样本时更常见的一步是：从 `apk.strings` 里抄出一条 C2 URL / 可疑日志串 / 加密标签，问「哪些方法引用了它」。
  新增只读工具 **`apk.string_xrefs`**（工具数 268→269）：`value` 按大小写敏感子串在字符串池里匹配（片段即可），逐个命中的
  常量取 androguard `StringAnalysis.get_xref_from()` 的 `(class, method)` 引用点；每个 caller 行为 `{class, method, string}`，
  其中 `string` 回显命中的常量（截到 256 字符）以便一个片段命中多条常量时仍可区分。返回 `value`、`matched_strings`（片段命中了
  几条常量）、`callers`、`count`/`total`/`offset`/`has_more` 及 `scan_capped`（收集触及 5000 行上限）；空 `value` 报
  `invalid_params`，无人引用的死常量（或仅经反射到达）给出空 `callers` 而非报错。与 native 侧 `frida` 的枚举链对称，把
  Android 静态侧的「串 → 用它的代码」这条 pivot 补齐。
- **`apk.manifest` 过了 200 KB 就把 XML 从中间切断、剩下的没了，而截断处的 XML 根本不成文档**。它把
  `manifest_xml` 内联切到 `_MAX_MANIFEST_CHARS`（200000 字符）、置 `truncated`，此外无任何补救——可
  AndroidManifest 在组件/intent-filter/metadata 堆多了的大 App 里确实会超，被切的那份既解析不了（元素切一半）、
  也无从取回完整正文。现在对齐 `web.dom.snapshot` 的溢出范式：一旦被切且服务层给了 `spill_dir`，就把**完整**
  XML 写到 `apk/<session_id>/manifest-<uuid>.xml` 并回 `manifest_path`；服务层 `apk_manifest` 经 `_register_capture`
  把它登记为 `apk_manifest` 制品（回 `artifact_id`），于是 `artifacts.read` 能打开、retention 能回收（裸路径两头
  不通的老毛病）。落盘超过抓包容量上限（`UNREGISTERED_CAPTURE_MAX_BYTES`，只有清单炸弹才可能）时删文件、降级成
  只有内联前缀而非报错整调用。新增 `apk/<session_id>` 到 `_session_artifact_roots` 使其成为会话自有子树（与
  `web`/`proxy` 同一范式）。清单在内联上限内时行为不变（无 `manifest_path`、`truncated=False`）。
- **`apk.xrefs` 只按方法名匹配、不认声明类，交叉引用因此既不精确也不完整**。它遍历所有方法、命中
  `method.name == 目标名` 就收集其调用点——文档原话「列出叫 method_name 的**每一个**方法的调用者」。可在混淆
  App 里方法全叫 `a`/`b`/`c`、或遇到 `decrypt`/`run`/`<init>` 这类常见名时，无数个毫不相干的同名方法的调用点被
  揉进一个列表、直接撑爆收集上限，于是对任何单个方法而言这份 xref 既不准也不全。现在 `apk.xrefs` 加可选
  `class_name`（点号或 `Lsmali/` 形式，与 `apk.methods` 同一套解析）把搜索限定到某个声明类，得到的就是「恰好这一个
  方法」的调用者；不传时行为不变（跨类按名聚合）。返回体加 `class_name` 回显本次范围（未限定为 null）。
  androguard 的 `MethodAnalysis.class_name` 提供声明类（smali 形式），据此比对。
  设备截图/拉取的目录保留由这个只按数量裁剪的 `prune_device_artifacts(keep=_MAX_DEVICE_ARTIFACTS=32)`
  实现——但 `device.screenshot` / `device.pull` 早已改走 `prune_capped_dir`（`UNREGISTERED_CAPTURE_MAX_ENTRIES`
  按数量、`UNREGISTERED_CAPTURE_MAX_BYTES` 按总量，比只裁数量更全），那个函数与常量遂再无调用方，只剩
  一个隔离单测在单独喂它。真正的坑是数值巧合：目录实际被裁到 `UNREGISTERED_CAPTURE_MAX_ENTRIES`，而集成
  测试却拿 `_MAX_DEVICE_ARTIFACTS` 当预期值断言——两者今天都等于 32 才碰巧过。谁要真去调 `_MAX_DEVICE_ARTIFACTS`
  改设备保留，改完是个静默的空操作、生产行为纹丝不动，测试还照样绿。现在删掉死函数与死常量，把「设备目录
  为何要自己兜底」的说明移到实际裁剪点，并让集成测试直接对 `UNREGISTERED_CAPTURE_MAX_ENTRIES`（真正生效的
  上限）断言；那条只喂死函数的隔离单测一并删除，免得它继续假装设备保留被覆盖到了。
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
