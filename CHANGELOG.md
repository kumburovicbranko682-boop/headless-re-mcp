# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

## [Unreleased]

本轮在既有 PE 逆向能力之外新增 Android 与 Web 两个目标域，并把监控台重做成对话居中的
Agent 工作台。工具面从 199 增至 **287（167 只读 / 120 写）**；读写分级在
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
- **进程内跑 mitmproxy 会被它自带的 mitmdump CLI 插件误杀**。`DumpMaster` 会带上
  `keepserving` / `readfilestdin` / `errorcheck`：前两个在 `running()` 里读共享的
  `ctx.options.rfile`，`errorcheck` 则装一个进程级 ERROR 根 handler，只要启动窗口内进程里
  任何组件（哪怕是别的 master 或无关工具）记了一条 error 就 `sys.exit(1)` 掉整个 master。
  而 mitmproxy 的 `ctx` 是普通模块全局，`Master.__init__` 在新 master 的选项注册完成之前就把它
  重置；`setup_servers` 又读共享的 `ctx.options.mode`。四个并发 `proxy.start` 实测能稳定复现
  两个 master 抢同一端口、`errorcheck` 再把包括健康 master 在内的三个杀掉。现在构造后即剥离这三个
  CLI 插件（并 `finish()` 掉 `errorcheck` 的根 handler，否则没人摘），用模块锁把构造到
  running 的危险窗口跨 master 串行化，且这把锁一直持有到我们自己的 running 信号确认危险的
  钩子链已跑完，而不是端口一接受连接就放。
- **APK 静态读取遇到坏 manifest 会被记成 `internal_error` 事故**。androguard 的 `APK()` /
  `AnalyzeAPK()` 对坏 manifest 不抛异常——它只记日志并返回一个对象，随后 `get_main_activity`
  / `get_permissions` 等 getter 才会从没解析成的树里抛出裸 `KeyError('Name')`。`ApkClient`
  过去只护住构造，这些裸异常逃逸到服务层被记成 `internal_error` 加一条事故——把输入文件的属性
  当成服务缺陷，正是 r2/jadx/apktool 适配器早已修掉的错判。现在每个 androguard 读取
  （open/manifest/permissions/certificates/components/native_libs/classes/methods/strings/
  xrefs）都把意外异常收敛成结构化 `backend_error`，而 `not_found` / `invalid_params` /
  `too_large` / `capability_unavailable` 这些刻意的码原样透出；Android gate 现在断言这些读取
  永远不会回成 `internal_error`。
- **`js.unpack_bundle` 每次必败**。适配器在调 webcrack 前先 `out_dir.mkdir(exist_ok=True)`
  把输出目录建好，而 webcrack 2.x 坚持自己创建 `-o` 目录、遇到已存在的目录直接
  `output directory already exists` 退 1——于是拆包在活体上从来没成功过，服务层只会回
  `backend_error`。因为只有 `js.deobfuscate` 有活体门，这条端到端断裂一直没人发现。现在只建
  父目录、把目录留给 webcrack 自己创建：空的残留目录先删掉让它接管，非空目录则先报
  `invalid_params` 而不是硬跑进去、再把里面本就存在的文件当成拆包结果误报成功。服务每次用
  全新的 `unpack-<uuid>` 目录，所以连续拆包都能成。
- **`frida.memory_read` 在 frida 17 上必败**。注入脚本用的是 `Memory.readByteArray(ptr,size)`，
  而 frida 17 已把 `Memory.read*` 系列全部移除、读操作改挂到 `NativePointer` 上
  （`ptr(addr).readByteArray(size)`）——于是脚本一调就抛 `TypeError: not a function`，
  `memory_read` 在所有现代 frida 上都读不到内存，而 `modules` / `exports`（走 `Process.*`）
  照常能用，掩盖了这条断裂。唯一的 frida 活体门要 Windows PE 夹具、在 Linux 核心上直接 skip，
  且从不读内存，所以这个回归一路溜过。现改用 `NativePointer` 读法；新增 `test_frida_local_live_gate.py`
  在 POSIX 核心上 attach 一个本地进程、跑通 attach/modules/exports/memory_read/hook，并断言在
  某模块基址读回 ELF 魔数——正是能逮住这个「API 被删」缺陷的断言（缺 frida / 无目标 / ptrace
  受限均 skip≠pass）。
- **抓包与浏览器抓取都只回响应体、丢掉请求体**。`proxy.flow.get` 只返回 `response` 的正文，
  `web.network.get` 只取 `Network.getResponseBody`——可对逆向 Web/移动 API 来说，POST 的
  请求体（表单/JSON 载荷、凭据、接口参数）往往才是要看的东西，而它被整份丢弃了（mitmproxy 的
  `request.raw_content`、CDP 的 `Network.getRequestPostData` 明明都留着）。现在两条线都对称地回请求体：
  `proxy.flow.get` 的 `request` 增加 `size` 与 `body`，超 200000 字节溢出为 `request.body_path`；
  `web.network.get` 在 `requestWillBeSent` 标记带体请求、按需取回 `request_body`（含
  `request_body_truncated` / `request_body_path`，浏览器已不留载荷时回 `request_body_error`）。
  溢出的请求体也登记为可下载产物。活体门各加一条 POST 断言（本地 origin 回读发出的 JSON 载荷）。
  两条摘要列表也各加 `has_request_body` 提示：`proxy.flows` 按 `request.raw_content` 是否非空标记，
  `web.network.list` 沿用 CDP 的 `requestWillBeSent`——扫一眼列表即可把 `flow.get`/`network.get` 指向
  真正带请求体的那几条，不必逐个打开。
- **页面里的 WebAssembly 模块列得出、却取不到字节**。`web.wasm.list` 能报出页面加载的 wasm 模块（scriptId、
  `wasm://` url），但唯一取内容的 `web.script.source` 只读 CDP `getScriptSource` 的 `scriptSource`——而对 wasm
  该字段恒为空，模块字节其实在 `bytecode`（base64）里，代码整份丢弃。结果「实时页面发现 wasm → 交给 `wasm.*`
  离线分析」这条链整条断了：列得到、却拿不到 `.wasm` 喂给 `wasm.wat`/`wasm.info`。现在 `web.script.source` 命中
  wasm 时解出 `bytecode`、落一个 `.wasm` 产物并登记为可下载捕获，返回 `is_wasm`、`wasm_bytes` 与 `wasm_path`
  （超捕获上限则拒绝）。活体门用一个真的 `add(i32,i32)->i32` 模块跑通：`web.wasm.list` 找到它、`web.script.source`
  取回与页面实际实例化**逐字节一致**的字节、并在装了 wabt 时把 `wasm_path` 喂给 `wasm.wat` 反汇编出可读模块
  （缺浏览器 / wabt 时 skip≠pass）；另加不依赖浏览器的单测用 mock 的 CDP `bytecode` 锁住该行为。
- **`web.console` 丢掉页面未捕获异常**。捕获只订阅 `Runtime.consoleAPICalled`（即 `console.*` 调用），而未捕获的
  JS 异常/Promise 拒绝走的是 `Runtime.exceptionThrown`——于是页面抛出的未处理错误与其调用栈（往往是分析一个页面
  时最有价值的一行）被整份丢弃、`web.console` 里看不到。现在同时订阅 `Runtime.exceptionThrown`，把异常按 `type`
  为 `error`、`source` 为 `exception` 记进同一 console 环（正文取 `exceptionDetails.exception.description` 的完整栈、
  按 console 文本上限截断；畸形事件忽略而非崩溃）。活体门用顶层 `throw` 的页面断言异常被捕获、且前后的普通
  `console.log` 仍在；单测用 mock 的 `exceptionThrown` 锁住入环行为。
- **`web.network.*` 看不出请求失败，被浏览器拦下/中断的请求与「还在跑」无法区分**。网络捕获只挂了
  `Network.requestWillBeSent` 与 `responseReceived`——被 CORS、CSP、`net::ERR_*` 或主动取消挡下的请求永远拿不到
  `responseReceived`，于是它一直停在 `status` 为 `null`，和一条尚未完成的请求长得一模一样，失败原因也被整份丢弃。
  对逆向而言这是实打实的假阴性：被拦的遥测端点、失败的接口调用、被 CSP 挡掉的外链，恰恰是要盯的目标，却在
  列表里查无实据。现在补挂 `Network.loadingFailed`，把对应请求标 `failed`、带上 `error_text`（并在有值时带
  `blocked_reason` / `canceled`），不再伪装成 `status` 待定；`web.network.list` / `web.network.get` 因为原样返回
  该请求记录，两个字段自动露出。活体门驱动一个 fetch 打向被内核直接拒连的回环端口的页面，断言该请求回来时标了
  `failed`、带非空 `error_text`、且没有假的 `status`（缺浏览器时 skip≠pass）；另加不依赖浏览器的单测直接驱动
  `loadingFailed` 钩子，覆盖标记、原因保留与对未知/已淘汰请求 id 的忽略。
- **`web.network.*` 从不返回请求/响应头，比同仓的抓包线缺一大块**。网络捕获只记 url/method/status/mimeType 与
  正文，可对 HTTP/接口逆向而言，头部才装着最关键的元数据——`Authorization`/`Cookie`/`Set-Cookie`、`Content-Type`、
  CORS 那一组；抓包线的 `proxy.flow.get` 早就回完整头部，Web 线却完全没有，只能靠正文猜。现在 `on_request` /
  `on_response` 分别把 `request.headers` / `response.headers` 收进按请求归档的条目，`web.network.get` 回
  `request_headers` 与 `response_headers`（有界 map）；头集大（长 cookie/token）时按头数与单值长度设上限、超限标
  `metadata_truncated`。`web.network.list` 刻意不带头部（每页保持轻量、返回去掉头部的副本，剥离动作不影响留存条目），
  要头部走 `network.get`。活体门在本地服务器上给 `/data.json` 加一个独特响应头、并让页面 POST 带 JSON 内容类型，
  断言 `network.get` 如实回响应头（含该标记与 content-type）与请求头、而列表行不含头部（缺浏览器时 skip≠pass）；
  单测直接驱动事件，覆盖有界化、超限截断标记、list 剥离与 get 保留。
- **`web.har.export` 导出的 HAR 不合规，导入工具打不开、且头部全空**。每个 entry 只有 request.method/url 与
  response.status/mimeType，缺 HAR 1.2 必需的 `startedDateTime`、`time`、`cookies`、`headers`、`queryString`、
  `cache`、`timings`——DevTools「Import HAR」、HAR Analyzer、har-validator 一律拒收；而 HAR 导出的全部意义就是喂给
  这些下游工具。加上刚补的头部捕获，现在导出补齐上述必需字段（httpVersion/headersSize/bodySize 用 HAR 允许的占位），
  并把捕获到的请求/响应头按 HAR 的 name/value 数组填入、URL 查询串解析进 `queryString`。活体门加载回落盘的 HAR，
  断言 entry 带齐必需字段、`timings` 有 send/wait/receive、且 `/data.json` 那条的响应头里有服务器设的自定义标记
  （缺浏览器时 skip≠pass）；单测直接读回 HAR，校验结构合规、请求/响应头进了 name/value 数组、查询串被解析。
- **HTTPS 抓包对自签/私有 CA/固定证书的上游无法解密，且失败时静默**。MITM 代理的核心价值就是解密 TLS，
  但 `proxy.start` 不暴露任何上游 TLS 选项，mitmproxy 默认要校验上游证书——而本工具面向的 App、
  移动端与自建/测试服务器几乎清一色用自签或私有 CA 证书。实测这类上游会被判 502、且**整条 flow 都不记录**
  （记录钩子只在 `response` 完成时触发，TLS 上游失败只产生 `error` flow），抓包看起来是空的、也没有任何线索。
  `proxy.start` 新增 `ssl_insecure`（对应 mitmproxy 的 `--ssl-insecure`：仅跳过对上游服务器证书的校验，
  代理照旧向客户端出示自己的 CA）：开启后客户端（信任代理 CA）拿到 200，`flow.get` 能回读代理从 TLS 流里
  解出的明文正文。`proxy.start` 返回值补上 `ssl_insecure`。新增活体门用现搓的自签 HTTPS origin 跑通整条
  解密链路（缺 mitmproxy 时 skip≠pass）。
- **`proxy.replay` 从来没有活体门**。重放（把抓到的请求原样再发一遍——改凭据/参数复现接口是逆向的常规动作）
  的成功标准是「上游真的又收到一次请求」，而 mitmproxy 的 `replay.client` 命令跨版本会变、又跑在代理自己的
  事件循环上，这条一直只有「命令是否排进去」的单测、没验证过真发出去。新增 `test_proxy_replay_reissues_a_captured_request_to_the_origin`：
  用会计数的本地 origin 抓一条 GET、重放它，断言 origin 计数从 1 涨到 2、且重放出的请求本身也被记进抓包
  （缺 mitmproxy 时 skip≠pass）。
- **`proxy.export_har` 也没有活体门**。抓包导 HAR 是把实时捕获交给 HAR 查看器/下游重放工具的标准出口。新增
  `test_proxy_export_har_serialises_the_capture`：抓一条 GET 后导出，断言落盘的是合法 HAR 1.2 日志、且其中一条
  entry 带上该请求的 `GET` 方法与 URL（缺 mitmproxy 时 skip≠pass）。
- **抓包看不到 WebSocket 帧**。`_FlowRecorder` 只实现了 `response` 钩子，只记下 101 升级握手那条 flow，之后的
  WebSocket 帧（`websocket_message` 钩子）整份丢弃——而聊天、交易、行情、推流这些实时应用几乎全靠 WebSocket，
  一个看不到 WS 的 MITM 代理对它们是瞎的。现在新增 `websocket_message` 钩子把每帧按 `from_client`、`size`、
  `text`（非 UTF-8 标 `binary`）、`truncated` 记入按 flow 归组的环，`proxy.flow.get` 对升级过的 flow 多回一个
  `websocket`（`messages` / `returned` / `message_count` / `truncated`），`proxy.flows` 摘要标 `is_websocket` 与
  `websocket_messages` 计数。内存四面设限：单帧内容、每 socket 环长、并发 socket 数、总字节都有上限，并把 mitmproxy
  自己那份「永不释放」的帧列表裁到很短的尾巴——否则我们持有的那条 flow 会随一个话痨 socket 撑爆内存。活体门用
  自搓的原始 WebSocket echo server + 原始客户端（不引第三方依赖）经代理跑通一次真正的 `ws://` 双工，断言
  `flow.get` 能按方向取回帧、摘要正确标记；另加不依赖 mitmproxy 的单测直接驱动 `websocket_message`，覆盖截断、
  计数、标记与裁列表。
- **抓包丢掉上游失败的请求，整条 flow 凭空消失**。`_FlowRecorder` 只实现 `response` 钩子，可上游连不上
  （拒连、DNS 失败、连接被重置、连 `ssl_insecure` 也救不了的 TLS 握手失败）时 mitmproxy 走的是 `error` 钩子、
  根本不产生 `response`——于是这条 flow 完全不被记录：明明发起过请求，抓包却是空的，失败原因也无从查起（这正是
  当初加 `ssl_insecure` 时记录的同一现象的另一半）。现在新增 `error` 钩子，把失败的 flow 按 `failed` + `error`
  （连接错误信息）、`status` 为 null 记入摘要环，并像 `response` 一样在内存预算内保留该 flow 供 `flow.get` 回读
  （请求在、响应空）；`error` 若发生在一次正常 `response` 之后，则只在原行上补标 `failed`/`error`、不新增一行。
  `response` 与 `error` 现共用抽出的 `_retain_raw` 记账，两条入口对内存/淘汰的看法不会分叉。活体门经代理向一个
  「已 bind 但从不 listen」的回环端口（内核直接拒连）发一次请求，断言该 flow 被标 `failed`、带非空 `error`、
  `status` 为 null、且 `flow.get` 如实回报失败（缺 mitmproxy 时 skip≠pass）；单测直接驱动 `error`，覆盖新建失败行、
  `flow.get` 透出失败、以及「响应后再报错只标注不重复建行」。
- **`web.dom.snapshot` 把 DOM 在浏览器里切到 200 KB、其余直接丢**。快照原来在页面内 `slice(0, 200KB)` 再回传，
  可一个真实 SPA 的 DOM 动辄几百 KB 到几 MB——而快照往往正是这次取证的核心，却拿回一段被截断、且无从补全的
  HTML。改用 `page.content()` 取完整 DOM，再按既有落盘范式（同 `web.script.source`）：内联一段预览、其余写进会话
  产物文件并回 `html_path`，另回 `bytes`（完整 DOM 长度）；`truncated` 现表示「内联只是预览、完整在 html_path」。落盘
  文件注册为 capture 走留存回收；直接调用后端（无产物目录）时退回内联预览+`truncated`，行为不变。活体门下发一个约
  500 KB DOM 的页面，断言 `web.dom.snapshot` 置 `truncated`、`html_path` 指向的文件逐字节等于 `bytes` 且含页面标记、内联
  html 仅为有界预览（缺浏览器时 skip≠pass）；单测覆盖大文档落盘（内联预览+完整可读回）与小文档不落盘。
- **Web 线读不到 Cookie——也就是会话/鉴权状态本身**。抓包线能看到 `Cookie`/`Set-Cookie` 头，但浏览器的
  Cookie 罐（含 HttpOnly——JS 读不到、只在罐里、且往往正是那枚会话令牌）此前没有任何工具能取。新增只读的
  `web.cookies`：驱动上下文的 `context.cookies()`，回 `cookies`/`count`/`has_more`，每条带 `name`、`value`
  （通常要找的令牌/会话 id，像头部值一样有界）、`domain`、`path`、`http_only`、`secure`、置了才给的 `same_site`，
  以及仅持久 Cookie 才有的 `expires`（会话 Cookie 的 -1 不当成真实时间戳外泄）；名字或值被裁到上限则标
  `metadata_truncated`。罐数量按 500 设上限（广告页一域能塞几十枚），安全标志一律给 False 而非缺省，避免「未知」
  被读成「未设」。活体门用本地站点下发一枚 HttpOnly 会话 Cookie + 一枚普通 Cookie，断言 `web.cookies` 取回其值与
  HttpOnly 标志、SameSite，且普通 Cookie 也在（缺浏览器时 skip≠pass）；单测覆盖标志归一化、会话 vs 持久 expires、
  超长值有界、以及大罐按上限截断。该工具计入读效果，工具面因此 266→267。
- **radare2 线看不到节区布局——`.text`/`.data`/`.rodata` 各在哪、多大、什么权限**。r2 线能列函数、字符串、
  导入导出，能在某地址反汇编，却没有工具回报节区表：分析者拿不到「代码/数据各落在哪段 VA、每段多大、可执行还是
  只读」这张在挑地址反汇编或读字符串之前最先要看的图。新增只读的 `r2.sections`：跑 `iSj`，回 `items`，每条带
  `name`、`size`（盘上字节）、`vsize`（映射后字节）、`paddr`（文件偏移）、`vaddr`、`perm`（rwx 串，如 `-r-x`），
  并由 `vaddr` 走与其它列表工具相同的统一 Address 富化给出 `address`（va/rva/module）、`count`；列表填满 4096 上限时
  标 `items_truncated`/`items_total`/`items_limit`，不另造 `sections`/`truncated`/`has_more` 字段。活体门用系统 C
  编译器现编一个 `-no-pie` ELF，断言 `r2.sections` 取回可执行的 `.text` 段、其 `address.va` 为正、ELF 不伪造 PE
  的 `rva`、`perm` 标记为可执行（缺 r2 或缺编译器时 skip≠pass）；单测覆盖 `iSj` 条目到 Address 的映射、列表截断标注、
  以及工具描述如实点名 `iSj`/`perm`/`vsize`/`items_truncated`。该工具计入读效果，工具面因此 267→268。
- **Web 线只读得到 Cookie，读不到 Web Storage——现代 SPA 真正存令牌/状态的地方**。刚加的 `web.cookies` 补上了
  Cookie 罐，但 localStorage/sessionStorage（JWT、refresh token、feature flag、应用状态常驻于此，且 `document.cookie`
  完全看不到）此前没有任何工具能取。新增只读的 `web.storage`：在页面内一次读出两个存储区，回 `origin` 与 `local`、
  `session` 两块，每块带 `items`（`key`/`value`）、`count`、`total`、`has_more`——某区被每区 500 上限截断时不会被当成
  整区读完。取值在页面内先按字符粗切（避免把几 MB 的值整段拉过 CDP 桥），再在 Python 里按字节封顶，`key`/`value` 触顶
  标 `metadata_truncated`。每个存储区各自走 getter 读取：`window.localStorage` 抛 SecurityError（不透明源、禁用存储）时
  该区退化为带 `error` 的空区、而非把「取不到」伪装成「空」，也不会连累另一区或整次调用。活体门用本地站点在页面里写入
  一枚 localStorage 令牌 + 一枚 sessionStorage 项，断言 `web.storage` 取回其 `key`/`value`、`origin` 指回被测源、两区
  `count` 正确（缺浏览器时 skip≠pass）；单测直接驱动 `page.evaluate`，覆盖两区键值映射、超长值有界、大区按上限截断置
  `has_more`、以及被拒存储区透出 `error`。该工具计入读效果，工具面因此 268→269。
- **`proxy.flows` 只能整页翻、没法过滤——真实抓包动辄上千条**。列表此前只有分页（`offset`/`limit`），要在成百上千
  条 flow 里找某一条请求只能一页页人肉翻。给 `proxy.flows` 加四个可选过滤器，在分页**之前**收窄：`method`（精确、
  大小写不敏感，GET 不等于 POST）、`host` 与 `url_contains`（大小写不敏感子串，便于按域名或路径片段定位）、`status`
  （精确状态码）。设了任一过滤器时，`total`/`count`/`has_more` 描述的是命中子集，另回 `filtered` 为真与
  `unfiltered_total`（整次抓包的规模）——一小撮命中不会被读成一小撮抓包；`dropped` 仍按整个环的淘汰量计（过滤前），
  免得过滤页误报历史丢了多少。`status` 过滤永远不匹配尚无状态的 flow（失败或在途、`status` 为 null），避免把「未知」
  当成「命中一切」。无过滤器时行为与字段完全不变（不多出 `filtered`/`unfiltered_total`），工具计数与读写归类不变。
  活体门经代理打一条 GET 和一条 POST，断言 `method`/`url_contains`/`status` 各自把实时抓包收窄到目标 flow、回
  `filtered`/`unfiltered_total`、且非命中 flow 不在过滤页里（缺 mitmproxy 时 skip≠pass）；单测覆盖四种过滤器与组合、
  `total` 报命中数而 `unfiltered_total` 留全量、无过滤器不多出字段、以及 `status` 过滤跳过失败 flow。
- **`web.network.list` 同样只能整页翻——一个页面动辄几百上千条请求**。CDP 抓包此前只有分页，要在文档、脚本、图片、
  XHR/fetch 里找某个打到 API 主机的调用只能一页页翻。与 `proxy.flows` 对齐，给 `web.network.list` 加五个可选过滤器，
  在分页**之前**收窄：`method`（精确、大小写不敏感）、`url_contains`（大小写不敏感子串，便于按主机或路径片段定位）、
  `status`（精确状态码，尚无状态的在途/失败请求永不匹配，避免把「未知」当成「命中一切」）、`resource_type`（精确、
  大小写不敏感：xhr/fetch/script/document/image…）、以及 `failed`（真只留被拦截/中止的请求，假只留未被标 `failed` 的）。
  过滤器可叠加（需全部命中）。设了任一过滤器时，`total`/`count`/`has_more` 描述命中子集，另回 `filtered` 为真与
  `unfiltered_total`（整次抓包规模）——一小撮命中不会被读成一小撮抓包；`dropped` 仍按整个环的淘汰量计（过滤前）。
  无过滤器时行为与字段完全不变（不多出 `filtered`/`unfiltered_total`），工具计数与读写归类不变。活体门用本地站点驱动
  一次含文档、GET fetch、POST fetch、图片 fetch 的混合抓包，断言 `method=POST` 只回带请求体的登录调用、`url_contains`
  折叠大小写并锁定该调用、`resource_type` 按 CDP 实际标注的类型收窄且非该类型的请求被排除，并核对 `filtered`/
  `unfiltered_total`（缺浏览器时 skip≠pass）；单测覆盖五种过滤器与组合、`total` 报命中数、`dropped` 留全量、以及
  无过滤器不多出字段。
- **`web.console` 也只能整页翻——页面把 console 刷满 debug 行时，那一条报错就淹了**。控制台缓冲此前只有分页，要在成千
  上万条日志里找报错只能一页页翻。给 `web.console` 加两个可选过滤器：`level`（对条目 `type` 的精确、大小写不敏感匹配，
  log/info/warning/error/debug…；`level=error` 连未捕获异常一并选中，因为异常也带 `type` error）与 `contains`（消息文本
  的大小写不敏感子串）。过滤在取尾页之前施加，故 `console` 是最近的命中、`count`/`has_more` 描述命中子集；设了任一时另回
  `filtered` 为真与 `unfiltered_total`（整个环的规模），免得一小撮命中被读成近乎空的控制台；`dropped` 仍按整环淘汰量计。
  无过滤器时行为与字段完全不变，工具计数与读写归类不变。活体门用会在顶层抛异常且前后各有一条 `console.log` 的本地页面，
  断言 `level=error` 捞到未捕获异常、排除 `console.log`、回 `filtered`/`unfiltered_total`，且 `contains` 按文本命中该异常
  （缺浏览器时 skip≠pass）；单测覆盖 level 精确匹配（含异常）、contains 文本匹配、二者组合、尾页 limit 与 `has_more`、
  以及无过滤器不多出字段。
- **`web.scripts` 同样只能整页翻——真实页面几十个 vendor/analytics 脚本里那一个 app bundle 得人肉翻**。脚本列表此前只有
  `wasm_only` 与分页，`web.network.list`/`web.console` 都能按子串过滤，唯独脚本列表不能，找某个 bundle 只能一页页翻。给
  `web.scripts` 加可选 `url_contains`（对 `url` 的大小写不敏感子串过滤），与 `web.network.list` 同一范式：在分页**之前**收窄，
  故 `total`/`count`/`has_more` 描述命中子集；设了时另回 `filtered` 为真与 `unfiltered_total`（整份脚本列表的规模），免得一小撮
  命中被读成近乎空的会话；`dropped` 仍按整环淘汰量计。可与 `wasm_only` 组合。无过滤器时行为与字段完全不变，工具计数与读写
  归类不变。活体门经本地站点断言 `url_contains="app.js"` 把实时脚本列表收窄到只含该子串的脚本、回 `filtered` 且
  `unfiltered_total` 等于全量 `total`，另断言无命中查询回 `total` 为 0（缺浏览器时 skip≠pass）；单测覆盖大小写折叠过滤、
  `filtered`/`unfiltered_total` 上报、`dropped` 经过滤不变、以及无过滤器不多出字段。
- **过滤之前，得先知道抓包里到底有什么——但 `web.network.list` 只能整页翻着看**。与代理线的 `proxy.stats` 对齐，新增
  只读的 `web.network.stats`：把整条请求环折叠一次成三角摘要，一眼看清该往哪过滤。回 `total`、`by_method`（每个 HTTP
  方法一个计数）、`by_status_class`（每个 2xx/3xx/4xx/5xx 一个计数；尚无状态的请求不计入这里，改计入 `no_status`）、
  `by_resource_type`（每个 xhr/fetch/script/document/image… 一个计数）、`top_hosts` 与 `top_content_types`（各为
  `{host|content_type, count}` 列表，按计数排序、上限 50，另回 `host_count`/`content_type_count` 给出去重总数，好让
  截断的列表被读成截断而非全貌），以及 `failed`/`with_request_body`/`finished`/`no_status` 计数；`dropped` 同
  `web.network.list` 为整环淘汰量。host 取自 URL 的 netloc，content type 取自 `mimeType` 并归一掉 `; charset=…`。
  摘要上没有 `requests`/`items`/`flows` 逐条字段——列表用 `web.network.list`、汇总用本工具。活体门用同一混合抓包断言
  摘要与列表口径一致（同 `total`、方法计数求和等于 `total`、POST 体计入 `with_request_body`、源主机进入 `top_hosts`），
  且摘要上无逐条列表（缺浏览器时 skip≠pass）；单测覆盖方法/状态类/资源类型/主机/内容类型的聚合与合并、以及 top 列表
  按上限截断而 `host_count` 仍报全量。该工具计入读效果，工具面因此 274→275。
- **`apk.strings` 只能整页翻，找一个 URL/密钥要人肉翻完整个 DEX**。列表此前只有分页；要在一个大 app 的几万条常量里
  定位某个域名、`api_key`/token 标记、或某个加密常量，只能一页页翻，而收集上限是 5000 条去重字符串——真正想找的那条
  可能就在这 5000 条之外，无过滤扫描到上限就停了，永远够不着。给 `apk.strings` 加可选 `contains`（大小写不敏感子串），
  且过滤在扫描**当中**施加，而非扫完再筛：这样 5000 上限约束的是**命中数**而非过滤前的集合，藏在远超上限之后的那条稀有
  字符串照样能被找到。设了 `contains` 时，`total`/`count`/`has_more` 描述命中子集，另回 `filtered` 为真与 `query`
  （查询词），`scan_capped` 为真则表示上限之外可能还有更多命中。无 `contains` 时行为与字段完全不变，工具计数与读写归类
  不变。活体门在自建 APK 上按 `contains="DECRYPT"` 断言只回含该子串的 DEX 字符串（大小写折叠）、带 `filtered`/`query`、
  且不含无关类名，另断言无命中查询回 `total` 为 0（缺 androguard 时 skip≠pass）；单测覆盖大小写折叠过滤、无过滤器不多出
  字段、以及一条埋在超过 5000 条非命中之后的字符串仍被找到（证明上限约束的是命中而非扫描位置）。
- **`apk.classes` 同样只能整页翻，找一个包/Activity 要在几万个类名里逐页扒**。类列表此前只有分页；要在一个大 app 里
  定位某个包（crypto、payment）、某个 Activity/Service、或某个混淆标记类，只能一页页翻，而收集上限是 10000 个类——
  真正想找的那个类可能就在这上限之外，无过滤扫描到上限就停了，永远够不着。给 `apk.classes` 加可选 `contains`（大小写
  不敏感子串），与 `apk.strings` 同一范式：过滤在扫描**当中**施加，故 10000 上限约束的是**命中数**而非过滤前的集合，藏在
  远超上限之后的那个稀有类照样能被找到。设了 `contains` 时，`total`/`count`/`has_more` 描述命中子集，另回 `filtered` 为真
  与 `query`（查询词），`scan_capped` 为真则表示上限之外可能还有更多命中。名字为 `Lsmali/` 形（点号 `a.b.C` 对应 `La/b/C`）。
  无 `contains` 时行为与字段完全不变，工具计数与读写归类不变。活体门在自建 APK 上按 `contains="SECRET"` 断言只回含该子串
  的类（大小写折叠）、带 `filtered`/`query`，另断言无命中查询回 `total` 为 0（缺 androguard 时 skip≠pass）；单测覆盖大小写
  折叠过滤、无过滤器不多出字段、以及一条埋在超过 10000 个非命中之后的类仍被找到（证明上限约束的是命中而非扫描位置）。
- **看不清 APK 里到底装了什么——只能看见 `.so`**。`apk.native_libs` 只列 `lib/*.so`，其余归档内容（有几个 dex、
  有没有 `assets/` 目录——藏 bundled dex/JS 载荷或配置的常见地方、资源表、META-INF 签名文件）此前没有任何工具能看到，
  想枚举只能 `apk.decode` 整包 apktool 解一遍。新增只读的 `apk.files`：先经 androguard 解析做门禁与校验（确是可解析
  APK、且 androguard 在场），再按 zip 中央目录列出真实归档条目——大小取自目录、不解压，大应用上也很轻。回 `files`，
  每条带 `name`、`size`（解压后字节）、`compressed`（盘上字节）、`category`（manifest/dex/native_lib/resource/asset/
  signature/other 之一），加 `count`/`total`/`offset`/`has_more`（填满每页 5000 上限时不会被当成整包读完）；`categories`
  给出各类在**整包**（非本页）的计数、`total_bytes` 为解压总大小，一次调用即可回答「有几个 dex」「有没有 assets 树」。
  超长条目名截断并标 `name_truncated`。活体门在自建 APK（含 manifest、dex、resources.arsc、两个 ABI 的 `.so`、
  `assets/config.json`）上断言各条目按正确 `category` 列出、`assets/config.json` 的 `size` 与内容相符、`categories`
  统计与归档一致（缺 androguard 时 skip≠pass）；单测直接驱动 zip 分页、类别归类、名字截断标记。该工具计入读效果，
  工具面因此 269→270。
- **列出 APK 内容后，除了 `.so` 谁也拿不出来**。`apk.files` 现在能看清归档，但要把某个条目取出来喂给别的工具，
  之前只有 `.so` 有 `apk.extract_native_lib`——assets 里的 bundled config/JS、藏起来的 dex/APK、资源、签名文件都
  只能靠 `apk.decode` 整包 apktool 解一遍才能落地。新增 `apk.extract_file`：`extract_native_lib` 的通用版，按 `apk.files`
  给出的确切归档路径取任意单个成员写入会话产物树，回 `entry`/`name`/`category`/`path`/`size`/`sha256`/`artifact_id`。
  只接受 androguard 已列出的条目（点不到任意 zip 成员或归档外路径），输出名把分隔符压平、去掉前导点，使嵌套条目无法
  爬出产物目录；单个成员超 64 MiB（与未注册产物预算一致）先行拒绝、不落盘。活体门在自建 APK 上抽 `assets/config.json`，
  断言落盘字节与打包内容逐字节相等、`size`/`sha256`/`category` 正确、有 `artifact_id`，且抽一个未列出的路径按 `not_found`
  拒绝（缺 androguard 时 skip≠pass）；单测覆盖真实字节落盘、路径压平（嵌套条目落成扁平名、不越界）、未列出/空条目的拒绝、
  以及结果不夹带内联字节。该工具计入写效果，工具面因此 270→271。
- **radare2 线只回报导入和导出，看不到完整符号表**。r2 线能列函数（`aflj`）、导入（`iij`）、导出（`iEj`），
  却没有工具回报 `is` 符号表：导入是外部引用、导出是对外可见项，各只切一片，而本地/静态符号、没进导出表的 `FUNC`、
  以及「这文件到底 strip 没 strip」的判断都落在完整符号表里，分析者只能靠 r2.functions 侧面猜。新增只读的
  `r2.symbols`：跑 `isj`，回 `items`，每条带 `name`、`realname`、`type`（FUNC/OBJ/SECTION/FILE…）、`bind`
  （GLOBAL/LOCAL/WEAK）、`size`、`vaddr`、`paddr`、`is_imported`，并由 `vaddr` 走与其它列表工具相同的统一 Address
  富化给出 `address`（va/rva/module）、`count`；列表填满 4096 上限时标 `items_truncated`/`items_total`/`items_limit`，
  不另造 `symbols`/`truncated`/`has_more` 字段。活体门用系统 C 编译器现编一个 `-no-pie` ELF，断言 `r2.symbols` 取回
  我们写的 `helper`/`compute`/`main` 三个 `FUNC` 符号、其 `address.va` 为正、ELF 不伪造 PE 的 `rva`，且符号表是导出表的
  超集（缺 r2 或缺编译器时 skip≠pass）；单测覆盖 `isj` 条目到 Address 的映射、`is_imported`/`bind`/`type` 原样透传、
  列表截断标注、以及工具描述如实点名 `isj`/`is_imported`/`items_truncated`。该工具计入读效果，工具面因此 271→272。
- **radare2 线看不到重定位表——不知道哪个导入被接到哪个 GOT/PLT 槽**。r2 线能列导入（`iij`，被拉进来的符号）
  却没有工具回报 `ir` 重定位：装载时被打补丁的那些槽（GOT/PLT），以及每个槽最终解析到哪个导入符号，都落在重定位表里，
  这正是「一个导入到底接在哪个地址」的答案——`r2.xrefs` 随后拿这个地址去找调用点。新增只读的 `r2.relocations`：跑
  `irj`，回 `items`，每条带 `type`（重定位类型，如 `JUMP_SLOT`/`GLOB_DAT`/`ADD_64`）、`name` 与 `demname`（该槽解析到的
  导入符号，匿名重定位为空）、`vaddr`、`paddr`、`is_ifunc`，并由 `vaddr` 走与其它列表工具相同的统一 Address 富化给出
  `address`（va/rva/module）、`count`；列表填满 4096 上限时标 `items_truncated`/`items_total`/`items_limit`，不另造
  `relocations`/`truncated`/`has_more` 字段。它与 `r2.imports`（被拉进来的符号）互补，点名这些符号落在哪些槽里。活体门用
  系统 C 编译器现编一个调用 printf 的 `-no-pie` ELF，断言 `r2.relocations` 取回带结构化 `address`（ELF 只给 `va`、不伪造
  PE `rva`）的重定位、且 libc 调用（printf/puts）出现在重定位表里（缺 r2 或缺编译器时 skip≠pass）；单测覆盖 `irj` 条目到
  Address 的映射（含匿名重定位仍映射槽地址）、列表截断标注、`irj` 在启动白名单内，以及工具描述如实点名
  `irj`/`is_ifunc`/`items_truncated`。该工具计入读效果，工具面因此 277→278。
- **`r2.strings` 只扫数据段（`izj`），加壳/混淆样本把字符串藏到别处就看不见了**。`izj` 只扫 radare2 归类为数据的
  段（.rodata/.data/…），可加壳器常把载荷字符串塞进非标准或不加载的段里——那正是分析者最想看的东西，却恰好在 `izj`
  的视野之外。给 `r2.strings` 加可选 `whole`：默认（`whole=false`）仍跑 `izj` 保持常见情形干净，`whole=true` 改跑
  `izzj` 全文件扫描，把藏在数据段之外的字符串也捞出来。全文件扫描是超集、也更吵（会把代码里看着像文本的字节串也报出来），
  条目形状与 4096 上限两种模式完全一致。无 `whole` 参数时行为不变，工具计数与读写归类不变。活体门用系统 C 编译器现编
  一个把标记字符串塞进非加载自定义段 `.r2hidden` 的 `-no-pie` ELF，断言默认 `izj` 扫描看得到 .rodata 标记却看不到隐藏段
  标记、而 `izzj` 全文件扫描两者都捞到、且是 `izj` 的超集（count 不小于），并核对捞回的隐藏字符串仍带 `.r2hidden` 段名与
  结构化 `address`（缺 r2 或缺编译器时 skip≠pass）；单测经服务层断言 `whole=false`→`izj`、`whole=true`→`izzj`，`izzj`
  在启动白名单内，以及工具描述如实点名 `whole`/`izzj`/`izj`。
- **WASM 线只有 wabt 文本大块，读不出模块的导入/导出结构**。`wasm.wat`（wasm2wat）、`wasm.info`
  （wasm-objdump）都要装 wabt，且只把结果当一坨文本回来；只想知道「这模块向宿主导入了什么、对外导出了什么」的
  分析者得先装 wabt、再去 objdump 文本里 grep。新增只读的 `wasm.summary`：**纯 Python** 直接读模块的 section 表，
  不依赖任何外部工具，wabt 缺席也能出结果。回 `imports`（每条 `module`/`name`/`kind`，kind 为 func/table/memory/global
  之一——这就是宿主/JS/WASI 互操作边界）、`import_count`，`exports`（每条 `name`/`kind`/`index`——对外可调用面）、
  `export_count`，`memory`（`initial`/`maximum` 页，模块没声明内存则为 null），`has_start`，`custom_sections`（如 `name`），
  以及 `counts`（`types`、本模块内定义的 `functions`、`imported_functions`、`tables`、`globals`、`memories`、
  `data_segments`、`elements`）。只解析摘要需要的 type/import/function/memory/export/start 与 custom 名，其余 section 按
  声明长度跳过，且每个 section body 都按自身边界切片，恶意长度读不出模块之外；截断、超长 LEB128、坏 magic 一律按
  `invalid_params` 返回而非崩溃，输入超 16 MiB 按 `too_large` 拒绝。导入/导出两张表各按 4096 上限，填满时标
  `imports_truncated`/`imports_total`/`imports_limit` 与对应的 `exports_*`。活体门用与既有 wabt 门相同的手法现搭一个带
  导入/导出/内存的合法模块，走完整 `AnalysisService.wasm_summary` 信封断言结构化结果，并对非模块断言返回 `invalid_params`
  信封（纯 Python，不依赖外部工具，总会跑）；另有一条在装了 wat2wasm 时把 WAT 现编成真模块交叉校验宿主导入/命名导出/内存/
  start（缺 wabt 时 skip≠pass）。单测手工构造模块字节覆盖导入/导出/内存/计数解析、导出表按上限截断、坏 magic、截断
  section 与超长 LEB128 的拒绝。该工具计入读效果，工具面因此 272→273。
- **WASM 线读得出导入/导出结构，却读不出模块自带的字符串**。编译出来的 WebAssembly 把字符串字面量（URL、主机名、
  api_key/token 标记、错误与格式串）放在初始化线性内存的 data 段里，而此前除了 `wasm.wat`/`wasm.info` 那两坨要装 wabt 的
  文本大块，没有工具能把这些串单独捞出来。新增只读的 `wasm.strings`，作为 `wasm.summary` 的姊妹：**纯 Python** 直接解析
  data 段（wabt 缺席也能出结果），逐段扫可打印 ASCII 串。回 `strings`，每条带 `string`、`segment`（data 段下标）与 `addr`
  （线性内存地址，仅当段偏移是字面常量时给出，好让分析者据此 pivot）；另回 `count`、`total`、`data_segments`（模块共几个
  data 段）、`min_length`、`scan_capped`（超过 4096 上限还有更多时为真）。`min_length` 是保留的最短串长（默认 4），可调高
  去噪、调低捕捉短标记；`contains` 做大小写不敏感子串过滤，且在扫描当中施加，故 4096 上限约束的是命中数，设了时另回
  `filtered`/`query`。只读 data 段，输入超 16 MiB 按 `too_large`、非模块按 `invalid_params` 拒绝而非硬猜。活体门手工搭一个
  data 段里埋了 C2 URL 与密钥标记的模块，走完整 `AnalysisService.wasm_strings` 信封断言两串连同 `addr` 都被捞回、`contains`
  收窄到命中、非模块回 `invalid_params`（纯 Python，总会跑）；另一条在装了 wat2wasm 时把带 `(data (i32.const 1024) …)` 的
  WAT 现编成真模块交叉校验串内容与 `addr==1024`（缺 wabt 时 skip≠pass）。单测手工构造模块字节覆盖串/段/addr 提取、
  `min_length` 抬高地板、`contains` 过滤、无 data 段、4096 截断、坏 magic 与截断 data 段的拒绝。该工具计入读效果，工具面
  因此 275→276。
- **WASM 线看得到导出，却看不到内部函数的名字**。`wasm.summary` 只列导出（对外可见的那一小片），可一个没被导出的内部
  函数——常是真正想找的解密/信标/校验例程——在导出表里根本不出现，只能拿函数下标当代号猜。可非 strip 的构建（或 dev 构建）
  会在名为 `name` 的 custom section 里把每个函数下标映射到可读名字，那正是 WASM 的调试符号表。新增只读的 `wasm.names`，
  作为 `r2.symbols` 在 WASM 上的对应物：**纯 Python** 直接解析 `name` section（wabt 缺席也能出结果），解出模块名（子段 0）
  与函数名映射（子段 1），local/label/type 名等其它子段按声明长度跳过。回 `has_name_section`（stripped 模块为 false——这与
  「有 name section 但没有函数名」是两个不同答案）、`module_name`（模块自身的名字，或 null）、`functions`（每条带 `index`
  与 `name`）、`count`、`total`、`scan_capped`（超过 4096 上限还有更多时为真）。`contains` 做大小写不敏感子串过滤（找某个
  getter、某个 crypto 例程），且在扫描当中施加，故 4096 上限约束的是命中数，设了时另回 `filtered`/`query`；函数名循环受
  子段自身字节数约束（每条至少 2 字节），谎报的 count 会读空数据自然停下，恶意长度读不出模块之外。输入超 16 MiB 按
  `too_large`、非模块按 `invalid_params` 拒绝。这样 `wasm.summary`/`wasm.strings`/`wasm.names` 三件套凑齐：导出面、字符串面、
  内部命名面。活体门手工搭一个 name section 命名了模块与三个函数（其一从不导出）的模块，走完整 `AnalysisService.wasm_names`
  信封断言 `has_name_section`、模块名、每条 `(index, name)` 与 `contains` 收窄、非模块回 `invalid_params`（纯 Python，总会
  跑）；另一条在装了 wat2wasm 时用 `--debug-names` 把带 `$名字` 的 WAT 现编成真模块，交叉校验连从不导出的函数名也被解出
  （缺 wabt 时 skip≠pass）。单测手工构造模块字节覆盖模块名/函数名解码、stripped 模块（`has_name_section` false）、非 `name`
  的 custom section 不误解、无关子段按长度跳过、`contains` 过滤、4096 截断、坏 magic 的拒绝。该工具计入读效果，工具面因此
  278→279。
- **WASM 线数得清 section 里有什么，却没有 section 表本身——不知道各段从哪儿起、多大**。`wasm.summary` 统计各 section 的
  内容（多少类型、多少函数…），但没有工具回报 section 表本身：每个 section 在文件里从哪个偏移开始、多大，以及每个 custom
  section 的名字和负载大小。要定位 code/data 段去 carve，或识破一个塞了载荷的超大 custom section，此前只能靠外部工具或人肉
  读字节。新增只读的 `wasm.sections`，作为 `r2.sections` 在 WASM 上的对应物：**纯 Python** 直接读 section 分帧（wabt 缺席也能
  出结果）。回 `version` 与 `sections`，每条带 `id`（数字 section id）、`name`（custom/type/import/function/table/memory/global/
  export/start/element/code/data/data_count/tag，新提案的未知 id 记为 `section <n>`）、`size`（body 字节数）与 `offset`（body 在
  文件里的字节偏移，好让调用方 seek/carve）；custom section 另带 `custom_name` 与 `payload_size`（名字之后的字节数），免得一个
  塞了载荷的 custom section 被当成体量正常的标准段。另回 `count` 与 `total`；模块 section 数超过 4096（恶意堆一堆小 custom
  section）时标 `sections_truncated`/`sections_total`/`sections_limit`。输入超 16 MiB 按 `too_large`、非模块按 `invalid_params`
  拒绝，谎报的 section 长度读不出模块之外。至此 `wasm.summary`/`wasm.strings`/`wasm.names`/`wasm.sections` 组成完整静态套件：
  导出面、字符串面、内部命名面、段布局面。活体门手工搭一个带 import/export/memory 的模块，走完整 `AnalysisService.wasm_sections`
  信封断言各标准段按序出现、每个 `offset` 落在文件内且严格递增、非模块回 `invalid_params`（纯 Python，总会跑）；另一条在装了
  wat2wasm 时把带 import/func/memory/data 的 WAT 现编成真模块，交叉校验 type/import/function/memory/export/code/data 各段都在
  布局里且偏移+大小不越界（缺 wabt 时 skip≠pass）。单测手工构造模块字节覆盖 id/name/size/offset 布局（含手算偏移）、custom
  段的 `custom_name`/`payload_size`、未知 id 记名、4096 截断、坏 magic 与谎报长度的拒绝。该工具计入读效果，工具面因此 280→281。
- **radare2 线能列符号、导入、导出、重定位，却没有「这东西链接了什么」——依赖库清单本身**。`r2.imports` 列的是被拉进来的
  单个符号，但没有工具回报二进制依赖的共享库清单：ELF 的 `DT_NEEDED`（`libc.so.6`…）、PE 的导入 DLL（`KERNEL32.dll`…）。
  这是比导入高一层的分诊视角——先看它链接了谁，再看那些库提供了哪些符号。新增只读的 `r2.libraries`，跑 `ilj`。`ilj` 回的是
  一个 JSON *字符串* 数组（不是共享 enrich 路径会整形的对象数组，那条路径只把对象数组变成带 Address 的 items），因此在后端
  单独解析该字符串清单。回 `libraries`（库名字符串列表）与 `count`；静态链接的二进制回空列表——空本身就是结论（装载期不解析
  任何东西）。另回 `total`；库数超过 4096（恶意堆一堆）时标 `libraries_truncated`/`libraries_total`/`libraries_limit`。没有
  `address`/`items`/`has_more` 字段：库名不是地址。为兼容将来把每个库包成对象的 r2 版本，对象条目按 `name`/`library` 字段取名。
  `ilj` 也纳入后端命令白名单。活体门在真 ELF 上跑：动态链接件的依赖清单里必有 `libc`、`module` 等于文件名；同一份源码用
  `-static` 现编（缺静态工具链时该分支 skip≠pass），依赖清单必为空。单测 mock `R2Client.run` 喂入 `ilj` 原始输出，钉住字符串
  清单整形、静态空列表、对象包裹格式的兼容、4096 截断、`ilj` 过白名单、docstring 形状。该工具计入读效果，工具面因此 281→282。
- **Android 静态线能列类名（`apk.classes`）、能列某类的方法（`apk.methods`），却说不清「这一个类是什么」**。缺一个
  类详情视角：它继承谁（角色——Activity/Service 基类，还是某个加密/混淆父类）、实现了哪些接口（`X509TrustManager` 是
  证书固定绕过的经典信号，`Runnable` 是后台任务）、类修饰符、以及声明的字段（静态密钥与配置就藏在这儿）。此前要看这些只能
  整包 jadx/apktool 反编。新增只读的 `apk.class_info`：`extends`/`implements` 取自高层 `ClassAnalysis`（恒在），访问标志与
  字段取自底层 class-def（androguard 仅见引用的外部类没有 class-def 时优雅留空）。回 `class_name`（解析成 smali 描述符）、
  `superclass`、`interfaces`、`access`、`fields`（各含 name/type/access）与 `field_count`、`method_count`、`is_external`；字段数
  超过 1000（混淆或生成类）时 `has_more` 置真。未知类回 not_found、空类名回 invalid_params。活体门在真 classes.dex 上驱动整条
  DEX 分析管线（class-def 读超类与访问标志、分析图数方法），断言超类、接口、访问、method_count 与未知类的 not_found——这正是
  androguard 版本升级最易破的 API 面。单测 mock 已解析分析，钉住完整形状（super/接口/access/字段）、点号类名解析、not_found、
  invalid_params、字段 1000 截断、docstring。该工具计入读效果，工具面因此 282→283。
- **Web 线只能整页 dump DOM（`web.dom.snapshot`），要找特定元素得把整份 HTML 拉回来再自己解析**。缺一个按 CSS 选择器
  定向查询实时 DOM 的能力。新增只读的 `web.dom.query`：给一个 CSS 选择器，回匹配元素的 `tag`（小写）、`attributes`（有界的
  名→值映射，专挑 href/src/name/value/data-* 这些逆向关心的信号）、`attrs_truncated`（元素属性数超过上限时置真）与 `text`
  （去空白且有界的 textContent）。另回 `selector`、`count`、`total`（页面里全部匹配数）与 `has_more`——于是「把每个 `<a href>`
  拉出来」「取某个 `<input>` 的 CSRF token」「列出所有 `<script src>`」都是一次调用，而不是 snapshot 加二次解析。查询在页内经
  `querySelectorAll` 执行；畸形选择器由页面抛出 SyntaxError，映射成 invalid_params，空选择器同样 invalid_params。元素列表硬上限
  200，每元素属性数上限 48，每个属性/文本值先在页内粗切再在 Python 按字节收紧（href 里的 data URL、内联 `<script>` 体可达数 MB）。
  没有 html/outerHTML 字段——要原始标记去 `web.dom.snapshot`。活体门在真浏览器上驱动整条栈（页内 querySelectorAll→有界→回服务）：
  `body` 选择器命中 1 个、tag 为 body、文本含 hello；`script` 选择器全部 tag 为 script；畸形选择器回 invalid_params。单测用桩
  page.evaluate 尊重后端传入的 maxItems/maxAttrs/maxValueChars，钉住 tag/属性/文本形状、元素 200 截断与 total、单元素属性 48
  截断、超大属性值按字节收紧、坏选择器与空选择器的 invalid_params、docstring。该工具计入读效果，工具面因此 283→284。
- **Ghidra 线能列已定义函数（`ghidra.functions`）与全部符号（`ghidra.symbols`），却没有单独的「导入了哪些库 API」视角**。
  外部（导入）函数——binary 调用的库 API，正是恶意样本三连问「它调了什么」的核心——被埋在符号表里，没有专门的一条。新增
  只读的 `ghidra.imports`：`ExportJson.java` 新增 `imports` 模式，遍历 `FunctionManager.getExternalFunctions()`，回 `items`，
  每条带 `name`（导入符号，如 strcmp/CreateFileW）、`entry`（Ghidra EXTERNAL 空间里的地址）与 `library`（来源模块，Ghidra 知道
  时给出如 KERNEL32.DLL/libc.so.6，否则空），外加 `count`、`has_more`。Java 端新增面极小：迭代与取字段完全照抄 `functions()`，
  只有 `getExternalFunctions()` 与带空值保护的 `getExternalLocation().getLibraryName()` 是新调用。Python 侧完整走桩测：伪造
  analyzeHeadless 写出 imports 形状的 JSON，钉住 mode 作为裸 postScript 参数抵达、外部函数负载（name/entry/library）经既有解析
  路径回来、`export_imports.json` 落盘；另有一条静态同步测试断言 `ExportJson.java` 确实分派 `imports` 模式并调 `getExternalFunctions`，
  避免 Java 与 Python 走偏（本环境无 Ghidra，端到端跑不了）。活体门（装了 Ghidra 才跑，skip≠pass）在真 PE fixture 上断言导入表
  至少解析出一条、每条带 name/entry/library。该工具计入读效果，工具面因此 284→285。
- **radare2 线能列函数、导入、重定位、依赖库，却没把「执行从哪儿开始」单列出来**——入口点只埋在 `r2.info` 的文本块里。
  新增只读的 `r2.entrypoints`，跑 `iej`。回 `items`，每条带 `type`（真入口是 `program`；PE 上还有 TLS 回调 `tls` 与 init/fini
  槽）、`vaddr`、`paddr`、头偏移（haddr/hvaddr），并由 vaddr 生成结构化 `address`（va/rva/module），外加 `count`。这是执行真正开始
  的地方——第一条要反汇编的指令——更关键的是把在主入口*之前*运行的 TLS 回调单独拎出来，那是恶意样本常见的反分析/抢先执行手法，
  而 `r2.info` 的文本块不会把它拆开。没有整型 address 字段；列表满 4096 时给 `items_truncated`/`items_total`/`items_limit`；没有
  entrypoints/truncated/has_more 字段。`iej` 纳入后端命令白名单。活体门在真 ELF 上断言 iej 解析出恰好一个 `program` 入口、带由
  vaddr 生成的结构化 va（ELF 不伪造 PE RVA）。单测用构造的 iej 输出钉住 vaddr→Address 映射与 type 保留（program 与 tls 各留其址）、
  4096 截断、`iej` 过白名单、docstring 形状。该工具计入读效果，工具面因此 285→286。
- **页面的嵌套结构（iframe 树）之前完全不可见**。`web.dom.snapshot` 只回主文档的 HTML，脚本/网络也不按 frame 分组，
  于是一个拉远端内容的跨域 iframe——钓鱼嵌页、第三方 widget、clickjack 覆盖层——作为*结构*根本浮不出来。新增只读的
  `web.frames`：一次调用列出整棵 frame 树（主文档加每个 (i)frame）。回 `frames`，每条带 `url`、`name`、`is_main`
  （主文档为真）与 `parent_url`（主 frame 上没有），外加 `count`、`total` 与 `has_more`。列表硬上限 200（广告/恶意页
  可嵌几十层 iframe），url/name 按元数据字节界收紧；读取中途 detach 的 frame 跳过不炸。没有 html 字段——要标记去
  `web.dom.snapshot`。活体门起本地站点、主页嵌一个具名 iframe，断言两个 frame 都在、主文档 `is_main`、子 frame 的
  `url` 指向嵌页且 `parent_url` 指回主文档；单测 mock Playwright 的 page.frames/main_frame 钉住整形、父子链、
  detach 跳过、200 截断与 docstring 形状。该工具计入读效果，工具面因此 286→287。
- **抓包上了几百条流就没法先看全貌再筛**。`proxy.flows` 是分页列表，`proxy.flows` 的方法/主机/URL/状态过滤要先知道
  「这次抓包里到底有哪些主机、哪些状态、哪些内容类型」才好下手，可这信息只能靠一页页翻整个 ring 才能拼出来。新增只读的
  `proxy.stats`：把整条 ring 折叠一次成三角摘要。回 `total`、`by_method`（每个 HTTP 方法一个计数）、`by_status_class`
  （按 2xx/3xx/4xx/5xx 计数；还没有状态的流——失败或在途——不计入这里，改计入 `no_status`）、`top_hosts` 与
  `top_content_types`（各是 `{host|content_type, count}` 列表，排序后按 50 截断，另给 `host_count`/`content_type_count`
  的去重总数，好让被截断的列表看得见），以及 `failed`、`websockets`、`with_request_body`、`no_status` 计数；`dropped` 同
  `proxy.flows`，是 ring 已淘汰、摘要再也看不到的条数。内容类型按 `;` 前缀归一，`text/html; charset=utf-8` 与
  `text/html` 归一桶。活体门在本地起 HTTP 服务经代理打 GET/POST/404，断言 `proxy.stats` 的方法计数、状态类计数、
  `top_hosts` 命中该主机、`with_request_body` 记到 POST；单测直接喂合成 ring 覆盖方法/状态类/主机/内容类型聚合、
  失败与 websocket 计数、以及 host/content-type 上限截断与去重计数。该工具计入读效果，工具面因此 273→274。
- **抓包里找一个 token/端点/报错串，得把每条流 `proxy.flow.get` 拉出来人肉读**。`proxy.flows`/`proxy.stats` 只能按元数据
  （方法/主机/URL/状态）定位流，回答不了「到底哪条请求或响应里出现了这个值」——那得逐条拉全内容自己翻。新增只读的
  `proxy.search`：一次性 grep 整个抓包，逐条命中流报出**命中在哪儿**。回 `matches`，每条带 `id`、`seq`、`method`、`url`、
  `host`、`status` 与 `where`——一个从 `url`/`request_headers`/`response_headers`/`request_body`/`response_body`/`websocket`
  里取值的列表，点明该 flow 里查询词出现的每一处；另回 `count`（本页返回数）、`total`（命中流总数）、`scanned`（扫过的流数）、
  `bodies_scanned`、`bodies_omitted`（体积超留存上限或已被淘汰、因而无法搜正文的流数）、`include_bodies`、`truncated`（上限之外
  还有命中）与 `dropped`（ring 淘汰数），免得部分结果被读成全部。正文搜的是 content-encoding 解码后的载荷——与 `proxy.flow.get`
  同样的字节，故 gzip/br/deflate/zstd 响应按解码后搜、而非压缩字节；拿命中的 `flow_id` 交给 `proxy.flow.get` 就能读上下文。
  `include_bodies=false` 只扫 url/头/WebSocket 帧，做一次更省的元数据级搜索。空查询按 `invalid_params` 拒绝。活体门在本地起
  HTTP 服务经代理打一条正文含标记的 GET 与一条请求体含标记的 POST，断言 `proxy.search` 分别在 `response_body`/`request_body`
  命中对应流、且 `include_bodies=false` 看不到只在正文里的命中（缺 mitmproxy 时 skip≠pass）；单测直接喂合成 ring 覆盖
  url/头/正文/帧四类命中与 `where` 上报、同一条流多处命中、`include_bodies=false` 跳过正文、超上限截断而 `total` 仍全量计、
  以及空查询拒绝。该工具计入读效果，工具面因此 279→280。
- **抓包途中想清掉噪声重来，只能停掉代理再重启——端口和 CA 都得重来一遍**。长时间拦截里常见的分流做法是：先做一遍
  嘈杂的登录/初始化，清掉，再复现真正关心的那一个动作、只读这段干净流量。可此前重置抓包的唯一办法是 `proxy.stop`+
  `proxy.start`，代价是丢掉监听端口、丢掉已装好的 CA。新增 `proxy.clear`：只清空 recorder 里的 flow（连同其摘要、留存的
  请求/响应体、WebSocket 帧），代理本身继续在同一端口监听、CA 原样不动。回 `cleared`（丢弃了几条 flow 摘要）与 `running`
  为真；`seq` 计数一并归零，故清空后 `proxy.flows`/`proxy.stats` 只报新流量、`dropped` 从清空基线重新计，而不是把清空前的
  历史误报成「已淘汰」。会话没有代理在跑时按 `invalid_state` 拒绝。活体门经代理打一条请求、`proxy.clear` 后断言 flows/stats
  归零、`proxy.status` 仍 `running` 且端口不变，再打一条断言仍能抓到、且 `dropped` 为 0（证明代理没被停、基线已重置；缺
  mitmproxy 时 skip≠pass）；单测直接驱动 recorder 覆盖清空计数、seq 归零、留存字节归零，以及后端回 `cleared`/`running`。
  该工具计入写效果（状态变更），工具面因此 276→277。
- **JS/WASM 输出超过 400 KB 就被截断且无从取回**。`js.deobfuscate`/`js.beautify`（webcrack）、`wasm.wat`
  （wasm2wat）、`wasm.info`（wasm-objdump）都只把结果内联返回、超 400 KB 直接切掉——而一份反混淆后的打包脚本常有
  几 MB，一个非平凡 WASM 模块的 WAT 反汇编动辄上兆，于是分析者拿到的是残缺的前 400 KB、且没有任何办法读到其余部分
  （与早先修的 web/proxy 大响应体、wasm bytecode 同类）。现在只要输出被截断，就把**完整**结果落进 jsre 产物目录并回一个
  `<key>_path`（`code_path` / `wat_path` / `objdump_path`），内联 `<key>` 仍是有界切片、`truncated` 为真——完整结果照旧
  可取。落盘文件与 unpack 树同在 jsre 根下，因为这些工具按文件路径而非会话归档、留存走查看不到它们，所以每次落盘后按总
  条目/字节给整个 jsre 目录设上限（保留最新、正好是这次刚写的那份）。活体门用真实 wabt：构造一个带大 data 段、WAT 约
  600 KB 的合法 `.wasm`，断言 `wasm.wat` 置 `truncated`、`wat_path` 指向的文件逐字节等于报告长度且大于内联切片、内容确是本
  模块的 WAT；另断言一个空模块不落盘（缺 wabt 时 skip≠pass）。单测把内联上限压低、直接驱动截断/不截断两路，校验落盘内容、
  路径字段与短输出不落盘。
- **能看见 APK 里的 .so 却拿不出来喂给 r2/Ghidra**。`apk.native_libs` 会列出每个打包的原生库，但现代
  Android 应用真正值钱的逻辑（加密、授权校验、反调试）都在这些原生代码里——而在此之前，把某个 `.so` 的字节
  取出来的唯一办法是 `apk.decode` 整包 apktool 解一遍（重、且会连资源一起铺开）。新增 `apk.extract_native_lib`：
  直接从 zip 里读出单个库写进会话产物树，回 `entry`/`abi`/`name`/`path`/`size`/`sha256`/`artifact_id`——注册一次
  即可用二进制线打开 `path`。只接受 androguard 已经列出的、形如 `lib/<abi>/<name>.so` 的真实可加载库（DEX 条目、
  越过 `lib/` 的路径、未列出的条目都按 `invalid_params`/`not_found` 拒绝，不写盘、也不读任意 zip 成员），ABI 拼进
  输出文件名避免两个 ABI 的同名库在盘上撞车，单库超 64 MiB（与未注册产物预算一致）先行拒绝。活体门在自建 APK 里放两
  个 `.so`、抽其中一个，断言落盘字节与打包内容逐字节相等、`size`/`sha256`/`abi` 正确、有 `artifact_id`，且抽一个
  androguard 没列出的路径按 `not_found` 拒绝（缺 androguard 时 skip≠pass）；单测覆盖真实字节落盘、非库/越界/未列出条目
  的拒绝，以及结果里不夹带内联字节。该工具计入写效果，工具面因此 265→266。
- **`web.console` 只留消息文本，丢掉了它从哪儿来**。控制台捕获只记 `type` 与 `text`——CDP 明明在
  `Runtime.consoleAPICalled` 与 `Runtime.exceptionThrown` 里随每条消息带了 `stackTrace`（首帧即调用点：
  url/lineNumber/columnNumber/functionName），异常还在 `exceptionDetails` 顶层另钉了 url/行号——过去全被丢弃，
  分析者看得到「报了个错」却定位不到是哪份脚本的哪一行，未捕获异常尤其如此。现在 `on_console` / `on_exception`
  统一抽取来源信息并并入条目：`url`、`line`、`column`（都转成 1 基，与 DevTools 及打印出的堆栈一致）、`function`；
  字符串沿用与其它页面元数据相同的有界处理，防止恶意页面借堆栈撑大环。没有 `stackTrace` 的普通 `console.log`
  不会凭空多出这些字段。活体门驱动一个顶层 `throw` 的页面，断言捕获到的异常条目 `url` 指回被测页面、`line` 为
  正整数（缺浏览器时 skip≠pass）；单测分别驱动带堆栈的 console、无堆栈的 console、带顶层 url/行号的异常，校验
  1 基转换、字段有无与函数名。
- **`web.network.*` 从不记录响应大小，HAR 里 `content.size` 恒为 0**。CDP 只订阅了 requestWillBeSent/
  responseReceived/loadingFailed，漏掉 `Network.dataReceived`（分块传来的响应体，`dataLength` 为解压后字节、
  `encodedDataLength` 为在线字节）与 `Network.loadingFinished`（总传输字节、完成标志）。于是 `web.network.list`
  的每条都没有大小，分析者无法在不逐个拉 body 的前提下看出哪条响应有几 MB；导出的 HAR 里 `response.content.size`
  硬编码 0、`bodySize` 恒 -1，HAR 查看器把每条都显示成空响应。现新增两个处理器：`dataReceived` 累加得到
  `response_size`（解码体大小）与 `response_encoded_size`（在线体大小），`loadingFinished` 记 `transfer_size`
  （含头的总传输）并置 `finished`；三者随列表行返回（不计入被剥离的 header 字段）。HAR 的 `content.size` 用解码体、
  `bodySize` 用在线体、条目另带 `_transferSize`。活体门断言 `/data.json` 响应完成后 `response_size` 等于服务端实际
  下发的字节、`finished` 为真、`transfer_size` 不小于体大小，且导出的 HAR 里该条 `content.size` 正是该长度（不再是 0）；
  单测直接驱动两次 dataReceived + 一次 loadingFinished，校验解码/在线体累加、总传输记录、以及对已淘汰 requestId 的分块
  安全忽略（缺浏览器时活体门 skip≠pass）。
- **抓包把响应体按在线字节原样返回，gzip/br 压缩的 API 响应读出来是二进制乱码**。`_message_body` 取的是
  `message.raw_content`——即在线字节，对 `Content-Encoding: gzip/br/deflate/zstd` 的响应仍是压缩态；docstring 甚至写着
  「decoded body」，其实根本没解。绝大多数现代 API 都压缩响应，于是 `proxy.flow.get` 读回的 `body`/`body_path`、连同
  `size`，全是压缩后的字节，分析者拿到的不是 JSON 而是一堆乱码（与刚修的 web 二进制体、更早的 wasm bytecode 同类）。
  改用 mitmproxy 自己的 `get_content(strict=False)`：按 Content-Encoding 解码（未知编码或流截断时回落到原始字节、不抛），
  正是 mitmproxy 各视图展示的口径；`size` 随之变为解码后长度。内存记账仍按 `raw_content`（保留的在线字节）不变。
  `flow.get` 另在压缩的那一侧补 `content_encoding`（在线编码），让「已解压、且 `size` 不等于 Content-Length」一目了然。
  活体门用本地 gzip origin 经代理跑一遍，断言客户端看到的是压缩字节（证明确实在线 gzip）、而 `flow.get` 回读的是解码后
  的 JSON、`size` 为解码长度、`content_encoding` 为 `gzip`（缺 mitmproxy 时 skip≠pass）；单测用真实 mitmproxy Response
  驱动 gzip 解码、大体解压后落盘不被二次压缩、明文请求不带 `content_encoding`。
- **`web.network.get` 把二进制响应体当基64文本落盘，`body_path` 里根本不是那份资源**。CDP 的
  `Network.getResponseBody` 对图片/字体/wasm/protobuf/任何 gzip 或非文本响应回 `base64Encoded=true`、`body`
  是基64字符串——过去代码只把这串基64当普通文本走 `_spill_text` 写进 `body-*.bin`，于是 `body_path` 存的是基64、
  不是解码后的字节：谁读回它去存图、解 protobuf、把模块喂给 `wasm.*`，拿到的都是错的（与早先修掉的 wasm bytecode
  同类问题）。现在 `base64_encoded` 为真时先 `b64decode` 再按**字节**落盘（复用 `_spill_bytes`，同 wasm 模块处理），
  `body_path` 是解码后的真实字节、`body_bytes` 是其长度、`body` 置空（本就不是文本）、另给有界的 `body_base64`
  预览（`body_base64_truncated` 标记裁剪）；解码失败则 `body` 空并记 `body_error`。文本响应路径不变。活体门用本地
  站点发一个 `image/png` 响应，断言 `web.network.get` 的 `body_path` 读回的字节与原图逐字节相等、`body_bytes` 正确、
  `body` 为空（缺浏览器时 skip≠pass）；单测直接驱动 base64 响应，校验落盘字节、`body_bytes` 与基64预览可解回原字节。
- **`apk.components` 只给四类组件的名字清单，攻击面无从判断**。活动/服务/接收器/提供者过去只回名字，
  分析者拿到列表却看不出哪些能被其它应用触达——而「哪些组件对外暴露」正是 Android 攻击面三连问的第一问。
  过去只能自己再去拉一遍 `apk.manifest` 原文、手动数 `android:exported` 与 `<intent-filter>`。现在
  `components` 在原有四个名字清单之外新增 `details`：把每类组件映射为逐个记录，含 `name`、`exported`
  （Android 的**有效**取值——显式 `android:exported` 优先，缺省时按是否声明 `<intent-filter>` 推断，这与
  activity/service/receiver 的平台默认一致，对 provider 亦是安全近似）、`exported_explicit`（原始属性，未设为
  null，好让「显式声明」与「推断」可区分）、`has_intent_filter`，以及组件被权限守卫时的 `permission`；再加
  `exported` 便捷映射，把每类只列出对外可达的组件名。原四个名字清单与 `main_activity`/`has_more` 契约不变，
  纯增量、不破坏既有调用方。经 androguard 的 `get_android_manifest_xml()` 读清单树逐元素取属性；清单无法被重新
  解析（畸形或老版本缺该 getter）时逐组件降级为「未暴露/未设」，绝不谎报可达，也不因此让整次调用失败。活体门在
  真实 APK 上断言带 LAUNCHER intent-filter 的启动 Activity 读作 `exported`、其余三类不暴露、`exported` 映射只含
  该 Activity；单测另覆盖显式 `exported="false"` 压过 intent-filter、`permission` 透出、以及清单不可解析时的降级。
- **`apk.components` 的 `<provider>` 默认暴露判定不分 API 版本**。ContentProvider 的默认导出规则在 API 17 翻过面：
  未显式设 `android:exported` 时，`targetSdk < 17` 默认**导出**、≥17 默认私有——与 activity/service/receiver 那套
  「看有没有 intent-filter」不同。此前对 provider 也套用 intent-filter 启发，等于对老应用漏报了默认导出的 provider
  攻击面（而老应用恰恰最值得审）。现读取有效 `targetSdk`（`get_effective_target_sdk_version`，回落 min），provider
  未显式声明时按 `has_filter or targetSdk<17` 判定；版本读不出则保守取现代默认（私有）。活体门里那份未声明 uses-sdk
  的清单被 androguard 解成有效 sdk=1，其无过滤 provider 遂如实落入 `exported` 映射（服务/接收器不落），在真实二进制
  清单上验证该规则；单测另分别用 targetSdk 16/17 断言 provider 默认从导出翻为私有。
- **`apk.components` 光有 `has_intent_filter` 布尔，却不给 intent-filter 里到底是什么**。判断深链攻击面要看
  具体的 action/category/data——自定义 URL scheme、host、path 模式、MIME 类型才是隐式 Intent 的真正入口，只知道
  「有没有 filter」远远不够。现在组件声明了 intent-filter 时，其 `details` 记录附带 `intent_filters`：每个元素为
  `{actions, categories, data}`，`data` 收集 `scheme/host/port/path*/mimeType`（空组省略，只声明 action 的
  filter 不会拖三个空数组）；逐组件封顶 32 个 filter、每类条目封顶 64，畸形/混淆清单也不至于撑爆。即便组件
  `exported=false` 也照样透出其 filter——那正是攻击者会去探的深链形状。活体门断言真实二进制清单里启动 Activity 的
  `MAIN`/`LAUNCHER` 能原样还原；单测另覆盖 `VIEW`+`BROWSABLE`+自定义 scheme 的深链 filter 与无 filter 组件不带该字段。
- **`r2.xrefs` 完全忽略传入地址，永远返回整个二进制的全部交叉引用**。用的命令是 `axj @ addr`——可 `axj`
  是「列出全部 refs」，`@ addr` 的 seek 对它毫无作用（实测某 ELF 上 `axj @ 任意地址` 与不带 seek 的 `axj` 都回
  相同的 20 条、`/bin/ls` 上都回 820 条）。于是 `r2.xrefs(某函数)` 拿到的是全程序 refs、而非该地址的引用者，
  `address` 参数形同虚设，文档许诺的「to/from 该地址」根本没兑现，而活体门只校验了 `parsed` 与 Address 结构、
  查不出这条。改用 `axtj @ addr`（列出**指向**该地址的引用，honors seek）：返回的是调用方/读取方列表，每条带
  `from`（引用点）、`type`、`from_address`；出边（该地址自身引用了谁）不在此列——从 `r2.disasm` 读。白名单正则
  放宽为同时接受 `axj`/`axtj`/`axfj` 的 seek 形式。活体门强化：编一个 `main→compute→helper` 的 ELF，断言
  `r2.xrefs(compute)` 非空、调用方落在 `main`、且其条数**严格小于**全程序 `axj` 条数——一旦有人退回忽略 seek 的
  写法，这条数相等即告警。
- **`web.screenshot` / `web.har.export` 两个取证工具没有活体门**。二者都以 mock 挡不住的方式跨 Playwright 边界：
  截图走 `page.screenshot()`、必须真落一个 PNG 文件并登记为可下载产物；HAR 要把会话记录的请求序列化成合法的
  HAR 1.2 日志、含首文档与子资源。Playwright API 漂移会静默弄坏其一。新增
  `test_web_cdp_screenshot_and_har_export`：驱动本地页面后截图（校验 PNG 魔数、`size` 与真实字节一致、
  `artifact_id` 已登记）并导出 HAR（`entry_count>=2`、`log.version==1.2`、条目含首文档与 `/data.json` 子资源；
  缺浏览器时 skip≠pass）。
- **APK 静态线整条没有活体覆盖**。androguard 单测全是 mock，一旦 androguard 升级改了 API（方法被删/改名、
  manifest 解码变化），单测照过、生产才炸——正是 frida `Memory.read*` 被删那类漏检。仓库此前没有任何 APK 夹具，
  于是 `apk.open/manifest/permissions/components/certificates/native_libs` 以及 `AnalyzeAPK` 分析流水线
  从未跑过真的 androguard。新增 `test_apk_static_gate.py`：用纯 Python 现搓一个**真正合法**的最小 APK
  （手工编译的二进制 `AndroidManifest.xml` + 一个带正确 adler32/SHA-1 的最小 `classes.dex` + 真实 zip 布局），
  经会话把整条静态线跑通——manifest 级的包名、版本、两项权限、四类组件、launcher activity、native ABI、
  证书（未签名），以及 DEX 分析流水线 `AnalyzeAPK`/`get_classes`/`get_methods`/`get_strings`/`get_xref_from`：
  断言列出真实类名、`decrypt ()V` 方法（并验证点分类名→smali 描述符的转换）、DEX 字符串池与空 xref
  的干净返回（缺 androguard 时 skip≠pass）。同一夹具还驱动 jadx 反编译线（此前也无活体覆盖）：跑通
  `apk.export_sources` 生成 `sources/…/Secret.java`、`apk.decompile` 取回该类的 Java 源码，验证
  `--output-dir` / `sources/` 目录布局、单类路径解析与退出码处理确实对得上真实 jadx（缺 jadx 时 skip≠pass）。
- **APK 改包线（apktool 解包/重打包、apksigner 签名）整条没有活体门**。`apk.decode`/`apk.repack`/`apk.sign`
  都是薄薄的子进程封装，其契约（`d`/`b` 参数向量、解包目录形态、「AndroidManifest.xml 必须存在」的成功判据，
  以及 apksigner 那四个带密码的 flag 和「签完再 verify 一遍」）只有对着真实 CLI 才现形，mock 一律挡不住。
  新增两条门：一条用无 `resources.arsc` 的现搓 APK 走 service 把 `apk.decode`→`apk.repack` 跑通（断言解出文本
  manifest + smali 目录 + 包名、重打出未签名 APK；缺 apktool 时 skip≠pass）——顺带记录一个真实约束：apktool 2.7
  只在装了框架时才把 manifest 重编成二进制，无资源树会原样拷文本 manifest，apksigner 便无法解析。另一条现搓一个
  **apksigner 真能解析**的二进制 manifest（`minSdkVersion` 按资源 id `0x0101020c` 走 XML resource-map、值按
  `TYPE_INT_DEC` 编码——否则 apksig 默认 API 1、又拒签自己的 SHA-256 v1 签名），用 keytool 现生成的 keystore
  驱动 `ApktoolClient.sign` 签名，断言产物签成、带 v1 JAR 签名块，再独立 `apksigner verify` 复核（缺 apksigner /
  keytool 时 skip≠pass）。
- **`apk.certificates` 只认 v1 签名，对绝大多数现代 App 会误判为未签名**。签名状态过去只报 `v1_signed`
  （= `get_signature_names()` 是否有 META-INF 签名文件），可 v2/v3 签名放在 APK Signing Block 里、根本不落
  META-INF——如今新 App 普遍 v2/v3-only（v1 早已可选甚至默认关闭），于是一个签得好好的包被读成 `v1_signed
  False` 就当成没签，签名方案与完整性保护整条信息缺失。现在按方案分别上报 `v1_signed`（JAR/META-INF）、
  `v2_signed` 与 `v3_signed`（APK Signing Block），外加「任一方案即视为已签」的 `signed`；证书列表本就走
  `get_certificates()`（androguard 会聚合 v1/v2/v3），v2/v3-only 也照样有证书。每个 `is_signed_v*` 探测都各自
  兜底（不同 androguard 版本 / APK 差异下不抛错）。单测锁 v1+v2 与 v2-only（无 META-INF 仍报 signed）两种；
  静态门里未签名夹具补断言三个方案位与 `signed` 全 False，签名门在装了 androguard 时回读 apksigner 产物、
  断言 `v2_signed` / `signed` 为真。
- **Ghidra 线在现代 Ghidra（11.4+/12.x）上整条不可用**，两处独立故障叠加：
  1) 导出脚本 `ExportJson.py` 标了 `@runtime Jython`，而 Ghidra 11.4 起不再内置 Jython，headless
     分析一执行 postScript 就以 `JythonStubException` 整体中止——`ghidra.functions/symbols/xrefs/decompile`
     全线报 `backend_error`。已把脚本移植为 Java 版 `ExportJson.java`（`GhidraScript`）：analyzeHeadless
     会即时编译，且 Java 脚本在所有 Ghidra 版本都受支持、无需任何扩展；输出 JSON 与原脚本逐字段等价
     （list 模式的 mode/items/count/has_more，decompile 的 function/entry/decompiled/truncated）。
  2) 项目落点撞上 Ghidra 的 `ProjectLocator` 校验——它拒绝任何以 `.` 开头的路径段，而默认 artifact 根在
     `~/.local/...` 下（含 `.local`），于是每次调用都以 “Path element starting with '.' is not permitted”
     中止。项目本就是一次性的（`-deleteProject`），改为在无点号的临时目录里建项目、用完即删；导出 JSON
     仍按普通文件 IO 写到调用方路径（不受命名规则约束）。
- **`_find_analyze_headless` 在 POSIX 上误选 `.bat`**。发行包同时带无扩展名的 shell 启动器与
  Windows `.bat`，解析器不分平台先挑 `.bat`——Linux/macOS 上于是选中不可执行的批处理，`available`
  仍报 True，随后每个 Ghidra 工具都以 “Permission denied” 死掉。现按宿主平台优先选对应启动器，另一
  平台的仅作兜底。
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

- **非 PE 线的活体门补齐了此前只打桩子进程的核心路径**。这些能力过去要么只在 Windows PE
  夹具上验过、要么整条链都被 mock，于是在 Linux 核心上端到端零覆盖——`js.unpack_bundle` 每次
  必败的缺陷正是这样溜过去的。新增/扩展：`test_web_re_gate` 起一个本地 HTTP 站点、驱动真实
  CDP 抓一次子资源与一次 fetch，断言 `web.network.get` 回原样响应体、`web.script.source` 回真
  脚本源码（此前只有 data: URL 门证明 scripts/console/dom 存在）；并新增 `js.unpack_bundle`
  与 `wasm.info` 的活体门（此前只有 `js.deobfuscate` / `wasm.wat`）。`test_proxy_lifecycle_gate`
  过去只验起停与端口，从不发一个字节；现增一条真的把 HTTP 请求经代理打到本地源、断言 flow 被
  记录且 `flow_get` 回原样响应体——这是 Web/Android 共用的拦截契约。`test_android_re_gate`
  过去只护 `device_list` 降级，现对所有带 serial 的设备控制口（info/properties/packages/
  current_activity/logcat/launch/force_stop/uninstall/screenshot/pull）断言：无论 adb 缺失
  （`capability_unavailable`）还是在场但无设备（`backend_error`），都回刻意码、永不 `internal_error`。
  `test_r2_elf_live_gate` 现在除 open/functions/disasm/xrefs 外还覆盖 strings/imports/exports：
  用系统 C 编译器编一个带已知字符串的小 ELF，断言 `izj`/`iij`/`iEj` 都解析成带统一 Address 的
  条目（编进去的字符串、一个 libc 导入、我们自己的一个导出）。缺工具/编译器一律 skip（≠pass）。
  `test_frida_local_live_gate` 是 frida 在 POSIX 核心上的首个活体门（此前只有需 Windows PE 夹具、
  在 Linux 直接 skip 的 M11 门，且从不读内存）：attach 一个本地进程、跑 attach/modules/exports/
  memory_read/hook，并断言 per-session pid 边界拒绝越权 pid、在模块基址读回 ELF 魔数——正是
  `frida.memory_read` 那条 API-被删缺陷的护栏。`test_web_re_gate` 再加一条 `web.wasm.list` 活体门：
  页面里真的编译实例化一个 WASM 模块，断言它被 CDP 报成 `wasm://`、语言 WebAssembly，且
  `wasm_only` 过滤确实收窄了完整脚本表（页面里另有 JS 脚本）。
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
- **r2 在 Linux 核心首获活体覆盖**：唯一另一个活体 r2 gate 需要一份 Linux 核心不随附的
  Windows PE 夹具,于是在这个平台上 radare2(已装、跨平台)端到端零覆盖——所有 r2 测试都在
  打桩子进程。新增 `test_r2_elf_live_gate.py` 用系统 C 编译器编一个小 ELF,驱动真实的一次性
  管线(argv 构造、跨 banner 的 JSON 提取、命令白名单、Address 映射),覆盖
  open/functions/disasm/xrefs,并断言白名单在活体路径上照样拒绝表外命令;缺 r2 或编译器
  时 skip(≠pass),ELF 无 PE ImageBase 故断言 item 只带 `va`、不伪造 RVA。
- **APK 坏文件读取回结构化码而非内部事故**：Android gate 现在对合成(manifest 不可解析的)
  APK 逐个跑 open/manifest/permissions/certificates/components/native_libs,断言它们即便失败也
  绝不回 `internal_error`;单元测试补一组参数化用例,证明任何 androguard 读取都不会漏出裸异常
  (否则服务层会记成事故),而 `not_found` 等刻意码原样透出。

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
