# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

## [Unreleased]

本轮在既有 PE 逆向能力之外新增 Android 与 Web 两个目标域，并把监控台重做成对话居中的
Agent 工作台。工具面从 199 增至 **268（149 只读 / 119 写）**；读写分级在
`tools/catalog.py` 里逐个显式声明（如 `memory.protection`、`workflow.breakpoint.put` /
`disable` 计入写，`static.search.text`、`patches.list` 计入读）。以下按类别列出。

新增 Linux x86_64 核心支持：wheel/sdist 与 `scripts/install-linux.sh` 可安装，`doctor --strict` 以平台动态必需项判断就绪，`serve` / `serve-web`、会话、制品和可移植后端可在 Linux 加载。doctor 与 `/readyz` 现在报告 `full`（Windows）或 `core`（Linux）支持级别。

x64dbg、WinDbg/cdb、Win32 UI/UIA/SendInput/Windows OCR、hidden desktop、MSI/WiX 及现有 Windows 专用 unpacker 适配在 Linux 明确报告 `unsupported_on_platform`，不再伪装 ready，也不阻塞 Linux 核心就绪。Windows 的原有 required 探针与 MSI/PowerShell 路径保留；IDA 探测同时识别 Windows `idalib.dll` 与 Linux `libidalib.so`。

CI 增加 Ubuntu/Python 3.11、3.12 的 lint、mypy、unit、doctor、核心服务与 wheel/sdist 构建；真实 Windows 后端 gate 继续留在 Windows job，Linux 收集时给 Windows-only 集成测试明确 skip 原因。

托管 quality job 只装 `.[test,dev,web]`：没有 PySide6 / winsdk 时 mypy 仍能过；导入 `native_app.bootstrap` 不再顺带加载 Qt GUI；没有编好的 PE 夹具时单元测试也能收集完。监控台 `webui/src/agent/state.ts` 的改动已重新打进提交的 SPA。UPX/XVLKC/Scylla/VMPDump/de4dot 在会话不是 PE 时先报 `target_mismatch`，不再因为本机没装 CLI 就说成 `capability_unavailable`。

CLI 工具超时不再可能卡死或漏杀孤儿进程。`run_bounded` 过去在 `with subprocess.Popen(...)` 里跑工具，其 `__exit__` 会在调用线程上关闭 stdout/stderr——当被启动进程派生的孙进程继承了这对管道并存活时，读取线程仍阻塞在 `read()` 上持有缓冲区锁，`close()` 便永久阻塞，有界超时变成永久挂起。现不再用上下文管理器：每个读取线程自持其流并在 `read()` 返回后关闭，主线程只回收进程、绝不碰管道。POSIX 下还让工具独立成会话，超时/取消时按进程组整体发信号（限组长，避免误杀服务自身的进程组），从而杀掉 ppid 遍历看不到、已被 init 收养的孙进程（如残留的 JVM/helper）。

die/exeinfope/upx/de4dot 各自的 `_capture_process` 采用同一范式收敛：读取线程自持自闭管道、捕获线程只在读取线程已结束时才关句柄，POSIX 下工具独立成会话。de4dot（及复用它的 NETReactorSlayer）正常退出后遗留的 runner 子进程（JVM/dotnet，常被 init 收养）以前 ppid 遍历看不到而泄漏；新增 `collect_process_group` / `terminate_process_group` 按会话组枚举并逐个按各自 `pgrp` 击杀，避免组长 pid 复用误伤无关进程组。

调用方取消（`BoundedCancelled`）在各适配器间统一为“取消不是失败”：NETReactorSlayer 适配器过去把取消重映射成 `process_failed`，与 scylla/vmp_dumper/xvlkc 等兄弟适配器不一致，现改为原样上抛；`unpack.auto` 的 UPX 阶段（`unpack_upx_test` / `unpack_upx_unpack`）过去把取消经通用 `except BaseException` 吞成 `internal_error` 事故与假的 `upx_test_failed`，现先行捕获并重抛给 `unpack.auto` 的取消处理器，最终干净地记为 `unpack_cancelled`。此外 `unpack.xvlkc/vmp/scylla` 各 CLI dump 在进入取消作用域前会像 `unpack.auto` 一样先 `_reset_unpack_cancel`，避免上一次 `unpack.cancel` 遗留的取消闩让后续同会话 dump 一进来就自我取消。

### 非 PE 后端 `timeout` 现在如实上报为 `retryable=True`：六个 `_as_rpc` 转换器此前都用 `XdbgRpcError` 的构造默认 `retryable=False`，把每一类非 PE 失败(含 timeout)拍平为“永久失败”，与 `_failure` 对 TimedOut / TimeoutError / DIE·Exeinfo 扫描 timeout 一律判 retryable 的全局约定相悖

- `RpcError.retryable` 是与 `code` 并列的机器契约:无人值守的调用方据此决定是否重试(见 `test_result_failure_mapping`
  的 docstring——存储故障可重试、`invalid_request` 不可)。`results._failure` 里全线一致:通用 `TimedOut`、stdlib
  `TimeoutError`、以及 DIE / Exeinfo 的扫描 timeout 都判 `retryable=True`——超时是可重试的瞬时上界。唯独非 PE 后端是例外:
  它们的错误类(`WebError` / `AdbError` / `FridaError` / `ProxyError` / `ApkError` / `JadxError` / `ApktoolError` /
  `JsReError`)不带 retryable 字段,而六个服务 mixin 的 `_as_rpc` 都写成 `XdbgRpcError(exc.code, exc.message, details=...)`,
  吃下构造函数默认 `retryable=False`。于是一次慢的 `web` / `frida` / `device` / `proxy` 调用抛出 `timeout`,到调用方却成了
  *永久* 失败——一个“跳过确定性错误”的 agent 会拒绝重试一次很可能第二次就成功的调用。转换点还把类型抹平(到 `_failure`
  时 `WebError` 与真正的 x64dbg 故障已是同一个 `XdbgRpcError`,无从回溯),所以推导只能落在 `_as_rpc` 这唯一有非 PE 类型
  信息的位置。新增共享 `backend_error_as_rpc`,在这一处按 code 推导 retryable(仅 `timeout` 判真,其余
  `invalid_params` / `not_found` / `capability_unavailable` / `invalid_state` / `permission_denied` / `too_large` /
  `backend_error` 皆为确定性失败,重试返回同一结果,保持假),六个转换器全部改走它,任何单点回退到丢标志的构造式都无法
  再悄悄降级。`_RETRYABLE_BACKEND_CODES` 收敛为 `{"timeout"}`,且约束为 canonical 词表的子集。新增
  `test_non_pe_error_retryable.py`:钉住规则本身(可重试码恰为 `{"timeout"}` 且 ⊆ 词表)、helper 跨整套词表只让 timeout
  可重试且 code/message/details 原样保留、六个转换器经 `_failure` 端到端各自让 `timeout` 上报为 retryable(断言里点名
  backend,单点回退即精确指认)、以及镜像方向(确定性码 `invalid_params` 经每个转换器仍 retryable=False,防止在某处放宽
  规则)。以非空注入验证:把 `service_web._as_rpc` 临时退回丢标志的裸构造式,守卫精确报出 `web`,还原后转绿。
- 补齐第二处 Frida 面:`_as_rpc` 只覆盖 Android 线(`service_frida`),但 optional-backend 的五个 Frida 方法
  (`frida.attach` / `frida.modules` / `frida.exports` / `frida.memory.read` / `frida.hook.template`)在 `service_ext` 里各有
  自己的 `except FridaError` 块,绕开 `_as_rpc` 就地写 `XdbgRpcError(exc.code, exc.message, details=...)`——同一 `FridaError`
  类、同一丢 `retryable` 的构造默认,于是这条支路上的 `frida` 超时仍报“永久失败”,恰是 `_as_rpc` 修复漏掉的第二个 Frida
  表面。五处全部改走 `backend_error_as_rpc`(r2 / ghidra / windbg 属原生/PE 邻接线,不在本轮范围,保持不动)。新增
  `test_frida_ext_error_retryable.py`:以抛错的 FridaClient 替身 + monkeypatch `_require_debuggee_pid`,端到端驱动这五个
  服务方法,参数化断言 `timeout` 上报 retryable、确定性码 `invalid_params` 不报;以“把 `frida.modules` 退回丢标志构造式”
  验证非空,守卫精确点名 `frida.modules`,还原后 14 条(10 参数化 + 4 单元)全绿。
- 把这个两轮修复固化成源码级漂移守卫:`service_ext` 的缺口之所以存在,正因转换是就地手写的
  `XdbgRpcError(exc.code, exc.message, details=...)` 而非走 helper——下一个手写转换会同样悄悄丢 `retryable`,而按方法逐个写
  行为测试拦不住“还没写测试的那个”。新增 `test_non_pe_error_conversion_guard.py`:AST 扫描全部 `core/service*.py`,凡
  `except` 绑定了非 PE 后端错误类(八类之一)的处理块,禁止其体内出现 `XdbgRpcError(<被捕获名>.code, ...)` 这种重包裹
  形态(必须改走 `backend_error_as_rpc` / `_as_rpc`);r2 / ghidra / windbg 属原生/PE 邻接线不在本约定内,故只按八个非 PE
  错误类圈定,不误伤。正向非空校验须真扫到 `service_web` / `service_frida` / `service_apk` / `service_ext` 的处理块,枚举一断
  即“无事可查”地失败。以把 `service_ext` 某处退回重包裹形态验证非空:守卫精确报出 `('service_ext','FridaError',517)`,
  还原后转绿——这条守卫本可在上一轮就自动逮住那个 `service_ext` 缺口。

### `adb device.list` 现在支持 `offset` 分页，让排在 cap(64)之后的设备序列号可达（此前排序封顶 64、只回 has_more，超过 64 台的设备农场里尾部序列号既看不到、也就无法操作——而 device.list 正是发现序列号的入口）

- `list_devices` 把设备按序列号排序、封顶 `_MAX_DEVICES`(64)、报 `has_more`,其注释明写“与 packages/properties 同款诚实:排在本页却缺失即
  确实未接入”。但它**没有 offset**,而它是**发现入口**——排在第 64 之后的序列号不仅列不出、连带也无从对其执行任何 device.* 操作,比包名/属性的
  尾部不可达更要命。补 offset(与 `device.packages` 完全同款):排序后切 `items[offset:offset+cap]`,回包补 `total`/`offset`,`has_more` 改为
  `offset + len(page) < total`,后端 `max(0,int(offset))`/`min(limit,64)` 兜底。`limit` 默认取 64(= 旧固定 cap),不传参的老调用返回量不变。
- service `device_list` 与工具 `device.list` 各加 `offset`/`limit`(schema `offset: Field(ge=0)`、`limit: Field(ge=1,le=64)`,过分页 schema/文档
  双守卫;docstring 现点名 `total`/`offset`/`has_more`)。单测钉住:农场超 cap 时首页取字母序头、`offset` 翻到被搁浅的尾且 `has_more` 归假、
  负 offset 归零、越界 offset 得空页;既有跨 adbutils 版本的行塑形与 socket_timeout 断言相应补上 `total`/`offset` 字段。

### `apk.native_libs` 现在支持 `offset`/`limit` 分页，让排在 cap 之后的 .so 可达（与 `device.packages`/`device.properties` 同一缺口：此前固定封顶 256、只回 has_more，多 ABI 大应用的 .so 超过 256 时尾部无法枚举，且这些库别处也不列）

- `apk.native_libs` 遍历整个 APK 文件表收集全部 `lib/` 条目与全部 ABI,排序后固定封顶 `_MAX_NATIVE_LIBS`(256)、报 `has_more`,
  其注释明写“排在 cap 之后、字母序靠前的 .so 会从页里消失”。但它既无 `offset` 也无 `limit`:一个多 ABI 的大应用(如 4 个 ABI ×
  上百个 .so)轻松超过 256,而 native 库**别的读取器都不列**,于是超出部分只被 `has_more` 标出“还有”、永远取不到——正是前两条为
  `device.packages`/`device.properties` 补的同一类“诚实但不可达”缺口,而这个读取器早已带了 sort-before-cap 那一半、独缺分页那一半。
- 新增 caller `offset`+`limit`,复用 apk 家的 `_clamp_page`(与 `apk.classes`/`strings`/`methods`/`xrefs` 同款):排序后切
  `libs[offset:offset+cap]`,回包补 `total`/`offset`,`has_more` 改为 `offset + len(window) < total`;`abis` 仍是**全量**(跨所有库、
  不随分页变),因为它本就来自整表遍历。schema `offset: Field(ge=0)`、`limit: Field(ge=1, le=256)`(过 `test_non_pe_pagination_schema_bounds`
  的 schema/文档双守卫——docstring 现点名 `total`/`offset`/`has_more`),后端 `_clamp_page` 兜底(过 `test_non_pe_backend_clamp_guard`)。
- 为纯粹加能力、不改既有默认返回量,`limit` 默认取 256(= 旧固定 cap):不传参的老调用仍拿到首 256 个 + `has_more`,新增的 `offset`
  才用来翻尾部。service 的 `_apk_call` 派发器扩成转发 `**kwargs`(其余零参读取器不受影响),`apk_native_libs` 据此透传 offset/limit。
- 单测钉住:300 个 .so 逆序输入下,首页是字母序前缀 `l0000..l0255` 且 `has_more` 为真、`offset=256` 取回其余 44 个且 `has_more` 归假、
  尾页 `abis` 仍全量;负 `offset` 归零、越界 `offset` 得空页。既有“字段名是 native_libs 而非 libraries”“capped 页是字母序前缀”等
  断言不受影响(limit 默认 256)。

### `device.properties` 现在支持 `offset` 分页，让排在 cap 之后的 getprop 键可达（与 `device.packages` 同一缺口：此前只回“按键字母序前缀 + has_more”，属性数超过 2000 时尾部键无法翻到，其注释自称“matching packages”却缺了这一半）

- `device.properties` 把 `getprop` 输出按键排序、按 `limit`(上限 2000)切、报 `has_more`,其注释明写“matching packages:一个封顶的
  map 必须是确定的字母序切片,好让调用方分辨‘这个键在页内缺失’与‘这个键可能排在 cap 之后’”。但它和上一条修的 `device.packages`
  一样**没有 offset**:`getprop` 每次完整、确定地列出全部属性,排在第 2000 个键之后的一旦被 cap 截掉就翻不到——只由 `has_more`
  标出“还有”,永远无法落定为 set/unset。于是那句“页内缺失即未设”只对**首页**成立,注释里“可能排在 cap 之后”那一态始终悬空。
- 新增 caller `offset`(与 `device.packages` 完全同款):排序后切 `items[offset:offset+capped]`,回包补 `total`/`offset`,`has_more`
  改为 `offset + len(page) < total`。schema `offset: Field(ge=0)`(过 `test_non_pe_pagination_schema_bounds` 的 schema/文档双守卫——
  docstring 现点名 `total`/`offset`/`has_more`),后端 `max(0, int(offset))` 兜底(过 `test_non_pe_backend_clamp_guard`)。翻到键应在的页
  即可判其 set/unset,注释那句诚实性推断对整张属性表成立而非仅首页。至此两个基于 `getprop`/`pm list` 全量确定性输出的 adb 读取器
  都补齐了 offset,与 `apk.classes`/`apk.strings` 对齐;live 运行时枚举(frida.modules/exports 等)因跨调用列表会变仍按无 offset 处理。
- 单测钉住:逆序键下首页取字母序头 `ro.k.a/b`、`offset=4` 翻到尾 `ro.k.e` 且 `has_more` 归假;负 `offset` 归零、越界 `offset` 得空
  map 而非报错。既有“host error 行不是空属性集”“capped 页是字母序前缀”等断言不受影响(offset 默认 0)。

### `device.packages` 现在支持 `offset` 分页，让排在 cap 之后的包名可达（此前只回“字母序前缀 + has_more”，装机数超过 2000 时尾部包名无法翻到，读取器 docstring 自己主张的“页内缺失即未安装”推断对尾部并不成立）

- `device.packages` 排序后按 `limit`(上限 2000)切页,回包带 `count`/`has_more`/`third_party_only`,并声明:packages 是字母序前缀,
  “页内应排到却缺失即确实未安装”。问题在于它**没有 offset**:`pm list packages` 每次都完整、确定地列出全部包,而排在第 2000 个
  之后的包一旦被 cap 截掉就再也翻不到——只由 `has_more` 如实标出“还有”,却无从抵达。于是它 docstring 自己那句推断只对**首页**
  成立:一个真实安装、但字母序排在 cap 之后的包,既不在首页、`has_more` 又为真,一个不核对 `has_more` 的 agent 会把它读成“未安装”。
  这正是 `apk.classes` / `apk.strings` 当初用 offset 补上的同一类“诚实但不可达”缺口——而 `apk`/`jadx` client 的注释早已把
  `device.packages` 列为“分页其排序集”的同门,实现却一直缺这一半。
- 新增 caller `offset`:排序后切 `names[offset:offset+capped]`,回包补 `total`(共多少)与 `offset`(本页起点),`has_more` 改为
  `offset + len(page) < total`。schema 层 `offset: Field(ge=0)`(与其它 offset 读取器一致,过 `test_non_pe_pagination_schema_bounds`
  的 schema/文档双守卫——docstring 现点名 `total`/`offset`/`has_more`),后端再 `max(0, int(offset))` 兜底(与 `apk._clamp_page`
  同款、过 `test_non_pe_backend_clamp_guard`)。这样翻到该包应在的页即可确定它在/不在,字母序前缀那句推断对整个集合成立而非仅首页。
- 单测钉住:首页是真实字母序前缀且 `has_more` 为真、`offset` 翻到尾部取回其余且 `has_more` 归假;负 `offset` 归零(而非按 Python
  负索引绕到列表尾)、越界 `offset` 得空页而非报错。既有“host error 行不是空设备”“无包行即空”等断言不受影响(offset 默认 0)。

### 测试（非 PE 分页读取器“后端夹取”漂移守卫：schema 的上界只在 MCP 通道生效，agent / OpenAI 桥直连后端时靠的是后端自己的 `min`/`max` 夹取，此前这半只零散测过，新增 AST 守卫钉住每个读取器都在后端夹 `limit`、兜 `offset`）

- `test_non_pe_pagination_schema_bounds` 钉的是“对外声明”那半:pydantic schema 声明 `limit` 有 maximum、`offset` 下界为 0。
  但 schema 只在 MCP 通道跑;agent 与 OpenAI 桥直接调后端 handler、跳过 schema。于是那条通道上真正兜底的是**后端自己**的
  `max(1, min(int(limit), MAX))` 夹取与 `max(0, int(offset))` 兜底——没有它,一个越过 schema 的 `limit=10**9` 会被读取器当成
  “全都要”,一个负 `offset` 进到 `items[start:start+cap]` 会按 Python 负索引绕到列表尾部、返回错误的一页。
- 这条后端兜底其实每个读取器都有,但此前只零散钉过(`test_apk_clamp_page` / `test_device_logcat_bounds` /
  `test_frida_java_input_bounds` 及各后端 envelope 测试)。一个新读取器完全可能 schema 合规、却漏掉后端夹取,而没有任何测试
  拦得住。新增 `test_non_pe_backend_clamp_guard.py`,是该 schema 守卫与 `test_non_pe_error_conversion_guard` 的源码扫描同门:
  AST 扫描每个非 PE 后端 client 的**类方法**(WebBackend / ProxyBackend / AdbBackend / FridaBackend / ApkClient / JsClient
  这些直接吃调用方 `limit`/`offset` 并据此取数的读取器),凡带 `limit` 的方法必须让它进过 `min(...)`(或共享的 `_clamp_page`
  助手),凡带 `offset` 的必须进过 `max(...)`(或该助手)。模块级纯切片助手(`_page` / `_cap_names` / `_capped_file_listing`)
  拿到的 `limit` 是读取器已夹好的页大小、不再夹取,故按“只扫类方法”天然排除,不误伤。
- 接受的形态就是代码库在用的两种:行内 `min`/`max` 点名该参数,或一次夹好两者的 `_clamp_page` 调用。正向非空:守卫断言扫到
  `web.network_list` / `proxy.flows` / `apk.classes` / `frida.modules` / `adb.properties` / `jsre.unpack_bundle` 等已知读取器,
  且其检测器对它们的真实夹取(行内与助手两种)都判为已夹;并离线验证检测器对“信 schema、不夹取”的合成读取器返回 False、对
  正确夹取返回 True,证明既非“恒真”也非“恒假”。留空的 `_CLAMP_EXEMPT` 允许清单沿用 schema 守卫 `_UNBOUNDED_NUMERIC_OK`
  的 fail-closed 形态:未来若真有豁免,须显式具名登记。

### 测试（非 PE `timeout` 的“后端夹取可达性”漂移守卫：schema 上界只在 MCP 通道生效，直连后端时靠后端自己的 clamp 兜底；这半此前只钉了 schema，新增按调用图做可达性分析的 AST 守卫钉住每个吃 `timeout` 的读取器都能到达一处 clamp）

- `test_non_pe_timeout_schema_bounds` 钉的是“对外声明”那半:每个非 PE 工具的 `timeout` 在 schema 里有有限 maximum。但 schema
  只在 MCP 通道跑;agent 与 OpenAI 桥直接调后端 handler、跳过它。于是那条通道上唯一挡住 `timeout=1e9` 把共享 worker 无限期
  占住(或直接喂给 `page.goto` / `run_bounded` / frida attach、活得比系统里其它一切上界都久)的,是后端自己的 clamp:CLI 走
  `clamp_cli_timeout`、浏览器走 `_bound_nav_timeout`、frida 走 `_bound_timeout`。一次永不返回的挂起,是无人值守任务唯一无法自愈的
  失败,所以这条运行期兜底比它的兄弟 `limit`/`offset` 守卫更要紧。
- 这条兜底每个读取器今天都有,但到达它未必是一次行内调用:CLI 读取器委派给会夹取的模块级 `_run`,`jadx.decompile` 委派给
  `export_sources` 再到 `_run`,`jsre.beautify` 委派给 `deobfuscate`,frida 读取器委派给会夹取的 `_attach_local` /
  `_run_local_script`。所以新增的 `test_non_pe_timeout_backend_clamp_guard.py` 不是找每个方法“内部”有没有 clamp,而是构建
  模块内调用图、断言每个吃 `timeout` 的**公开后端类**方法都能顺着自己的调用**到达**三个 clamp 原语之一——`_safe_names` 以
  不动点从“直接调用 clamp 原语”的函数出发,逐层把“调用了已判安全者”的函数并入,`_direct_call_names` 只收方法自身语句层的调用、
  不下潜进 `work`/`use` 闭包,免得内层驱动调用污染调用图。
- 两个私有辅助类上的 `timeout`(`_Runner.call` / `_ProxyInstance.start`)按“只扫公开类”天然排除:前者拿到的是其后端方法已夹好的
  timeout,后者用的是固定内部默认值,都非调用方输入,要求它们再夹一次没有意义。正向非空:守卫断言扫到 `web.open` /
  `frida.attach` / `frida.modules` / `apktool.decode` / `jadx.decompile` / `jsre.beautify`(含纯委派的两个,专门压住传递可达那条路),
  且检测器对它们真实的夹取(行内、单跳、两跳委派)都判为可达;并离线验证检测器对“吃 timeout 却既不夹也不委派”的合成公开方法返回
  False、对行内与多跳委派返回 True、对私有类方法完全不检,证明既非“恒真”也非“恒假”。

### `device.install` 校验现在能读出 UTF-8 字符串池的 APK 包名（此前只解 UTF-16LE，aapt2 默认产出的现代 APK 一律读不出包名，成功安装被降级成 `installed: null`）

- `device.install` 装完后从会话 APK 里读回包名,再用 `pm path` 校验是否真的落到设备上。`_apk_package_name` 走的是“不拉
  androguard 进来”的轻量路径:先按纯文本试 `package="..."`(真机里 AndroidManifest.xml 是二进制 AXML,没有这个字面量,必然
  落空),再把整段数据当二进制 AXML 的字符串池扫描。问题在于扫描只按 `utf-16-le` 解一次——而 AXML 字符串池只有 aapt 经典
  构建才是 UTF-16LE,aapt2 的默认(以及很多现代构建)是 **UTF-8 池**。UTF-8 池按 UTF-16LE 解出来是逐字节错位的乱码,包名
  token 一个都匹配不到,于是 `_apk_package_name` 返回 `None`,`install` 只能吐 `installed: null` + “package name not
  readable from the APK”——对一次其实成功的安装,无人值守的 agent 拿到的是“装没装成不知道”。
- 二进制路径改为对 `utf-16-le` 与 `utf-8` 两种编码各扫一遍(经典池命中前者、现代池命中后者):包名/token 两个正则都只认
  ASCII 点分标识符,而错误编码把另一种池解出的只是成对错位的非 ASCII 噪声,匹配不出任何点分标识符,所以“解错的那一遍”只会
  一无所获、绝不会伪造出一个假包名。`android.*` / `com.android.*` 框架 id 仍在两种编码下一致跳过,让应用自身包名胜出。
- 二进制 AXML 路径此前无任何单元测试(现存用例全走纯文本 `package="..."`)。`test_adb_manifest_read_bound.py` 新增三例,
  用带 AXML chunk 头前缀的合成串迫使走字符串池扫描:UTF-16LE 池读出 `com.example.legacy`(钉经典行为)、UTF-8 池读出
  `com.example.utf8only`(钉本次修复——旧的“只解 UTF-16LE”对该串返回 `None`,已离线验证,故新用例非空)、以及池内先列
  `android.permission.INTERNET` 再列应用包时跳过框架 id 取到 `com.example.realapp`。

### `apk.export_sources` 的 `java_file_count` 在走查触顶时如实标注为下界（对齐兄弟工具 `js.unpack` 的双信号，不再把两种截断混成一个 `has_more`）

- jadx 的 `_capped_java_listing` 沿两个轴设限:返回名单的页大小(`_MAX_LISTED_FILES`)与走查的文件总数上限
  (`_MAX_COUNTED_FILES`)。此前它把“走查触顶”折进 `has_more` 一并上报,`java_file_count` 却按精确值给出——一个 `.java`
  文件数超过走查上限、但整棵树字节数仍在 `_refuse_oversized_tree` 的 64 MiB 上限之内(因而不会被先行拒绝)的巨型 APK,会
  把那个上限当作精确的 `java_file_count` 交给调用方,而调用方无从把它与“恰好有这么多文件”的树区分开,读成了确定的类计数。
  其兄弟工具 `js.unpack` 的 `_capped_file_listing` 早已把走查触顶单列为 `listing_truncated`,两者本应一致。
- `_capped_java_listing` 现返回四元组,新增第四个布尔 `listing_truncated`(即走查触顶),`export_sources` 结果新增同名字段
  (与 `jsre/client.py` 的字段名一字不差);`has_more` 保留原语义(返回名单被页大小裁剪,且为兼容 cap ≥ 走查上限的调用仍
  或上走查触顶),`listing_truncated` 则专表“计数本身是下界”。`decompile` 只透传 `exit_code` / `tool_failed` / `stderr`,
  不含名单字段,不受影响。`test_jadx_pure_helpers.py` 全部改按四元组解包并逐例断言 `listing_truncated`,新增一例以
  monkeypatch 压低 `_MAX_COUNTED_FILES` 钉住:走查触顶时 `listing_truncated` 为真、页未被裁(cap 高于上限)时 `has_more`
  仍为真但计数精确的普通分页 `listing_truncated` 为假,把两条轴分开验证。

### 测试（非 PE 后端错误码词表守卫：八个后端的 code 是 agent 路由所依的机器契约，此前为散落的裸字符串、无枚举无校验，新增守卫钉住“抛出的 code 恰等于 canonical 词表”——拼写错 / 混入 PE 线方言 / 词表烂成宽集三向皆拦）

- 每个非 PE 后端(web / proxy / adb / apk 静态 / apktool / frida / jsre / jadx)抛出的类型化错误,其首参 `code` 经
  `_as_rpc` 原样进入调用方看到的 `RpcError.code`;agent 与 OpenAI 桥据此分支——`timeout` 重试、`capability_unavailable`
  降级绕过、`permission_denied` 中止、`too_large` 改分页——所以 code 是契约而非日志串。契约成立的前提是词表小而共享:
  一个拼写错(`capabilty_unavailable` / `invalid_param`)铸出无人分支的码,静默落到通用失败路径;而 PE 线说的是另一套
  方言(`invalid_argument` / `process_failed` / `input_too_large` / `executable_not_found` …),某非 PE 后端若照搬 PE 模式
  或经共享 helper 漏入,便把错方言的码交给按非 PE 词表路由的调用方而漏接。此前无人钉住词表:code 是散落在八个后端里的
  裸字符串字面量,无枚举、无校验,两种漂移都会悄悄上线。新增 `test_non_pe_error_taxonomy.py` 扫描八个 `client.py` 抛出的
  码字面量(正则的 `\s*` 跨行,容多行 raise;类定义 `class WebError(RuntimeError):` 与 `except WebError` 不会误匹配),
  断言其并集**恰等于** `_NON_PE_ERROR_CODES`(当前 8 个:`backend_error` / `capability_unavailable` / `invalid_params` /
  `invalid_state` / `not_found` / `permission_denied` / `timeout` / `too_large`):词表之外的码报错(拼写 / PE 方言污染守卫),
  词表之内却无人抛的码也报错(防其烂成“放行一切”的宽集)。一个真新码必须显式加进词表并附理由——这正是要逼出的显式决定。
  正反双向非空校验(须真扫到 web / adb / frida / apk 的码,且并集含 `capability_unavailable` / `invalid_params` /
  `backend_error` / `too_large`)避免枚举一断即空过。以双向注入验证非空:往 web 后端塞一条 `capabilty_unavailable` 的探针
  raise,守卫报出该越界码(证明扫描器确从源码抓码,含新增 raise),还原后转绿;临时把 PE 线的 `invalid_argument` 塞进
  canonical 词表,守卫报出该“无人抛”的死码,移除后转绿。

### 测试（非 PE 数值入参上界守卫从“按名钉 limit”推广到“钉所有整数/浮点入参”：device.logcat 的 lines 正因不叫 limit 逃过通用守卫、只能靠专测拦下，新增第四条守卫扫全部数值参数，钉住下一个换名的越界页大小 / 资源上限）

- `test_non_pe_pagination_schema_bounds.py` 前三条守卫按名字钉 `limit`(整数、下限 1、须有上界)、`offset`(整数、下限 0)
  与 offset 读取器 docstring 的诚实字段。但“按名字”看不到换了名字的同类:`device.logcat` 的 `lines`(返回多少条
  尾部日志)本质是页大小,却因不叫 `limit` 逃过通用守卫,当初只能靠一条专门的 `test_device_logcat_bounds.py` 拦下——
  钉的是那个实例,不是那类缺陷。一个跳过 schema 的传输(agent / OpenAI 桥直调 handler)拿到无上界的数值参数,就等于
  向后端要“全部”:十亿行、10^9 秒超时、4 GiB logcat,轻则挂起重则只能指望后端恰好再钳一次。新增第四条守卫
  `test_every_non_pe_numeric_param_declares_an_upper_bound` 扫描整个非 PE 工具面的每个 `integer` / `number` 入参,
  要求其声明 `maximum`,从而钉住“下一个换名的越界参数”(`depth` / `count` / `rows` …)在裸 int 上线时即报错,而不是等
  人察觉。两类合法无上界者按规则排除而非按名放行:`offset` 下限 0、上界无意义(翻页翻到 has_more 为假,设上界反而
  截断尾部),且已被 offset 守卫正面钉住;唯一另设的是 fail-closed 的 `_UNBOUNDED_NUMERIC_OK`——以 `(工具, 参数)` 精确
  列出 `frida.memory.read` 的 `address`(裸内存地址跨整个地址空间,该管的是可达性不是量级,由后端校验),故一个新的
  无上界参数(哪怕在别处复用 `address` 这个名)仍会触发守卫,须显式加进白名单并附理由——这正是我们要的“显式决定”而
  非静默放过。正反双向非空校验:断言扫描确实触及 `device.logcat.lines` / `frida.memory.read.size` / `proxy.start.port` /
  `web.wait.timeout` / `apk.classes.limit` 等跨后端数值参数,枚举一旦断裂即“无事可查”地失败。以“临时把 lines 退回裸
  int”与“临时清空地址白名单”双向验证非空过:前者精确报出 `('device.logcat','lines')`,后者报出
  `('frida.memory.read','address')`,恢复后 4 条守卫全绿。

### device.list 补齐“先排序再切页”：设备列表在 _MAX_DEVICES(64) 处截断却不排序，超限时可见/被弃的 serial 随 adb 枚举序逐次漂移——改为按 serial 排序后再截，向 packages / properties 的诚实范式看齐

- `AdbBackend.list_devices` 过去 `page = items[:_MAX_DEVICES]` 直接切 adb 交回的原始顺序,只置 `has_more`。同门的
  `device.packages`(`names.sort()`)与 `device.properties`(`sorted(props.items())`)早已确立“先排序再切页”,唯独设备
  列表漏了:一旦某设备农场 / CI 机架挂载超过 64 台(`_MAX_DEVICES=64`),返回的 64 台便是 adb 枚举序的任意一段——
  哪些 serial 可见、哪些被弃在截断之外,会随枚举顺序逐次漂移,且 `has_more=True` 之外并无 offset 可达其余。这与
  已修的 classes / strings / packages / applications 同属“截断但不排序 → 首页不诚实、超限不可达”的缺口。改为
  `items.sort(key=lambda row: row["serial"])` 后再截:页面成为按 serial(每个其它设备调用都以之为键)的真字母序
  前缀,一个落在页内字母区间却缺席的 serial 即“确未挂载”,而非“被任意切点甩到页外”。`device.list` docstring
  同步补上与 packages / properties 一致的诚实措辞(devices 按 serial 排序、截断页为字母序最前、has_more 义)。
- `test_adb_list_devices_shaping.py`:原两条“行整形”用例的 `devices` 断言顺序随之改为 serial 序(整形意图不变,
  只是顺序如今由排序决定);新增 `test_the_capped_page_is_the_serial_sorted_prefix_not_a_raw_adb_slice`——以逆序
  交回、超 `_MAX_DEVICES` 的 `d000..` 行,要求页面仍是字母序最前的 `_MAX_DEVICES` 个(头 `d000`、窗口严格升序、
  尾 `d{cap-1}`、越过 cap 的高位 serial 缺席)。既有 cap 用例喂的是升序 `emulator-0..`,排不排序都过,只钉溢出旗标;
  逆序用例才真正钉住排序。以“临时删掉 `items.sort`”验证非空过:三条依赖排序的用例(含两条整形)齐失败
  (溢出用例首元素变成逆序头 `d073`),恢复后 144 条 adb/device 用例全绿。
- 随此排序改动落下一处过时的位置断言:`test_unattended_resource_bounds.py` 的
  `test_list_includes_offline_devices_and_does_not_probe_get_state` 喂 `emulator-5554`(offline)/`ZY223KDTM7`(device),
  排序后 `ZY223KDTM7` 因大写 `Z`(0x5A)< 小写 `e`(0x65)排到首位,原 `devices[0]["state"] == "offline"` 遂失败。
  该用例本意是“offline 设备被*包含*且无需逐台 get_state 探测”,与顺序无关——改为按 serial 建映射断言两台各自的
  state,既修红又如实钉住其真实意图。

### 测试（超大解压树 backstop 的三个调用点，apk.decompile 一直没被任何测试驱动——补钉该第三站，把守卫 docstring “去掉任一处都会静默回归” 的承诺真正落成强制）

- `_refuse_oversized_tree` 是 `check_zip_expansion`（声明尺寸预检）之外的第二层防线:一个 central directory 诚实、
  却在真实解压时膨胀到磁盘的敌意归档(嵌套压缩、密集生成的 smali、超出存储尺寸的资源表),要靠它在工具实际写完后
  量一遍产出树,超过 `UNREGISTERED_CAPTURE_MAX_BYTES` 便删树并抛 `too_large`,免得一次填满磁盘的 decode 把填充物
  留给下一次 close / artifacts.gc 继承。它被 `service_apk` 在**三条不同的源码行**上调用——`apk.decode`(apktool 树)、
  `apk.export_sources` 与 `apk.decompile`(两者共用同一 jadx out 目录,但各自单独调一次守卫)。守卫 docstring 自陈
  “去掉三处中任一处都会静默回归”,可 `test_apk_oversized_tree_guard.py` 只驱动了 decode 与 export_sources 两站,
  第三站 `apk.decompile`(第 215 行)从未被任何用例覆盖:一次只删这一行的重构,会让“单类反编译膨胀过界”照样回
  `ok` 并把填充物滞留在 artifact_root 下,而其余用例全绿、无人察觉——这正是该守卫自己警告的“三处去其一”缺口。
  新增 `test_apk_decompile_refuses_and_deletes_an_oversized_jadx_tree`:以假 `JadxClient.decompile` 往 out 目录写出
  超(缩小后)上限的树,断言 `apk.decompile` 回 `too_large`、且 jadx out 目录被删。以“临时删掉第 215 行守卫调用”
  验证其非空过——新用例失败(结果为 `ok=True`、树被滞留)而另 6 条照过,证明它精确钉住 decompile 这一站。至此
  backstop 的三条调用点各有直测,export_sources 用例的 docstring 也从“顺带覆盖 decompile”改为如实只述本站。

### 测试（apk.classes / strings 的“先排序再切页”是兄弟读取器共同对标的诚实范式，但此前只被喂了升序输入的 clamp 用例覆盖——补钉逆序输入的字母序前缀，掉了 sort 也能被抓住）

- `apk.classes`(`names.sort()`)与 `apk.strings`(`sorted(seen)`)是最早确立“先排序再切页”的两个读取器,`apk.xrefs` /\
  jadx `java_files` / ADB `device.packages` 等后来都对标它们。可讽刺的是,这两个范式源头自己的排序从未被真正钉住:\
  `test_apk_page_clamp.py` 里 classes / strings 的 clamp 用例喂的是**已经升序**的假名字(`L0000..`、`s0000..`),于是断言\
  `classes[0] == "L0000;"` 无论代码排不排序都成立——它们钉的是 offset/limit 窗口算术,不是顺序。一次把 `names.sort()` \
  误删、直接切 `get_classes()` 原始 DEX 序的重构会让这些用例照过,而超限页悄悄退化成“遍历序的任意切片”,字母序靠前\
  但遍历晚的类从有序页中间消失。新增两条逆序输入用例补上:classes 以逆序喂入,要求 cap-3 首页仍是 `L0000..L0002`、\
  `offset=3` 取到 `L0003..L0005`(掉 sort 会切出 `L0009..L0007` 而失败);strings 同理钉 `s0000..` 前缀(其经 set 收集,\
  掉 `sorted` 会退化为随哈希种子变动的 set 迭代序,六个有序值不可能碰巧对上)。与既有的 xrefs 字母序前缀用例合起来,\
  四个 DEX 分页读取器的“先排序再切页”这下都各有逆序输入把关。

### 测试（_session_work_dir 是会话关闭清理交给 rmtree 的目录选择器，补钉其穿越防护 fail-closed：敌意 session_id 绝不能把工作目录塌回共享父目录而误删邻居会话或制品根）

- 关闭会话时,`_forget_session_work_dirs` 把 `_session_work_dir(kind, session_id)` 选出的 jadx / apktool / ghidra 工作树\
  交给 `shutil.rmtree`。happy path(关闭后回收本会话的树)已被 apk 关闭用例覆盖,但 fail-closed 的另一半——敌意 `session_id`\
  不得把工作目录解析到共享父目录、进而在清理时删掉邻居会话的产物乃至制品根——从未被直接钉住。该防护是一对:\
  `Path(session_id).name != session_id` 与 `relative_to` 容纳性检查,且缺一不可——`Path("..").name == ".."` 能溜过名字检查,\
  只有 `relative_to` backstop 才拦得住(`<root>/<kind>/..` 塌成 `<root>`,不在 `<root>/<kind>` 之下)。一次把防护“精简”到只剩\
  名字检查的重构会悄悄重开“删到树外”的洞。新增 `test_session_work_dir_traversal.py` 以轻量 stub 直接调这两个方法:钉合法\
  单段 id 解析到 `<root>/<kind>/<id>`;`..` / `.` / `a/b` / `../../etc` / `/etc` / 空串一律选出 `None`(fail-closed);`..` 走\
  `_forget` 时邻居 victim 树、`Main.java`、`jadx` / `apktool` 根全都存活;并以“合法 id 确实删掉自己的 jadx / apktool 树、\
  但留下另一会话的”作反例,使上面的拒绝有意义。

### 测试（会话制品“所有权目录”补完整性守卫：任何 <root>/<类别>/<session_id> 写入路径都必须在 _session_artifact_roots 里登记，否则会话既不拥有也不清理它）

- `_session_artifact_roots` 是“会话拥有哪些制品子树”的唯一真相:会话关闭时的清理只回收它列出的目录,所有权守卫\
  (`_session_owns_artifact_path`)也只放行落在其下的路径。某后端若开始往新的 `<root>/newcat/<session_id>` 落盘却忘了\
  把 `newcat` 加进这张表,不会有任何报错——那棵树被判为“外人”,于是关闭时永不清理(只能等全局按体积 / 时龄的 GC 兜底,\
  是一处慢泄漏),且拥有它的会话连自己的产物都读不回来。`apk/` 早先就这么漏过一次。新增\
  `test_every_session_scoped_artifact_category_is_advertised_as_owned`:扫描整个包,用正则抓出每一处\
  `"<类别>" / session_id` 的构造(`\s` 跨行,容多行路径),断言其类别集合⊆ `_session_artifact_roots` 通告的类别集合;\
  正反双向非空校验(通告表须真的列了根,扫描须触及多个 service 模块)避免“拿空集比空集”地假过。当前 14 个类别\
  (dotnet / unpack / dump / detection / web / proxy / apktool / jadx / apk / ghidra / trace / ui / reports / static)\
  全部对齐;`jsre` / `device` 因无会话键(以路径而非 session 为键、从不登记进制品表、靠 `prune_capped_dir` 或全局审计\
  兜底)本就不该在表内,故不会被扫进。唯一显式排除的是 `sessions`:`<root>/sessions/<id>/` 是会话元数据存储\
  (时间线落在此,Windows 虚拟桌面把帧写到 `sessions/<id>/desktop/`),由会话记录生命周期保管回收,而非制品 GC 路径——\
  把它塞进所有权表反而会让关闭清理误删时间线,故以带注释的排除集列明,其余任何新类别仍须登记。

### 测试（device.logcat 的 lines 是唯一逃出通用分页守卫的“页大小”参数，补钉 schema 上限 == 后端 clamp 常量 的对等与越界钳制）

- `device.logcat` 的 `lines`(返回多少条尾部日志)本质是页大小,和其它非 PE 读取器的 `limit` 同类,但名字叫 `lines`,\
  于是只扫 `limit` / `offset` 的通用分页 schema 守卫看不到它。这让它缺了那两条对其它读取器成立的保证:schema 声明上限\
  (MCP 路径能对荒唐请求 fail-fast、且对外承诺的最大页是诚实的),以及后端钳到同一上限(对跳过 schema 的 agent /\
  OpenAI 传输的 backstop,使裸 `lines=10**9` 不会把尾读变成无界 `-t`)。新增 `test_device_logcat_bounds.py` 是\
  `test_apk_page_clamp` schema/cap 对等断言的 logcat 版:钉 `lines` 为整数、下限 1、且 **schema 上限恰等于后端常量\
  `_MAX_LOGCAT_LINES`**(任一侧漂移都是 bug——schema 承诺了后端不供的页,或后端上限调高却没更新契约),并以记录参数的\
  假设备证明越界 `lines` 在抵达 `adb` 前确被钳成 `-t _MAX_LOGCAT_LINES`、非正 `lines` 被 `max(1, …)` 落到 `-t 1`\
  (而非 `-t 0`——adb 会把 0 读成“全部”)。

### 测试（非 PE offset 读取器新增“文档层诚实分页”守卫：docstring 必须点名 total / offset / has_more，把 apk.xrefs / frida.applications 曾经的“无 offset、首页装作完整”缺陷钉在 agent 实际消费的那一层）

- `test_non_pe_pagination_schema_bounds.py` 原有两条守卫只钉 schema:`limit` 必须有上限、`offset` 必须以 0 为下限。\
  但 schema 只管“分页参数有界”,管不到“工具有没有如实告诉 agent 这一页不是全部”。而恰恰是后者出过两次事故——\
  `apk.xrefs` 与 `frida.applications` 都曾以“只收首页、置 `has_more`、既不排序也无 `offset`”上线,首页看着像完整列表,\
  agent 据此判断“就这些了”便漏掉其余。新增第三条守卫扫描每个声明 `offset` 的非 PE 工具,要求其 docstring 同时点名\
  `total`(共有多少)、`offset`(本页起点)与 `has_more`(后续页是否还有行)——这正是 agent 读工具说明时据以决策的那层契约。\
  一个新 offset 读取器若只描述“一页”却不提 `total` / `has_more`(诱导“这就是全部”)便会在此报错,与既有的 schema 守卫\
  (offset 有界)和各后端的 envelope 测试(字段确实回包)三层叠合,分别钉住 边界 + 承诺 + 载荷。守卫用 `_NON_PE_BUILDERS` \
  复用同一套发现逻辑,并断言 web / proxy / apk / frida 的已知 offset 读取器都在扫描内(含触发本守卫的那两个),避免枚举\
  一旦断裂便“无事可查”地空过。当前 10 个 offset 读取器(`web.network.list` / `web.scripts` / `web.wasm.list`、\
  `proxy.flows`、`apk.classes` / `methods` / `strings` / `xrefs`、`frida.applications`、`js.unpack_bundle`)均已满足,守卫\
  即刻转为对未来读取器的强制项。

### 契约（web.wait 的 state 在 schema 层声明允许值枚举，与 frida.hook.template / workspace.mode.set 的做法对齐）

- `web.wait` 的 `state`（`visible` / `hidden` / `attached` / `detached`）此前是裸 `str`,允许值只在后端\
  `_WAIT_STATES` 里校验。后端二次校验对跳过 schema 的 agent / OpenAI 传输是必需的,但 MCP 路径的 schema 不声明\
  枚举:客户端无从给出可选项,传错的 state 也要等占用了浏览器 worker、attach 之后才被后端拒。现改为\
  `Annotated[str, Field(pattern="^(visible|hidden|attached|detached)$")]`,与 `frida.hook.template`（Literal 式\
  pattern）、`workspace.mode.set`（profile pattern）的枚举收敛一致——MCP 路径当场拒,后端 `_WAIT_STATES` 校验保留。
- `tests/unit/test_web_wait_state_schema.py` 新增一例:把工具 schema 的 `state` pattern 钉到后端 `_WAIT_STATES`\
  允许表(并断言默认值落在表内),两者不再能各改各的——给一处加状态必须同时加到另一处。

### 完整性（apk.manifest 超限时把完整清单溢出到已注册制品，不再只剩 truncated 标志而丢尾）

- `apk.manifest` 过去把解码后的 AndroidManifest.xml 在 200,000 字符处硬截断,只留 `truncated: true`。大型应用\
  （动辄声明数百个组件）的清单常常超过这个上限,而被切掉的尾部恰是后半段的 activity / service / receiver,\
  做组件盘点时必需;此前唯一的补救是对整个 APK 跑一遍重量级的 `apk.decode`。现改为:超限时把完整清单写入\
  会话制品区并注册,回包带 `manifest_xml_path` 与 `artifact_id`,`artifacts.read` 可直接读回全文——与\
  `web.dom.snapshot` 对超大 DOM 的处理一致。未超限的常见清单不写文件、不建空目录,回包形状保持不变。
- 落盘尽力而为:清单本已解码在内存,溢出只是换个名字搬到磁盘;写失败(磁盘满/权限)只丢补救路径,\
  截断的内联副本与 `truncated` 标志照常返回——清单读取不因记账失败而变成失败。
- 新的 `artifact_root/apk/<session_id>` 子树登记进 `_session_artifact_roots`(会话制品归属清单),与\
  `web/`、`jadx/`、`proxy/` 等每一个每会话捕获目录一致:归属模型据此判定该目录属于本会话,`_apk_capture_dir`\
  也像其它制品目录助手一样先用 `_is_safe_session_segment` 拒掉 `..` / `.` / `a/b` 等非单段 session id。
- `tests/unit/test_session_artifact_ownership.py` 钉住 apk 溢出目录被判为会话自有;\
  `test_web_proxy_artifact_dir_safety.py` 把 `_apk_capture_dir` 纳入段守卫用例。
- `tests/unit/test_apk_manifest_reads_faults.py` 与 `test_apk_service_envelopes.py` 新增覆盖:超限且给\
  `spill_dir` 时落全文并带 `manifest_xml_path`、未超限不落盘且不建空目录、不给 `spill_dir` 保持旧形状(向后\
  兼容)、写失败降级为无路径,以及服务层把溢出文件注册成带 `artifact_id` 的制品。

### 诚实（device.packages / properties、apk.permissions / components / native_libs 与 jadx java_files 先排序再切页，超限页是真正的字母序前缀，而非装作有序的遍历序切片）

- `device.packages` / `device.properties` 过去按设备返回顺序(安装序 / getprop 序)收满 `capped` 条就 `break`,\
  再对这一页 `sort()`。结果是“任意子集,排过序”:一个字母序靠前的包/键完全可能排在设备返回的第 501 位而被丢在\
  cap 之外,于是它从有序页的中间凭空消失——agent 查“com.foo 装了吗”在有序列表里找不到,便误判为未安装,哪怕它\
  其实在设备上。现改为先收全、`sort()`、再切 `[:capped]`:超限页是确定的字母序前缀,`has_more` 为真表示更多项\
  排在最后一条之后。这样“名字落在页内区间却缺席”才等价于“确实没有”,与 `apk.strings` / `apk.classes` 先排序\
  再分页的诚实范式一致。收全再切页的内存开销可忽略(原始 shell 文本本就整段在内存里)。
- 文档串补明这一语义;`tests/unit/test_adb_device_readouts.py` 与 `test_device_properties_fields.py` 把\
  逆序输入下的返回页钉到字母序前缀(`com.a/b/c`、`ro.k.a/b/c`),cap-then-sort 会失败。
- 同一 cap-then-sort 反模式在 APK 侧一并收敛:`apk.permissions` / `apk.components`(activities / services /\
  receivers / providers)共用的 `_cap_names`,以及 `apk.native_libs`,过去都按解析顺序收满 256 条再对这一页排序。\
  大型应用动辄声明数百个组件,于是一个字母序靠前的 activity/权限/`.so` 会排在解析顺序的 cap 之外而从有序页中间\
  消失,agent 查“声明了组件 Y 吗”便误判为“没有”。三者都改为先排序整表再切 `[:limit]`——源列表本就整份在内存里\
  (`native_libs` 更是已经遍历了全部文件以收集 abi),开销可忽略。`certificates` 不动:签名顺序有意义,不能按主题\
  重排。`tests/unit/test_apk_components_fields.py` 与 `test_apk_native_libs_fields.py` 以逆序输入把返回页钉到\
  字母序前缀。
- 同一反模式在 jadx 侧收尾:`apk.decompile` / `export_sources` 汇报的 `java_files` 由 `_capped_java_listing`\
  按 `rglob` 遍历顺序收满 `_MAX_LISTED_FILES`(2000)条再对这一页 `sort()`。反编译一棵超过 2000 个类的大树时,\
  返回页只是“遍历序的任意 2000 个,排过序”:一个字母序靠前但被晚遍历到的类会落在 cap 之外,从有序清单中间消失,\
  agent 扫这份清单找某个类找不到便误判为“没反编译出来”。现改为先收全(仍受 `_MAX_COUNTED_FILES`=50000 的遍历\
  上限约束)、`sort()`、再切 `[:cap]`,返回页是真正的字母序前缀,`total` 仍如实计每个遍历到的文件。`rglob` 的\
  遍历顺序依赖文件系统,故 `tests/unit/test_jadx_pure_helpers.py` 用逆序喂给遍历,把 cap-3 页钉到 `C000..C002`——\
  cap-then-sort 会切出 `C007..C009` 而失败。

### 完整性（apk.xrefs 补齐与 apk.classes / methods / strings 一致的 offset 分页、排序与 total / scan_capped，热点方法的调用者不再只有不可翻页的首页）

- `apk.xrefs` 是 DEX 分页读取器里唯一的异类:兄弟三件套 `apk.classes` / `apk.methods` / `apk.strings` 都提供\
  `offset` 分页、排序,并回 `total` / `scan_capped`,唯独 `xrefs` 只接受 `limit`,按枚举顺序收满一页就 `break`、\
  置 `has_more`,既不排序也不给 `offset`。于是一个被上千处调用的热点方法(常见的工具/加解密函数),回来的是\
  “枚举序的任意首 1000 个调用者”,`has_more` 虽诚实地说“还有”,却没有任何手段能翻到其余——agent 想确认\
  “类 X 是否调用了它”只能在这不可翻页、未排序的首页里碰运气。现改为与三兄弟对齐:先把调用点收全(受新的\
  `_MAX_XREFS_COLLECT`=10000 收集上限约束,越过即置 `scan_capped`)、按 `(class, method)` 排序、再用\
  `_clamp_page` 按 `offset` / `limit` 切页,回包新增 `total` / `offset` / `scan_capped`。这样超限页是真正的\
  字母序前缀,更大的 `offset` 能走完余下的调用者,`has_more` 表示后续页还有行、`scan_capped` 表示收集本身在\
  分页前就被截。`offset` 在 schema 层 `Field(ge=0)`、后端 `_clamp_page` 再钳(与其它读取器一致),既有的\
  `callers` / `method_name` 形状与 `has_more` 语义保持不变(纯增字段,向后兼容)。
- `tests/unit/test_apk_page_clamp.py` 以逆序调用点钉住“首页是字母序前缀、`offset=3` 取到其余”、负 `offset` 归零页、\
  越界 `offset` 是空的末页,以及把 `_MAX_XREFS_COLLECT` 调小后 `scan_capped` 为真;`test_apk_offset_schema.py` 把\
  `apk.xrefs` 纳入“offset 必须 `minimum=0` 且无上限”的用例;`test_apk_service_envelopes.py` 的假后端补上 `offset` 形参。

### 完整性（frida.applications 补齐 offset 分页与按 identifier 排序，装了很多应用的设备不再只有不可翻页、未排序的首页）

- `frida.applications` 与旧 `apk.xrefs` 是同一类缺陷:`enumerate_applications` 返回设备枚举序,读取器按这个顺序\
  切掉首个 `capped`(默认 256、上限 1000)条就置 `has_more`,既不排序也不接受 `offset`。装了超过一页应用的设备\
  (`total` 与 `has_more` 虽如实上报)其余应用无从翻到,且默认页只是设备序的任意前 256 个——agent 想确认\
  “com.foo.bar 在不在这台设备上”既不能按字母序前缀判断,也没法翻页找过去。现改为:把全部应用先建表、按\
  `(identifier, name)` 排序、再用 `offset` / `limit` 切页(`offset` 落 0 下限、`limit` 钳到 1..1000),回包新增\
  `offset`。这样超限页是真正的 identifier 字母序前缀,更大的 `offset` 能走完整台设备,`total` / `has_more` 语义\
  与既有的 `applications` / `count` 形状保持不变(纯增字段,向后兼容)。
- `offset` 在 schema 层 `Field(ge=0)`,自动纳入 `test_non_pe_pagination_schema_bounds.py` 的 offset 扫描;\
  `tests/unit/test_frida_fields.py` 以逆序应用钉住“首页是 identifier 前缀、`offset=3` 取到其余”与负 `offset` 归零页;\
  `test_frida_audit.py` 与 `test_frida_service_envelopes.py` 的假客户端补上 `offset` 形参。

### 测试（钉住 frida.java.classes / methods 的 has_more 全靠“向脚本多要一个”：脚本按 limit+1 枚举，回包按 limit 切页）

- `frida.java.classes` / `frida.java.methods` 的 `has_more` 是否诚实,取决于后端向设备脚本请求的是\
  `capped + 1` 而非 `capped`——那多出来的一个,正是区分“就这些了”和“只是你要的这些”的唯一依据。这条不变量此前\
  只有真机路径能碰到,而没装 frida 的 CI 会 skip,一次把 `capped + 1` 改回 `capped` 的回归会让 `has_more` 悄悄\
  永远为假,agent 便据此误判“已枚举全部已加载类”。`_page` 本身有单测,但“后端多要一个”这一步没有被钉住。
- `tests/unit/test_frida_device_path_faults.py` 复用既有的假设备/假脚本注入缝,新增四例(不需真机):classes\
  多出一条时请求数为 11(=10+1)、回包切到 10 且 `has_more` 为真;恰好填满一页时仍请求 11、只回 10 且 `has_more`\
  为假;methods 路径独立钉住同一 limit+1 纪律;越过 schema 上限的 `limit=10000` 被后端重钳到 2000,故向脚本请求\
  2001——证明是后端在重新收口枚举,而不仅是 schema。

### 测试（非 PE 写工具的可观测性守卫改为“按声明的机制”校验，能抓住把持久审计悄悄降级为纯时间线的重构）

- `test_declared_observability_traces_are_actually_wired` 过去只断言事件字面量在 service 层“某处出现”。可\
  `frida.hook.template` / `frida.spawn` / `frida.server.ensure` / `proxy.ca.install_android` 都同时写审计行与\
  时间线条目,并以更强的跨会话审计作声明;一次只删掉 `append_audit` 调用、留下 `_timeline_append` 的重构会让字面量\
  仍在源码里,裸子串检查照过,运维却悄悄失去那条能挺过会话裁剪的持久行。现改为按声明的机制校验:审计声明必须命中\
  一处审计写入(`action="…"`、`_audit_device(…)`、`_audit_frida(…)`),时间线声明必须命中一处时间线写入\
  (`event="…"`、`_timeline_append(…)`、`_note_web_action(…)`),`[^()]` 与 `\s` 跨行匹配以容纳多行调用。这样上述\
  降级会让审计侧命中失败而报错;并用一组正反例证明该检查确实按机制区分(device.install 只算审计、不算时间线,\
  web.click 反之),而非恒真。



- `timeline.list` 是无人值守跑完后运维要看的可观测性面，一旦某条时间线 `details` 里进了密钥就是一次持久泄漏。\
  审计行、Agent 事件、Provider 配置都在各自写入边界跑共用的 `redact`，唯独时间线没有——它完全依赖每个\
  `_timeline_append` 调用方手工只传不含密钥的字段（如 `web.type` 只记 selector 与 length、绝不记键入文本），\
  离一次疏忽就差一步。现在文件版（`append_session_timeline`）与内存版（`InMemoryAnalysisRepository`）时间线\
  都在写入点脱敏：按密钥名（token / authorization / password / secret / credential …）与 `Bearer` 子串遮蔽，\
  而调用方真正在传的 `url` / `selector` / `pid` / `count` 原样保留——是给未来某次疏忽兜底，不改动今天的条目。

### 可观测性（frida.hook.template 的脚本注入写入持久审计行，与 frida.spawn / frida.server.ensure 对齐）

- `frida.hook.template` 会把模板脚本编译后加载进目标进程——在设备会话上就是把代码跑进设备 App 里，是 frida 面\
  最高危的动作（哪怕探针随即 detach、`persisted=false`）。它此前只落会话时间线（`frida.hook`），而时间线随会话\
  裁剪；同为高危的 `frida.spawn` / `frida.server.ensure` 早已在时间线之外再写一条跨会话留存的审计行，注入却没有，\
  于是一位在无人值守跑完后追问"agent 到底往哪个进程注入了什么"的审计者拿不到持久记录。现在注入在时间线之外\
  另写一条 `frida.hook.template` 审计行（成功记结构化的 pid / persisted / device，失败记错误码），\
  与 `proxy.ca.install_android` 同为"时间线 + 审计"双写并在面级守卫里按审计声明。审计写失败仅尽力而为，\
  绝不把一次已经在目标里跑过的注入翻成失败的工具调用。

### 诚实（js.* / wasm.* 返回的服务端路径点明"不是已登记制品、artifacts.read 打不开"，与 device.screenshot / device.pull 的口径对齐）

- `js.deobfuscate` / `js.beautify` / `wasm.wat` / `wasm.info` 溢出时回的 `code_path` / `wat_path` / `objdump_path`，\
  以及 `js.unpack_bundle` 的 `output_dir` 与文件列表，都是 jsre 暂存区里的服务端文件、不入制品表——但文档没说，\
  一个 agent 很容易拿 `code_path` 去 `artifacts.read` 然后把 `not_found` 读成 bug 而不是"用错了工具"。现在这些\
  工具的描述像 `device.screenshot` / `device.pull` 那样明说"不是已登记制品、artifacts.read 打不开、暂存区按最旧\
  先淘汰"，并新增文档断言把这条口径钉住。纯文档改动，不动行为。

### 完整性（js.deobfuscate / js.beautify / wasm.wat / wasm.info 超出内联上限时把完整输出落盘、回 `<key>_path`，别在 400 KiB 处把大段结果丢掉）

- 这四个一次性读工具过去把输出裁到 400 KiB 内联上限、只回 `truncated=True`，超出部分无从取回——而\
  webcrack 反混淆后的单文件源码、大模块的 WAT 反汇编别处都拿不到。现在共用的 `_bounded_output` 在被裁剪时\
  把完整输出写入 jsre 暂存区，并按各自负载键回 `code_path` / `wat_path` / `objdump_path`（内联仍给一段有界预览），\
  与 `web.dom.snapshot` / `web.network.get` 的溢出范式一致。
- 落盘是会话无关的（这些工具按文件路径取参、没有 session，制品表登记不了），所以和 `js.unpack_bundle` 的\
  `unpack-<uuid>/` 树共用同一个 `artifact_root/jsre` 暂存目录与同一套 `prune_capped_dir` 上限（≤8 项 / ≤256 MiB），\
  服务层在 `finally` 里收敛，避免无界增长。单个溢出文件另设 256 MiB 上限，超出则只保留内联答案、不落盘、不留半个\
  文件；写盘失败同样只降级为"没有 path"，绝不掀翻一次已经产出内联结果的分析。

- `web.dom.snapshot` 过去在浏览器内把 `outerHTML` 裁到 200 KiB 内联上限、只回 `truncated=True`，超出部分\
  无从取回——而大型 SPA 的完整 DOM 别处都拿不到，等于永久丢失。现在改用它的两个同类"大负载"读工具\
  （`web.network.get` / `web.script.source`）已有的溢出范式：内联仍给一段有界预览，完整文档写入会话制品区\
  并登记，`html_path`（登记成功后再带 `artifact_id`）指向它，`truncated` 只表示"内联是前缀"。
- 传输仍在浏览器内按"字符预算=磁盘上限（64 MiB）"截断：因为一个 UTF-8 字节不会少于一个 JS 码元，任何能\
  塞进 64 MiB 溢出的 DOM 字符数都不超过该上限，所以这道闸只会截掉 `_spill_text` 本就要按 `too_large` 拒绝的\
  文档，同时避免病态 DOM 在驱动里无界物化。服务层沿用 `network.get` 的 `_register_capture` 接线，登记失败\
  经 `artifact_error` 上报而不掀翻这次快照。

- `handle.requests` 是有界环:超过 `_MAX_REQUESTS` 就从最旧开始淘汰(并累加 `requests_dropped`),所以 `web.network_get`\
  对一个已掉出环的 request_id 会 `not_found`——但旧消息只说\"unknown request id\",读起来像\"你给错了 id\",而真实\
  原因往往是淘汰。`proxy.flow_get` 早已在同样场景写明\"(it may have been evicted from the capture ring)\"。现让\
  `web.network_get` 的消息与之对齐,点明淘汰这一可能。新增后端测试钉住:未知/已淘汰的 request_id 得 `not_found`、\
  消息含\"evicted from the capture ring\"、且对不在环里的 id 绝不发起 CDP 取 body(顺带覆盖此前未测到的 not_found 分支)。

### 测试（钉住 frida 授权窗口 _append_recent 的\"中段目标重生即成最近\"契约：Java 工具默认目标随之更新且不重复占位）

- frida 的 Java 工具默认作用于 `_last_pid`(授权窗口末位)。此前的测试钉住了两不同值的近时序、封顶、以及\
  连续同值去重成 `[777]`,却漏了一个真实场景:一个已在窗口**中段**的 pid 被重新 spawn 时,必须被**移到**末位\
  (从而成为 Java 工具的新默认目标),而不是留在原位让某个不相关的最新 pid 当默认;且必须是移动而非追加——重复\
  会在有界窗口里白占一个槽,把仍存活的授权更早挤出。新增一例:`(111,222,333)` 后再 append `222` → `[111,333,222]`,\
  末位为 `222`、`222` 只出现一次。(纯测试补充,无行为变更。)

### 清理（删除 adb/client 里的死常量 _MANIFEST_PROBE_BYTES：与 _MAX_MANIFEST_BYTES 完全重复且无人引用）

- adb 客户端里有两个值相同(`64 * 1024`)、注释都在讲\"只读 AndroidManifest.xml 前缀、挡住解压炸弹撑爆内存\"的\
  常量:`_MAX_MANIFEST_BYTES` 是真正在用的(`_package_from_manifest` 里 `manifest.read(_MAX_MANIFEST_BYTES)`),\
  而 `_MANIFEST_PROBE_BYTES` 全代码库(含测试)除定义外无任何引用,是换实现时留下的重复死常量。删掉它及其冗余\
  注释,消除\"到底该用哪个清单字节上限\"的歧义。无行为变更。

### 清理（删除 service_device 里已成死代码的 prune_device_artifacts：真正的清扫早已换成 prune_capped_dir）

- `device.screenshot` / `device.pull` 的目录清扫早已改用 `prune_capped_dir(max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES=32,\
  max_bytes=UNREGISTERED_CAPTURE_MAX_BYTES=64 MiB)`——它按条数**和**字节双重封顶、永远保留最新一个、mtime 排序、遇\
  OSError 静默降级——严格覆盖了老的 `prune_device_artifacts(keep=32)`(只按条数封顶)。后者及常量 `_MAX_DEVICE_ARTIFACTS`\
  在生产代码里已无任何调用点,纯属换实现时留下的死代码;更糟的是,还有 4 个单测(1 个在 `test_device_artifacts.py`、\
  3 个降级守卫在 `test_device_service_envelopes.py`)直接测这个没人调用的函数,给出\"设备抓取清扫已被测到\"的**虚假**\
  信心——而真正跑的 `prune_capped_dir` 早在 `test_core_limits_eviction.py` 里被完整钉住(非目录空跑、不可读目录、\
  条数/字节驱逐、保留最新、跳过 stat 失败的子项、删除持续失败时终止、子目录计量)。删除死函数与死常量,把仍有价值\
  的端到端抓取回环测试(经 `device_screenshot` 真实走 `prune_capped_dir`)改引用 `UNREGISTERED_CAPTURE_MAX_ENTRIES`,\
  并修正模块注释指向真实机制。行为不变(生产路径本就没用过被删的函数),失去的只是对死代码的虚假覆盖。

### 测试（钉住 APK 工具在非 APK 会话上报 target_mismatch 而非 capability_unavailable：别叫人去装其实用不上的依赖）

- 已有 `TestPeOnlyToolsRefuseApkSessions` 钉住了 PE→APK 方向(在 APK 会话上调 detect/dotnet/unpack/static/dynamic\
  得 `target_mismatch`,且注明“托管环境没有 UPX,目标检查也必须先赢”)。对称的反向此前没测:在 PE/web 会话上调\
  APK 工具应答 `target_mismatch`——可操作的“你选错会话了”——而绝不能是 `capability_unavailable`,后者会把调用方\
  支去装它根本不需要的 androguard/jadx/apktool。关键在于目标检查跑在后端能力闸**之前**:所有 `apk_*` 方法都先\
  过 `_apk_binary`(即 `require_target(APK)`)再构造后端 client。新增 `TestApkToolsRefuseNonApkSessions`,把 service\
  的 jadx/apktool/apksigner 全设为 None(托管环境也没有 androguard),于是这些工具若目标闸没先赢**本会**报\
  `capability_unavailable`;会话直接 adopt 进 registry(WEB 与 PE 两种错目标),故不依赖磁盘上真有 PE/APK 文件。\
  覆盖 androguard 面(open/manifest/permissions/certificates/components/native_libs/classes/methods/xrefs/strings)\
  与 jadx+apktool 面(decompile/export_sources/decode/repack/sign),两种错目标各一遍,全部必须是 `target_mismatch`。\
  (纯测试补充,无行为变更。)

### 测试（钉住 _pids_for_package 的三态：device.force_stop 是否成功全靠它，别把“没读到”当成“已停”）

- `device.force_stop` 之所以能诚实作答,全靠 `_pids_for_package` 在一台它无法尽信的设备上区分三种结局:\
  返回 pid 列表=进程还在(`stopped: False`);返回空列表=确认已停(`stopped: True`);返回 `None`=探针本身没跑成\
  (`stopped: None` + “could not read process list”)。把 `None` 塌成 `[]`,force-stop 就会对一次根本没做的读取\
  谎报成功;把 `[]` 塌成 `None`,又会对亲眼看着离场的进程含糊其辞。它还得扛住 `pidof` 缺失的设备(较老/精简\
  Android)——回退到 `ps -A` 扫描并读取 pid 列,同时把该扫描封顶(16),使暴涨的进程表不能返回无界列表。这些此前\
  只在活设备路径后面跑,一条都没钉。新增 `test_adb_pids_for_package.py` 用打桩的设备 shell(无 adbutils、无设备)\
  钉住:空格/逗号分隔的 pid 解析、空输出=`[]`、纯噪声(无数字无 not-found 标记)=`None`、pidof 探针报错=`None`、\
  pidof 缺失回退 ps 并读 pid 列、ps 无匹配行=`[]`、ps 回退报错=`None`、pid 只认前导列而非名字里的数字、以及\
  16 条封顶。(纯测试补充,无行为变更。)

### 测试（钉住进程级 adb forward 的空闲回收门控：最后一个 Android 会话在时不回收，走后才回收）

- `adb forward` 绑定活在 adb server 上而非本进程，关会话并不会移除它，后端又把进程持有的转发数封在\
  `_MAX_FORWARDS`(32)，故长期运行的 agent 每次转发 frida/调试端口最终会绑不出新的。`_release_adb_forwards_if_idle`\
  在每次 `close_session` 时充当清扫，但它是刻意门控的，且两侧都要紧：只要还有任一 Android(APK)会话存活就\
  **不能**回收——正在跑的 frida/gdb 会话正是经这样一条转发抵达目标，因为**另一个**会话恰好关闭就把它拆掉会\
  无声打断在跑的插桩；而一旦最后一个存活 APK 会话消失就**必须**回收，否则转发会在 adb server 上泄漏到进程退出、\
  径直逼近那个会拒绝新绑定的 32 上限。此前只钉住了 `release_forwards` 本身与 `close_all` 的接线，决定**是否**\
  调用它的空闲门控没有测试。新增 `test_adb_forward_idle_release.py` 钉住它:无会话/仅终态(closed/failed/closing)\
  APK/仅存活 web/PE 会话都算空闲并回收;任一存活(created/ready/running/suspended)APK 会话都抑制回收——哪怕它\
  旁边还站着已关闭的同类;缺少自持的 adb 后端时安静容忍、绝不崩。(纯测试补充,无行为变更。)

### 测试（钉住 device.pull 本地文件名的后缀消毒：设备可控的远端路径不能左右落盘位置）

- `device.pull` 的远端路径是设备可控输入,而本地落盘名的扩展名由 `_safe_pull_suffix` 从该字符串派生(其余部分\
  由服务固定),故远端侧绝不能借它把路径分量、绝对路径或 NTFS 备用数据流注入到落盘位置。该 helper 此前无\
  直接测试。新增 `test_device_pull_suffix.py` 钉住其契约:短、纯、ASCII 字母数字的扩展名为可读性保留(大小写\
  原样、只取最后一段的最后一个扩展名),其余一律塌缩为惰性的 `.bin`——分隔符(`\`)、NTFS 流(`x.txt:evil`、\
  `data.bin:$DATA`)、标点(`-`/`_`/空格)、超过 16 字符、非 ASCII、以及根本没有扩展名(裸名/目录/空串/`.bashrc`\
  隐藏文件/绝对或穿越路径)都归为 `.bin`,并钉住 16 字符长度上限的精确边界。(纯测试补充,无行为变更。)

### 修复（web.open 在非 web 会话上缺少 url 时快速失败，而非把文件路径当作导航目标）

- `web.open` 的目标解析此前对任意会话都回退到 `session.locator`。web 会话的 locator 本就是它创建时的 URL,\
  回退合理;但非 web 会话(PE/APK)的 locator 是它打开的 .exe/.apk **文件路径**,绝非浏览器可导航的地址。\
  于是在非 web 会话上不带 url 调用 `web.open` 时,那条本应拦下它的服务层守卫(“a url is required for a\
  non-web session”)被这个无用的文件路径回退绕过:文件路径被送进浏览器,`page.goto` 以不透明的\
  `backend_error` 拒绝——更糟的是在未装 Playwright 的机器上,后端的可用性检查更早触发,报出误导性的\
  `capability_unavailable`,而真正的原因是“请给一个 url”。现在回退只对 web 会话生效:非 web 会话缺少显式\
  url 时在触碰后端之前就以 `invalid_params` 快速失败,显式 url 一律原样使用(绝不被 locator 悄悄替换),web\
  会话省略 url 时仍复用其 locator。新增 `test_web_open_target_guard.py` 钉住这四条路径。

### 测试（钉住 measure_usage 在恶劣条件下仍诚实计量：文件数上限截断为下限、跳过无法 stat 的项）

- artifact GC 在每条线的会话关闭时都会跑(web 会话的 HAR/截图、APK pull、PE dump 一视同仁),并依据\
  `measure_usage` 的结果决定是否回收,故这个遍历既不能在超大目录上卡死、也不能在不可读项上崩掉。既有\
  retention 测试只跑了正常遍历,新增 `test_measure_usage_bounds.py` 以真实临时目录钉住两条恶劣路径:超过\
  文件数上限时提前停止,`files` 停在上限且 `truncated=True`——同时 `bytes` 明确为“下限”,调用方不会把提前\
  停止误当成一个令人安心的小目录;遇到无法 stat 的项(断裂符号链接)时跨过它、仍把可读文件计全,而非中止\
  整次计量。core/retention.py 的 `measure_usage` 上限截断与跳过支(58、61-62)由此覆盖(外层 rglob 的\
  OSError 兜底在 3.12 上因 rglob 吞掉 scandir 错误而不可达,属防御性深度)。(纯测试补充,无行为变更。)

### 测试（钉住会话水合的降级契约：单条坏行/坏存储不拖垮整队恢复，含 web 会话按 URL 恢复）

- 控制台重启时,上一轮遗留为 `unclean` 的会话(PE / APK / web 一视同仁)要从 sessions.db 行里重新绑定;\
  该恢复在其它一切之前运行、且面对的是崩溃可能留下的半截数据,故单条坏行——或整个存储读不出来——必须降级为\
  “跳过它、继续走”,绝不能抛异常把其余会话一起丢掉。既有 test_session 只钉了正常路径与“文件已不在”,新增\
  `test_session_hydration_robustness.py` 钉住降级面:存储读取抛错时注册表留空但仍照常启动;非 mapping 行、\
  路径穿越/空 id、无 locator 的行被逐一跳过而周围好行仍恢复;无法识别的 state 字符串回退为 `CREATED` 而非\
  丢弃(只有真正终态 closed/failed/closing 才跳过);恢复的 **web** 会话保留其 http locator 且不被误标\
  `missing_file`(URL 在磁盘上没有文件);无法解析的架构或时间戳被容忍而非致命。core/session.py 的\
  `hydrate_persisted_sessions` / `session_from_store_row` 降级支由此覆盖。(纯测试补充,无行为变更。)

### 测试（钉住 frida.spawn 的失败分类与“绝不泄漏被挂起进程”的清理契约，不依赖 frida）

- `frida.spawn` 先挂起启动一个 Android 包再 resume 它;其成功路径、包名 fail-fast 与 resume 卡死的\
  超时清理已被钉住,但其余失败面此前未测。新增 `test_frida_spawn_lifecycle.py`,以可按需在 spawn/resume\
  抛错的假设备与一个 kill 记录器补齐:`device.spawn` 自身抛错时(原始异常/超时)映射为 `backend_error` /\
  `timeout` 且无 pid 可清理(kill 不被调用);`device.resume` 在成功 spawn **之后** 抛错时必须先 kill 掉已\
  spawn 的 pid 再上抛——否则每次失败的启动都会在设备上泄漏一个被挂起的进程。分类被保留:已分类的\
  `FridaError`(如 `permission_denied`)原样重抛、code 不被压平,原始异常变为消息含“was killed”的\
  `backend_error`,同步超时变为 `timeout`,三条都先杀进程。frida/client.py 的 spawn 失败/清理支\
  (729-744)由此覆盖(其余未覆盖行为为 device 会话真实 frida 路径或防御性外层分支)。(纯测试补充,无行为变更。)
- 同时补齐 device 路径(`java_enumerate` / `hook_template_device`)的超时分类:此前只钉了“attach 同步\
  超时报 timeout”一条,新增“枚举 RPC 超时”“hook 的 attach 同步超时”“脚本 load 超时”三条变体——它们\
  分别命中外层与内层的 `_is_timeout` 分支,证明卡死的枚举/挂钩被归为 `timeout`(而非泛化的\
  `backend_error`)且 `finally` 仍会 detach 会话,不在目标进程里留下常驻 agent。

### 测试（钉住 ensure_frida_server 的 root push/launch 降级诚实与 forward 已分类错误的回滚，不依赖 adbutils）

- `ensure_frida_server` 是最高权限的设备变更(以 su 推送并启动 frida-server),但其 push/launch/verify\
  分支此前只有“已在运行”短路与“启动了但 ps 看不到”两条被钉住。新增 `test_adb_frida_server_ensure.py`\
  以注入的假设备与真实临时二进制补齐其余降级路径:确认可见的启动同时上报 `running` 与是否 `pushed`;\
  push 失败(原始异常)映射为 `backend_error` 且绝不进入 su 启动;push 交回已分类的 `AdbError`(如\
  `timeout`)时原样上抛、保留 code;su 启动本身抛错(su 提示阻塞/超时)时不谎报 `running` True,而是回读\
  真实 ps 结果并附 `verify manually` 备注。`forward` 侧补一条对称用例:设备直接交回 `AdbError`(如\
  `timeout`)时,预留的转发槽仍被回滚且 code 不被压平成 `backend_error`——此前只测了原始异常映射一支。\
  adb/client.py 覆盖率由 80% 升至约 82%(其余未覆盖行为需真实 adbutils 的 socket 路径)。(纯测试补充,无行为变更。)

### 测试（钉住 proxy.flow.get / proxy.replay 的 fail-closed 守卫，不依赖 mitmproxy）

- `flow_get` 与 `replay` 都先从抓包环里解析一条 flow,且都必须在其不存在时精确失败:未知或已被淘汰的 id\
  报 `not_found`,body 被丢弃(过大未保留)的 flow 报 `too_large`,代理未运行时的重放报 `invalid_state`。\
  这些守卫都在触碰任何 mitmproxy 对象之前运行,故以一个 recorder 返回当下哨兵的假实例即可驱动(与\
  `test_proxy_flow_get_bounds` 同一 `_get` 接缝),无需真实代理。新增 `test_proxy_flow_get_replay_guards.py`\
  钉住上述三条守卫,并补齐请求侧 `metadata_truncated` 标记——既有 bounds 测试只标了响应侧,超长的请求\
  method/url/头映射此前未测。proxy/client.py 覆盖率由 82% 升至 84%(其余未覆盖行为需 mitmproxy 的\
  start/_run/stop 与防御性 asyncio/socket helper)。(纯测试补充,无行为变更。)

### 测试（用假 CDP 钉住 web 抓包环淘汰/dropped 记账与截断标记，及驱动进程回收守卫）

- `_wire_events` 注册的四个 CDP 处理器负责填充每会话抓包环(requests/scripts/console)并维护\
  web.status 与 HAR 导出现在上报的 `dropped` 淘汰计数,但这些处理器过去只有真实浏览器驱动 CDP 事件时才跑,\
  其淘汰与截断分支从未被测——而 `dropped` 正是操作者判断某个环是否已开始丢历史的诚实信号。新增\
  `test_web_capture_rings.py`,以一个记录已注册回调的假 CDP 直接驱动这些处理器,喂合成事件钉住:每个环在\
  超上限时淘汰最旧条目并把各自 `dropped` 计数精确加上被丢弃的条数;response 更新其匹配的 request 而对\
  从未见过的 requestId 静默忽略(不崩、不造幽灵条目);超长 url/method/mime/console 字段被标记\
  `metadata_truncated`/`text_truncated` 而非整体入环。另钉住驱动进程回收守卫:`_playwright_driver_pid`\
  沿私有链 `_impl_obj._connection._transport._proc.pid` 取 pid、链断或 pid 非正/非整数时返回 None;\
  `_reap_driver_pid` 对非正 pid 直接短路(绝不先问 OS),且只对镜像形似 node/chromium 驱动的 pid 施加\
  `terminate_pid_tree`——pid 会被系统回收,仅凭编号杀树可能误伤无关进程,故普通 python 进程被放过。\
  web/client.py 覆盖率随之回补(抓包处理器分支与回收守卫此前未覆盖),其余未覆盖行均为需 playwright 的\
  浏览器驱动方法。(纯测试补充,无行为变更。)

### 测试（用假 DEX 分析钉住 apk 的 external 过滤、缓存复用与原生库 ABI 解析）

- apk 的 DEX 分析方法(`classes`/`methods`/`xrefs`)由分页夹紧测试通过 monkeypatch `_parsed` 驱动,而那些\
  假类/假方法的 `is_external()` 恒为 False——于是这些方法赖以存在的"排除 external 符号"过滤从未运行。\
  external 类是 androguard 为"被引用但未定义"的类型(应用调用的框架类)合成出来的;把它列进应用自有类、\
  或把框架方法的调用方算作应用的,正是无人值守 agent 会据以得出的错误结论。新增 `test_apk_dex_filters.py`,\
  改为把真实 `_ParsedApk` 播入进程缓存(而非桩掉 `_parsed`),从而顺带覆盖缓存命中路径与 `_ParsedApk` 容器,\
  并钉住:`classes()` 丢弃 external 类;`xrefs()` 跳过 external 方法与名字非目标的方法(某名字若无 in-app\
  定义则如实返回空,而非把 external 调用方算进来);`native_libs()` 仅从正确嵌套的 lib/<abi>/<file> 路径\
  提取 ABI、对顶层 lib/<file> 不臆造 ABI 但仍计为一条 lib 条目、非 lib 条目整体忽略;以及无 androguard 的\
  客户端 `available=False` 且 DEX 读取以 `capability_unavailable` 拒绝而非佯装可用。apk/client.py 覆盖率\
  由 86% 升至 91%(其余未覆盖行均为需真实 androguard 的解析/未命中路径)。(纯测试补充,无行为变更。)

### 测试（用假 APK 钉住 apk 清单级读取的故障映射、版本回退与输出诚实，不依赖 androguard）

- `ApkClient` 的清单级读取(`manifest`/`permissions`/`certificates`)只解析 APK 容器,但仍走 androguard 的\
  APK 对象,本机没装 androguard 时其故障分支与版本兼容回退从不执行。`_apk` 命中缓存时会在导入 androguard\
  *之前*返回已解析对象,故往 light 缓存里播入一个假 APK 即可确定性驱动这些方法(与 frida 设备测试同一\
  注入接缝)。新增 `test_apk_manifest_reads_faults.py`,钉住对无人值守 agent 要紧的分支:文件缺失先报\
  `not_found`(而非稍后更费解的解析错误);清单解不出来映射成精确的 `backend_error` 而非泄漏原始异常;\
  读取容忍它本就要吸收的 androguard 版本差异(旧版缺 `get_requested_permissions` 时回退到已声明集、APK 无\
  v1 签名块时 `v1_signed=False` 而不抛、证书对象字段取值崩溃时跳过而非致命);证书与签名文件列表按上限\
  截断并如实 `has_more`,不把无界签名史整体铺开;并覆盖纯helper `_dotted_to_smali` 对已是 smali 形态的\
  名字原样透传。(纯测试补充,无行为变更;autouse fixture 在每例后清空进程级解析缓存以免污染其他用例。)

### 测试（用假设备钉住 frida 设备路径的授权门与故障分类，不依赖真实 frida）

- 安卓动态分析方法(`java_enumerate`/`hook_template_device`)共用授权门 `_authorize` 与一段\
  attach→load→RPC→finally detach 的 work() 主体。其成功路径与 `permission_denied` 边界已被覆盖\
  (`test_android_backends`、`test_frida_java_input_bounds`),但退化分支过去只有装了真实 frida 才跑得到——\
  本机没装时那些真实客户端用例只能 skip。新增 `test_frida_device_path_faults.py`,注入假设备/会话/脚本\
  (沿用 `client._available = True; client._frida = ...` 接缝)确定性地钉住无人值守 agent 真正会撞上的分支:\
  frida 缺失时授权门先报 `capability_unavailable`;非正/非整数 pid 在解析任何设备前即以 `invalid_params`\
  拒绝(0/负数/浮点/字符串,授权集只对良构 pid 才查);attach 失败与枚举 RPC 崩溃各自映射成带 pid 的\
  `backend_error`(并在 finally 里 detach,失败调用不把 agent 留驻目标进程),且脚本 `load` 崩溃映射成\
  另一条 `backend_error`("hook template failed");旧脚本回传的裸数组 methods 形状被当作 `found=True`\
  分页容忍(与 `modules` 同法);hook 模板白名单对未知名以 `invalid_params` 拒绝并披露允许集;以及\
  "超时仍归超时"——frida 同步抛出的超时形异常被映射成 `timeout` 而非泛化的 `backend_error`。\
  (纯测试补充,无行为变更;仅本机 skip 的退化分支现由假设备确定性覆盖。)

### 测试（用假 frida 模块钉住设备解析路径与其错误分类，不依赖真实 frida）

- `FridaClient` 服务安卓线的设备操作——`enumerate_devices`、`_resolve_device`(local/usb/纯序列号/\
  `host:port` 远端)与公开的 `add_remote_device`——过去只有装了真实 frida 才跑得到,本机没装便\
  从不执行;服务层测试(`test_frida_service_envelopes`)又刻意整只桩掉 `FridaClient`,只覆盖 service_frida\
  的信封而碰不到这段解析逻辑。新增 `test_frida_device_resolution.py`,沿用 `test_frida_attach_fields` 的\
  `client._available = True; client._frida = <假模块>` 接缝注入假 frida,钉住对无人值守 agent 要紧的分支:\
  每个 `device_id` 选中哪条查找(local/usb/get_device/远端),远端端点先复用已注册设备、缺失时才 add(不\
  每次调用都 churn frida 的 device manager),以及查找失败被映射成精确信封(解析失败 `not_found` 且 details\
  带上 `device_id`、枚举失败 `backend_error`)而非把原始 frida 异常泄给 RPC 循环。frida/client.py 覆盖率\
  相应回补(此前 `_resolve_device`/`enumerate_devices`/`add_remote_device`/`applications` 的解析与错误\
  分支未覆盖)。(纯测试补充,无行为变更。)

### 测试（钉住 frida.applications 的 limit 在绕过工具 schema 时的后端重夹紧）

- `frida.applications` 的 `limit` 在工具 schema 里限 1..256,但 agent 与 OpenAI 传输直接调服务层、\
  从不经过该 schema,所以后端另行 `max(1, min(limit, 1000))` 重夹紧。既有测试只覆盖 `limit<total`\
  (limit 10 与 3),两个绕过传输能触到的边界都没钉:非正 `limit` 必须下探到一页(`limit<=0` 若走\
  Python 尾切片会得到 `apps[:0]` 空页,读起来像一台没装应用的设备),超大 `limit` 必须封顶到 1000\
  (而非把整机已装应用一次性铺进单条回复)。新增 `test_frida_application_limit_is_reclamped_against_a_bypassing_transport`\
  以 1500 个假应用钉住这两端,并确认 `has_more` 在夹紧后的尺寸上仍如实报被截断——与 apk `_clamp_page`、\
  adb 端口的后端重校验同口径。(纯测试补充,无行为变更。)

### 可观测性（web.status 增加 capture 抓包健康块，与 proxy.status 对齐）

- `web.status` 本是页面身份快照(open/url/title),唯独不报抓包环健康。web 会话有三个有界抓包环
  (requests ≤3000、console ≤2000、scripts ≤2000),各自的列表读取器(`web.network.list`/`web.console`/
  `web.scripts`)虽已分别报自己的 `dropped`,却没有一个"抓了多少、哪个环开始丢历史"的统一快照——
  web 控制台路由(`session_web_status`)与会话 monitor 读 `web.status` 展示给操作者时因此看不到抓包是否
  已在淘汰。现 `web.status` 增加 `capture` 块,内含 requests/console/scripts 各自的 `count` 与 `dropped`,
  与 `proxy.status` 的 `dropped` 健康快照口径一致;计数在持会话锁内读取(抓包由 CDP 事件线程写入),不放到
  拥有 Playwright 对象的 runner 线程上。(新增字段,向后兼容;`web.status` 经控制台/monitor 消费,非 MCP 工具。)

### 可观测性（proxy/web 的 HAR 导出补报 dropped，区分“环丢弃”与“文件截断”）

- `proxy.export_har` / `web.har.export` 都从各自的抓包环(proxy ≤2000 flow、web ≤3000 request)取条目导出,只返回
  `truncated`——而 `truncated` 仅指 HAR *文件* 为了压进字节上限被裁剪,与“环在导出前就已淘汰旧条目”是两码事。抓包一旦
  超环容量,最旧的条目根本不在导出里,消费方看到 N 条且 `truncated=false` 便当成“全部流量”,正是全仓处处防的
  “这就是全部”误判。现两处导出都补返回 `dropped`(proxy 用 `_FlowRecorder.dropped()`,web 在持锁内与条目一起读
  `requests_dropped`,口径与条目完全对齐),docstring 同步说明二者正交:`truncated` 是文件裁剪、`dropped` 是环淘汰,
  `dropped>0` 即“此 HAR 不是整个会话的流量”。(新增字段,向后兼容。)

### 可观测性（proxy.status 增加 dropped 字段，抓包环开始丢弃时可提前预警）

- `proxy.status` 本就是抓包健康快照(报 `flow_count` / `retained_bytes` 及各上限),却唯独不报已被环形缓冲淘汰的
  条数。抓包一旦超过 `_MAX_FLOWS`(2000),最旧的 flow 摘要被静默丢弃,`flow_count` 饱和在 2000,轮询 status 的调用方
  无法在不翻 `proxy.flows` 的情况下看出“环已经在丢历史”。`proxy.flows` 早已用序号算术报 `dropped`;现给 `_FlowRecorder`
  加 `dropped()`(= `_seq - len(flows)`),`proxy.status` 一并返回 `dropped`,补齐健康快照,便于及时 export/fetch。
  (新增字段,向后兼容;docstring 同步说明。)

### 测试（钉住 proxy 的 status / flows / export_har 对同一抓包环报告一致的 dropped 淘汰计数）

- 三个工具都回 `dropped`（抓包环因溢出淘汰了多少条摘要），`recorder.dropped()` 的契约是它们应是同一个数:\
  `status` / `export_har` 读 `recorder.dropped()`（`_seq - 保留数`），而 `flows` 从自己的分页快照重算\
  （`items[-1].seq - len(items)`）。两个公式在构造上相等,但此前没有测试钉住它们保持一致——一旦任一处重构,\
  运维就会对同一个环拿到两个不同的"我丢了多少"答案。
- `tests/unit/test_proxy_fields.py` 新增一例:用容量 4 的真实 `_FlowRecorder` 灌入 10 条(六条被淘汰),\
  断言 `status` / `flows` / `export_har` 三者的 `dropped` 都等于 6、彼此相等。(纯测试新增,无行为变更。)

### 测试（新增 drift guard：非 PE 工具的 timeout 参数一律在 schema 层上下界收敛）

- 非 PE 的所有超时入参（web 五个驱动 `open` / `navigate` / `click` / `type` / `wait`、JS/WASM 的
  `js.deobfuscate` / `beautify` / `unpack_bundle` 与 `wasm.wat` / `info`、APK 的 `decompile` / `decode` /
  `repack` / `sign` / `export_sources`，共 15 个）都接受调用方传入的 `timeout`，各自声明 `Field(gt=0, le=...)`。\
  超时是"一次调用能占住共享 worker 多久"的天花板：裸 `timeout: float`、负值或 `1e9` 就是拒绝服务向量——要么把\
  worker 近乎永久钉住，要么被直接交给驱动、让一个卡死的调用绕过系统里其它所有界。此前 `port` / 分页有 schema\
  漂移护栏，`timeout` 没有。
- `tests/unit/test_non_pe_timeout_schema_bounds.py` 新增一例（port / 分页守卫的姊妹）:扫描 web/proxy/device/frida/
  apk/js_wasm/workspace 全部工具,凡暴露 `timeout` 者必须是 number、有非负下界（`exclusiveMinimum>=0` 或
  `minimum>0`）且声明有限的正 `maximum`;并断言已知超时工具确实被扫到（防止枚举失效导致空过）。新增工具若漏掉\
  上界会在此失败。(纯测试新增,无行为变更。)

### 测试（新增 drift guard：非 PE 工具的 port 参数一律在 schema 层收敛为 1..65535）

- `proxy.start` / `frida.server.ensure` / `device.connect` 三个非 PE 操作都接受调用方传入的 TCP 端口,各自在 schema
  声明 `1..65535`、并在后端二次校验(后端半部由 test_proxy_port_reservation / test_frida_server_bind_host /
  test_device_connect_honesty 钉住)。此前没有任何测试从整个非 PE 工具面统一检查 schema 半部。
- `tests/unit/test_non_pe_port_schema_bounds.py` 新增一例:扫描 web/proxy/device/frida/apk/js_wasm/workspace 全部工具,
  凡暴露 `port` 参数者必须是 integer 且 `minimum==1`、`maximum==65535`;并断言三个已知端口工具确实被扫到(防止枚举
  失效导致空过)。新增端口工具若漏掉该 bound 会在此失败,逼出一次自觉决定。(纯测试新增,无行为变更。)

### 测试（新增 drift guard：非 PE 分页读取工具的 limit/offset 参数在 schema 层一律收敛）

- 非 PE 的所有分页读取（`web.network.list` / `web.console` / `web.scripts` / `web.wasm.list`、`proxy.flows`、
  `apk.classes` / `apk.methods` / `apk.strings` / `apk.xrefs`、`frida.modules` / `frida.exports` /
  `frida.applications` / `frida.java.classes` / `frida.java.methods`、`device.properties` / `device.packages`）都接受
  调用方传入的 `limit`（页大小）与部分的 `offset`。它们与 `port` 同属数值型调用方输入:MCP 路径跑 pydantic schema,
  但 agent 与 OpenAI-bridge 传输直接调 handler 会跳过它,因此 schema 边界是 fail-fast/对外契约,后端 clamp
  (`max(1, min(int(limit), MAX))` / `max(0, int(offset))`) 是运行期兜底。此前只钉了 `port` 的 schema 半部。
- `tests/unit/test_non_pe_pagination_schema_bounds.py` 新增两例(port 守卫的姊妹):扫描整个非 PE 工具面,凡暴露
  `limit` 者必须是 integer 且 `minimum==1` 并声明正的 `maximum`(无上界的 `limit` 才是要害——跳过 schema 的传输会把它
  当成"全取",把页大小变成无界抓取);凡暴露 `offset` 者必须是 integer 且 `minimum==0`(不要求上界,超大 offset 只会切到
  末尾之后返回空页,不可被滥用)。两例都断言各后端的已知分页工具确实被扫到,防止枚举失效导致空过。新增分页工具若漏掉
  bound 会在此失败。(纯测试新增,无行为变更。)

### 测试（钉住 close_session 释放 APK 的 DEX 分析缓存，堵住 unattended 内存泄漏）

- `AnalysisService` 以 path+mtime 为键缓存 androguard 的整包分析(apk.methods / xrefs / classes / strings 共用),单份
  常驻数十到数百 MB,而缓存只按条数上限;`close_session` 在浏览器/代理拆除旁以 best-effort 的
  `ApkClient.release(session.binary)` 释放该会话对应缓存,让内存随会话结束归还。此前 web/proxy 的关闭释放有
  `test_close_session_releases_web_and_proxy` 钉住,紧挨着的这条 APK 缓存释放却无测试——一次 refactor 若丢掉它,连开
  多个 APK 的长跑会一路吃内存,且只有跑上数小时才显形。
- `tests/unit/test_close_session_releases_apk_cache.py` 新增两例:关闭 APK 会话必须以该会话 binary 恰好调用一次
  `ApkClient.release`(用 spy 钉住);关闭非 APK(PE)会话则完全不碰该释放(钉住 `target is APK` 的作用域守卫)。
  (纯测试新增,无行为变更。)

### 测试（钉住 proxy 服务层对“非 ProxyError 意外故障”的 fail-closed 契约）

- proxy 各服务包装器先 catch `ProxyError`(按 code 映射),再以末尾 `except BaseException` 把*意外*故障(bug、
  adbutils/mitmproxy 内部错误等一切非 `ProxyError`)经统一信封记为 `internal_error`,而非让它逃逸掀翻 worker 循环。
  此前 `proxy.stop` / `proxy.replay` / 读形 `_proxy_wrap`(status/flows)三处 catch-all,以及 `proxy.flow_get` 的
  ProxyError 映射与“跳过非 dict part”分支都无测试覆盖(`service_proxy.py` 是服务层里最低的 94%)。
- `tests/unit/test_proxy_service_failclosed.py` 新增五例,用注入故障的假后端在服务层钉住:`proxy.stop` /
  `proxy.replay` / `proxy.status` 遇非 `ProxyError` 异常一律 `internal_error`(且崩掉的 replay 不留 `proxy.replay`
  时间线条目);`proxy.flow_get` 的 `ProxyError` 按原 code 返回(`not_found`),非 dict 的 request/response part 被
  原样跳过、整次读取仍 `ok`。service_proxy.py 覆盖率 94%→~99%,仅剩两处不可达的防御分支
  (`_register_capture` 必返回 artifact_id 或 artifact_error 二者其一;`_failure` 必置 error)。(纯测试新增,无行为变更。)

### 测试（修复 unattended 线程泄漏守卫在整套并跑时的假失败）

- `test_unattended_resource_bounds.py` 的三处线程守卫过去用 `threading.active_count() == baseline` 断言“操作不泄漏
  线程”。但 `active_count()` 是进程级全局计数,而 pytest 串行执行:被测代码本身不会让计数低于基线(自起自收,净零;泄漏
  才净增),真正在多秒循环里波动的只有更早的用例遗留、正在收尾的线程,它们把计数压到基线*以下*——于是会话 churn 守卫
  在整套运行里偶发 `assert 10 == 12`(收缩,并非泄漏)。
- 两处纯泄漏检查(`repeated_refused_starts_leave_no_residue` 的 8 次拒绝、`repeated_cycles_leave_no_threads` 的 120 次
  会话 churn)改断言 `active_count() <= baseline`:泄漏使计数随次数增长,`<=` 照抓;遗留线程收尾只会下降,不再误判。
- `runner_thread_does_not_outlive_shutdown` 改为直接对 runner 自有的 `_thread` 断言 `is_alive()` / `join` 后
  `not is_alive()`,不再借道全局计数——这正是用例名所述属性,且完全不受无关线程波动影响。(纯测试改动,无行为变更。)

### 测试（钉住 proxy.flow_get 的制品登记与登记失败降级契约）

- `proxy.flow_get` 会把请求/响应体各自 spill 到磁盘并登记为独立 kind 的制品(`proxy_flow_request_body` /
  `proxy_flow_response_body`),两者 id 互不覆盖、都可回读与回收;而登记是 best-effort——文件已在磁盘上,登记失败
  只应在该 part 上以 `artifact_error` 返回、整个读取仍 `ok`。这条降级分支此前无测试覆盖。
- `tests/unit/test_proxy_flow_get_artifact.py` 新增两例:成功路径下两个 body 各自登记到不同 kind、id 互异且可
  `describe_artifact` 回读;登记抛错时两个 part 各自带上 `artifact_error`、不带 `artifact_id`,且 `flow_get`
  不崩、仍返回 `ok` 与完整流数据。(纯测试新增,无行为变更。)

### 加固（device.connect 在触碰 adb 客户端之前先校验 port/endpoint，畸形端口不再被 capability_unavailable 盖过）

- `device.connect` 过去先 `self._client()`——它在 adbutils 未安装时抛 `capability_unavailable`——再校验 `port`
  范围与 endpoint 格式。于是在没装 adbutils 的主机上,一个越界端口会被 `capability_unavailable` 盖过,而不是它
  应得的 `invalid_params`,与 `proxy.start`(本轮已修)、以及 frida/jadx/apk 的 fail-fast 惯例相悖。
- 现把 `port` 范围校验与 `_check_serial(endpoint)`(都是纯本地检查)移到 `_client()` 之前:越界端口/畸形 endpoint
  一律先拿到 `invalid_params`,与 adbutils 是否安装无关。
- `tests/unit/test_device_connect_honesty.py` 新增参数化用例(在 `_available=False` 下四种越界端口都以
  `invalid_params` 失败)。

### 加固（frida.server.ensure 在后端也校验 port 范围，不再只依赖会被非 MCP 传输绕过的 schema）

- `frida.server.ensure` 的 `port` 在工具 schema 里已声明 `ge=1, le=65535`,但 agent / OpenAI-bridge 传输直接调用
  handler、跳过这层 pydantic 校验——只有 MCP 路径会跑它(与 `apk._clamp_page`、`web._bound_nav_timeout` 记录的
  同一现象)。后端 `ensure_frida_server` 过去只用 regex 校验 `remote_path` / `bind_host`,却直接信任 `port`,把它
  插进 `su -c '... -l {bind_host}:{int(port)} ...'` 启动行。于是来自非 MCP 调用方的越界端口会变成一次晦涩的
  frida-server 绑定失败,而不是它应得的 `invalid_params`。
- 现在后端像 `proxy.start`、forward-spec 解析器一样自校验 port:越界端口在解析设备、构造 su 启动行之前即以
  `invalid_params` 拒掉(与已前置于 `_device` 的 remote_path / bind_host / server_binary 校验并列)。
- `tests/unit/test_frida_server_bind_host.py` 新增参数化用例(四种越界端口):端口在 `_device` 被调用前即以
  `invalid_params` 拒掉(记录式 resolver 保持空)。

### 加固（proxy.start 在能力检查之前先校验 port，畸形端口不再被 capability_unavailable 盖过）

- `proxy.start` 过去先 `_check_available()`(mitmproxy 是否安装)再校验 `port` 是否落在 1..65535。于是在没装
  mitmproxy 的主机上,一个越界端口会被 `capability_unavailable` 盖过,而不是它应得的 `invalid_params`——与
  `frida.spawn` / `jadx.decompile` / `apk.methods` 先校验便宜的调用方输入、再过能力门的惯例相悖。
- 现把端口校验移到 `_check_available()` 之前:越界端口一律先拿到 `invalid_params`,与 mitmproxy 是否安装无关,
  且不会预留任何实例。
- `tests/unit/test_proxy_port_reservation.py` 新增参数化用例(在 `_available=False` 下四种越界端口都以
  `invalid_params` 失败且不预留实例);`tests/unit/test_web_backends.py` 里原先"没装 mitmproxy 就 skip"的端口用例
  改为无条件运行——校验既已前置于能力门,该用例在没有后端的 CI 上也能真正执行并通过。

### 加固（web.open / web.navigate 在把 URL 交给 page.goto 之前先按 _MAX_URL_BYTES 收敛长度）

- web 后端的 `_require_selector`（2 KiB）、`_require_type_text`（64 KiB）都对调用方输入做了硬上限,但
  `_require_http_url` 只用 `_MAX_URL_BYTES`(16 KiB)去截断*错误信息里*回显的 URL,从不在接受路径上拒绝超长 URL。
  于是一个合法 scheme 但长达数 MB 的 `http(s)` URL 会被原样返回并交给 `page.goto`——一次跨 CDP 通道的无界推送,
  还会以全长写进 timeline。
- 现让 `_require_http_url` 在确认 http(s) 之后再按字节长度收敛:超过 16 KiB 的 URL 以 `invalid_params` fail-closed
  (带上实测字节数与被截断的回显),与 selector / type-text 的处理一致;恰好等于上限的 URL 仍然通过。校验仍在
  会话查找、浏览器启动、乃至 Playwright 导入之前,故超长 URL 一个字节都到不了浏览器线程。
- `tests/unit/test_web_url_guard.py` 新增两例:超长(多字节字符)URL 在 `_require_http_url` 即被拒且回显本身有界、
  恰好卡上限的 URL 通过;`web.navigate` 的超长 URL 在会话查找之前即以 `invalid_params` 拒掉(毒化的 `_get` 从不触发)。

### 加固（apk.methods / apk.xrefs 在整包 DEX 分析之前先校验类名/方法名，避免白付一次全量分析）

- androguard 的 `methods` / `xrefs` 过去先 `_parsed`(即 `AnalyzeAPK`——解析整包、缓存未命中时可达数十到数百 MB、
  数秒)再校验调用方传入的 `class_name` / `method_name` 是否为空。于是一个空/纯空白名字在新 APK 上要等整包分析
  跑完才被拒成 `invalid_params`;在没装 androguard 的主机上更会被 `_parsed` 抛的 `capability_unavailable` 盖过,
  而不是它应得的 `invalid_params`。
- 现把这个便宜的空值校验移到 `_parsed` 之前,与 `jadx.decompile`、`apk.decode` 等一致:空名字一律先拿到
  `invalid_params`,与 androguard 是否就绪、APK 有多大都无关;真正的 DEX 分析只在名字非空时才启动(缓存语义不变)。
- `tests/unit/test_apk_fields.py` 新增一例:空的 `class_name` / `method_name` 各自在 `_parsed` 被调用之前即以
  `invalid_params` 拒掉(记录式 spy 全程保持空),合法名字则每次都触达一次解析。

### 加固（apk.decompile 在整包 jadx 反编译之前先校验 class_name，避免白付一次全量反编译）

- jadx 的 `decompile` 过去先 `export_sources`（对整个 APK 跑一次 jadx——最长 1800s、可能写出一整棵源码树）
  再用 `_class_to_java_path` 校验 `class_name`。于是一个畸形 `class_name`(含 `\`、`:`、NUL,或 `..` / 空路径
  段)要等整包反编译跑完才被拒成 `invalid_params`;在没装 jadx 的主机上更会被 `export_sources` 抛的
  `capability_unavailable` 盖过,而不是它应得的 `invalid_params`。
- `_class_to_java_path` 是纯本地校验(只看 `class_name` 字符串),现把它移到 `export_sources` 之前:畸形类名
  一律先拿到 `invalid_params`,与 jadx 是否就绪、APK 有多大都无关;真正的整包反编译只在类名合法时才启动。
  路径逃逸/容器校验(需要磁盘上已有 sources 树)仍留在 export 之后,行为不变。
- `tests/unit/test_jadx_path_safety.py` 新增一例:四种畸形 `class_name` 各自在 `export_sources` 被调用之前即以
  `invalid_params` 拒掉(记录式 spy 全程保持空),合法类名恰好触达 export 一次。

### 加固（frida.server.ensure 在解析设备前先校验 remote_path/bind_host/server_binary，与 install/push/forward 看齐）

- `ensure_frida_server`（`frida.server.ensure` 背后、以 root 推送并启动 frida-server 的高风险设备变更）过去先
  `_device(serial)`（触达 adb server）再校验三个便宜的本地输入:`remote_path` 的绝对路径 regex、`bind_host` 的
  严格主机集、以及 `server_binary` 是否存在。于是在 adb server 或设备不可达时,一个畸形 `remote_path`/`bind_host`
  或打错的二进制路径会被解析器抛的设备错误盖过,而不是它应得的 `invalid_params` / `not_found`,还白付一次它用不上
  的设备解析代价。
- 现把这三个校验移到 `_device` 之前,与 `install` / `push` / `forward` 的 fail-fast 次序一致;真正的 `sync.push`
  仍留在设备解析之后(它本就需要 `dev`)。三者都是纯本地校验,无设备依赖,移动零风险。
- `tests/unit/test_frida_server_bind_host.py` 新增一例:畸形 `remote_path`/`bind_host` 与缺失的 `server_binary` 各自
  在 `_device` 被调用之前即以 `invalid_params` / `not_found` 拒掉(记录式 resolver 全程保持空)。

### 加固（device 的 uninstall/launch/force_stop 在解析设备前先校验 package，与 install/push/forward 看齐）

- adb 后端里 `install` / `push` 先做便宜的本地校验(apk 存在且是 zip / 本地文件存在且不超限)再 `_device`
  (触达 adb server),`forward` 也先 `_check_forward_spec` 再 `_device`——三处都带注释,把"畸形本地输入应
  fail-fast 成精确错误、别被 server 或设备不可达的错误盖过"立为惯例。
- 但 `uninstall` / `launch` / `force_stop` 是例外:先 `_device(serial)` 再 `_check_package(package)`,于是一个
  畸形/空 package 在 adb server 或设备不可达时会被设备错误盖过,而不是它应得的 `invalid_params`,还白付一次
  它用不上的设备解析代价。
- 现把 `_check_package` 移到 `_device` 之前,三处与 `install` / `push` / `forward` 的 fail-fast 次序一致。
  `_check_package` 是纯本地校验(strip + 包名 regex),无设备依赖,移动零风险。
- `tests/unit/test_adb_transfer_and_lifecycle.py` 新增参数化用例(3 方法 × 5 种畸形 package):畸形 package 在
  `_device` 被调用前即以 `invalid_params` 拒掉(记录式 resolver 全程保持空)。

### 加固（frida.spawn 在解析设备前先校验 package，与 java_enumerate 的 fail-fast 次序看齐）

- `frida.spawn` 过去先 `_resolve_device` 再校验 `package`;而兄弟 `java_enumerate` 明确把便宜的本地字符串校验
  (`class_name` / `name_filter` 的界)放在 `_resolve_device` 之前,好让畸形输入在任何设备工作之前就以精确的
  `invalid_params` 失败。spawn 的次序与之不一致:一个畸形 package(空、非包名 id)在没装 frida 或没连设备的主机
  上,会被 `_resolve_device` 抛的 `capability_unavailable` / `backend_error` 盖过,而不是它应得的
  `invalid_params`,还白付了一次它根本用不上的设备解析代价。
- 现把 package 的 required + Android 包名 regex 校验移到 `_resolve_device` 之前(该 regex 有锚点、每段强制以
  `.` 前缀,无灾难性回溯,故无需再加长度界)。行为的净变化:畸形 package 一律先拿到 `invalid_params`,与 device
  / frida 是否就绪无关。
- `tests/unit/test_frida_fields.py` 新增一例:畸形 package 在 `_resolve_device` 被调用之前即以 `invalid_params`
  拒掉(resolved 保持空),合法 package 恰好解析设备一次。

### 加固（把 frida.java 工具的 pid 参数在 schema 层收敛为非负并文档化其契约）

- `frida.java.classes` / `frida.java.methods` 的 `pid` 过去是裸 `int`(默认 0),而它是 OS 进程号:唯一哨兵是
  0(取"最近一次 spawn/授权的 pid"),负值永远不是合法 pid。兄弟 PE 工具 `dynamic.attach` 早已在 schema 里给
  pid 加了 `Field(ge=1, le=0xFFFFFFFF)` 界;这两条设备工具的 pid 却无界,于是一个负 pid 会溜过 schema、一路走到
  设备授权检查才以 `permission_denied`("pid not allowed")被拒——对畸形输入来说是错的错误分类,也没在 schema
  里向客户端公布有效区间。
- 现给 pid 加 `Annotated[int, Field(ge=0, le=0xFFFFFFFF)]`(0 仍是合法默认哨兵),让框架在 schema 层就 fail-fast
  拒掉负 pid 并登记有效区间;同时把 pid 契约(0=最近 spawn 的 pid;指定 pid 必须是本会话经 `frida.spawn` 授权过
  的;非负)写进两条工具的 docstring,与既有 `name_filter` / `class_name` 界的可发现性看齐。
- `tests/unit/test_frida_java_input_bounds.py` 新增两例:经 `input_schema_for` 断言 pid 的 schema 界
  (minimum=0、maximum=0xFFFFFFFF、默认 0),以及两条 docstring 都公布了 pid 契约。

### 加固（把 proxy.export_har 的服务层制品登记与时间线留痕钉进测试）

- `ProxyBackend.export_har` 的后端行为(spec-valid HAR、按抓取上限做字节裁剪)已有测试,但它外面那层**服务**接线
  从没被覆盖过——而正是这层接线让导出可用:导出的 HAR 会被登记为制品(裸路径两头不通:工具面没有工具能打开它,
  保留巡检也只回收仓库知道的东西,所以未登记的 HAR 既对发起它的 agent 隐身、又让制品根无限增长),并落一条
  `proxy.export_har` 时间线,和 proxy.start/stop/replay/ca.install_android 并列。
- 新增 `tests/unit/test_proxy_export_har_timeline.py`(沿用 replay 时间线测试的 `AnalysisService` + 注入式假后端
  骨架):成功导出会挂上一个真实可 `describe_artifact` 回来、kind 为 `proxy_har`、文件在盘的制品 id,并恰好留一条
  `proxy.export_har` 时间线;失败导出(和所有只在成功时留痕的写类兄弟一样)不留误导性的"已导出"痕迹。
  `core/service_proxy.py` 的 `proxy_export_har` 成功接线补齐覆盖,纯补测、不改行为。

### 加固（把共享保留原语在抓取目录不可读时的软降级钉进测试）

- `core/limits.py` 的 `prune_capped_dir` / `_dir_size` 是唯一挡在各条非 PE 抓取工具（`device.pull`、
  `device.screenshot`、`js.unpack_bundle`——它们写的目录不入制品表、保留巡检看不见）与磁盘无界增长之间的
  原语。它已有充分的驱逐/happy 路径测试,唯独三条「软降级」分支没被触及——而它们要紧:一旦抓取目录变得不可读
  就抛异常,整趟保留巡检会连同它身后所有目录一起崩掉、磁盘随之泄漏。
- 补上三例(纯补测、不改行为):抓取目录过了 `is_dir()` 却在 `iterdir()` 抛 `OSError`(权限被撤，或 is_dir 与
  iterdir 之间目录被拆的 TOCTOU 竞态)时,`prune_capped_dir` 回 0 而非让异常逃逸;`_dir_size` 遇到某个子项在
  遍历途中抛错(被并发覆盖/删除)时跳过它接着数;遍历本身抛错(目录已消失)时返回已数到的字节数。`core/limits.py`
  的非 Win32 分支补齐至满覆盖(仅剩 `available_memory_bytes` 的 Win32 探针按项目惯例 skip≠pass)。

### 加固（把 HAR 导出对畸形抓取 URL 的降级钉进测试）

- 共享的 HAR 1.2 组装(web 与 proxy 两条抓取线都用)里,`_query_string` 从抓来的 URL 解析出查询参数。抓来的
  URL 是不可信的服务端数据,可能畸形到 `urlsplit` 直接抛错(未闭合的 IPv6 字面量会抛 ValueError)。现有 har
  契约测试很全,唯独这条 `except (ValueError, TypeError)` 降级没被触及——而它要紧:一个坏 URL 不能把整份 HAR
  导出带崩。
- 在 `tests/unit/test_har_export_spec.py` 新增一例:`_query_string("http://[::1")` 回空列表,且 `har_entry` 拿
  这个畸形 URL 仍产出 spec-complete 的条目、URL 原样带回、queryString 为空。`common/har.py` 补齐至满覆盖,
  纯补测、不改行为。

### 加固（把 apktool/jadx 的 _run 子进程错误分类钉进测试）

- apktool 与 jadx 都经 `run_bounded` 起 JVM,必须把它的失败形态收敛成结构化错误而非让原始异常逃逸:非法
  截止→`invalid_params`、超时→`timeout`(带被杀 pid)、起不来的二进制→`backend_error`。jadx 的 `_run` 还额外
  守可用性、缺失 apk,并且——因为 jadx 在部分类反编译失败时仍会写出可用源码——只在盘上什么都没落时才硬失败。
  这些路径此前只在真 JVM 下跑过。
- 新增 `tests/unit/test_jvm_backend_run_taxonomy.py`,用 monkeypatch 驱动 `run_bounded`/`clamp_cli_timeout`:
  apktool `_run` 钉住非法截止→`invalid_params`、超时→`timeout` 带 killed_pids、启动失败→`backend_error`、
  正常解码流;jadx `_run` 钉住同三类外加缺执行档→`capability_unavailable`、缺 apk→`not_found`、非零退出但有
  源码→原样返回(退出码回带)、非零且无源码→`backend_error`(带 exit_code)、干净退出→解码流。`apktool/client.py`
  的 `_run`(81-91)与 `jadx/client.py` 的 `_run`(191-228)错误分类补齐,纯补测、不改行为。

### 加固（把 frida 的超时/自省/清理 helper 钉进测试）

- 每个 frida 调用底下都压着一族纯 helper,却没有一个有直接单测:`_bound_timeout` 是截止时间守卫(拒非正、
  其余夹到工作流上限);`_accepts_timeout` 判一个原生方法能否收 deadline——必须对只有 `**kwargs` 的可调用回
  否(frida `spawn` 的 aux 选项走 `**kwargs`,把 timeout 塞那儿会变成 spawn 参数而非挂起上限);`_is_timeout`
  按类型名或消息把异常归为超时;`_invoke` 只在方法具名 timeout 时才传;`_run_deadline` 用守护线程 future 给
  不可中断的原生调用兜底,超时时尽力而为地跑 `on_timeout` 再抛 frida 超时;`_detach_all`/`_kill_spawned` 跑在
  `finally` 清理里,即便 detach/kill 抛错也必须把列表抽干。
- 新增 `tests/unit/test_frida_pure_helpers.py`(不需 frida 或设备):`_bound_timeout` 正常/夹顶/拒非正;
  `_is_timeout` 按名或消息识别;`_accepts_timeout` 具名为真、只 `**kwargs` 或都没有为假、签名读不出时为假;
  `_invoke` 仅在具名时传 timeout;`_detach_all`/`_kill_spawned` 抽干列表并吞掉抛错;`_run_deadline` 正常回值、
  透传 work 异常、超时抛 frida 超时(带/不带 on_timeout,且 on_timeout 自身抛错被吞不掩盖超时);`_timeout_error`
  带上截止秒数。`frida/client.py` 中 262-263、270、274-289、292-328 的纯逻辑补齐,纯补测、不改行为。

### 加固（把 proxy 流的字节计量与 body/header 整形 helper 钉进测试）

- 抓到的流全是不可信的服务端数据,而这条后端把整个流对象留在环里,于是一族纯 helper 负责约束它存什么、
  回什么:`_content_len`/`_encoded_len`/`_headers_len`/`_flow_stored_bytes` 为内存上限计量一条流的留存开销,
  遇到行为异常的 part 必须**往多了算**(或安全归零)而非抛错;`_raw_body` 读 body 字节、把惰性解码失败当空
  body 而非抓取失败;`_emit_body` 描述 body 时绝不回有损解码——上限内的文本内联,否则落成 `.bin` 并标
  `too_large`/`binary`,免得调用方把替换字符当真字节;`_bounded_headers` 的计数/单值上限已测,但还剩迭代抛错
  与总字节上限两条边没覆盖。
- 新增 `tests/unit/test_proxy_pure_helpers.py`(不需 mitmproxy):`_content_len` 读长度或对无 len 对象归零;
  `_encoded_len` 量 utf-8、`str()` 失败时回 `_MAX_STORED_BODY+1`;`_headers_len` 求和、迭代抛错归零、越
  `_MAX_STORED_BODY` 即停;`_flow_stored_bytes` 合计 body+元信息+头;`_raw_body` 回字节/空(None、非字节、
  惰性解码抛错);`_emit_body` 短文本内联、空 body、非 utf-8 落 `binary`、超 `_MAX_INLINE_BODY` 落 `too_large`;
  `_bounded_headers` 迭代抛错记为整体丢弃、命中总字节上限即停。`proxy/client.py` 中 159-300 的整形/计量区补齐,
  纯补测、不改行为。

### 加固（把 web 线的三个文本封顶 helper 钉进测试）

- 浏览器回来的东西全是不可信且可能巨大——一个页面能 `console.log` 整份文档、把 `<title>` 设成一兆字节
  ——所以三个纯 helper 在文本落进会话环或回信之前先给它封顶,但都没有直接单测:`_bounded_metadata` 把值
  按字节上限裁剪并回报是否裁过;`_safe_title` 让页面标题过这道上限,且标题读失败时绝不外抛(回空串);
  `_clip_console_text` 拼接 console 参数、参数间各记一个空格,并在 `_MAX_CONSOLE_TEXT` 处停手,免得一条巨型
  `console.log` 把环占满整个会话生命周期。
- 新增 `tests/unit/test_web_pure_helpers.py`(不起浏览器):`_bounded_metadata` 短文本原样、超上限裁剪并置
  截断位、None/非串强转;`_safe_title` 正常标题过上限、`title()` 抛错回空串;`_clip_console_text` 无参回
  空、值以单空格拼接、跳过非 dict 参数、`value`→`description`→`type` 逐级回退、单个超长参数裁剪、恰好填满
  预算后下一参数触顶层守卫、参数间空格计入预算导致下一参数进不来即停。`web/client.py` 中 155-160、163-200、
  1010-1014 补齐,纯补测、不改行为。

### 加固（把 jadx 的类名→路径守卫补全、并把 java 源列举钉进测试）

- `_class_to_java_path` 把调用方给的类名映射成文件系统路径,是拦住构造类名(`..`、`\`、`:`、NUL、首尾点、
  绝对路径)越出解包树的守卫;既有 `test_jadx_path_safety` 钉了几例,但接受/拒绝契约还有缺口。补齐拒绝:
  绝对路径 `/etc/passwd`(前导斜杠→空段)、首/尾点、裸 `..`/`.`、空串与纯空白、只有 `$Inner` 后缀(剥空);
  补齐接受:单段裸类名、斜杠分隔(非 smali)、点分内部类折进外层文件、无内部类的 smali、首尾空白先剥。
- `_capped_java_listing` 与 jsre 的解包列举同构:按返回名数 `cap` 与遍历总数 `_MAX_COUNTED_FILES` 双轴封顶,
  `has_more` 是调用方得知源树被裁剪的唯一信号,且它 glob `*.java`——一个恰好叫 `pkg.java` 的目录不能被当成
  源文件计数。新增 `tests/unit/test_jadx_pure_helpers.py` 钉住:cap 内排序返回、超 cap 数全并置 `has_more`、
  非目录回空、`is_file` 滤掉像源文件的目录、嵌套按相对路径、到遍历上限即停且 total 不越界。
  `jadx/client.py` 中 33-51 与 231-243 补齐,纯补测、不改行为。

### 加固（把 jsre 的列举/输入守卫与 _run 错误分类钉进测试）

- jsre 线有三个纯 helper 决定它报什么、收什么,却薄测或没测:`_capped_file_listing` 从两个维度约束
  `js.unpack_bundle` 的目录列举(返回名数 `cap` 与遍历总数 `_MAX_COUNTED_FILES`),它的 `has_more` 是
  agent 得知列举被裁剪的唯一信号——一个填满 cap 却报 `has_more=False` 的列举会让 agent 以为看全了所有解包
  文件;`_looks_like_wasm` 的魔数有/无已在别处钉住,但读不开路径那条(必须为 False 而非崩)没测;
  `_require_existing_file` 是每个 jsre 工具把文件交给子进程前的大小/存在守卫。
- 新增 `tests/unit/test_jsre_pure_helpers.py`(不需 webcrack/wabt):`_capped_file_listing` 钉住名数封顶
  内排序返回、超 cap 时仍数全并置 `has_more`、非目录/缺失根回空、只数文件不数目录且嵌套按相对路径、
  到遍历上限即停且 total 不越界;`_looks_like_wasm` 对目录路径回 False;`_require_existing_file` 缺失回
  `not_found`、正常回原文件、超字节上限回 `too_large` 并带 size/max_file_size;并直接驱动 `_run` 钉住其
  错误分类——`InvalidTimeout`→`invalid_params`、超时→`timeout` 且带 `killed_pids`、启动失败(OSError)→
  `backend_error`。`jsre/client.py` 中 50/53/61、100-101、78/84-91、109-121 补齐,纯补测、不改行为。

### 加固（把 classify_target 的目标路由矩阵钉进测试）

- `classify_target` 是多线分析器的前门:它决定一个进来的目标交给 PE / APK / Web 哪条线,而且**先信后缀
  再看内容**,所以一个判错的名字会在任何字节被读之前就把文件送错线。既有测试只钉了 `.apk`、一个带
  manifest 的 `.bin` zip、一个纯 zip、两个 URL、`.js` 和一个 `\x00asm` blob,矩阵其余大半没覆盖。
- 新增 `tests/unit/test_target_classification.py`,补齐:完整的 APK/Web 后缀集(此前只有 `.apk`/`.js`)
  且大小写折叠(`.APK` 仍走 APK);无已知后缀时 `MZ` 魔数兜底为 PE(保留最贴切的"不是 PE"报错)、非
  魔数字节默认 PE、路径读不开(缺失/不可读)吞成 PE 不抛;文档化的**后缀优先**契约——一个装着 PE 字节
  却叫 `.js` 的文件仍判 Web、一个根本不是 zip 却叫 `.apk` 的文件仍判 APK(内容压根不嗅,错也交给对应
  线自己 fail-closed);以及 `is_http_url` 的 scheme 闸门:任意大小写的 http(s) 为 Web,`file://` /
  `ftp://` / `chrome://` / `javascript:` / `data:` / 空串一律不是(浏览器拒开 `file://` 之类的底层原语)。
  `core/session.py` 中 366-398(`is_http_url`+`classify_target`)补齐,纯补测、不改行为。

### 加固（把 adb 三个纯校验/解析 helper 的契约钉进测试）

- adb 后端的设备读出(logcat/packages/force_stop)已由 `test_adb_device_readouts` 用脚本化假设备钉住,
  但还有三个纯函数只在真设备路径上跑过、从没单测:`_check_forward_spec` 是 `device.forward` 让 adb
  绑定什么的唯一守卫,`_is_host_error_output` 决定一台离线设备的 stdout 该判成失败还是真回复,
  `_frida_server_visible` 读 ps 表给 `frida.server.ensure` 做幂等判定。这三条都是对不可信输入/输出的
  行为契约:转发规范放错会泄漏 adb-server 监听器,离线判错会把真日志当失败(或反之),ps 探测答错会让
  ensure 在一个它没看见的 server 上再推一个。
- 新增 `tests/unit/test_adb_pure_helpers.py`,不需 adbutils 或设备,直接钉住:`_check_forward_spec` 接受
  合法 tcp/localabstract(远端另含 jdwp)、拒绝五位非端口与 `tcp:0`、拒绝空/垃圾/带 shell 元字符的规范
  且把被拒规范按 side 键回带、jdwp 只在放行的一侧才收;`_is_host_error_output` 仅当每条非空行都是
  `error:`/`adb:` 时才为真(容忍前导空白)、空/纯空白为假、只要有一条真行(哪怕日志里出现 "error")即为假;
  `_frida_server_visible` 从 `ps -A` 命中即真、`ps` 兜底命中亦真、两处都无为假、shell 读不出时为 None
  (不谎报没有)。`adb/client.py` 中 127-138 / 182-195 / 213-220 三段纯逻辑补齐,纯补测、不改行为。

### 加固（把 workspace.mode 的 fail-closed 包装钉进测试）

- workspace 审计测试覆盖了正常路径、被拒的非法档、以及尽力而为的写审计,但两处 `except BaseException`
  包装没被触及:`workspace.mode.get` 概述档位时出错、`workspace.mode.set` 持久化新档位时出错。后者尤其
  要紧——若 `update_config_values` 抛错,进程内档位还没改,工具必须如实回失败而非报一个没达成的成功。
- 新增 `tests/unit/test_workspace_mode_envelopes.py`:`mode.get` 概述出错时收敛成失败信封;`mode.set`
  持久化失败时回 `internal_error`、运行档位保持不变、且这条没达成的变更不进审计。`service_workspace`
  覆盖率 89%→100%,纯补测、不改行为。

### 加固（把 device 服务层的只读透传、后端兜底与抓取分支钉进测试）

- device 审计测试钉住每个变更与抓取的溯源、artifacts 测试钉住字节/条数上限,但还剩几条服务层路径没被
  触及:只读透传(list/properties/packages/current_activity)、`_adb_wrap` 的 `except BaseException`
  兜底、服务自身没持有后端时 `_backend()` 现构一个 AdbBackend 的兜底、`device.connect` 的 AdbError 臂
  (跳过\"已连接\"降级判定)、抓取失败时跳过超限检查那条分支、`device.pull` 的超限拒绝,以及
  `prune_device_artifacts` 的两处 OSError 守卫和\"未满\"提前返回。
- 新增 `tests/unit/test_device_service_envelopes.py`,用假 AdbBackend(不需 adbutils 或真设备)在服务层
  钉住:六个只读透传都带 backend 回信封且一个都不进审计;读遇 AdbError→原样 code、遇非 AdbError→
  `internal_error`;无自持后端时 `_backend()` 兜底构出 AdbBackend;`device.connect` 的后端异常直接落失败
  信封且仍带 code 记审计;抓取失败跳过超限检查、仍记审计;`device.pull` 命中超限被删并记成
  `output_too_large`;`prune_device_artifacts` 对非目录静默返回、未满时空跑、排序途中 stat 失败按 age 0
  兜底。`service_device` 覆盖率 92%→99%(仅剩 `_audit_device` 里一条 `_failure` 永不产生的防御分支),
  纯补测、不改行为。

### 加固（把 frida 服务层的枚举/连接/java 路径与错误分类钉进测试）

- frida 审计测试驱动 spawn/server.ensure/applications,closed-session 测试驱动入口与泄漏守卫,本地
  device.connect 也另有覆盖——但因共享假 client 只有 spawn/applications,还剩一整条没被触及:
  `frida.devices`(无会话枚举)、`frida.device.connect` 的**远端 endpoint** 分支及其 FridaError 映射、
  整条 java 路径(`frida.java.classes`/`methods`→`_java`→`_last_pid`)、`frida.applications` 的错误映射,
  以及 `_frida_auth` 那句\"先连设备\"的拒绝。
- 新增 `tests/unit/test_frida_service_envelopes.py`,用带 `raises` 注入的假 FridaClient(不需真设备或
  frida 模块)在服务层钉住:`frida.devices` 成功盖 backend、FridaError→原样 code、意外→`internal_error`;
  `device.connect` 走远端 endpoint 成功记 auth+timeline、FridaError 失败不留 auth;未连设备时
  `applications`/java 一律 `invalid_state` fail-closed;java 路径成功默认落到最近 spawn 的 pid、无 pid 时
  拒绝、FridaError/意外各自分类;`server.ensure` 的 AdbError 透传原样 code 且失败仍带 code 记审计。
  `service_frida` 覆盖率 85%→99%(仅剩 `_audit_frida` 里一条 `_failure` 永不产生的防御分支),纯补测、
  不改行为。

### 加固（把 apk 服务层的成功尾段与错误分类钉进测试）

- APK 线的入口守卫与运行中泄漏守卫(会话中途关闭→删树重抛)已由各 `*_closed_session` 测试钉住,`..`
  产物目录守卫由 `test_web_proxy_artifact_dir_safety` 钉住。但这条线的**成功**那一半只在 androguard/
  jadx/apktool 真解析到东西时才跑,而测试机上这些工具都不在——于是读包装
  (open/manifest/permissions/certificates/components/native_libs/classes/methods/strings/xrefs)、
  `_apk_call` 分发,以及 decompile/export_sources/decode/repack/sign 的成功尾段(记 backend + timeline)
  都没有单测覆盖,它们的 ApkError→原样 code、意外异常→`internal_error` 映射也没有。
- 新增 `tests/unit/test_apk_service_envelopes.py`,用假 Apk/Jadx/Apktool client(不需真工具)在服务层钉住:
  十个读包装都带 session_id+backend 回信封、并各自钉住 ApkError→code 与意外→`internal_error` 两类
  fail-closed(参数化);`apk.open` 成功记 backend+timeline;decompile/export_sources/decode/repack/sign
  成功各记一条 timeline;decompile 的 JadxError、decode 的 ApktoolError 都透传原样 code;真正的
  `_apktool_client`(其余测试都桩掉了)按配置路径构造出 ApktoolClient。`service_apk` 覆盖率 85%→约 99%
  (仅剩超限树守卫里一条 OSError 兜底和\"关闭时尚未落树\"的泄漏守卫分支),纯补测、不改行为。

### 加固（把 web 服务层的读透传、抓取落盘登记与信封分类钉进测试）

- web 后端由 field 测试驱动、`web.open` 的泄漏守卫由 `test_web_backends.py` 钉住,但服务层还有一整条
  只在真开浏览器(需 Playwright)时才跑的带子从没被单测触及:几个薄读透传(`web.network.list` /
  `console` / `scripts` / `wasm.list` / `dom.snapshot`)、`web.network.get` / `web.script.source` 的
  落盘→`_register_capture` 登记接线、`web.status` / `web.preview` / `web.close`、`web.open` 的**成功**
  尾段(记 backend+timeline),以及 `_web_wrap` 那句把非 WebError 意外故障收敛成 `internal_error` 的
  `except BaseException`。
- 新增 `tests/unit/test_web_service_envelopes.py`,用假 WebBackend(不起浏览器)在服务层钉住:每个读
  透传都带 session_id+backend 回信封且 `wasm.list` 恒定 `wasm_only=True`;`network.get`/`script.source`
  在有落盘时把文件登记成 artifact(回带 `artifact_id`)、无落盘时原样裹;`status` 合并会话
  locator/state/target;`preview` 落稳定 PNG;`open` 成功记 backend+timeline、`close` 记 timeline;以及
  status/preview/open/close/screenshot/har/dom 各自的 WebError→原样 code 与意外异常→`internal_error`
  两类 fail-closed 分类。`service_web` 覆盖率 83%→99%(仅剩一条正常建会话到不了的防御分支),纯补测、
  不改行为。

### 加固（把 jsre 服务层四个一次性包装的成功/错误分类钉进测试）

- `js.deobfuscate` / `js.beautify` / `wasm.wat` / `wasm.info` 在服务层都是薄包装:把文件交给
  JsClient/WasmClient、再把回复裹成信封。后端测试直接驱动那两个 client(打桩 `run_bounded`),
  于是**服务层包装本身**从没被触及过——测试机上根本没装 webcrack/wabt,只有
  `capability_unavailable` 这一条 JsReError 路径真跑过服务层。这样每个方法都留了三处未钉的契约:
  盖上 backend 名的成功信封、JsReError→原样 code 的映射,以及那句 `except BaseException`——它把
  非 JsReError 的意外故障收敛成结构化 `internal_error`,而不是让它逃出服务层冲进 RPC 循环。
- 新增 `tests/unit/test_jsre_service_envelopes.py`,在服务层钉住这四个一次性方法的三种结局(成功盖
  backend、JsReError 透传 code、意外异常 fail-closed 成 `internal_error`)、`js.unpack_bundle` 同一条
  意外异常 catch-all,以及 `prune_jsre_unpack_dirs` 的两处 OSError 守卫(根不是目录/不存在时静默返回、
  排序途中 stat 失败时按 age 0 兜底继续清理)。`service_jsre` 覆盖率 81%→98%,纯补测、不改行为。

### 加固（把 proxy.start/ca 的失败与竞态守卫钉进测试）

- proxy 服务层是非 PE 各线里覆盖最低的一档(74%),其中最大的一段未测代码正是 `proxy.start` 的
  防泄漏守卫:mitmproxy 绑定端口后会二次核对会话,若绑定期间有 close 抢先进来,就先停掉刚起的代理
  再失败,免得一个已消失的会话遗下一个谁也 stop 不掉的在途端口。这段行为此前无任何测试触及,一次
  重构就能把它悄悄改坏。
- 新增 `tests/unit/test_proxy_service_lifecycle.py`,在服务层(而非各兄弟测试驱动的后端层)钉住:
  `proxy.start` 成功记 backend+timeline、绑定中途会话消失时回滚(停代理、不留误导性 timeline 条目)、
  ProxyError 映射成信封;`proxy.stop` 成功与失败都回信封;`proxy.ca.install_android` 在 CA 缺失、
  会话入口即已关闭、以及推送中途会话消失(证书已上设备但拒绝记到已死会话、不留 timeline)三条
  fail-closed 路径。纯补测、不改行为。

### 加固（README 把审计/时间线写进可观测面）

- README「可观测」条此前只列 `meta.metrics`(聚合遥测),完全没提这一轮大量补齐的审计轨:`audit.list`
  (跨会话留存的高危/特权操作记录)与 `timeline.list`(单会话按序动作流水)。运维想知道"无人值守跑完后
  哪些高危操作真的发生过",光看计数器是答不上来的,而承载这答案的两个工具在前台文档里不存在。
- 现在「可观测」条如实交代 `timeline.list` 与 `audit.list` 的分工,并点出 `audit.list` 覆盖的高危面
  (会话生命周期、UI 驱动、设备变更与抓取、frida 设备变更、`proxy.ca.install_android`、
  `workspace.mode.set`、`js.unpack_bundle` 等),以及"口令/token 写入前统一脱敏、写审计失败绝不连累
  工具本身"两条性质。纯文档、不改行为,只把已有的可观测能力讲全。

### 加固（SECURITY.md 如实交代默认预设自动放行的非 PE 状态变更半径）

- 默认 *packed-analysis 预设*按*效应类*放开 `state_change`,因此它不仅自动跑补壳 PE 分析的写,还
  一并放开**全部非 PE 状态变更**——Android 设备线、Frida 设备线、拦截代理(含开启 MITM、推送 CA、
  重放请求)、浏览器驱动与全局 `workspace.mode.set`。SECURITY.md 此前只列出被排除的 `file_write`
  (patches、APK 改包签名、产物 GC、设备/Web 抓取),把自动放行集描述成"补壳 PE 分析常用的写",
  未点明这批非 PE 状态变更同样无人值守自动运行;对照之下还有一处反直觉的不对称:只读性更强的设备
  抓取(`device.pull`/`screenshot`)留给人工,破坏性更强的 `device.uninstall` 却自动跑。
- 现在 SECURITY.md 的 autonomy 小节如实列出这批随预设自动运行的非 PE 状态变更、点出该不对称,并指向
  缓解手段(`agent_never_auto_approve` 逐个钉死、或 `local_full_access: false` 只读部署)。这不改变
  任何行为,只把默认放行的真实半径讲清楚,使无人值守部署方能据实做取舍;该集合仍由
  `tests/unit/test_agent_autonomy.py` 钉住。

### 加固（proxy.ca.install_android 的 CA 推送补记持久 audit）

- `proxy.ca.install_android` 通过 adb 把 mitmproxy 根证书推到设备上——与 `frida.server.ensure`
  （同样经 adb 推送并启动 frida-server 二进制）属同一类会话内设备变更,且更敏感:一张被信任的 CA
  正是代理能读取该设备 TLS 的前提。`frida.server.ensure` 与各 `device.*` 变更早已各落一条能挺过
  会话时间线裁剪的持久 audit 行,而 CA 推送此前只有随会话裁剪的 timeline 条目,于是"某序列号的设备
  被推入过 MITM 证书"这一事实无法像其兄弟 frida 推送那样跨会话留存。
- 现让 `proxy.ca.install_android` 在保留原 timeline 条目的同时,补记一条会话内(带 session_id)的
  持久 audit 行:成功记 `pushed_to`、失败记错误码,写 audit 失败绝不使工具失败(证书已在设备上)。
  `tests/unit/test_proxy_ca_audit.py` 钉住这四点;`audit.list` docstring 与
  `test_tool_surface_boundaries.py` 的记痕映射同步把它从 timeline 归为 audit。

### 加固（把五个非 PE 后端的"缺依赖即优雅降级"钉成契约）

- 每个可选非 PE 后端在其依赖缺失时都必须降级为 `capability_unavailable`——一个 agent 能识别并绕开的
  干净错误,而不是 ImportError、AttributeError 或对着 `None` 调用出来的半截结果。这行为本就写在各后端的
  可用性守卫里,但只有 adb、apktool、apksigner、jsre 的 CLI、r2、windbg 被测试钉住;web(Playwright)、
  proxy(mitmproxy)、frida 模块、jadx、apk(androguard)这五个源码里有守卫却无测试兜底。一次对可用性检查的
  重构就可能把"缺依赖"悄悄变回硬崩溃,而对无人值守任务来说,这是"跳过该线"与"任务卡死"之别。
- 新增 `tests/unit/test_backend_degradation.py`,为这五个后端各钉一条:强制进入不可用态(而非"依赖装了就
  跳过"),因此无论环境是否装了依赖,降级路径都会被真正走一遍;并断言抛出的是带 `capability_unavailable`
  码的对应类型错误——守卫一旦被移除,调用会改抛 ImportError/AttributeError,测试即失败。

### 加固（把非 PE 写操作的"必留痕"钉成整面不变量）

- 这一整轮为非 PE 各线逐个补齐了可观测性（device.* 变更与抓取、frida.spawn/server.ensure、
  proxy.replay、workspace.mode.set、js.unpack_bundle,以及 web.* 交互),但这些都是逐工具的契约测试:
  新加一个非 PE 写工具却忘了记痕,没有任何测试会发现。现在把它钉成一条整面不变量:非 PE 各线
  (apk./device./frida./js./proxy./web./workspace.)的每个写工具都必须落一条痕——要么是能挺过会话时间线
  裁剪的持久 audit 行(会话无关或高风险设备变更),要么是随会话走的 timeline 条目。
- `tests/unit/test_tool_surface_boundaries.py` 新增两项:一是把 33 个非 PE 写工具与其记痕机制的映射
  钉死等于目录里的实际非 PE 写面(少一个、多一个、改名都失败),逼出"这工具怎么被观测"的自觉决定,与
  autonomy 文件写 denylist 用的是同一种强制手段;二是把映射从"账面"变成"有牙":读服务层源码、断言每个
  声明的事件/动作字符串字面量确有落地调用点,从而同时抓住"加进映射却没接线"和"重构里把记痕删了、映射
  却还留着"两种腐化。经审计确认当前 33 个非 PE 写工具全部已记痕,不变量成立。

### 加固（钉住无人值守预设里搭车的非 PE 状态变更工具）

- 无人值守的 packed-PE 预设按 effect 授予整个 `state_change` 类(而非像文件写那样按具名工具白名单),
  这是有意为之:PE 拆包要让 dynamic/unpack/workflow 一整片都能自跑,逐个枚举既繁且脆。代价是同一授权也
  把所有非 PE 状态变更一并扫入——device.* 一族的连接/安装/卸载/启动/停止/推送/转发、frida.* 的设备路径
  (attach/spawn/server.ensure 等)、proxy.start/stop/replay/ca.install_android、web.* 浏览器驱动
  (open/close/navigate/click/type)以及全局 workspace.mode.set——它们都不是 PE 工作,却都在默认预设下
  自动执行。与文件写的 denylist 不同,effect 授权无处记录它到底覆盖了哪些工具,于是新加一个非 PE 状态变更
  工具就会悄悄搭上这趟无人值守的车、无人复核。
- 不改任何运行期策略(有意保留这份宽度),而是把这 22 个搭车的非 PE 写工具按实际目录钉死:在
  `agent/autonomy.py` 于 `PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS` 处加注说明这一跨线后果,并新增
  `test_non_pe_state_change_tools_riding_the_packed_preset_are_pinned`——新增一个此类工具会让测试失败,逼
  出一次"它是否真该无人值守自跑"的自觉判断;同时反向钉住这些线上的文件写抠除项(device.pull/screenshot、
  proxy.export_har、web.har.export/screenshot)始终保持需人工批准。

### 新增（js.unpack_bundle 补记会话无关出处）

- `js.unpack_bundle` 把拆出来的文件树写到 `artifact_root/jsre/unpack-<uuid>/`,但它按文件路径寻址、不
  属于任何会话——和 device.pull/screenshot 一模一样:制品表需要 `session_id` 而它给不出,所以那棵树从不
  登记、也没有会话时间线可落。于是它成了 JS 线里唯一"落盘却毫无出处"的操作:拆了哪个 bundle、落到哪个
  目录、拆出多少文件,事后全无记录。现在成功的拆包会像 device.* 一样以空 `session_id` 写入全局审计日志,
  记输入路径、输出目录与文件数。
- 记账尽力而为:树已经写到磁盘,一次审计写入失败绝不能把已成功的拆包变成失败的工具调用;失败的调用也
  照记(带其错误码),只拷贝结构化字段(输出目录、文件数)。`audit.list` 描述更新为点名 js.unpack_bundle;
  新增 `tests/unit/test_jsre_unpack_audit.py` 钉住:成功记一条带出处的空会话审计、失败记错误码、审计写
  失败不拖垮拆包。

### 新增（workspace.mode.set 补记会话无关审计）

- `workspace.mode.set` 在 `tools/catalog.py` 里被归为写操作:它改写全局的工作方向 profile、持久化到用户
  配置(跨重启生效),并决定下一次 MCP 连接看到哪一套工具面。它不属于任何会话——没有可落的时间线——也
  从不写审计,于是它成了非 PE 写操作里唯一时间线与审计都不留痕的那个:一个无人值守的 agent 半夜把自己
  切到别的 profile、换出一批工具,操作者事后无从查证。现在成功的切换会像 device.* 一样以空 `session_id`
  写入全局审计日志,记 `{"from": 旧 profile, "to": 新 profile}`。
- 只记真正落地的切换:未知 profile 是一次尚未改动任何东西的校验拒绝,不记。记账尽力而为——profile 已经
  持久化,一次审计写入失败绝不能把已成功的切换变成失败的工具调用;只记 profile 名(取自固定集合、无机密)。
  `audit.list` 描述更新为点名 workspace.mode.set;新增 `tests/unit/test_workspace_mode_audit.py` 钉住:
  成功记一条带 from/to 的空会话审计、非法 profile 不记、审计写失败不拖垮切换。

### 新增（proxy.replay 补记会话时间线）

- `proxy.replay` 在 `tools/catalog.py` 里被归为写操作:它把一条已捕获的请求重新发往真实服务器,是有副
  作用的出站动作(可能再次下单、重放一次攻击、改动服务端状态)。它的写操作同类兄弟——proxy.start /
  stop / export_har / ca.install_android——都会往会话时间线写一条,唯独 replay 走的是读操作形状的
  `_proxy_wrap`、什么都不记。于是 `timeline.list` 能看到代理起停、HAR 导出,却看不到有没有对目标重放过
  流量。现在成功的 replay 会记一条 `proxy.replay` 时间线条目并点名 flow_id。
- 与兄弟们一致,只在成功时记:一次失败的 replay 不会留下误导性的"已重放"痕迹。新增
  `tests/unit/test_proxy_replay_timeline.py` 钉住成功记一条(带 flow_id)、失败不记。

### 新增（frida 路径的设备变更补齐审计日志）

- 上一步把 adb 路径的设备变更(device.install/launch/push/…)写入了审计日志,但同一类"改动目标设备"
  的 frida 路径没进去,于是设备变更审计留了个口子:`frida.spawn` 在设备上以插桩方式拉起一个进程、
  `frida.server.ensure` 往设备推送并启动一个 frida-server 二进制——论侵入性不亚于 device.launch/install
  ——却只落在按会话的时间线里。时间线随会话被裁剪清掉,审计日志则跨会话留存,这正是 `ui.drive`
  为何既写时间线又写审计。现在这两个 frida 设备变更同样写入审计日志。
- 与 device.* 不同,它们跑在某个会话内,所以带真实 `session_id` 落库:既能在按该会话过滤的 `audit.list`
  里看到,也能在不带过滤的列举里看到,而且在该会话自己的时间线被裁剪之后依然留在审计里。纯枚举
  (frida.devices/applications/java.*)只读、不改动任何东西,因此不记。
- 记账是尽力而为:进程已经拉起、server 已经在跑,一次审计写入失败绝不能把已成功的 spawn 变成失败的
  工具调用;写入只拷贝结构化字段(pid、端口、running/pushed 布尔),不含机密,store 侧另有脱敏兜底。
  失败的调用也照记(带其错误码),与 `ui.drive` 同时审计成败两种结局一致。
- `audit.list` 描述更新为点名这两个 frida 设备变更并解释其会话内性质;新增
  `tests/unit/test_frida_audit.py` 钉住:spawn/server.ensure 各记一条带会话 id 的审计、失败仍记且带
  错误码、纯枚举不记、按会话过滤看得到、以及审计写失败不拖垮 spawn。

### 新增（有副作用的 device.* 操作进入审计日志）

- 高风险的设备变更——`device.connect/install/uninstall/launch/force_stop/push/forward`——此前在任何
  日志里都不留痕:它们按序列号(serial)寻址、不属于任何会话,因此 apk.*/frida.*/web.* 用的按会话时间线
  对它们不适用,而审计日志当时只记会话开关与 `ui.drive`。于是一个无人值守的 agent 夜里往设备装/卸了哪个
  应用、转发了哪个端口,操作者事后无从查证。现在这七个状态变更调用会写入全局审计日志:`append_audit`
  本就接受 `session_id=None`——正是为"归属某序列号却不属于任何会话"的动作准备的——所以它们以空
  `session_id` 落库,通过 `audit.list` 不带 `session_id` 的列举可见。失败的调用也照记(带其错误码),
  与 `ui.drive` 同时审计成败两种结局的做法一致。
- 两个捕获类操作 `device.pull` / `device.screenshot` 同样纳入审计,理由更硬:它们把文件写到
  `artifact_root/device/` 下,但制品表需要 `session_id` 而这些操作按序列号寻址、给不出,所以文件从不登记
  ——没有会话时间线、不进制品表、原本也不在审计里,一次 pull/截图落在磁盘上的文件毫无出处可查。现在这条
  审计就是它唯一的出处:哪台设备、拉了哪个远端路径、落到哪个本地文件、多大。真正的只读操作
  (info/properties/packages/logcat/current_activity)只回数据、不动任何东西,因此不记。
- 记账是尽力而为:设备上的操作已经发生,一次审计写入失败绝不能把一个已成功的 install 或 pull 变成失败的
  工具调用。写入只拷贝结构化字段(序列号、包名、校验布尔、端口、捕获文件路径与大小),不含机密,store 侧
  另有脱敏兜底。
- `audit.list` 描述更新为点名设备的变更与捕获,并解释它们为何以空 `session_id` 落在这里;新增
  `tests/unit/test_device_audit.py` 钉住:各操作各记一条空会话审计、失败仍记且带错误码、connect 被
  降级为失败时按最终结局记 `ok=False`、捕获文件的出处被记录、超限捕获记 `output_too_large`、纯只读操作
  不记、按会话过滤看不到而不带过滤看得到、以及审计写失败不拖垮设备调用。

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

### 测试（APK 解包的实际尺寸兜底此前无契约覆盖）

- `_refuse_oversized_tree` 是 `apk.decode` / `apk.decompile` / `apk.export_sources` 三处的实际
  尺寸兜底：`check_zip_expansion` 只挡住*声明*尺寸的炸弹，而中央目录诚实、运行后才在磁盘上膨胀
  到数 GB 的归档（嵌套压缩、密集生成的 smali、展开远超存储尺寸的资源表）要靠它——量出工具真正
  写下的树，一旦超过 `UNREGISTERED_CAPTURE_MAX_BYTES` 就删树并以 `too_large` 拒绝，使填满磁盘的
  解包不把残留留给下一次 close 或 artifacts.gc 继承。声明尺寸护栏有测试、这个实际尺寸兜底却没有，
  三处任一调用被删都不会有测试报警。`tests/unit/test_apk_oversized_tree_guard.py` 钉住 helper 契约
  （超限删除并拒绝、界内不动、缺失即无操作、单文件产物同样覆盖）以及它仍接在 apktool 与 jadx 两条
  路径上（超限的解包回 `too_large` 且树被删除）。

### 修复（proxy.start 空 host 会静默绑定所有网卡，把 MITM 暴露到全网）

- `proxy.start` 的 host 默认回环，但空串/纯空白会原样交给 mitmproxy 的 `listen_host`，
  而 mitmproxy 把 `""` 解读为 bind-all（`0.0.0.0` + `::`）：一个能签发并向设备安装 CA 的
  在途 HTTPS MITM 就此监听到每一张可路由的网卡上，凡能路由到本机者皆可经它转发流量。
  工具文档写明默认回环，缺省或空白值不该反把默认变成 bind-all。现在后端 `start` 先把
  host 归一为 `(host or "").strip() or "127.0.0.1"`：空/空白落回回环，显式地址（含为物理
  设备拦截而刻意绑定的可路由网卡）保持调用方的选择不动，只纠正空这一种情形。
  `tests/unit/test_proxy_start_host_bind.py` 用假监听器钉住空/空白/None 均绑定回环、
  首尾空白被裁剪、显式 `0.0.0.0` 原样保留——断言的是交给监听器的 host，而非报告字段。

### 修复（APK 解包三处入口不设声明尺寸上限——zip 炸弹直至超时才停）

- apktool（`apk.decode`）与 jadx（`apk.export_sources` / `apk.decompile`）把归档膨胀到磁盘、
  androguard（`apk.open` 等静态读取）把条目解压进内存，三处都只有调用超时这一个界：中央目录
  声明 PB 级展开的经典 42.zip 形态会让工具在截止时间到来前实打实写几分钟磁盘、或直接把整个
  服务进程 OOM——而中央目录本身读起来近乎免费。新增共享的 `check_zip_expansion`
  （`backends/common/zip_guard.py`，成员数上限 100k、声明展开上限 4 GiB，与 installer 的
  依赖包护栏同型）：apktool/jadx 在 JVM 启动前、androguard 在缓存未命中解析前先查先拒，
  超限以 `too_large` 拒绝，中央目录不可读则以 `invalid_params` 失败即拒（下游工具反正也解不了）。
  `tests/unit/test_apk_zip_bomb_guard.py` 钉住三处入口都在花费任何资源之前拒绝、
  不可读归档不放行。

### 修复（web.open / web.navigate 可导航到 file:// 等本地 scheme）

- `web.open` / `web.navigate` 把调用方的 URL 原样交给 `page.goto`，而 goto 对 `file://`、
  `chrome://`、`view-source:`、`data:` 一视同仁：导航到 `file:///etc/passwd` 后，
  `web.dom_snapshot` / `web.network_get` 就把文件内容递回来——Web 分析线因此变成本地文件读取器，
  绕过系统其余部分的所有路径护栏。现新增 `_require_http_url`：非 http(s) 目标在浏览器启动、
  会话槽位保留之前即以 `invalid_params` 拒绝（空 URL 仍打开空白页）；校验的是去除首尾空白后
  实际交给 goto 的字符串，控制字符前缀混淆不过关。`tests/unit/test_web_url_guard.py` 钉住
  file/chrome/view-source/javascript/data/协议相对等敌意形态全部拒绝、真实 http(s) 目标放行，
  且拒绝发生在触碰会话与 Playwright 导入之前。

### 修复（frida 本地读取 RPC 无外层超时）

- `frida.modules` / `frida.exports` / `frida.memory_read` 只给 attach 上了超时（经 `_attach_local`），
  随后的 `script.load()` 与同步 `exports_sync.*` RPC 却在 worker 线程上无界执行。目标若在加载脚
  本或枚举时卡死（超大模块表、`Memory.readByteArray` 触发缺页）就会把那个 worker 永久占住——正
  是设备侧操作（`java_enumerate` / `hook_template_device`）早已用 `_run_deadline` 挡掉的挂起。新增
  共享的 `_run_local_script` 把 attach、load 与 RPC 收进同一个 `work()`、共用一个截止时间，超时即
  detach 掉探针；三个方法新增与设备侧同默认值的关键字 `timeout`。`tests/unit/test_frida_fields.py`
  钉住卡死的读取会在截止时间内 detach 并抛 `timeout`。

### 修复（切换线程丢失进行中的 run）

- 停在批准上的 run 服务端是持久的，但监控台只会重连自己手里已有 id 的 run（`history.state`
  里那一个）。从侧栏点开这条线程只拿得到转录：批准卡片不见了，事件流也没接上，除非撞巧重载
  否则无从应答。现在 `GET /api/agent/threads/{id}` 回传该线程仍在跑的 run（`active_run`，
  终态与已请求取消的 run 不算，见 `store.active_run_for_thread`），`selectThread` 据此重放
  它的事件并重连流；切换线程时也会先掐断上一条线程的事件流，事件不再串台。
  `tests/unit/test_agent_web_api.py` 钉住 `active_run` 的取值生命周期，
  `useWorkbench.resume.test.ts` 断言选中线程后批准卡片与活跃 run 都回来了。

### 修复（监控台重载后对话空白）

- 运行中重载监控台会丢掉整段对话。恢复逻辑能从 `history.state` 认出还在跑的 run、重放它的
  事件、把停着的批准卡片带回来，却始终没把 `selectedThread` 选回去：转录区因此空白，而 run
  一旦结束，`stream_ended` 又没有线程可供回捞助手回复，对话就在一个号称「会话能扛住重启」的
  页面上凭空消失。现在恢复时先用 run 行自带的 `thread_id`（`GET /api/agent/runs/{id}` 一直
  在回传）把它所属线程选回来，再重放事件——转录与批准都回到重载前的样子；线程若已删除则退化
  为只恢复 run 与批准，不让复原失败。`webui/src/app/useWorkbench.resume.test.ts` 断言重载后
  线程被选回、转录与停着的批准都还在。
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

### 修复（`frida.java.classes/methods` 的 `class_name` / `name_filter` 无长度上界）

- 全库每个跨后端边界的字符串都在后端就地设界——ADB 序列号与包名、Web 选择器、Frida 的
  `module_name`——唯独 `java_enumerate` 把 `class_name` 与 `name_filter` 原样送过 Frida RPC 到
  设备,既不做类型检查、也不设长度上限,而工具层只对 `limit` 设了界。这两个值是作为 RPC **数据**
  参数交给固定脚本的(从不拼进脚本),所以这是资源/编组护栏而非注入护栏:重点是调用方不能每次调用都把
  一个兆字节级字符串编组到设备上。Java 名合法地带 `$`(内部类)/`[`(数组)/`.`(包),严格正则会误杀
  合法目标,故按长度设界(512 字节)才是诚实的做法;`class_name` 另需非空,`name_filter` 可空(即"不过滤")。
  含 NUL 的值一律拒绝,免得在编组途中被截断。校验挪到解析设备之前:坏 `mode`、超长或含 NUL 的
  输入在任何 attach 发生**之前**当场以 `invalid_params` 拒绝(与 `install`/`push` 先判本地事实同一
  次序),越权 pid 仍先于输入校验被 `permission_denied` 拦下。
- 新增 `tests/unit/test_frida_java_input_bounds.py` 钉住:`class_name` 必填且设界、`name_filter`
  可选且设界、含 NUL 拒绝、`class_name` 会被 strip、界内值原样抵达脚本、未知 `mode` 与超长输入都
  在触碰设备之前失败(以 `resolved`/`attached` 均为空断言快失败)、以及授权边界仍先于输入校验生效。

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
- **动态**：`web.*` 15 个工具，Playwright 驱动 CDP，采集网络请求、console、已解析脚本与
  WASM 模块、DOM 快照、截图与 HAR。大响应体（响应正文、脚本源码）落盘为产物并回引用，
  不撑爆上下文。**刻意不提供 `web.evaluate`**——它是浏览器侧的 `dynamic.command`。
- **交互**：`web.click` / `web.type` 让 Web 线从"只能观察"进到"能驱动多步流程"——按 CSS
  选择器点击 / 填值(用 `fill` 一次性置值,不是逐键事件)。二者都是有界交互而非任意执行：
  选择器与可操作等待都在排队前夹取(空/超长选择器与非正/超大超时都先拒为 `invalid_params`,
  不会卡住或 wedge 会话线程),`web.type` 只回填入文本的长度、绝不回显文本本身,免得口令/令牌
  落进转写;元素在超时内始终不可操作则以 `backend_error` 拒绝。仍**只接受选择器,不接受脚本**,
  与不提供 `web.evaluate` 同一条边界。
- **同步**：`web.wait` 补上多步流程缺的那一环——点击触发异步导航/AJAX 更新后,先等预期元素
  到达某个 DOM 状态(`visible`/`hidden`/`attached`/`detached`)再读,免得 `dom.snapshot` /
  `network.get` 与页面抢跑。只读工具(不改状态),同样在触碰会话前校验选择器与状态、排队前夹取
  超时;未知状态先拒为 `invalid_params`,状态在超时内未到达则记 `backend_error`。
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
- 修正文档口径：README 里「敌意输入下全部返回信封」的工具数从过时的 262 改为 267（=全部
  268 个 MCP 工具减去会真删数据的 `artifacts.gc`），并改述为「绑定工具数 − 1」的不变式，
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
- **全表面资源策略有界**：全部 268 个工具的 `resource_policy` 都有有限且为正的超时与为正的
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
  新增契约:钉住出厂全表面 268 个 MCP 名折叠后无碰撞,并直测别名解析(点名/下划线/多段名都命中同一
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
