# 安全政策

本项目是驱动真实调试器与真实设备的逆向工程工具。它的安全边界不是"分析恶意样本时保护你的机器"——
调试器会真实执行目标代码,隔离是部署方的责任(见 [README「隔离部署」](README.md#隔离部署))。
本文界定的是**工具自身**的安全承诺:受限工具面、回环+token 的控制台、写操作审批与参数校验。

## 支持的版本

| 版本 | 是否接收安全修复 |
|------|------------------|
| 0.2.x(最新 release) | 是 |
| < 0.2 | 否,请升级 |

单维护者、公开历史短,修复只进最新 release 线,不做旧版本回携(backport)。

## 报告漏洞

**不要**用公开 issue 报告安全问题。请使用 GitHub 的私密漏洞报告:
仓库页面 **Security → Report a vulnerability**
([私密报告入口](https://github.com/kumburovicbranko682-boop/headless-re-mcp/security/advisories/new))。

报告请尽量包含:

- 受影响版本(`headless-re-mcp --version` 或 MSI 版本号)与部署方式(源码 / MSI);
- 复现步骤或 PoC——最好能落到具体的工具调用序列或 HTTP 请求;
- 影响面判断:越权执行了什么、绕过了哪条边界、泄露了什么。

响应口径(诚实版):单维护者,7 天内确认收到,修复按严重程度尽力而为;
修复随下一个 release 发布并记入 CHANGELOG,愿意署名的报告者会致谢。

## 范围:什么算本项目的漏洞

工具面刻意不提供 `dynamic.command`、`device.shell`、`web.evaluate`,也不接受调用方自带
Frida 脚本——每个能力都是具名、参数经校验的工具。任何绕开这条原则的路径都是漏洞,包括但不限于:

- **任意命令/代码执行逃逸**:通过某个工具的参数注入,让 adb / jadx / apktool / apksigner /
  UPX / DIE 等外部 CLI 执行了非预期命令,或让调试器/浏览器执行了任意脚本;
- **控制台认证绕过**:未持有本地 token 即可调用 Web 监控台 API,或服务在默认配置下
  监听了回环以外的地址;
- **写策略绕过**:`local_full_access: false` 时仍能执行状态变更或文件写入;
  autonomy 处于 `请求批准` 档时写操作未经批准即执行;`agent_never_auto_approve`
  名单内的工具被自动放行;
- **路径逃逸**:产物库、会话工作树的读写或清理(prune)越出其专属目录,
  能读写或删除仓库外的文件;浏览器驱动同理——`web.open` / `web.navigate` 只接受
  http(s),若能让它导航到 `file://` / `chrome://` 等本地 scheme 并经
  `dom_snapshot` 读回内容,按本类漏洞处理;
- **敏感信息泄露**:签名口令、token 等出现在错误信封、日志或产物中
  (现有实现会抹掉 apksigner stderr 里的口令,并经环境变量而非命令行把口令交给 apksigner,
  以免 `/proc/<pid>/cmdline` 对本机用户暴露;同类泄露按漏洞处理);
- **错误信封契约失效导致的边界失守**:敌意输入让工具抛出未捕获异常并因此
  跳过了本应执行的策略检查。

## 范围之外

- **样本本身的恶意行为**。`dynamic.launch` 就是要运行目标代码;样本逃出你的分析环境
  是部署隔离问题,不是本项目漏洞。请按 README 的隔离基线部署(可丢弃的
  VM/物理机、专用低权限账户、默认断网)。
- **第三方后端自身的漏洞**(IDA、x64dbg、Frida、mitmproxy、Playwright 等)——请报给上游;
  但如果是本项目的**集成方式**放大了上游问题(例如把不该暴露的上游接口暴露给了调用方),在范围内。
- **隐藏桌面被样本识破**。`HEADLESS_RE_HIDDEN_DESKTOP` 解决的是"不干扰你的桌面",
  从来不承诺反检测,README 有明文。
- **需要本机管理员/同用户权限才能实施的攻击**。本服务以你的用户身份运行,
  同权限的本地攻击者本来就能做到一切。

## 部署加固基线

漏洞报告之外,这些是使用方自己要做对的事:

- 未知样本只在可随时丢弃的环境里分析(快照 VM / 可还原物理机),每个 mission 之后回滚;
- 专用低权限账户运行,不共享宿主目录、剪贴板与凭据;
- Web 监控台保持默认的回环 + token,不要端口转发到局域网;即使端口被转发,
  非回环来源也会收到 `403 loopback_only`——唯一的例外是 `/healthz` 活性探针,
  它只回 ok/版本信息,不含任何秘密(`/readyz` 与其余全部路由仍限回环)。
  回环之内,除 `/healthz` 外还有两条刻意免 token 的监督探针:`/readyz`(就绪)与
  `/metrics`(Prometheus 抓取)——这样本机 supervisor 无需持有控制台 token 即可探活,
  三者的响应都不含任何秘密;其余全部路由(含 SPA 页面本身)一律要求 token,
  这条性质由契约测试逐路由强制;
- 给不可信的 MCP 客户端只读部署(`local_full_access: false`),
  或用 `agent_never_auto_approve` 把高危写操作钉死为人工批准。

## 安全开关速查(配置项)

上面提到的边界都是具体的配置项,均可写进 `config.json` 或用环境变量覆盖(环境变量优先)。
下表是与安全直接相关的开关及其效果:

| 配置键 | 环境变量 | 作用 |
|--------|----------|------|
| `local_full_access`(默认 `true`) | `HEADLESS_RE_LOCAL_FULL_ACCESS` | 置 `false` 即**只读部署**:所有写工具在到达处理器前返回 `write_disabled`,只读工具照常。 |
| `agent_auto_approve_effects` | `HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS` | 允许自动批准的效应类,取 `state_change` / `file_write`(逗号分隔)。两类都放开等价于 UI 的「完全访问」。 |
| `agent_auto_approve_tools` | `HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS` | 具名放行的工具(不牵连整类),用于只想自动跑少数几个写工具的场景。 |
| `agent_never_auto_approve` | `HEADLESS_RE_AGENT_NEVER_AUTO_APPROVE` | **硬停名单,优先级最高**:名单内工具永远等待人工批准,覆盖上面所有放行(连只读基线也压过)。 |

关于 autonomy(无人值守)默认值,有三条容易踩坑、务必记牢的规则:

- **完全不配置这三个键** → 应用 *packed-analysis 预设*:自动批准 `state_change` 以及**非敏感**的
  `file_write`。补壳 PE 分析常用的写会自动跑,但 patches(打补丁/回滚/改字节)、APK 改包与签名、
  产物 GC(`artifacts.gc`)、设备与 Web 抓取(截图 / pull / HAR 导出等)始终留给人工。
- **显式写成空列表**(`"agent_auto_approve_effects": []`)→ *fail-closed*:只有只读工具自动运行,
  任何写都等待批准。空列表不是"沿用默认",而是"什么都别自动批准"。
- **想彻底只读**用 `local_full_access: false`;**想无人值守但钉死个别高危工具**,
  在开放效应类的同时把它们列进 `agent_never_auto_approve`。

这些行为由契约测试固定(`tests/unit/test_write_policy_surface.py`、`tests/unit/test_agent_autonomy.py`),
改动预设或名单会让测试失败,以防高危写操作被悄悄放开。
