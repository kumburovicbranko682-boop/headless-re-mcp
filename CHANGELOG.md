# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org/lang/zh-CN/);
until 1.0 the tool surface may still change between minor versions.

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

[0.2.0]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0
