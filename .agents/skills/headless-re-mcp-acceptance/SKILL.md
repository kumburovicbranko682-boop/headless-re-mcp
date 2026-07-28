---
name: headless-re-mcp-acceptance
description: Evidence-driven acceptance review for the Headless RE-MCP project in E:\x64dbgmcp. Use whenever the user asks to 验收、复核、审查、核对完成度、检查 M1-M6、判断是否闭环、核实真 Headless、检查交接或发布状态—even if they do not explicitly request this skill. Reviews actual current source and runtime evidence, distinguishes code wiring from tested behavior, and never treats roadmap claims or test names as proof.
---

# Headless RE-MCP Acceptance

对 `E:\x64dbgmcp` 做项目专用、证据驱动的验收。目标不是替开发者背书，而是回答：**当前磁盘上的实际实现，究竟完成了什么，哪些闭环已被什么证据证明，哪些仍未证明或存在缺陷。**

## 1. 先冻结本轮模式

从用户当前请求判断模式，不复用旧会话里更宽的授权。用户只说“验收/重新验收/看看是否完成”时，默认采用**实际运行验收**，因为文件存在、文档声明和测试源码都不能代替真实执行证据：

- **纯代码验收**：只读产品源码、构建/配置/许可证文档和必要的接口定义；不修改文件，不运行测试、构建、Doctor、Gate，不启动 IDA/x64dbg/目标程序。
- **测试结果验收**：只审核用户或其他通道已经提供的原始输出与 artifact；不自行重跑。
- **实际运行验收（默认）**：在静态控制流审查后，实际执行聚焦门禁、双架构真实后端 Gate 和适用的完整门禁；不得以测试文件存在、mock 成功或 skip 计通过。
- **发布验收**：另加 Source/Portable/MSI、许可证、校验和、第三方来源、零窗口和干净机边界。

用户明确说“纯代码”“先不测试”“测试在跑了”时，降为纯代码/测试结果验收；这时不能输出“实测通过”。无论哪种模式，发现缺陷只报告，不顺手修复，不执行 formatter 的 `--fix`，不编辑测试或文档，除非用户另行明确要求从验收切换到修复。

默认由主助手直接审查，不使用子智能体。只有用户明确撤销该项目约束时才可委派。

## 2. 以当前磁盘为唯一代码基线

此目录可能不是 Git 仓库，也可能在审查期间被其他通道修改：

1. 读取项目自有清单、路线图、配置和产品入口，建立当前文件清单。
2. 直接读取当前产品源码；无 `.git` 时不要用不存在的提交/diff 推断来源。
3. 审查期间若文件发生变化，重新读取受影响文件并声明取证时间边界。
4. 不把旧聊天、旧 handoff、旧 README 数字当成当前实现。
5. `tests/` 只能证明“作者打算测什么”；未执行时不能证明运行行为。纯代码验收通常不展开测试文件，除非需要核对一项“声称已有测试”的具体口径。
6. 不读取或引入 `upstream/` 大型第三方源码，除非某条来源、许可证或算法归属必须核验。

先读 `references/acceptance-matrix.md`。需要实际运行时，再读 `references/runtime-gates.md`。

## 3. 建立需求—实现—暴露—证据矩阵

每项能力必须分别检查四层，不能看到函数名就判定完成：

1. **实现（Implementation）**：领域逻辑或 native 方法是否真实存在，不是 placeholder、硬编码成功、`not_implemented` 或只返回计划。
2. **接线（Wiring）**：配置 → worker/client → service → MCP tool 是否全链路可达；错误和 capability 是否一致。
3. **闭环（Closure）**：输出是否被下一阶段消费，状态/游标/artifact 是否推进，资源是否释放；“工具可单独调用”不等于编排闭环。
4. **证据（Evidence）**：
   - 纯代码模式只能给 `代码已接线` / `代码上未闭环`，不能给 `实测通过`。
   - 实际运行结果必须来自本轮原始命令输出或可核验 artifact。
   - 文档和测试名称仅为声明，不是运行证据。

对每项记录：`要求 | 源码证据 | MCP 暴露 | 状态/副作用 | 运行证据 | 判定`。

判定词固定使用：

- **代码已闭环**：从输入到结果/状态/清理的产品代码链完整，但未声称本轮跑过。
- **代码已接线、闭环未证明**：入口存在，但关键状态推进、artifact ownership、后继消费或真实后端行为未证明。
- **实测通过**：本轮或用户提供的可核验原始证据证明通过，且无 skip。
- **部分通过**：只覆盖架构、层级或场景的一部分。
- **未实现**：产品路径不存在或显式 placeholder。
- **阻塞**：违反核心产品定义、安全不变量，或使完成声明失真。
- **不适用/明确延期**：必须有 ADR/路线图和不冒充完成的产品行为。

## 4. 审查实际控制流，而非表面数量

对关键路径至少沿调用链追到真实副作用：

- MCP 参数约束是否与 service 一致。
- service 是否调用正确 adapter/native capability。
- client 的 capability、鉴权、超时和错误是否被验证。
- native/Python 实现是否执行真实读取、调试或重建，而非返回固定结构。
- 成功后是否记录 artifact、SHA、timeline、phase；失败/取消/超时后是否保持一致。
- 同一资源是否有唯一 owner：runtime、cursor、session state、breakpoint intent、artifact path。
- `read-modify-write` 是否在统一锁/事务内，避免并发丢更新。
- 生命周期是否覆盖 create/open/use/close/fail/restart，而不只覆盖 happy path。

主动搜索并核对：`TODO`、`FIXME`、`pass`、`NotImplemented`、`not_implemented`、`deferred`、`placeholder`、`claims_universal_unpack`、宽泛 `except`、无界读写、任意命令入口、shell 执行和跨 session 路径。

## 5. 不可妥协的项目硬门槛

以下任一成立，不能给项目级通过：

- 启动 `x32dbg.exe`/`x64dbg.exe` 后隐藏，或分析器进程拥有任何顶层窗口（隐藏窗口也失败）。
- IDA 不是 `idapro`/`idalib` 隔离 worker，或导入顺序可能在 `idapro` 初始化前加载 IDAPython。
- x64dbg RPC 不是编入官方 `src/headless` target 的受限接口。
- 暴露任意 x64dbg 命令、CMD、PowerShell、Python、shell/system command MCP 工具。
- Named Pipe 无随机 token/PID/协议/版本/capability 校验，重复 hello 未 fail closed。
- 无路径、超时、frame/字节、批量、并发或资源边界。
- `dynamic.events` 与 workflow 争抢多个 cursor，或事件丢失后继续信任旧地址。
- 模块卸载后仍保留有效绑定；RVA 重绑定未遵守 remove-before-set；陈旧操作可确认新 revision。
- 启发式候选、OEP 候选、UPX modified 或部分 IL 被冒充为确定/通用结果。
- 外部工具来源未锁定或绕过 SHA/许可证/白名单 argv/无窗口/输入不变验证。
- 路线图把未实测、skip 或文档自述写成完成。

“本地全部开放”仅表示本机 stdio 对授权目标开放已实现的语义化工具，不解除以上边界。始终保留适用范围：**自有样本研究、授权渗透测试、CTF/教学实验**。

## 6. 实际验收方法（来自项目历史有效做法）

若用户明确授权运行，按以下原则取证：

- 先核对当前产物和有效配置，缺环境时明确 `skip/blocked`，不能算通过。
- 使用进程级临时环境变量，不猜路径、不污染全局配置。
- 测试真实 x86 与 x64；只测一侧则为部分通过。
- 真实 lifecycle 必须观察完整状态链，不以固定 sleep 或无限重试掩盖竞态。
- 对异步调试动作使用事件锚点：先确认本次 `resumed/paused/module.loaded/module.unloaded` 转换，再采样状态。
- `modules.list` 等 paused-only 能力只在稳定暂停读取；运行中通过事件流观察，再 pause 后取快照。
- 如果包装命令的环境变量被 shell 提前展开导致全 skip，明确该轮无效并重跑正确命令。
- 单测通过不能关闭真实 Gate；真实 Gate 通过也不能替代静态质量、协议边界和发布检查。
- 最终数字只能采用最后一次实际输出，并拆分 unit、integration、IDA Gate、x86/x64 Gate、Doctor；不要混用旧总数。
- 测试后被动检查项目进程和允许范围内的临时 userdir；不得清理无关 Python/MCP/调试任务。

详细顺序和通过条件见 `references/runtime-gates.md`。

## 7. 缺陷定级

- **P0 / 核心定义失败**：不是真 Headless；有任意命令执行；鉴权绕过；将不确定结果伪造为成功；不可控地执行目标/外部工具。
- **P1 / 阻塞里程碑**：接口存在但核心闭环不可达；并发会丢状态；跨 session artifact 越权；active session 可静默覆盖；事件/断点 fail-open；真实双架构 Gate 失败。
- **P2 / 高优先级**：输出文件无硬上限；timeout 只杀父进程；不完整 metadata 边界可误解析；Doctor 会 false-ready；状态和 artifact phase 不一致。
- **P3 / 中低优先级**：文档基线冲突；锁文件时间元数据陈旧；错误信息/可维护性问题；已明确且不冒充完成的限制。

按影响定级，不按修改行数定级。每个问题必须写：

- 可复现/可达条件；
- 受影响不变量；
- 产品源码证据 `path:line`；
- 为什么不是单纯测试或文档问题；
- 当前模式下的验证限制。

## 8. 输出格式

先写 findings，按 P0→P3 排序；如果没有发现，也明确写“未发现阻塞项”，同时列残余未验证风险。不要先写长篇项目简介。实际运行验收还必须把每条 Gate 的命令、退出码、pass/fail/skip 和关键原始输出落到报告或验收 artifact；报告中的每个“实测通过”都应能反查到这条证据。

```markdown
# Headless RE-MCP 验收结论

**模式**：纯代码 / 测试结果 / 实际运行 / 发布
**基线**：当前磁盘；审查时间；是否观察到并发变更
**总判定**：通过 / 有条件通过 / 不通过 / 无法判定

## 阻塞与缺陷
### P1-1 标题
- 证据：`src/...py:123`
- 实际控制流：...
- 影响：...
- 判定：代码缺陷 / 未闭环 / 证据缺失

## 能力矩阵
| 能力 | 实现 | 接线 | 闭环 | 实测 | 判定 |
|---|---|---|---|---|---|

## 已确认的硬边界
- 真 Headless：代码证据 / 实测证据 / 尚待 Gate
- 任意命令：不存在 / 存在（列入口）
- 资源与供应链：...

## 尚待实际证明
- 精确列出需要哪条 Gate；不要泛写“多测试”。

## 文档口径问题
- 区分产品缺陷与文档陈旧。
```

结论纪律：

- 无本轮运行证据时写“源码层通过/接线完整”，不写“测试通过”“正式完成”。
- 测试正在其他通道运行时，结论中标明“等待外部原始结果”，不引用自述数字。
- 对明确限制（例如 M6 metadata walker 非 dnlib、MemberRef 非完整 callgraph、IL 可 partial）检查是否诚实暴露；诚实限制本身不是缺陷。
- 不因工具数量多而给高评价；以正确性、边界、可达性、闭环和实际证据为准。
