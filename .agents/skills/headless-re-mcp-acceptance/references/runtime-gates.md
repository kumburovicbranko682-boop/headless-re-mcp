# Headless RE-MCP 实际运行验收 Gate

用于默认的实际运行验收，或用户明确要求本轮执行测试、构建、Gate 时使用。只有用户明确限定“纯代码”“先不测试”“测试在跑了”时才不得执行本文件中的命令。

## 1. 证据等级

从弱到强：

1. 文档声明；
2. 测试源码存在；
3. 产品源码静态控制流；
4. mock/unit 实际输出；
5. service/MCP integration 实际输出；
6. 真实 IDA/x64dbg 双架构 Gate；
7. 发布包/干净机 Gate。

高等级证据不能自动覆盖另一维度。例如真实 happy-path Gate 不证明输入边界；unit 不证明真 Headless。

每条命令保存：命令、开始/结束时间、退出码、stdout/stderr、环境变量名称（token 值脱敏）、产物 SHA。若无法保存，最终报告至少逐字引用末尾 summary 与失败。

## 2. 环境与干扰控制

- 先检查是否已有同项目构建/测试进程。不要并发启动多个 x64dbg/IDA Gate。
- 优先使用项目已存在的完整后端运行目录，不无谓重编。
- 仅设置当前进程环境：
  - `HEADLESS_RE_IDA_HOME`
  - `HEADLESS_RE_IDA_GATE_BINARY`
  - `HEADLESS_RE_X64DBG_HEADLESS_X86`
  - `HEADLESS_RE_X64DBG_HEADLESS_X64`
  - 需要时的 DIE/UPX/de4dot/NRS 路径
- 不写系统/用户永久环境，除非用户明确要求。
- 路径必须从 `Settings.load()` 或已验证 artifact 得到，不猜测。
- 使用无害、自建、无窗口 fixture。分析器无窗口是硬要求；目标 fixture 也尽量无窗口以减少桌面干扰。
- 不使用固定 sleep 作为正确性判据；等待必须有 timeout 和状态/事件条件。

## 3. 构建 Gate

### Fixture

- 构建 x86/x64。
- 检查 PE architecture、subsystem、入口和脚本自检。
- lifecycle fixture 的二进制必须来自当前源码，不沿用旧产物。

### Native x64dbg RPC

- 使用 `native/xdbg-headless-rpc/build.ps1` 构建 x86/x64。
- 验证 RPC 源实际注入官方 headless target。
- `-Architecture all -RunGate` 脚本自身必须成功；若脚本输出收集报错，即使手工两侧 Gate 成功，也应分别记录“native binary 可用”和“build script 缺陷”。
- 核对输出 PE architecture、依赖文件和完整 runtime 目录。

## 4. 静态质量门禁

根据 `pyproject.toml` 的当前配置执行，不硬编码旧文件数：

- Ruff（不使用 `--fix`）；
- Mypy strict；
- Compileall；
- `pip check`。

质量门禁与运行 Gate 分开报告。失败不得因 unit 通过而忽略。

## 5. 聚焦测试优先

先运行变更/里程碑最相关的测试，确认失败属于产品还是 harness，再决定完整套件：

- M1：events/workflow/address sync + x86/x64 lifecycle/rebind + MCP stdio。
- M2：内置 PE、DIE adapter（可用时）；确认 detection 不执行目标。
- M3：官方 UPX `-t/-d` artifact 闭环。
- M4：真实 paused runtime header、module dump、IAT scan/read；不要在重复 hello 前失败。
- M5：phase/timeline/artifact/timeout/cancel/OEP confirm；并发状态操作应有定向测试。
- M6：CLR inspect、de4dot/NRS bounded adapter、metadata bounds、session ownership。

任何 skip 都记录原因。环境缺失导致 skip 的 Gate 是“未验”，不是 pass。

## 6. 真 Headless Gate

### IDA Gate

验证：

- `idapro`/idalib worker 能真实打开 fixture 并产出静态结果；
- worker PID 无任何顶层窗口（包括 hidden）；
- 退出码、timeout、临时 userdir 清理；
- 不启动 `ida.exe`/`ida64.exe` GUI。

### x64dbg CLI Gate（x86 + x64）

验证：

- 启动的是 `headless.exe`，不是 x32dbg/x64dbg；
- hello protocol/version/token/PID/architecture/capabilities；
- `command_loop_seen=true`；
- analyzer PID `EnumWindows` 结果为空；
- 正常 shutdown 和 exit code 0；
- 目标 GUI 如有不计 analyzer 窗口，但 PID 必须分离。

## 7. 异步动态 Gate 的正确观测法

项目历史中有效的真实验收模式：

```text
提交 resume
→ 从唯一 cursor 读取并确认本次 debug.resumed
→ 通过事件观察 module.loaded / breakpoint.hit / module.unloaded
→ 主动或自然进入新的 debug.paused
→ 在暂停后的状态采样 modules.list / registers / memory
```

不得：

- 提交 resume 后立即把提交前的旧 `paused` 当成新停点；
- 在 running 时轮询 paused-only `modules.list`；
- 依赖一次 resume 一定直接到 idle；x64dbg 可有中间 system breakpoint/pause；
- 用增加 sleep/retry 掩盖事件/状态竞态；
- 多个消费者各自推进 native event cursor。

### M1 多模块真实链

x86/x64 的 service 与 MCP stdio 均应覆盖：

1. 初始模块快照；
2. DLL loaded 事件；
3. pause 后显式 base/path/name(+SHA) resolve；
4. preferred↔runtime RVA 往返；
5. one-shot/persistent breakpoint 命中；
6. unload 事件和旧 binding 失效；
7. 不同 base 重载；
8. remove-before-set 和 persistent breakpoint 再命中；
9. workflow ID/state/cursor 跨 MCP 调用持久；
10. 正常退出与资源清理。

## 8. M4 真实闭环注意事项

- xdbg client 构造时已自动调用 `rpc.hello`；集成 Gate 不得再次 hello。若重复 hello 收到 `RPC connection is already authenticated`，native 是正确 fail closed，测试脚本有误。
- Gate 必须进入真正的：paused runtime header → module dump → imports scan/read → Python rebuild/verify（按完成定义需要的范围）。
- 如果失败发生在第一个真实 M4 RPC 之前，不能声称 M4 live 闭环已测。
- dump/header artifact 检查 SHA、路径 ownership、原子写和大小上限。

## 9. M5/M6 实际闭环

### M5

- 同一个 active session 的并发调用不能丢 timeline/artifact 更新。
- 第二次 `unpack.start` 应按设计拒绝/替换且不静默覆盖。
- timeout/cancel 后 in-flight 操作返回时不能复活终态或覆盖 failure。
- OEP candidate 不自动确认；confirm 后才能 dump。
- dump/rebuild/verify 必须真实推进对应 phase。

### M6

- not_dotnet、CLR hint、pure managed、mixed mode 均有 fixture。
- malformed streams/tables/index/method body 不崩溃、不越界、不返回虚假完整结果。
- de4dot/NRS 仅对已验证 CLR 调用；输入 SHA 前后不变。
- stdout/stderr 超限、artifact 超限、timeout、非零退出、missing/ambiguous output 全部 fail closed 并删除 partial。
- `dotnet.verify` 拒绝另一个 session 的 artifact。
- 若 M5 .NET route 宣称闭环，deobfuscate/NRS output 必须进入 M5 ledger 并推进 verified/reanalyzed（按产品定义）。

外部 CLI 测试必须使用无害、授权 fixture，不下载或执行来源不明工具包样本。

## 10. 完整套件与 Doctor

聚焦 Gate 稳定后再执行完整套件。避免多个 debugger 验收并发互扰。

最终至少分列：

- unit：`N passed, M failed, K skipped`；
- integration：同上；
- IDA Gate；
- x86 x64dbg Gate；
- x64 x64dbg Gate；
- M1/M4/M6 专项 Gate（如本轮范围需要）；
- Doctor strict `ready` 和每个 optional capability。

Doctor `ready=true` 只证明 Doctor 当前定义的依赖准备好，不自动证明功能闭环。Doctor probe 对错误 executable 的 false positive 也需单独审查。

## 11. 失败归因纪律

先判断失败在哪层：

- 包装命令/quoting/env 展开：该轮无效，不算产品失败或通过。
- 测试脚本违反已定义协议（例如重复 hello）：测试缺陷，但被阻断的产品路径仍是“未验”。
- fixture 不形成稳定状态：fixture/harness 缺陷；不要改产品迎合错误同步原语。
- 双架构一致暴露竞态：优先审查共享客户端/service 状态机。
- native 后置条件已成立但命令报“not found”：只有通过列表复核目标确实不存在后才能幂等成功。
- 单独通过、按完整顺序失败：调查资源泄漏、事件 cursor、命令队列和顺序依赖，不把它归因于机器抖动。

如测试失败，报告实际输出；不要把“预计修复后会通过”写成通过。

## 12. 残留和最终记录

- 被动检查本项目绝对路径关联的 headless/fixture/IDA worker 进程。
- 只清理本项目创建且可明确识别的临时目录；不触碰其他 Python/MCP/调试任务。
- 最终 README/ROADMAP 数字只采用最后一次有效完整输出。
- 如果代码在测试后又变更，旧结果失去“当前代码最终基线”资格，必须标注覆盖的 commit/hash/文件时间或重跑。
