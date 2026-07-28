# ADR：Exeinfo PE 可选第二查壳源

> 状态：**Accepted（受限接入）**（2026-07-24）  
> 范围：将 Exeinfo PE 作为 `detect.scan` 的 optional second opinion adapter  
> 相关：`docs/ROADMAP_TODO.md` §M2.3、`src/headless_re_mcp/detection/exeinfope.py`、`artifacts/exeinfope-probe/`、`upstream.lock.json`

## 1. 背景

ROADMAP M2.3：Exeinfo PE **仅作为结果交叉验证，不随项目分发**。在 DIE（`diec`）之外提供用户自备的第二意见，写入统一模型（`DetectionFinding` / `source=exeinfope`），**不**替换 DIE、**不**合并为单一权威结论。

工具包路径仅行为参考：

```text
F:\学技术网工具包V2.0\Tools\PE\Exeinfo\Exeinfope 0.0.9.3.exe
```

| 角色 | 位置 | 锁定点 |
|------|------|--------|
| 官方仓库 | https://github.com/ExeinfoASL/ASL | tag `v0.0.9.7` → `bc35b48908ab33800653c4477bb40dc63af5005b` |
| 官方 release | `exeinfope.zip` | SHA-256 `812e210f834a60845b2cc11136817a244dd9a0137994d33d9f2cd2ab662dc797` |
| 行为参考 | 工具包 0.0.9.3 | **非**发行来源 |

许可：Freeware（非 OSI）。只允许用户自备 + `HEADLESS_RE_EXEINFOPE`。

## 2. 隔离探测与窗口策略

探测原始数据：`artifacts/exeinfope-probe/`。

| 场景 | 结果 |
|------|------|
| `/?` | 弹 GUI；不可用于 Doctor |
| `<file> /s /log:`（无 `*`） | 易卡 Auto-close；不可用 |
| `<file>* /s /log:` | rc=0、写出可解析 log；Delphi 窗体对象仍存在 |

复测（`IsWindowVisible`）：

- `/s` 下 `TForm1` / Multfile / Help 等多为**不可见**；
- 仅短暂出现可见 `TApplication`（如 `BIN ... Please wait`）。

**产品策略（本 ADR）：**

1. argv 白名单：`[<exe>, <resolved-input>*, /s, /log:<artifact>]`（无 shell、无 `/un7zip`）。
2. 监视进程顶层窗口；若 **可见** 且 class ∈ `{TForm1, TMessageForm, TMultiS_GUI, …}` → `gui_window_detected` 失败，Doctor=`blocked`，不得 ready。
3. 允许短暂可见的 `TApplication` 等待标题；不可见 Delphi 窗体不单独判失败（与“禁止窗口自动化隐藏主界面冒充 headless”区分：我们不 `ShowWindow` 藏窗，只拒绝可见分析器 UI）。
4. 无 JSON 协议 → best-effort 解析 `/log` 文本；`confidence=0.55`；格式变更时结构化失败，不假装高精度。
5. `use_exeinfope` 默认 **false**；仅调用方显式打开且已配置时运行。
6. `claims_universal_unpack=false`；与 builtin / diec **并列**。

## 3. 决策

**接入** `detection/exeinfope.py` + Settings/Doctor/`detect.scan`（MCP 同参）。

- 不捆绑、不进 portable/MSI。
- 不集成解包/Inno/7z 副作用功能。
- 不与 DIE 合并结论。

## 4. 配置与验收

- 环境变量 / config：`HEADLESS_RE_EXEINFOPE` → `Settings.exeinfope`
- Doctor：未配置 → `missing`（不挡核心 ready）；配置且静默扫描产出 findings → `ready`；可见主窗 → `blocked`
- MCP：`detect.scan(use_exeinfope=false)`（默认关）
- 真机 Gate：`tests/integration/test_exeinfope_gate.py`（需配置或本机工具包参考路径）

## 5. 剩余风险

- 仍是 GUI 程序写 log，不是原生 headless CLI；未来官方若提供真 console 应切换。
- Unicode 路径可能触发消息框 → 会被可见窗检测拦住。
- log 文本无稳定 schema；交叉验证勿当权威。
- 短暂 `TApplication` 等待窗可能在任务栏闪一下（可接受残余 UX，已文档化）。
