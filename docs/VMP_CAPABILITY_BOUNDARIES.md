# VMProtect / 动态脱壳能力边界与产物命名

> 状态：Active（2026-07-24）  
> 相关：Acid burn.vmp 实战、`imports.scan`、`unpack.*`、M7 外部适配器 ADR

## 1. 明确不承诺

- `claims_universal_unpack` **恒为 false**。
- DIE / Exeinfo 漏检 VMP 时，可用 `force_route=bounded_dynamic` 或 PE `pe_vm_like` 启发式进入有界动态路径，**不等于**识别成功或可脱壳。
- `0x2090` 一类地址若仅为 Delphi InitTable / 首次 native CODE handoff，角色是 `first_native_handoff`，**不是**经典原始 `AddressOfEntryPoint`（虚拟化 EntryPoint 时尤其如此）。
- `imports.scan` 的 `consecutive` / `sparse` / `call_site` 仅为候选；必须 `unpack.iat.validate` 后才可 rebuild。
- Scylla / XVLKC / VMP dumper **不捆绑**；未配置时 Doctor 为 `missing`，**不挡**核心 `ready`。

## 2. OEP 角色（`role`）

| role | 含义 |
|------|------|
| `packed_ep` | 加壳后 PE EP / stub 入口 |
| `first_native_handoff` | 首次落到原生 CODE 的实用 handoff（启发式） |
| `confirmed` | 仅 `unpack.confirm_oep` 写出；调用方确认 |

## 3. 产物命名约定

| 阶段 | 命名片段 / artifact_kind | 说明 |
|------|--------------------------|------|
| dumped | `dumped-module-…` / `module_dump` | 原始内存映像 dump；**不等于** IAT 就绪 |
| iat-rebuilt | `iat-rebuilt-…` / `iat_rebuilt` | 仅当 `unpack.iat.validate`/`rebuild` gate 通过后升级 |
| runnable | `runnable_pe` | **仅** UI gate 匹配 **且** PE 结构校验 OK 后升级；工具不因“窗口可见”自动打 runnable |

`gate_stage_upgrade` / `assess_pause_quality`：`UI 可见 ≠ IAT ready`。`bounded_dynamic` 默认 `recoverability_hint=vm_coupled_dump_only`，直到 validate 报告 `iat_recoverable`。

## 3.1 recoverability 分流

| 值 | 含义 |
|----|------|
| `iat_recoverable` | 布局+stub 门禁允许尝试 IAT rebuild |
| `iat_insufficient` | 候选不足或 junk/IME，禁止 rebuild |
| `vm_coupled_dump_only` | E8→VMP stub 仍占主导；只保留 dump 观察 |

## 4. CallMcpTool hang（诊断）

实战中 `GetMcpTools` 正常但 `CallMcpTool` 长时间无返回时：

1. 重启 Cursor MCP / `headless-re-mcp` serve 进程。
2. 确认命名管道 headless 未僵死（doctor + 重新 `dynamic.open`）。
3. 大内存读已抬到 2 MiB；仍应避免在单次工具调用里串超长阻塞链路。
4. 本仓库后续可加客户端级 RPC 超时；当前以重启恢复为主。

## 5. Attach 降级

- `dynamic.attach` 默认接受 `paused|running`（GUI 友好）；需要停稳时再 `pause_after_attach=True`。
- Attach 失败时优先改 `dynamic.launch`；VMP 样本常需 launch + UI 等到业务窗口再 pause。
- `pass_system_breakpoint=True` 会在首次 pause 后自动 resume 一次，便于越过系统/入口断点；**不**等同于关闭所有入口断点引擎选项。

## 6. 验证 gate

`unpack.verify` 可选：

- `expect_window_title` / `expect_window_class`
- `ui_pid`（或会话内 debuggee pid）

未匹配时写入 `unfixed`，仍不宣称通用脱壳成功。`runnable` 阶段标签仅在 UI gate 匹配且 PE 结构校验通过时升级。

## 7. Acid burn.vmp 验收结论（2026-07-24）

证据：`artifacts/acid_vmp_iat/accept_2026-07-24.json`

- UI 可见且 `CODE` 已解密（`code_nonzero_ratio≈0.87`）时，`still_vm_stub_count=345`。
- 候选 IAT（含 `0x431678` IME、`0xf81000` half-sparse）全部 `confirmed=false`，`unpack.iat.rebuild` 返回 `iat_rebuild_blocked`。
- 门禁判定：`vm_coupled_dump_only`（IAT-only 无法产出独立可运行 PE）。
- `claims_universal_unpack=false`。
