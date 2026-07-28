# M4 现状报告：运行时 Dump、IAT 搜索与 PE 重建

> 日期：2026-07-24（M4.5 清项更新）  
> 口径：完成定义 + M4.5 专项  
> 相关：`docs/ROADMAP_TODO.md` §M4、`tests/integration/test_unpack_live_gate.py`、`tests/integration/test_m4_unload_dump_gate.py`

---

## 1. 一句话结论

**M4 完成定义与 M4.5 专项均已勾选通过。**  
工具链覆盖 `dump → IAT 确认 → PE/IAT 重建 → verify(parser + DIE + IDA)`；另含事件丢失重同步、卸载竞态 dump、runtime_decrypt / predictable_imports fixture。

| 维度 | 状态 |
|------|------|
| 架构决策（M4.1） | 已完成 |
| Native / MCP 工具链 | 已挂上 |
| 完成定义 | **已通过** |
| M4.5 专项 | **已清** |

---

## 2. M4.5 清项摘要

1. **事件丢失重同步**：`dropped>0` → `snapshot_resync_required`；dump/IAT 返回 `event_gap_resync_required`；`modules.list` 清除  
2. **卸载竞态 dump**：dump 前后 `modules.list`；native `module_unloaded_during_dump`（需重编 headless 才走 mid-dump 路径）  
3. **Fixture**：`runtime_decrypt_fixture.dll`、`predictable_imports_fixture.exe`

测试：`test_m4_event_gap_and_unload` / `test_m4_predictable_imports_fixture` / `test_m4_runtime_decrypt_fixture` / `test_m4_unload_dump_gate`。

---

## 3. 仍刻意未做（非勾选阻塞）

| 项 | 说明 |
|----|------|
| dump 按 OptionalHeader.`SizeOfImage` | 仍用 `ModSizeFromAddr` |
| forwarded export 展开 | `unfixed` |
| PE checksum 重算 | `unfixed` |
| native `imports.rebuild` | 固定 `not_implemented` |

---

## 4. 里程碑位置

```text
M3 UPX          → 已收口
M4 + M4.5       → 完成定义与专项均已清（本报告）
M5 编排         → 完成定义已勾
M6 .NET         → 完成定义已勾；M6.4=有界 metadata（非 dnlib）
M7+             → 下一档
```
