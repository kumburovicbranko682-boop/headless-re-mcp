---
name: headless-re-accept
description: >-
  Gate-first acceptance for Headless RE-MCP (M8/M10 and ROADMAP checkboxes).
  Use when verifying milestones, updating ROADMAP_TODO.md, running Gates, or
  deciding whether a feature is done. Skip is never pass.
---

# Headless RE-MCP 验收（Gate-first）

## 硬纪律

1. **单元绿 ≠ 里程碑完成**。完成定义以真机 Gate **PASSED** 为准。
2. **`pytest.skip` 不算通过**。缺 env / 缺 fixture / 缺后端时必须写明原因，不得勾 ROADMAP。
3. **只勾有实测证据的项**。证据：Gate 文件名、命令、日期、关键断言（analyzer 零窗口 / PID 边界等）。
4. **分析器窗口必须为 0**（IDA / x64dbg headless）。目标程序（debuggee）窗口允许存在。
5. **UI 只能碰 debuggee PID**（及显式授权的子进程 PID）；禁止 headless / MCP host。

## 环境速查

| 用途 | 变量 / 路径 |
|------|-------------|
| IDA Gate 样本 | `HEADLESS_RE_IDA_GATE_BINARY` 或 `artifacts/fixtures-x64/headless_fixture.exe` |
| x64dbg headless x64 | `HEADLESS_RE_X64DBG_HEADLESS_X64` 或 `artifacts/x64dbg-x64/Release/headless.exe` |
| x64dbg headless x86 | `HEADLESS_RE_X64DBG_HEADLESS_X86` 或 `artifacts/x64dbg-x86/Release/headless.exe` |
| GUI fixture | `artifacts/fixtures-{x86,x64}/gui_fixture.exe` |
| PYTHONPATH | `E:\x64dbgmcp\src`（或已 editable install） |

建议产物目录：`artifacts/_accept_*.txt|json`（自行重定向 pytest/doctor 输出）。

## 里程碑检查表

### M8.1 静态只读（已有 Gate）

```powershell
$env:PYTHONPATH='E:\x64dbgmcp\src'
$env:HEADLESS_RE_IDA_GATE_BINARY='E:\x64dbgmcp\artifacts\fixtures-x64\headless_fixture.exe'
python -m pytest tests/integration/test_m8_static_batch1_gate.py -vv --tb=short
```

- 期望：**1 passed**（非 skip）。
- ROADMAP：`docs/ROADMAP_TODO.md` §M8.1 查询项。
- **M8.2 写库仍未验收**（name.set / patch 等保持未勾）。

### M10.1 PID 边界 + `ui.windows.list`（本竖切）

```powershell
$env:PYTHONPATH='E:\x64dbgmcp\src'
$env:HEADLESS_RE_X64DBG_HEADLESS_X64='E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe'
$env:HEADLESS_RE_X64DBG_HEADLESS_X86='E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe'
python -m pytest tests/integration/test_m10_ui_pid_gate.py -vv --tb=short
```

- 期望：**2 passed**（x64 + x86，非 skip）。
- 断言要点：
  - `dynamic.state` 含 `debuggee_pid` / `debugger_pid`，且二者不等。
  - 无 debuggee 时 `ui.windows.list` → `invalid_state`。
  - 命中 `HeadlessReFixtureWindow`；每个窗口 `pid == debuggee_pid`。
  - `allow_child_pids` 含 debugger/host → `permission_denied`。
- ROADMAP 可勾（仅在 Gate 绿后）：
  - M10.1：从 session 取 debuggee PID；枚举并严格过滤目标 PID；禁止操作分析器/MCP 窗口（最小实现：blocked debugger+host）。
  - M10.2：仅 `ui.windows.list`。
- **未验收**：`ui.click` / `ui.key` / UIA / OCR / `SendInput` / `ui.drive_to_*`。

### M10.2 Win32 交互（tree/resolve/click/text/key/invoke/wait）

```powershell
$env:PYTHONPATH='E:\x64dbgmcp\src'
$env:HEADLESS_RE_X64DBG_HEADLESS_X64='E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe'
$env:HEADLESS_RE_X64DBG_HEADLESS_X86='E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe'
python -m pytest tests/integration/test_m10_ui_interact_gate.py -vv --tb=short
```

- 期望：**2 passed**（gui_fixture Transform：set text → click → title `result N`；另断言 `ui.screenshot` BMP + PID 边界）。
- **未验收**：UIA、OCR、`SendInput`、`ui.drive_to_*`（drive 见 M10.3）。

### M5 真机全编排

```powershell
$env:PYTHONPATH='E:\x64dbgmcp\src'
$env:HEADLESS_RE_UPX='E:\x64dbgmcp\artifacts\tools\upx-5.2.0\upx.exe'
$env:HEADLESS_RE_DIEC='E:\x64dbgmcp\artifacts\tools\die_win64_portable_3.21_x64\die\diec.exe'
$env:HEADLESS_RE_IDA_HOME='C:\Program Files\IDA Professional 9.3'
$env:HEADLESS_RE_X64DBG_HEADLESS_X64='E:\x64dbgmcp\artifacts\x64dbg-x64\Release\headless.exe'
$env:HEADLESS_RE_X64DBG_HEADLESS_X86='E:\x64dbgmcp\artifacts\x64dbg-x86\Release\headless.exe'
python -m pytest tests/integration/test_m5_unpack_live_gate.py -vv --tb=short
```

- 期望：**4 passed**（UPX x86/x64 + dynamic x86/x64）。
- 断言要点：`unpack.start→verified`（UPX）；动态 `confirm_oep(auto_dump)→dumped→imports_rebuilt→verified/reanalyzed`；timeline/state 落盘；`unpack_already_active` / `replace=True`；cancel `safe_rollback=false`；`claims_universal_unpack=false`；`analyzer_windows == []`。

### 暂缓（不要提前勾）

| 块 | 说明 |
|----|------|
| M8.2 | IDA 写库 |
| M9.1 大部 | threads/stack/trace/patches/硬件断点等（`memory.regions` 等已有能力另证） |
| M10.2 剩余 | UIA / OCR / SendInput（screenshot 已验收） |
| M10.3 | `ui.drive_to_event` / `ui.drive_to_breakpoint` |

## 勾选 ROADMAP 时的写法

在对应节落后追加一行证据注释，例如：

> **M10.1（YYYY-MM-DD）**：`test_m10_ui_pid_gate.py` → 2 passed；debuggee_pid≠debugger_pid；`ui.windows.list` PID 过滤。

## 相关单测（辅助，不替代 Gate）

```powershell
python -m pytest tests/unit/test_windows_pid.py tests/unit/test_dynamic_service.py::test_dynamic_state_exposes_debuggee_and_debugger_pids tests/unit/test_dynamic_service.py::test_ui_windows_list_pid_boundary tests/unit/test_mcp_server.py -q
```

## 扩展本 skill

用户可继续补充：M4/M5/M6 Gate 命令块、Doctor `--strict` 清单、最终产品验收定义逐条映射。保持「命令可复制 + skip≠pass + 证据日期」格式即可。
