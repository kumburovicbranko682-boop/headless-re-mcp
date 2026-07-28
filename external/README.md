# external/ — 外部运行时与可选工具位

本目录是 **本机/发布包放置外部二进制** 的统一入口，与源码、`artifacts/`（构建缓存）分离。

## 打包策略（硬边界）

| 类别 | 是否可放入本目录并随包分发 | 说明 |
|---|---|---|
| **x64dbg headless Release 树** | **可以** | 基于 GPL-3.0 自建产物；需整棵 `Release`（含 Qt / TitanEngine 等 DLL），不是单独一个 exe |
| **IDA / idalib / Hex-Rays** | **禁止** | 专有软件；用户自备已授权安装，仅通过 `HEADLESS_RE_IDA_HOME` 指向 |
| DIE / UPX / de4dot / Exeinfo / VMPDump 等 | **默认不捆绑** | 可选适配器；放 `optional/` 仅供本机开发，不进 portable/MSI，见各 ADR |

权威声明见仓库根目录 `THIRD_PARTY_NOTICES.md`。

## 推荐布局

```text
external/
  README.md                 ← 本说明
  x64dbg-x64/               ← 整棵 Release 内容（含 headless.exe）
  x64dbg-x86/               ← 同上（x86）
  optional/                 ← 可选 CLI 占位（默认不随包）
    README.md
```

也接受：

- `external/x64dbg-x64/Release/headless.exe`
- 便携包内的 `runtime/x64dbg-{arch}/headless.exe`（由 `scripts/build_portable.ps1` 生成）

## 如何填充 x64dbg（可打包）

1. 先构建 headless（见 `native/xdbg-headless-rpc/README.md`），产物通常在：
   - `artifacts/x64dbg-x64/Release/`
   - `artifacts/x64dbg-x86/Release/`
2. 同步到本目录：

```powershell
pwsh -File scripts/sync_external_x64dbg.ps1
```

3. 确认：

```text
external/x64dbg-x64/headless.exe
external/x64dbg-x86/headless.exe
```

`Settings` 会自动发现上述路径（仍可用环境变量覆盖）：

- `HEADLESS_RE_X64DBG_HEADLESS_X64`
- `HEADLESS_RE_X64DBG_HEADLESS_X86`

## IDA（不可打包）

**不要**把 IDA 安装目录、`idalib.dll`、许可证或 Hex-Rays 插件拷进 `external/`。

正确做法：

1. 本机安装已授权的 IDA Pro 9.x
2. 运行官方 `py-activate-idalib.py`
3. 设置 `HEADLESS_RE_IDA_HOME` 或写入 `%APPDATA%\headless-re-mcp\config.json` 的 `ida_home`

Doctor 的 `ida_idalib` 探针只检查本机授权环境，从不期望仓库内出现 IDA 二进制。

## 可选工具（不随默认包）

见 `optional/README.md`。可配置环境变量示例：

| 工具 | 环境变量 |
|---|---|
| Detect It Easy CLI | `HEADLESS_RE_DIEC` |
| Exeinfo PE | `HEADLESS_RE_EXEINFOPE` |
| UPX | `HEADLESS_RE_UPX` |
| de4dotEx | `HEADLESS_RE_DE4DOT` |
| NETReactorSlayer | `HEADLESS_RE_NET_REACTOR_SLAYER` |
| VMPDump | `HEADLESS_RE_VMP_DUMPER` |
| Scylla | `HEADLESS_RE_SCYLLA` |
| Ghidra | `HEADLESS_RE_GHIDRA_HOME` |
| cdb | `HEADLESS_RE_CDB` |

能力声明：`claims_universal_unpack=false`。

## Web 监控台

`serve-web` 的「外部依赖」面板与首次向导会读取本目录发现结果；缺失项只提示，不会把 IDA 标成可打包组件。
