# Headless RE-MCP

Windows 上的无分析器窗口逆向 MCP（v0.1.0 早期原型）。把 IDA `idalib` 静态分析与 x64dbg `headless.exe` 动态调试收成受限语义工具，供 Cursor 等 MCP 客户端调用；不开放任意调试器命令，也不弹 IDA/x64dbg GUI。

**现状口径（偏保守）：** 公开仓库历史很短、单维护者，适合隔离环境实验，不建议当作生产级核心依赖。缺后端时集成测试会 `skip`，`skip ≠ pass`。

## 依赖

| 依赖 | 说明 |
|------|------|
| Windows 10/11 x64 + Python 3.11+ | 仅 Windows |
| IDA Professional 9.x（含 idalib） | 商业软件，本仓库不捆绑 |
| x64dbg `headless.exe`（x86/x64） | 可从 [deps Release](https://github.com/kumburovicbranko682-boop/headless-re-mcp/releases/tag/v0.1.0-deps) 取，或本地构建 |
| 可选 CLI | UPX / DIE `diec` / de4dot / cdb 等：用户自备，缺失则降级 |

```powershell
powershell -File .\scripts\build_deps_bundle.ps1
# -> artifacts/release/deps-bundle/headless-re-mcp-win.x64.zip
```

解压后执行 `activate_deps.ps1`，再设置 `HEADLESS_RE_IDA_HOME`。

## 快速开始

```powershell
cd <repo-root>
python -m pip install -U pip
python first_setup.py              # 终端问答，生成本机 MCP JSON
python first_setup.py --gui        # 可选 PySide6 原生壳（无 WebView）
python -m headless_re_mcp doctor --json --strict
python -m headless_re_mcp serve
```

`first_setup.py` 会校验 IDA / headless 路径，写入用户 `config.json`，并可选生成 `.cursor/mcp.json`（本机文件，已 gitignore）。

```powershell
python -m headless_re_mcp serve-web   # 仅 loopback + 本地 token
python start_web.py                   # 监控台（系统浏览器，非内嵌）
```

## 能力概览

同一会话可同时附着 IDA 与 x64dbg；支持主模块与显式模块的 `preferred VA ↔ RVA ↔ runtime VA` 换算、真实插件回调事件流（原生 1024 槽环形缓冲 + 会话级持久化 drain/重放；仅当 drain 也未能赶上覆盖窗口时才 `unrecovered_gap`）、以及 workflow 导航/断点意图。

主要工具面（节选）：

- 会话：`session.create/get/list/close`
- 静态：`static.open/functions/strings/decompile` 等
- 动态：`dynamic.open/state/events/wait/launch/attach/stop/pause/resume`、单步、寄存器/内存、模块与断点
- 地址：`sync.*`、`modules.list/resolve`
- Workflow：`workflow.*`
- 检测/脱壳（可选外部 CLI）：`detect.*`、`unpack.*`（非通杀承诺；`claims_universal_unpack=false`）
- 目标 UI（有界）：Win32 交互与截图；UIA/OCR/SendInput 为实验路径，勿默认依赖

动态写操作仅接受明确参数与白名单寄存器；无 `dynamic.command`。

## 仓库结构

```text
src/headless_re_mcp/   # Python 包与 MCP 服务
tests/                 # unit / integration / gate
native/                # x64dbg headless RPC
fixtures/              # 无害测试样本
scripts/               # 构建、同步、打包
packaging/             # WiX 等
external/              # 本机大型依赖占位（二进制多半 gitignore）
upstream/              # 本地上游 checkout（gitignore）
artifacts/             # 本地构建产物（gitignore）
```

根目录元数据：`pyproject.toml`、`README.md`、`first_setup.py`、`start_web.py`、`upstream.lock.json`、`LICENSE`。

上游不进 Git：复制 `.cursor/mcp.json.example` 或跑 `first_setup.py`；拉取锁定上游：

```powershell
powershell -File .\scripts\sync_upstream.ps1
powershell -File .\scripts\sync_upstream.ps1 -Name x64dbg
```

## 安装与构建

```powershell
python -m pip install -e ".[dev,ida,pe,web]"

powershell -File .\fixtures\native\build.ps1 -Architecture all

powershell -File .\native\xdbg-headless-rpc\build.ps1 `
  -Architecture all -BuildParallelism 2 -RunGate
```

`headless.exe` 必须保留完整 `Release` 目录（同目录 DLL / Qt / TitanEngine）。

```powershell
$env:HEADLESS_RE_X64DBG_HEADLESS_X86 = "$PWD\artifacts\x64dbg-x86\Release\headless.exe"
$env:HEADLESS_RE_X64DBG_HEADLESS_X64 = "$PWD\artifacts\x64dbg-x64\Release\headless.exe"
$env:HEADLESS_RE_DIEC = "C:\path\to\diec.exe"   # 可选
$env:HEADLESS_RE_UPX  = "C:\path\to\upx.exe"    # 可选
```

## 验收

先跑零窗口 Gate，再按需跑 pytest。集成 Gate 依赖本机后端；缺环境出现 `skip` 时不能当通过。

```powershell
python -m headless_re_mcp gate-xdbg --architecture x86 --timeout 60
python -m headless_re_mcp gate-xdbg --architecture x64 --timeout 60

python -m ruff check src tests fixtures
python -m mypy
python -m compileall -q src tests
python -m pip check
python -m pytest tests/unit -q
python -m headless_re_mcp doctor --json --strict
```

硬约束：分析器进程（IDA / x64dbg headless）顶层窗口必须为 0；目标程序 GUI 不受此限。

## 范围与风险

已有较完整的静态查询、动态调试闭环、事件流、地址同步、workflow，以及 dump / IAT / UPX 等脱壳相关路径的代码与部分真机 Gate——但整体仍是 **v0.1 原型**：公开提交少、文档与证据可能滞后，可选后端（r2/Ghidra/Frida/cdb）与 UI 自动化成熟度参差。

不适合：跨平台、无 IDA 授权、需要稳定长期 SLA 的生产工作流。  
适合：已有 Windows + IDA 9.x，想在隔离环境试 MCP 驱动的逆向辅助。

仅分析你拥有或获明确授权的样本。本地服务含写寄存器/内存能力，勿对不可信代理暴露，勿在未隔离环境处理未知样本。

## License

GPL-3.0-only。见根目录 `LICENSE`。第三方工具由用户自行获取与授权；上游修订锁定见 `upstream.lock.json`。
