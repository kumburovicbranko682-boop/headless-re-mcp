# M2 / M3 验收矩阵与缺口清单

> 盘点日期：2026-07-23  
> 对照：`docs/ROADMAP_TODO.md` §M2.4 / §M3.3  
> 范围：质量验收（不实现 M3 业务合入；官方 UPX 下载/集成为 CH-1 范围）  
> 证据命令：`python -m pytest tests/unit/test_detection_die.py tests/unit/test_detection_pe.py tests/unit/test_detection_service.py tests/unit/test_doctor.py -q`

## 总览

| 里程碑 | 实现水位 | 测试水位 | 验收结论 |
|--------|----------|----------|----------|
| M2 查壳 / 检测 | DIE adapter + PE 启发式 + Doctor `probe_die` + MCP `detect.*` / `packer.classify` 已落地 | 单测较完整；1 处测试缺陷已修 | **条件通过**（缺官方 UPX 打包 fixture、缺「检测不启动目标」显式断言） |
| M3 官方 UPX 脱壳 | `src/headless_re_mcp/unpack/upx.py` / `recommend.py` 有 adapter 草稿 | **无** `tests/unit/test_upx*` / `test_unpack*`；无 MCP `unpack.upx.*`；无 `HEADLESS_RE_UPX` / Doctor UPX probe；`upstream.lock.json` 无 UPX | **阻塞 / 未验收**（依赖 CH-1 M3 合入） |

---

## M2.4 验收矩阵

| ID | 验收项 | 状态 | 证据 / 说明 |
|----|--------|------|-------------|
| M2.4-01 | 未加壳 x86/x64 fixture | **通过** | `test_detection_pe.py::test_compiled_fixture_if_present` 使用 `artifacts/fixtures-x86|x64/console_fixture.exe`；合成 PE 覆盖见 `test_scan_synthetic_x86_and_x64_*` |
| M2.4-02 | 官方 UPX 打包的 x86/x64 fixture | **未测 / 阻塞** | 仓库无 `*upx*` packed fixture；`fixtures/` 仅 native 源码；`artifacts/tools/upx-5.2.0/` 目录存在但为空；`upstream.lock.json` 无 UPX 条目（CH-1） |
| M2.4-03 | .NET fixture | **部分通过** | 合成 PE：`test_imports_tls_entropy_rwx_and_dotnet_findings`；无独立编译 .NET 样本 fixture |
| M2.4-04 | overlay / TLS / 异常 section / 高 entropy 无害 fixture | **通过** | `test_imports_tls_*`、`test_overlay_*`、`test_entry_point_*`、entropy/RWX 同文件覆盖 |
| M2.4-05 | DIE 不存在时 capability unavailable，不影响核心 | **通过** | `test_detection_service_uses_builtin_fallback_when_die_is_missing`；`test_die_probe_is_optional_when_unconfigured`（`ProbeStatus.MISSING` + `HEADLESS_RE_DIEC` 提示） |
| M2.4-06 | DIE 超时 / 异常退出 / 无效 JSON / 超大输出 | **通过** | `test_detection_die.py`：`DieTimeoutError`、`DieProcessError`、`DieProtocolError`、`DieOutputLimitError`、`DieInputTooLargeError` |
| M2.4-07 | 检测操作不得启动目标程序 | **未测（实现侧静态满足）** | DIE 仅对 `diec` 起子进程且 argv 白名单；PE 扫描为纯解析。缺「对 sample.exe 不做 CreateProcess」的显式断言；仅有 oversized input 不 spawn diec |
| M2.4-08 | Doctor 报告 DIE 可用性与版本 | **通过** | `test_die_probe_verifies_version_and_json_interface`；无 JSON 能力时 `BLOCKED` |
| M2.4-09 | DIE 原始结果写入 artifact，MCP 返回有界摘要 | **通过** | `test_detection_service_merges_die_and_persists_raw_artifact`；`_write_die_artifact` → `{artifact_root}/detection/{session_id}/die-*.json`（临时文件 + `os.replace`） |
| M2.4-10 | `detect.explain` / `packer.classify` 非权威结论 | **通过（曾失败，已修测试）** | 原测试注入 `die_scanner` 但未配置 `settings.diec`，服务跳过 DIE → `finding_not_found`。已改为与 merge 测试一致提供 placeholder `diec` |

### M2 相关运行结果（修复后应全绿）

```text
tests/unit/test_detection_*.py + test_doctor.py
预期：全部通过
```

---

## M3.3 验收矩阵

| ID | 验收项 | 状态 | 证据 / 说明 |
|----|--------|------|-------------|
| M3.3-01 | CI/本地用官方 UPX 生成无害 x86 fixture | **未测 / 阻塞** | 无生成脚本、无 packed fixture；空目录 `artifacts/tools/upx-5.2.0/` 不能当作已集成 |
| M3.3-02 | 官方 UPX 生成无害 x64 fixture | **未测 / 阻塞** | 同上 |
| M3.3-03 | 正常解包与重新分析 | **未测 / 阻塞** | 无 `unpack.auto` 服务/MCP；无 IDA 重分析接线单测 |
| M3.3-04 | 修改头部 / 截断 / 非 UPX / 不支持版本 | **未测** | 无对应测试；adapter 仅有 `upx -t` / `upx -d -o` 白名单实现草稿 |
| M3.3-05 | 原始输入不得被修改 | **未测（实现有意图）** | `test_upx` / `unpack_upx` 前后校验 `input_sha256`；**无单测覆盖** |
| M3.3-06 | 所有输出位于会话 artifact 目录 | **未测 / 缺口** | adapter 接受调用方 `output_path`，**未**在 adapter/service 层强制 `artifact_root` 约束；MCP 层未暴露 |
| M3.3-07 | 魔改 UPX 不得伪造成功 | **未测 / 风险** | `recommend_unpack_route` 文案提示可能失败；`upx -t` 失败会抛错；缺负例 fixture 与端到端断言 |
| M3.3-08 | Doctor `HEADLESS_RE_UPX` / 版本探测 | **未测 / 阻塞** | `Settings` 无 `upx` 字段；`doctor.py` 无 `probe_upx`；lock 无 UPX |
| M3.3-09 | MCP `unpack.upx.test` / `unpack.upx.unpack` / `unpack.auto` | **未测 / 阻塞** | `mcp/server.py` 无 unpack 工具；`AnalysisService` 无 unpack 方法 |
| M3.3-10 | `unpack.recommend` 路由 | **部分实现 / 未测** | `recommend_unpack_route` 已存在；未挂 MCP/service；无单测 |

### M3 实现草稿已知缺陷（阻塞后续接线）

| 缺陷 | 位置 | 影响 |
|------|------|------|
| `suppress_os` 未定义 | `unpack/upx.py` `unpack_upx` | 调用 `unpack_upx` 会 `NameError`（应使用 `contextlib.suppress(OSError)` 或等价） |
| 无 UPX 单测文件 | `tests/unit/` | M3.3 全部无法自动验收 |
| 配置/Doctor/MCP 未接线 | `config.py` / `doctor.py` / `mcp/server.py` | 即使用户本机有 UPX，产品路径不可达 |

---

## 重点关注项对照

| 关注点 | 结论 |
|--------|------|
| DIE 缺失降级 | **通过** — source=`unavailable` + builtin 仍可用；Doctor=`MISSING` 且不挡核心 ready 门禁（DIE 为可选 probe） |
| 检测不启动目标 | **实现静态满足，测试缺口** — 建议补「spy CreateProcess/Popen 目标路径」断言 |
| 输入不被原地改写 | **M2 通过**（`input_changed`）；**M3 未测**（adapter 有 SHA 守卫但无测试；且 `unpack_upx` 当前不可运行） |
| artifact 目录约束 | **M2 DIE artifact 通过**；**M3 输出路径未强制会话目录** |
| 官方 UPX x86/x64 fixture | **未测 / 阻塞（CH-1）** |
| 魔改 UPX 不得伪造成功 | **未测**；需负例 + `upx -t` 失败路径端到端 |

---

## 失败项 / 已处理

| 项 | 处理 |
|----|------|
| `test_detection_explain_and_packer_classify_are_non_authoritative` 失败 | **已修测试**：补 placeholder `diec`，与 merge 测试一致。属测试缺陷，非 DIE 降级逻辑回归。 |

未改 M3 业务实现（越界禁止）。

---

## 残余风险

1. **M3 表面有代码、产品路径未通**：易误判「UPX 已可用」。验收应以 MCP/Doctor/fixture/绿测为准。  
2. **`unpack_upx` 的 `suppress_os` NameError**：一旦提前接线会直接崩。  
3. **空的 `artifacts/tools/upx-5.2.0/`**：可能造成「工具已下载」错觉。  
4. **artifact 路径信任调用方**：M3 adapter 不校验输出落在会话目录，存在写到任意路径的风险（待 service 层收口）。  
5. **魔改 UPX**：无负例时可能把「未覆盖」误当成「已拒绝伪造成功」。

---

## 建议修复顺序（不越界执行）

1. **CH-1**：锁定官方 UPX → `upstream.lock.json` + `HEADLESS_RE_UPX` + 填充/生成 x86/x64 packed fixture + Doctor `probe_upx`。  
2. **CH-1 / 实现**：修复 `unpack/upx.py` 的 `suppress_os`；补 `tests/unit/test_upx.py`（输入不变、输出 `-o`、超时/失败、非 UPX、`upx -t` 拒绝魔改）。  
3. **实现**：`AnalysisService` + MCP 暴露 `unpack.upx.test` / `unpack.upx.unpack` / `unpack.auto`，强制 `output_path` ∈ session artifact。  
4. **QA**：补「检测不启动目标」显式单测；补 .NET 编译 fixture（可选）；端到端：标准 UPX 成功 + 魔改失败不宣称成功。  
5. **回归**：本清单 M2 段保持绿；M3 段逐项把「未测/阻塞」改为「通过」后再勾 ROADMAP 完成定义。

---

## 可执行验收命令

```powershell
# M2 当前可跑
python -m pytest tests/unit/test_detection_die.py tests/unit/test_detection_pe.py tests/unit/test_detection_service.py tests/unit/test_doctor.py -q

# M3（合入后预期出现）
# python -m pytest tests/unit/test_upx.py tests/unit/test_unpack*.py -q
```

## 影响范围与回滚

- 本任务产出：`docs/QA_M2_M3_CHECKLIST.md`  
- 唯一代码改动：`tests/unit/test_detection_service.py`（补 `diec` placeholder）  
- 回滚：还原该测试文件即可；清单可删除不影响运行时  
