# 贡献指南

感谢你的兴趣。本仓库单维护者、公开历史短,贡献流程因此偏简单:小改动直接提 PR;
大改动(新工具域、新后端、改契约)请先开 issue 对齐方向,避免白做。

安全问题不走 issue/PR,见 [SECURITY.md](SECURITY.md)。

## 开发环境

完整栈只在 Windows 上可用(IDA idalib、x64dbg headless),但**日常开发不需要**:
lint、单元测试与 OpenAI 桥接导出在 Linux/macOS 上照常跑,CI 的 quality job
也只装 `.[test,dev,web]`,不装任何商业后端。

一个平台差异要知道:CI 的 quality job 跑在 **windows-latest**,`python -m mypy` 的
权威门也在那里(零错误)。在 Linux/macOS 上直接跑 mypy 会额外报出若干 **Windows 专属
stdlib 属性**的假阳性(`msvcrt.locking`/`get_last_error`、`ctypes.windll` 等)——这是
mypy 在非 Windows 上解析不到这些属性所致,不是真错误;同理少数单元测试是 Windows 专属,
在其它平台可能失败或跳过。判定类型是否真的干净,以 Windows 为准。

```bash
python -m pip install -e ".[test,dev,web]"
```

需要真机后端时按 [README「安装与构建」](README.md#安装与构建) 配置;
可选 CLI(UPX、DIE、jadx 等)缺失只降级,`doctor` 会逐项报告。

## 质量门

CI(`.github/workflows/ci.yml`)对每个 PR 跑下面这套,提交前请在本地过一遍:

```bash
python -m ruff check src tests fixtures openai_bridge.py
python -m mypy                          # strict;零错误以 Windows 为准(见上「平台差异」)
python -m compileall -q src
python -m pip check
python -m pytest tests/unit -q -rs      # -rs 列出每个 skip 的原因
```

改动 `webui/` 时,前端三件套加"提交产物必须同步":

```bash
cd webui
npm ci
npm run typecheck
npx vitest run
npm run build    # 产物直接写入 src/headless_re_mcp/web/spa,必须一并提交
```

CI 会断言提交的 SPA 与 `webui/src` 匹配,忘了重编会红。

覆盖率是**棘轮**:`pyproject.toml` 里的 `fail_under` 只升不降。
实际覆盖率涨了就把它抬上去,但永远不要为了转绿而调低它。

## 测试约定

### 目录与命名

- `tests/unit/`:不依赖任何商业后端,CI 每次全量跑。命名即契约:
  - `test_*_fields.py` —— 某工具**成功结果**的字段契约;
  - `test_*_schema.py` —— 某工具**输入 schema** 与参数校验;
  - `test_*_closed_session.py` —— 对已关闭/不存在会话返回结构化错误信封,而不是异常。
- `tests/integration/`:`*_gate.py` 需要真机后端,缺环境时会 `skip`。
  **skip 不等于 pass**——判断改动没破坏集成路径,要在配好后端的机器上看到 `passed`。
- 标记:`integration`(需本机后端)、`headless`(校验零分析器窗口)、
  `visible_desktop`(驱动真实窗口,与 `HEADLESS_RE_HIDDEN_DESKTOP=1` 互斥)。

### 全表面契约(改工具面必读)

有几条性质是**对全部工具批量强制**的,新工具不用单独接线,注册进 catalog 就会被覆盖;
反过来说,破坏这几条的改动无法绕过测试:

- `tests/unit/test_tool_fault_contract.py`:每个工具面对敌意输入必须返回 `ok/error`
  信封,任何未捕获异常都是失败;
- `tests/unit/test_write_policy.py` 等:每个工具在 `tools/catalog.py` 里显式声明
  只读/写,`local_full_access: false` 时写操作必须返回 `write_disabled`;
- `tests/unit/test_unattended_resource_bounds.py`:长驻状态(缓冲、缓存、脚本表)
  必须有界,会话关闭后不得有任何字典仍以其 id 为键。

### 加新工具的硬规矩

- 在 `tools/catalog.py` 注册并**显式声明读写分级**;工具数与读写计数变了,
  README/CHANGELOG 里的口径数字要跟着改;
- 不接受自由命令面:任何等价于 `dynamic.command` / `device.shell` / `web.evaluate`
  的"透传"工具都不会被合并——能力必须具名、参数必须校验(序列号、包名等走严格正则);
- PE 专属工具入口用 `require_pe()`,对非 PE 会话返回结构化 `target_mismatch`;
- 外部输入(口令、token)不得进入错误信封与日志。

### 硬约束(与功能同级)

分析器进程(IDA / x64dbg headless)顶层窗口必须为 0,`headless` 标记的测试守着这条;
目标程序 GUI 不受此限。

## 提交与 PR

- **小步提交**,每个 commit 一个逻辑改动;commit message 用完整句子说清
  "改了什么、为什么"(看 `git log` 就知道本仓库的风格——message 常常就是变更说明本身);
- 用户可见的改动在 `CHANGELOG.md` 的 `[Unreleased]` 一节记一条,归入
  `新增 / 变更 / 修复 / 依赖` 小节;
- PR 描述里写清测试证据:本地跑了哪些命令、结果如何;动了集成路径但没有对应
  后端时如实说明,不要把 skip 说成通过。

## 发布流程

版本号有四个必须一起动的落点,漏掉任何一个都有守卫拦截:

1. `pyproject.toml` 的 `version`;
2. `packaging/wix/Product.wxs` 的 `Product/@Version`(打包脚本校验它与 pyproject 一致,
   否则 MSI 的 `MajorUpgrade` 会失效);
3. README 首行横幅的 `（vX.Y.Z）`(`test_readme_catalog_consistency` 钉死它与 pyproject
   和运行时 `build_info()` 三者一致);
4. `CHANGELOG.md`:把 `## [Unreleased]` 改成 `## [X.Y.Z] - 日期`,底部补
   `[X.Y.Z]:` 发布链接,并把 `[Unreleased]:` 比较链接的基点移到新 tag。

步骤:main 全绿为前提;改完四处后**重装 editable 包再跑质量门**(版本一致性测试读的是
安装元数据,不重装它就用旧版本号比对);提交 `Release X.Y.Z` 并推上 main,等 CI 绿;
打附注 tag `vX.Y.Z`(tag 消息写发布摘要,惯例见 `git tag -n9`)并推送——release
workflow 会构建 MSI、做装-跑-卸往返验证,然后自动创建 GitHub Release 并附上安装包
与校验和。想只验打包路径不发布,用 release workflow 的 `workflow_dispatch` 空跑。

有配好真实 IDA / x64dbg 的机器时,发布前手动触发 `windows-integration` 的集成 gate
(需要 `[self-hosted, Windows, headless-re]` 标签的 runner);没有也不阻塞发布,
但 CHANGELOG 的「验证」小节不要声称集成 gate 通过。

## 许可证

GPL-3.0-only。提交贡献即表示你同意以同一许可证发布你的改动。
第三方工具(IDA、x64dbg 等)由用户自行获取与授权,永远不进仓库与依赖包。
