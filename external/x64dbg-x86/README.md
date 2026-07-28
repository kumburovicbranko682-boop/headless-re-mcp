# x64dbg-x86（可随包）

将完整 **Release** 目录内容放到此处（与 `artifacts/x64dbg-x86/Release/` 同级结构），至少包含：

- `headless.exe`
- 同目录依赖 DLL 与 Qt 插件目录

同步命令：

```powershell
pwsh -File scripts/sync_external_x64dbg.ps1
```

**禁止**在此放置 IDA 相关文件。
