# x64dbg-x64（可随包）

将完整 **Release** 目录内容放到此处（与 `artifacts/x64dbg-x64/Release/` 同级结构），至少包含：

- `headless.exe`
- 同目录依赖 DLL（Qt、TitanEngine、asmjit 等）
- `platforms/`、`plugins/` 等 Qt 插件目录（若构建产物带有）

也可直接运行一键安装，由固定 Release 依赖包自动配置：

```powershell
python setup.py
```

**禁止**在此放置 IDA 相关文件。
