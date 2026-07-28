# optional/ — 可选外部 CLI（默认不打包）

此目录仅作**本机开发占位**。默认 portable / MSI **不会**复制这里的内容。

| 子目录建议名 | 用途 | 许可注意 |
|---|---|---|
| `die/` | Detect It Easy `diec` | MIT 源；二进制自备，不进默认包 |
| `upx/` | 官方 UPX | GPL-2.0+；不捆绑 |
| `de4dot/` | de4dotEx | GPL-3.0；不捆绑 |
| `exeinfope/` | Exeinfo PE | Freeware（非 OSI）；**禁止**进源码树与发布包 |
| `vmpdump/` | VMPDump | GPL-3.0；自备，不拷工具包闭源壳 |

配置后用环境变量指向具体 exe（见上级 `README.md`）。
不要把工具包里许可不明的 GUI 壳直接丢进仓库。
