# ADR M6.4：.NET 分析后端形态（dnlib 评估）

- 状态：Accepted
- 日期：2026-07-24
- 相关：`docs/ROADMAP_TODO.md` §M6.4、`src/headless_re_mcp/dotnet/`

## 背景

M6 需要在不捆绑第三方 .NET 运行时/分析库的前提下，提供有界的类型/方法/字段/资源/字符串枚举、有限 IL 反汇编与弱引用查询，并与原生 IDA idalib 后端明确区分。

## 决策

1. **不嵌入 / 不捆绑 dnlib**（C# 库；Python 侧无稳定官方绑定，且会引入额外运行时与许可证分发复杂度）。
2. **采用 ECMA-335 有界 Python metadata walker**（扩展 `clr_inspect` / `dotnet_metadata`），仅解析 `#~`/`#-` 表与堆，设置 offset/limit 与输出上限。
3. **IL 反汇编为子集**：按 MethodDef RVA 读取 method body，仅解码常用 opcode；超限返回 `partial` 并可选写 artifact。
4. **xref / 调用关系为弱模型**：基于 MemberRef / MethodDef token 与 call 操作数的启发式，**不**宣称完整 callgraph。
5. **Capability 命名**：`dotnet_metadata`（非 `ida_idalib`）；结果始终 `claims_universal_unpack=false`。

## 后果

- 优点：无外部 CLR 宿主依赖；与 M6.1/M6.2 Gate 同栈；可单测。
- 代价：达不到 dnlib 级完整语义（generic、custom attr、完整 IL、精确 callgraph）。
- 后续若用户自行提供 dnlib/worker，可作为 **optional external** 再评估，不进入核心发行包。
