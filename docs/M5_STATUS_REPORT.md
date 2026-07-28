# M5 现状报告：通用脱壳编排

> 日期：2026-07-24  
> 口径：完成定义验收（unit）  
> 相关：`docs/ROADMAP_TODO.md` §M5、`tests/unit/test_m5_*.py`

---

## 1. 进度位置

| 里程碑 | 完成定义 |
|--------|----------|
| M1 Workflow | 已勾 |
| M2 Detect | 已勾 |
| M3 UPX | 已勾 |
| M4 Dump/IAT/PE | 已勾 |
| **M5 编排** | **本轮已勾** |
| M6 .NET 主路径 | 已勾；M6.4=有界 `dotnet_metadata`（非 dnlib，见 ADR） |
| M7+ | 未开验收 |

---

## 2. 结论

**M5 完成定义已通过。**  
编排工具齐全；路由覆盖 UPX→M3、.NET→M6（inspect）、原生/VM→M4；不伪造成功；cancel/timeout 显式 `safe_rollback=false`。

本轮补齐：去掉 `deferred_m6` 桩，`.NET` 路由真实调用 `dotnet.inspect`，`unpack.auto` 返回 `routed_m6`。

---

## 3. 验收结果

```text
tests/unit/test_m5_* + test_unpack_* + test_upx_fixtures
→ 41 passed
```

新增：`tests/unit/test_m5_dotnet_route.py`

---

## 4. 非完成定义保留项

- 安全回滚（cancel 不删产物、不 undo）
- 六类 OEP「持续信号订阅」（现为有界观测快照 + `score_oep`）
