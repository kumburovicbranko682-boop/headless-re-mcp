# ADR: M7 optional external unpack adapters (XVLKC / VMPDump / Scylla)

> Status: **Accepted (limited)** — 2026-07-24  
> Scope: optional user-configured external unpack CLIs  
> Related: `docs/ROADMAP_TODO.md` §M7, `src/headless_re_mcp/unpack/{xvlkc,vmp_dumper,scylla}.py`

## 1. Background

Toolkit binaries under `F:\学技术网工具包V2.0\Tools\Unpacker\` are **reference locations only** and are **not** bundled into the core release.

| Toolkit path | Identity / license finding |
|--------------|----------------------------|
| `...\vmp64dumper\VMPx64Dump3.x-3.5.exe` | Binary embeds `...\GitHub\vmpdump\...` PDB paths and upstream CLI (`-ep=`, `-disable-reloc`). Matches **[0xnobody/vmpdump](https://github.com/0xnobody/vmpdump)** (**GPL-3.0**). **x64 / VMProtect 3.x** only. |
| `...\xvlk\base\xvlkc.exe` | **XVolkolak** — AUR/upstream license **custom**; author stated intent to open-source but no public OSS repo as of review. **Not** treated as open-source for vendoring. |
| Scylla CN GUI in toolkit | Not integrated; see `docs/ADR_M4_SCYLLA.md`. |

There are **no** VMP unpack **scripts** (`.py` / `.idc` / …) under the toolkit Unpacker tree—only binaries.

## 2. Decision

| Item | Policy |
|------|--------|
| Distribution | Do **not** bundle toolkit binaries or VMPDump builds into portable/MSI |
| Configuration | `HEADLESS_RE_XVLKC` / `HEADLESS_RE_VMP_DUMPER` / `HEADLESS_RE_SCYLLA` |
| VMPDump argv | Upstream only: `<exe> <pid> <module> [-ep=<hex>] [-disable-reloc]` |
| Windows | `CREATE_NO_WINDOW`; no ShowWindow GUI headless fake |
| Claims | `claims_universal_unpack=false`; `vm_restored` default false |
| Acid burn.vmp (x86) | VMPDump **cannot** target this sample (x64 tool) |

## 3. MCP / Doctor

- `unpack.external.probe` — probe configured paths (no target run)
- `unpack.vmp.dump` — requires configured exe **and** live debuggee PID
- Unconfigured → Doctor `missing` (does **not** block core `ready`)

## 4. Remaining risks

- Toolkit binary may differ from a clean upstream build; caller owns authorization.
- VMPDump import-fix success is heuristic from stdout; not a VM decompilation proof.
- XVLKC remains optional/user-owned under unclear license — adapter only, never vendored.
