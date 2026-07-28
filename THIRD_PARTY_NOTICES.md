# Third-party notices

No third-party source has been copied into the main implementation yet. The
repositories under `upstream/` are research checkouts and are excluded from
release packages. Their locked revisions and licenses are listed in
`upstream.lock.json`.

When code is adapted, the relevant copyright notice, license, source commit,
and local modifications must be added here before release.

## Optional Detect It Easy adapter

The detection adapter can invoke a user-installed official Detect It Easy
`diec` executable. The reference source is `horsicq/DIE-engine` (MIT), tag
`3.21`, commit `72947a0c71dc741165411d63c01bfca79809513e`; its
`horsicq/Detect-It-Easy` signature submodule is locked separately in
`upstream.lock.json`. No DIE source, database, binary, or Qt runtime is copied
or bundled by this project. Users must obtain and license the external CLI
independently and configure `HEADLESS_RE_DIEC`.

## Optional official UPX adapter

The unpack adapter can invoke a user-installed official UPX CLI for whitelisted
`upx -t` / `upx -d -o <out> <in>` operations only. The reference source is
`upx/upx` (GPL-2.0-or-later with the UPX special exception), tag `v5.2.0`,
commit `034b6d0d81c53998c07ad6f34bfead6f5c5445ce`. No UPX source or binary is
copied or bundled; configure `HEADLESS_RE_UPX`. Modified/cracked UPX builds from
toolkits must not be treated as the official adapter.

## Optional de4dotEx adapter (M6)

The .NET deobfuscate adapter can invoke a user-installed GPL-3.0
`de4dot` CLI from the maintained fork `GDATAAdvancedAnalytics/de4dotEx`,
tag `3.2.4`, commit `a5fd177fdf2ee0304485eba3afb14e008f421697`. Release
asset `de4dotEx-3.2.4-net48.zip` SHA-256
`34F4E6DF6392620A9C6D97B5871E527FF3AB7493CA40F790DF88E1FCF2CBE8AC`.
No de4dot source or binary is bundled; configure `HEADLESS_RE_DE4DOT`.
Toolkit samples (`Test.Rename.exe`, cleaned outputs, PDBs) must not be
copied into the repository or release packages.

## Optional NETReactorSlayer adapter (M6)

The optional Reactor unpack adapter can invoke a user-installed GPL-3.0
`NETReactorSlayer` CLI from `SychicBoy/NETReactorSlayer`, tag `v6.4.0.0`,
commit `ea8e5c80136ae3eebc600daccb97f872fafd874e`. Release asset
`NETReactorSlayer-windows.zip` SHA-256
`4E0EAA4C0B33DA23C792ABC4F097478A772700939945C8C3E7956A09C32B7B6C`.
No binary is bundled; configure `HEADLESS_RE_NET_REACTOR_SLAYER`. Authorized
samples only; `claims_universal_unpack=false`.

## Optional Exeinfo PE second opinion

Exeinfo PE (A.S.L Soft) may be invoked as an optional **second-opinion**
detector via a user-installed binary. Official repository
`ExeinfoASL/ASL`, tag `v0.0.9.7`, commit
`bc35b48908ab33800653c4477bb40dc63af5005b`. Release asset
`exeinfope.zip` SHA-256
`812e210f834a60845b2cc11136817a244dd9a0137994d33d9f2cd2ab662dc797`.
License: **Freeware (non-OSI)** — users must obtain it independently;
this project does **not** bundle, redistribute, or ship Exeinfo PE in
portable/MSI packages. Toolkit builds (e.g. `Exeinfope 0.0.9.3.exe`) are
behavior-reference only and must not be copied into the source tree or
release artifacts.

Configure `HEADLESS_RE_EXEINFOPE` and call `detect.scan(use_exeinfope=true)`.
The adapter uses a fixed argv whitelist
(`<file>* /s /log:<session-artifact>`), refuses visible analyzer UI
(`TForm1` / modal forms), and never claims universal unpack. See
`docs/ADR_EXEINFOPE.md`.

## VMPDump / VMPx64Dump (M7 optional adapter; not bundled)

Upstream: [0xnobody/vmpdump](https://github.com/0xnobody/vmpdump) (GPL-3.0).
Dynamic VMP dumper + import fixer for VMProtect 3.x **x64**, powered by VTIL.

The optional adapter `src/headless_re_mcp/unpack/vmp_dumper.py` invokes a
**user-configured** executable via `HEADLESS_RE_VMP_DUMPER` using the upstream
process CLI (`<exe> <pid> <module> [-ep=] [-disable-reloc]`). No VMPDump
source or toolkit binary is copied into this repository or portable/MSI
packages.

The toolkit file
`F:\学技术网工具包V2.0\Tools\Unpacker\vmp64dumper\VMPx64Dump3.x-3.5.exe`
embeds PDB paths under `...\GitHub\vmpdump\...` and is treated as a local
build of that project for operator configuration only.

## Scylla (M4 reference lock; no source copied)

Import reconstruction research is locked against the official
`NtQuery/Scylla` repository (GPL-3.0), commit
`e87fd578a3fa0e68b873dcc98951788f3a40e055` (nearest release tag reference
`v0.9.8` → `db5eb01d99bdb9c992328c10bc821f5bb45b2a73`). The
`x64dbg/Scylla` fork (`vs13`, commit
`aa89026b9e469b0c4b3d2bedb464dd7ab521cd6e`) is locked only as a secondary
patch/build reference.

**No Scylla source, GUI binary, DLL, or toolkit Chinese build
(`Scylla_*_CN.exe`) has been copied, adapted, linked, or bundled yet.**
Architecture and license decisions are recorded in `docs/ADR_M4_SCYLLA.md`.
When M4.2+ selectively adapts Scylla algorithms into
`native/xdbg-headless-rpc` or the Python PE rebuild path, this section must
gain per-file copyright, commit, and local-modification notices before
release.
## Bundled x64dbg headless under external/ (optional in portable)

Portable / handoff packages **may** include self-built x64dbg headless
Release trees under `external/x64dbg-{x86,x64}/` and `runtime/x64dbg-{x86,x64}/`.
These are GPL-3.0-derived build outputs of the pinned upstream revision in
`upstream.lock.json`. Ship the **full Release directory** (Qt/TitanEngine DLLs
included), not a lone `headless.exe`.

**IDA Pro, idalib, Hex-Rays decompiler, and license files must never be copied
into `external/`, portable ZIPs, or MSI packages.** Users supply a licensed
local install via `HEADLESS_RE_IDA_HOME`.

Optional detectors/unpackers (DIE, UPX, de4dot, Exeinfo, VMPDump, …) remain
user-provided; see sections below. `external/optional/` is a local-only
placeholder and is not part of the default ship set.

