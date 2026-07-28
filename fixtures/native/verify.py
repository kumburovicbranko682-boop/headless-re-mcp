from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.session import detect_pe_architecture

_EXPECTED_SUBSYSTEMS = {
    "console_fixture.exe": 3,
    "headless_fixture.exe": 2,
    "gui_fixture.exe": 2,
}


def _pe_subsystem(path: Path) -> int:
    image = path.read_bytes()
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_header = pe_offset + 24
    return int.from_bytes(image[optional_header + 68 : optional_header + 70], "little")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate native fixture PE architectures")
    parser.add_argument("--architecture", type=Architecture, required=True)
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args(argv)

    mismatches = {
        str(path): actual.value
        for path in args.binaries
        if (actual := detect_pe_architecture(path)) != args.architecture
    }
    if mismatches:
        parser.error(f"expected {args.architecture.value}, got {mismatches}")

    subsystem_mismatches = {
        str(path): actual
        for path in args.binaries
        if (
            (expected := _EXPECTED_SUBSYSTEMS.get(path.name.casefold())) is not None
            and (actual := _pe_subsystem(path)) != expected
        )
    }
    if subsystem_mismatches:
        parser.error(f"unexpected PE subsystems: {subsystem_mismatches}")

    print(f"{args.architecture.value}: {len(args.binaries)} fixtures verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())