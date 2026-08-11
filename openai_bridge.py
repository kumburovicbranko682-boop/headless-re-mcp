"""Project-root entry point: export MCP tools as OpenAI function-calling JSON.

Usage:
  python openai_bridge.py
  python openai_bridge.py --output openai_tools.json
  python openai_bridge.py --names-only

The implementation lives in ``headless_re_mcp.openai_bridge`` so the logic stays
importable from installed environments; this shim only fixes up ``sys.path`` for
a source checkout, mirroring ``start_web.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    src = Path(__file__).resolve().parent / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))


if __name__ == "__main__":
    _ensure_src_on_path()
    from headless_re_mcp.openai_bridge import main

    raise SystemExit(main())
