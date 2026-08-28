"""Cross-validate the JS source-map facts against terser and Node's runtime.

describe_js reports what a sourceMappingURL actually delivers -- whether the
map resolves, and above all whether the original sources travel inside it
(sourcesContent), the difference between recovering the pre-minification
codebase outright and merely getting names and line numbers. The unit suite
proves that arithmetic over hand-written maps; this gate proves it over the
real thing, twice over:

* terser, a production minifier, generates the map -- so the JSON shape the
  reader parses is what real toolchains emit, not our own fixture dialect;
* node --enable-source-maps *consumes* the same map: a stack trace from the
  minified file must land on the original file and line. When the reader says
  resolved with mappings, Node maps the error to original.js:2; when the map
  is gone and the reader says resolved=False, Node falls back to minified
  coordinates. The reader's verdict and the runtime's behavior must move
  together, on the external and the inline (data: URI) forms both.

skip != pass: the gate skips, naming the missing piece, only when node or
terser is absent (CI installs both in the JS/WASM tool step).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.session import describe_js

# The throw sits on line 2 of the original source; the whole point of the gate
# is that Node's rewritten stack names this exact coordinate.
_ORIGINAL = """function boom() {
  throw new Error("mapped-error");
}
boom();
"""


def _terser(terser: str, args: list[str], cwd: Path) -> None:
    result = subprocess.run(
        [terser, *args], cwd=cwd, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _node_stack(node: str, script: Path) -> str:
    result = subprocess.run(
        [node, "--enable-source-maps", str(script)],
        cwd=script.parent,
        capture_output=True,
        text=True,
        timeout=120,
    )
    # The probe script throws by design; the stack is the artifact under test.
    assert result.returncode != 0
    return result.stderr


@pytest.mark.integration
def test_source_map_facts_move_with_nodes_runtime(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed — source-map gate not run (skip != pass)")
    terser = shutil.which("terser")
    if terser is None:
        pytest.skip("terser not installed — source-map gate not run (skip != pass)")

    original = tmp_path / "original.js"
    original.write_text(_ORIGINAL, encoding="utf-8")

    # External map, sources embedded: the reader must call it the full prize,
    # and Node must be able to walk the same map back to original.js line 2.
    _terser(
        terser,
        [
            "original.js", "-c", "-m",
            "--source-map", "includeSources=true,url='min.js.map'",
            "-o", "min.js",
        ],
        tmp_path,
    )
    info = describe_js(tmp_path / "min.js")["js"]
    assert info["source_map"] == "min.js.map"
    facts = info["source_map_facts"]
    assert facts is not None
    assert facts["kind"] == "external"
    assert facts["resolved"] is True
    assert facts["version"] == 3
    assert facts["sources_count"] == 1
    assert facts["sources_content"] == "embedded"
    assert facts["mappings"] is True
    stack = _node_stack(node, tmp_path / "min.js")
    assert "original.js:2" in stack

    # Orphaned reference: same minified code, but the directive names a map
    # that shipped nowhere. The reader must call the claim unbacked and Node,
    # with nothing to resolve, must fall back to minified coordinates.
    orphan = tmp_path / "orphan.js"
    orphan.write_text(
        (tmp_path / "min.js").read_text(encoding="utf-8").replace("min.js.map", "gone.js.map"),
        encoding="utf-8",
    )
    assert describe_js(orphan)["js"]["source_map_facts"] == {
        "kind": "external",
        "resolved": False,
    }
    stack = _node_stack(node, orphan)
    assert "original.js" not in stack
    assert "orphan.js:1" in stack

    # Inline data: URI (terser emits base64 with a charset parameter): the
    # reader decodes it in place and Node maps the stack the same way.
    _terser(
        terser,
        [
            "original.js", "-c", "-m",
            "--source-map", "includeSources=true,url=inline",
            "-o", "inline.js",
        ],
        tmp_path,
    )
    inline_info = describe_js(tmp_path / "inline.js")["js"]
    assert inline_info["source_map_inline"] is True
    inline_facts = inline_info["source_map_facts"]
    assert inline_facts is not None
    assert inline_facts["kind"] == "inline"
    assert inline_facts["resolved"] is True
    assert inline_facts["sources_content"] == "embedded"
    assert inline_facts["mappings"] is True
    stack = _node_stack(node, tmp_path / "inline.js")
    assert "original.js:2" in stack
