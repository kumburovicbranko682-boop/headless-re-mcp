"""The README must list every registered Android/Web tool.

The README's capability overview enumerates the Android and Web tool surface by
name, and that list is maintained by hand, so it silently falls behind whenever
a tool is added without a matching README edit -- exactly how frida.attach,
frida.modules, frida.exports and frida.memory.read came to be registered,
cataloged and tested yet absent from the "Android 动态" line. An analyst reading
the README to learn what the less-mature lines can do would never discover the
missing tools. This pins the two in sync: every bound tool under an Android/Web
prefix must appear in the README, so a new tool on these lines fails here until
it is documented.

The README writes each group as ``prefix.first/second/third`` on one line -- the
first tool in full, the rest as bare suffixes -- so a tool ``a.b.c`` is accepted
when the README contains the full dotted name, or a single line carries both the
``a.`` prefix and the ``b.c`` remainder. Requiring the prefix on the same line
stops a bare suffix from matching an unrelated tool elsewhere (``attach`` also
lives in ``dynamic.attach``, ``modules`` in ``modules.list``, ``exports`` in
``r2.exports``), which would otherwise hide a missing frida.* tool. The check
only requires the name to appear, so rewording the prose is fine; removing a
tool from the list, or adding one without documenting it, is what trips it.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.assembly import bind_all_tools

# The tool namespaces that make up the Android and Web analysis lines. The PE
# reversing surface is documented separately and is out of this guard's scope.
_ANDROID_WEB_PREFIXES = ("apk.", "device.", "frida.", "web.", "js.", "wasm.", "proxy.")


def _readme_text() -> str:
    return (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")


def _android_web_tool_names() -> list[str]:
    analysis = AnalysisService()
    try:
        names = [binding.name for binding in bind_all_tools(analysis)]
    finally:
        analysis.close_all()
    return sorted(name for name in names if name.startswith(_ANDROID_WEB_PREFIXES))


def _is_documented(name: str, readme: str, lines: list[str]) -> bool:
    if name in readme:
        return True
    # README shorthand: the group's line carries the ``prefix.`` once and the
    # rest as bare suffixes. Require both on one line so a suffix cannot match an
    # unrelated tool documented elsewhere.
    prefix = name.split(".", 1)[0] + "."
    suffix = name.split(".", 1)[1]
    return any(prefix in line and suffix in line for line in lines)


def test_readme_lists_every_registered_android_web_tool() -> None:
    readme = _readme_text()
    lines = readme.splitlines()
    missing = [
        name for name in _android_web_tool_names() if not _is_documented(name, readme, lines)
    ]
    assert missing == [], f"README does not document these Android/Web tools: {missing}"
