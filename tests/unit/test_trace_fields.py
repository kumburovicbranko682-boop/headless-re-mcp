"""trace.* descriptions must say the caller path is not the file."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.service_trace import TraceMixin, _TraceArtifactState
from headless_re_mcp.tools.trace import build_trace_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_trace_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_trace_start_file_is_artifact_path_not_the_caller_path() -> None:
    """The catalog said recording goes to the absolute path argument.

    Measured: requested_path C:/ignored-caller-path.trace, artifact_path
    E:/art/trace/s/run.trace, session_owned True, they are not the same.
    Reading requested_path after a successful start looks at a path the
    tracer never wrote, so the overnight pass treats a live trace as empty.
    """
    state = _TraceArtifactState(
        session_id="s",
        path=Path(r"E:/art/trace/s/run.trace"),
        requested_path=r"C:/ignored-caller-path.trace",
        max_events=1,
        timeout_ms=1500,
        max_file_bytes=65536,
        started_monotonic=0.0,
    )
    payload = TraceMixin._trace_result_payload(object(), state, {"recording": True})
    assert payload["requested_path"] == r"C:/ignored-caller-path.trace"
    assert payload["artifact_path"] == str(Path(r"E:/art/trace/s/run.trace"))
    assert payload["path"] == payload["artifact_path"]
    assert payload["path"] != payload["requested_path"]
    assert payload["session_owned"] is True
    assert payload["recording"] is True
    doc = _tool_docstring("trace.start")
    assert "Answers with artifact_path" in doc
    assert "requested_path" in doc
    assert "session_owned" in doc
    stop_doc = _tool_docstring("trace.stop")
    assert "Answers with artifact_path" in stop_doc
