"""Pin that ``openai_function_name`` honors OpenAI's ASCII name contract.

OpenAI restricts function names to ``[A-Za-z0-9_-]{1,64}``. The sanitizer filters
with an ASCII check rather than the Unicode-aware :meth:`str.isalnum`, which would
otherwise pass through accented letters, CJK, and full-width digits and emit a
name the API rejects. The real catalog is all ASCII, so this behavior is only
observable when the public helper is handed an arbitrary tool name.
"""

from __future__ import annotations

import re

from headless_re_mcp.openai_bridge import MAX_FUNCTION_NAME, openai_function_name

_OPENAI_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def test_ascii_names_are_unchanged() -> None:
    # The common case must not regress.
    assert openai_function_name("static.functions") == "static_functions"
    assert openai_function_name("ui.virtual_desktop.capture") == "ui_virtual_desktop_capture"
    assert openai_function_name("dynamic-run") == "dynamic-run"


def test_non_ascii_letters_are_replaced() -> None:
    # 'é' is Unicode-alphanumeric but not ASCII; it must become '_'.
    result = openai_function_name("static.café")
    assert result == "static_caf"
    assert _OPENAI_SAFE.fullmatch(result)


def test_cjk_characters_are_replaced() -> None:
    result = openai_function_name("工具.run")
    # Leading run of replaced CJK chars is stripped; only the ASCII tail remains.
    assert result == "run"
    assert _OPENAI_SAFE.fullmatch(result)


def test_fullwidth_digits_are_replaced() -> None:
    # Full-width '１２３' are Unicode digits but not ASCII digits.
    result = openai_function_name("tool.１２３")
    assert result == "tool"
    assert _OPENAI_SAFE.fullmatch(result)


def test_all_non_ascii_falls_back_to_tool() -> None:
    # A name with no ASCII alnum at all collapses to the sentinel.
    assert openai_function_name("中文名") == "tool"


def test_mixed_unicode_output_is_always_ascii_safe() -> None:
    for raw in ("naïve.tool", "Ω.measure", "tool\uff0ename", "emoji😀.scan", "½.value"):
        result = openai_function_name(raw)
        assert result.isascii(), raw
        assert _OPENAI_SAFE.fullmatch(result), (raw, result)


def test_length_cap_still_applies_after_ascii_filter() -> None:
    result = openai_function_name("工" * 10 + "a" * 200)
    assert len(result) <= MAX_FUNCTION_NAME
    assert _OPENAI_SAFE.fullmatch(result)
