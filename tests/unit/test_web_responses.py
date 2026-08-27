"""The console's JSONResponse must degrade, not 500, on hostile-influenced values.

Starlette renders with ensure_ascii=False, allow_nan=False and encodes to
UTF-8 inside JSONResponse.__init__. Backend JSON parses pass two kinds of
values through into route payloads that break that render: unpaired
surrogates (json.loads accepts a lone \\ud800 escape, so a hostile binary's
strings can carry one) and non-finite floats. Either one turned a whole
console panel into a 500 over a single string field.
"""

from __future__ import annotations

import json

import pytest

from headless_re_mcp.web.responses import JSONResponse


def _parsed(response: JSONResponse) -> object:
    return json.loads(response.body.decode("utf-8"))


def test_a_surrogate_in_a_payload_string_is_replaced_not_fatal() -> None:
    response = JSONResponse({"ok": True, "data": {"note": "from \ud800 binary"}})

    payload = _parsed(response)
    assert payload["ok"] is True
    note = payload["data"]["note"]
    assert "\ud800" not in note
    assert note.startswith("from ") and note.endswith(" binary")


def test_a_surrogate_in_a_dict_key_is_replaced_not_fatal() -> None:
    response = JSONResponse({"strings": {"k\ud800ey": 1}})

    payload = _parsed(response)
    assert list(payload["strings"].values()) == [1]
    assert all("\ud800" not in key for key in payload["strings"])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_float_becomes_null_not_fatal(value: float) -> None:
    """allow_nan=False raised ValueError; the strict SPA cannot parse NaN either.

    null is the one JSON-compliant stand-in that keeps the rest of the
    payload intact.
    """
    response = JSONResponse({"ok": True, "data": {"score": value, "kept": 7}})

    payload = _parsed(response)
    assert payload["data"]["score"] is None
    assert payload["data"]["kept"] == 7


def test_clean_content_renders_byte_identical_to_starlette() -> None:
    from starlette.responses import JSONResponse as StarletteJSONResponse

    content = {"ok": True, "data": {"值": [1, 2.5, None, "text"]}}
    assert JSONResponse(content).body == StarletteJSONResponse(content).body


def test_lists_and_tuples_inside_a_bad_payload_survive_repair() -> None:
    response = JSONResponse({"items": [("a", "b \ud800"), [float("nan"), 3]]})

    payload = _parsed(response)
    assert payload["items"][0][0] == "a"
    assert "\ud800" not in payload["items"][0][1]
    assert payload["items"][1] == [None, 3]
