"""``har_entry`` distinguishes a known-empty body from an unknown one, and caps params.

``har_entry`` fills ``content.size`` / ``response.bodySize`` from the decoded body
length the capture recorded, guarding on ``>= 0``::

    if isinstance(response_body_size, int) and response_body_size >= 0:
        content_size = response_body_size
    else:
        content_size = _UNKNOWN_SIZE          # -1, the spec's "not available"

and ``_query_string`` bounds the parsed parameter list::

    return [{"name": n, "value": v} for n, v in pairs[:_MAX_QUERY_PARAMS]]

The existing HAR spec test checks a *positive* body size (1234) and an *absent*
one (``None`` -> -1), and query strings well under the cap. Three edges that the
guards exist for are therefore never exercised:

* **A body size of exactly zero is a real length, not "unknown".** A 204, a
  HEAD, or an empty 200 has a body of zero bytes, which the recorder knows;
  ``>= 0`` keeps it as ``0`` so a HAR viewer shows "0 B", not "size unknown".
  Tighten the guard to ``> 0`` and every empty response silently becomes -1 --
  indistinguishable from a flow whose length was never measured.

* **A negative size is the "unknown" sentinel's job, and must map to -1.** The
  docstring says "absent or negative", but only absent is tested; a stray
  negative int (a miscomputed length) must not be copied through as a bogus
  ``content.size`` of -5.

* **The query list is capped.** A URL with a pathological parameter count must
  not inflate a single entry past ``_MAX_QUERY_PARAMS``; drop the slice and one
  crafted URL blows the bound the upstream 16 KiB URL cap only partly contains.

These drive ``har_entry`` / ``_query_string`` directly -- no browser, no proxy.
"""

from __future__ import annotations

from headless_re_mcp.backends.common import har as har_mod
from headless_re_mcp.backends.common.har import _query_string, har_entry


def test_a_known_empty_body_reports_size_zero_not_unknown() -> None:
    """A zero-length body is a measured 0, distinct from the -1 "not available"."""
    entry = har_entry(
        method="GET",
        url="https://x/empty",
        status=204,
        mime_type="",
        response_body_size=0,
    )
    assert entry["response"]["content"]["size"] == 0
    assert entry["response"]["bodySize"] == 0


def test_a_negative_body_size_falls_back_to_unknown() -> None:
    """A miscomputed negative length is not copied through; it becomes -1."""
    entry = har_entry(
        method="GET",
        url="https://x/1",
        status=200,
        mime_type="",
        response_body_size=-5,
    )
    assert entry["response"]["content"]["size"] == -1
    assert entry["response"]["bodySize"] == -1


def test_an_absent_body_size_is_unknown() -> None:
    """The default (no size recorded) stays the spec's -1 sentinel."""
    entry = har_entry(method="GET", url="https://x/1", status=200, mime_type="")
    assert entry["response"]["content"]["size"] == -1
    assert entry["response"]["bodySize"] == -1


def test_query_string_is_capped_to_the_parameter_ceiling() -> None:
    """A pathologically long query is truncated to _MAX_QUERY_PARAMS leading pairs."""
    cap = har_mod._MAX_QUERY_PARAMS
    url = "https://x/?" + "&".join(f"k{i}=v{i}" for i in range(cap + 50))
    params = _query_string(url)
    assert len(params) == cap
    assert params[0] == {"name": "k0", "value": "v0"}
    assert params[-1] == {"name": f"k{cap - 1}", "value": f"v{cap - 1}"}


def test_query_string_under_the_cap_keeps_every_parameter() -> None:
    """Below the ceiling, every parameter (repeats and blanks included) survives."""
    params = _query_string("https://x/?a=1&a=2&b=&c=3")
    assert [(p["name"], p["value"]) for p in params] == [
        ("a", "1"),
        ("a", "2"),
        ("b", ""),
        ("c", "3"),
    ]
