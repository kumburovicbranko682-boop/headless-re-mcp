"""``_bounded_metadata`` is the one gate every web metadata field passes through.

Network method, resource type, MIME type, script language, and the page title are
all clipped through this single helper before they reach a caller, so a hostile or
chatty page cannot store an unbounded string per field::

    def _bounded_metadata(value: object, max_bytes: int) -> tuple[str, bool]:
        text = value if isinstance(value, str) else ("" if value is None else str(value));
        payload = text.encode("utf-8", errors="replace");
        if len(payload) <= max_bytes:
            return text, False;                       # fits: original text, verbatim
        return payload[:max_bytes].decode("utf-8", errors="ignore"), True;  # cut on a BYTE

The existing web tests only reach this helper *indirectly*, through the CDP
capture handlers, and always with an over-cap ASCII string (``"x" * big``). That
pins "an oversized ASCII field is clipped and flagged" and nothing else. Four
parts of the contract a single over-cap ASCII path cannot show:

* **The bound is ``<=``: a value exactly at the cap is not truncated.** Off-by-one
  here (``<`` instead of ``<=``) would drop the last legal byte and flag a
  complete field as cut. Only inputs at exactly the cap and one past it can tell
  the two apart; the over-cap ASCII fixture is nowhere near the boundary.

* **Non-string values are coerced, and ``None`` becomes ``""`` (not ``"None"``).**
  CDP fields arrive as whatever the protocol sent -- a missing value is ``None``, a
  numeric field an ``int``. ``None`` must render as empty, everything else via
  ``str``; drop the ``None`` arm and a missing field surfaces as the literal
  string ``"None"``.

* **A multibyte value that fits is returned verbatim, byte-for-byte.** The fitting
  branch returns the *original* ``text``, so a title full of accented or CJK
  characters that is under the cap is not silently re-encoded or altered.

* **An oversized multibyte value is cut on a byte boundary and the dangling
  partial character is dropped, not turned into U+FFFD.** The slice is on
  ``payload`` (bytes) and the re-decode uses ``errors="ignore"``, so the result
  stays within the byte cap and contains no replacement character. A char-based
  slice would blow the byte budget; ``errors="replace"`` would leave a U+FFFD.

These call ``_bounded_metadata`` directly -- no Playwright, no CDP, no browser.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.web.client import _MAX_METADATA_BYTES, _bounded_metadata


def test_a_value_under_the_cap_is_returned_unchanged() -> None:
    """A short field passes through verbatim and unflagged."""
    text, truncated = _bounded_metadata("application/json", _MAX_METADATA_BYTES)
    assert text == "application/json"
    assert truncated is False


def test_a_value_exactly_at_the_cap_is_not_truncated() -> None:
    """A field of exactly ``_MAX_METADATA_BYTES`` bytes is complete, not cut.

    ``len(payload) <= max_bytes`` means the cap itself still fits -- the boundary a
    ``<`` mutation would get wrong, dropping the last legal byte.
    """
    value = "a" * _MAX_METADATA_BYTES
    text, truncated = _bounded_metadata(value, _MAX_METADATA_BYTES)
    assert truncated is False
    assert text == value
    assert len(text.encode("utf-8")) == _MAX_METADATA_BYTES


def test_a_value_one_byte_over_the_cap_is_cut_and_flagged() -> None:
    """One byte past the cap flips truncated True and clips to the cap."""
    text, truncated = _bounded_metadata("a" * (_MAX_METADATA_BYTES + 1), _MAX_METADATA_BYTES)
    assert truncated is True
    assert len(text.encode("utf-8")) == _MAX_METADATA_BYTES


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ""),
        (200, "200"),
        (True, "True"),
        (3.5, "3.5"),
    ],
)
def test_non_string_values_are_coerced(value: object, expected: str) -> None:
    """None renders empty; other non-strings render via ``str`` -- never truncated here.

    A missing CDP field (``None``) must not surface as the literal ``"None"``; a
    numeric field is stringified. All are far under the cap, so truncated is False.
    """
    text, truncated = _bounded_metadata(value, _MAX_METADATA_BYTES)
    assert text == expected
    assert truncated is False


def test_a_multibyte_value_that_fits_is_preserved_exactly() -> None:
    """A sub-cap multibyte field returns the original text byte-for-byte.

    Each 'é' is two UTF-8 bytes, so ``_MAX//2`` of them sit exactly at the cap and
    take the fitting branch, which returns the original ``text`` unaltered.
    """
    value = "\u00e9" * (_MAX_METADATA_BYTES // 2)
    text, truncated = _bounded_metadata(value, _MAX_METADATA_BYTES)
    assert truncated is False
    assert text == value
    assert len(text.encode("utf-8")) == _MAX_METADATA_BYTES


def test_an_oversized_multibyte_value_drops_the_partial_char_cleanly() -> None:
    """An over-cap multibyte field is cut on a byte boundary, no U+FFFD left behind.

    ``"a"`` plus ``_MAX//2`` two-byte chars is one byte over the cap, so the byte
    slice lands mid-character. ``errors="ignore"`` drops that dangling lead byte:
    the result stays within the byte cap and carries no replacement character -- a
    char-slice would exceed the budget and ``errors="replace"`` would leave U+FFFD.
    """
    value = "a" + "\u00e9" * (_MAX_METADATA_BYTES // 2)  # 1 + _MAX bytes = _MAX + 1
    text, truncated = _bounded_metadata(value, _MAX_METADATA_BYTES)
    assert truncated is True
    assert len(text.encode("utf-8")) <= _MAX_METADATA_BYTES
    assert "\ufffd" not in text
    # The leading ASCII byte and all whole 'é' chars that fit survive.
    assert text.startswith("a\u00e9")
