"""``tokens_match`` must treat a malformed token as a miss, not raise.

``secrets.compare_digest`` raises ``TypeError`` on a non-ASCII ``str``, and
Starlette decodes request headers and cookies as latin-1 -- so a credential
carrying a byte above 0x7f reached the bare comparison as a non-ASCII str and
turned a bad token into a 500 rather than the 401 it means. The helper compares
UTF-8 bytes so the same input is simply "no match".
"""

from __future__ import annotations

import pytest

from headless_re_mcp.web.auth import tokens_match

_EXPECTED = "spa-token-value-0123456789abcdef"


def test_the_correct_token_matches() -> None:
    assert tokens_match(_EXPECTED, _EXPECTED) is True


def test_a_wrong_ascii_token_is_a_miss() -> None:
    assert tokens_match(_EXPECTED[:-1] + "X", _EXPECTED) is False


@pytest.mark.parametrize("provided", [None, ""])
def test_an_absent_token_is_a_miss(provided: str | None) -> None:
    assert tokens_match(provided, _EXPECTED) is False


@pytest.mark.parametrize(
    "provided",
    [
        # A latin-1 high byte (0xE9) is exactly what Starlette hands the route
        # when a raw non-ASCII byte arrives in a header, query or cookie; the
        # bare compare_digest raised TypeError on this.
        "\u00e9" + _EXPECTED[1:],
        # A run entirely of non-ASCII characters, still latin-1 shaped.
        "\u00ff\u00fe\u00fd",
        # Matching character length but non-ASCII, which the old length-guarded
        # bootstrap-cookie path did not protect against either.
        "\u00e9" * len(_EXPECTED),
    ],
)
def test_a_non_ascii_token_is_a_miss_not_an_error(provided: str) -> None:
    assert tokens_match(provided, _EXPECTED) is False
