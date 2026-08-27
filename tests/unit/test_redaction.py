"""The shared credential redactor, pinned key by key.

``redaction.redact`` masks credentials across every persisted and public payload
the server emits (incident logs, audit rows, the ``/providers`` surface). No test
imported this module directly -- it was only ever exercised through a repository
audit path -- yet its contract is unusually specific and a well-meaning edit
could quietly turn it into a credential leak:

* It masks by **key name**, not by value, because reverse-engineering output
  legitimately contains credential-looking strings pulled from the target, and
  masking those would blind the analyst. So ``{"note": "the key is sk-..."}``
  survives verbatim while ``{"api_key": "sk-..."}`` is masked.
* A **numeric** value under a secret-looking key stays visible: it is metadata
  (a count, an id), not a secret.
* A ``Bearer <token>`` substring is scrubbed wherever it appears in a string,
  because that shape is a credential regardless of the key it sits under.
* Recursion is depth-bounded and fail-safe: past the limit a value is replaced
  wholesale, and an ambiguous value under a secret key is assumed to hold a
  credential.

These tests lock each of those so a regression fails loudly here instead of
leaking silently in production.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.redaction import (
    MAX_DEPTH,
    _could_hold_a_credential,
    is_secret_key,
    masked_secret,
    redact,
)

_MASK = "***REDACTED***"


# --- is_secret_key ------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "apiKey",
        "api-key",
        "APIKEY",
        "private_key",
        "private-key",
        "access_key",
        "authorization",
        "Authorization",
        "token",
        "refresh_token",  # substring match
        "secret",
        "client_secret",
        "password",
        "passwd",
        "credential",
        "credentials",
        "providerApiKeys",
    ],
)
def test_secret_key_names_are_recognized(key: str) -> None:
    assert is_secret_key(key) is True


@pytest.mark.parametrize("key", ["name", "note", "value", "path", "count", "id", "summary"])
def test_ordinary_key_names_are_not_secret(key: str) -> None:
    assert is_secret_key(key) is False


def test_a_non_string_key_is_never_secret() -> None:
    # is_secret_key guards the type so redact can be handed dicts with int keys.
    assert is_secret_key(5) is False
    assert is_secret_key(None) is False


# --- redact: key-based masking ------------------------------------------------


def test_a_string_under_a_secret_key_is_masked() -> None:
    assert redact({"password": "hunter2"}) == {"password": _MASK}


def test_a_numeric_under_a_secret_key_stays_visible() -> None:
    # Documented: a number under a secret-looking key is metadata, not a secret.
    assert redact({"token_count": 5}) == {"token_count": 5}
    assert redact({"api_key_version": 3}) == {"api_key_version": 3}


def test_a_structured_value_under_a_secret_key_is_masked_whole() -> None:
    # A dict or a list-with-text under a secret key is replaced entirely rather
    # than walked, so no nested credential slips through.
    assert redact({"providerApiKeys": {"p1": "sk-x"}}) == {"providerApiKeys": _MASK}
    assert redact({"secret": ["a", "b"]}) == {"secret": _MASK}


def test_a_list_of_only_numbers_under_a_secret_key_stays_visible() -> None:
    # Numbers cannot be a credential, so an all-numeric list is left intact.
    assert redact({"access_key": [1, 2, 3]}) == {"access_key": [1, 2, 3]}


def test_nested_secret_keys_are_reached_through_ordinary_containers() -> None:
    payload = {"outer": {"api_key": "sk-y", "ok": 1}, "list": [{"secret": "z"}]}
    assert redact(payload) == {
        "outer": {"api_key": _MASK, "ok": 1},
        "list": [{"secret": _MASK}],
    }


# --- redact: value-based bearer scrub -----------------------------------------


def test_a_bearer_token_is_scrubbed_wherever_it_appears() -> None:
    # The Bearer shape is a credential regardless of the key, and even as a bare
    # string in a list, so the value scrub is the safety net over the key rules.
    assert redact({"note": "use Authorization: Bearer sk-DEADBEEF now"}) == {
        "note": "use Authorization: Bearer ***REDACTED*** now"
    }
    assert redact(["Bearer abc.def-123"]) == ["Bearer ***REDACTED***"]


def test_a_credential_like_string_under_an_ordinary_key_is_preserved() -> None:
    # The whole reason redaction is key-based: an RE result carrying a key it
    # found in the target must survive, or the analyst loses the finding.
    assert redact({"note": "the target embeds sk-DEADBEEF in .rdata"}) == {
        "note": "the target embeds sk-DEADBEEF in .rdata"
    }


def test_bearer_needs_the_keyword_and_whitespace() -> None:
    # "Bearerish" is not a bearer header; without the space the scrub must not
    # fire and eat ordinary prose.
    assert redact("Bearerish token store") == "Bearerish token store"


# --- redact: masks, primitives, immutability ----------------------------------


def test_a_custom_mask_is_honored() -> None:
    assert redact({"token": "x"}, mask="XX") == {"token": "XX"}


def test_primitives_pass_through_unchanged() -> None:
    assert redact(5) == 5
    assert redact(True) is True
    assert redact(None) is None
    assert redact("plain text with no secrets") == "plain text with no secrets"


def test_redact_does_not_mutate_its_input() -> None:
    original = {"api_key": "sk", "keep": [1, {"secret": "s"}]}
    snapshot = {"api_key": "sk", "keep": [1, {"secret": "s"}]}
    redact(original)
    assert original == snapshot, "redact must return a new structure, not edit in place"


# --- redact: depth bound ------------------------------------------------------


def test_recursion_past_the_depth_limit_is_replaced_with_a_marker() -> None:
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(MAX_DEPTH + 5):
        nxt: dict[str, object] = {}
        cursor["x"] = nxt
        cursor = nxt

    result = redact(deep)

    walked = 0
    node: object = result
    while isinstance(node, dict) and "x" in node:
        node = node["x"]
        walked += 1
    # The walk stops at the marker the recursion planted at MAX_DEPTH.
    assert walked == MAX_DEPTH
    assert node == {"redaction_depth_exceeded": True, "depth": MAX_DEPTH}


# --- _could_hold_a_credential -------------------------------------------------


def test_only_pure_numbers_and_number_lists_are_declared_credential_free() -> None:
    assert _could_hold_a_credential(5) is False
    assert _could_hold_a_credential(1.5) is False
    assert _could_hold_a_credential(True) is False
    assert _could_hold_a_credential([1, 2, 3]) is False
    # Anything that can carry text -- a string, a dict, a mixed list -- could.
    assert _could_hold_a_credential("x") is True
    assert _could_hold_a_credential({}) is True
    assert _could_hold_a_credential([1, "x"]) is True


def test_could_hold_a_credential_is_fail_safe_past_the_depth_limit() -> None:
    # An unresolvably deep value under a secret key defaults to "yes, mask it".
    nested: list[object] = []
    cursor = nested
    for _ in range(MAX_DEPTH + 2):
        inner: list[object] = []
        cursor.append(inner)
        cursor = inner
    assert _could_hold_a_credential(nested) is True


# --- masked_secret ------------------------------------------------------------


def test_masked_secret_hides_none_and_empty() -> None:
    assert masked_secret(None) is None
    assert masked_secret("") is None


def test_masked_secret_fully_stars_a_short_value() -> None:
    # <= 8 chars would leak too much of itself through a prefix/suffix, so it is
    # replaced entirely rather than previewed.
    assert masked_secret("abc") == "********"
    assert masked_secret("12345678") == "********"


def test_masked_secret_previews_only_the_ends_of_a_long_value() -> None:
    assert masked_secret("abcdefghij") == "ab…ij"
