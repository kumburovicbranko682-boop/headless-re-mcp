"""Redaction has to hide credentials without deleting the analysis.

It runs over tool results, and those carry what the run was started to find.
The module already excludes "cookie" because __security_cookie is a real symbol
in almost every Windows binary; "token" needed the same care, since a .NET
metadata token is exactly the sort of thing a binary is described with.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.agent.redaction import is_secret_key, redact

ANALYSIS_THAT_MUST_SURVIVE: list[tuple[str, dict[str, Any]]] = [
    ("dotnet il call graph", {"call_tokens": [100663297, 167772161], "instructions": 12}),
    ("dotnet enumerate rows", {"rows": [{"token": 100663297, "name": "System.String"}]}),
    ("a metadata token", {"metadata_token": 33554433}),
    ("a thread access token handle", {"thread_id": 1234, "token_handle": 4198400}),
    ("pseudocode mentioning a password", {"text": 'if (strcmp(password, "hunter2"))'}),
    ("a function named auth", {"name": "auth", "address": 4198400}),
    ("a struct field named credential", {"fields": [{"name": "credential", "offset": 8}]}),
    ("a string scan hit", {"strings": [{"value": "password=admin", "address": 4210688}]}),
]

SECRETS_THAT_MUST_NOT_LEAK: list[tuple[str, dict[str, Any]]] = [
    ("a bearer token", {"token": "eyJhbGciOiJIUzI1NiJ9.abc.def"}),
    ("an api key", {"api_key": "sk-live-abcdef"}),
    ("a provider key from the environment", {"HEADLESS_RE_PROVIDER_API_KEY": "secret"}),
    ("a password", {"password": "hunter2"}),
    ("a nested credential", {"credential": {"user": "u", "pass": "p"}}),
    ("an authorization header", {"authorization": "Bearer abc.def"}),
]


@pytest.mark.parametrize(
    ("label", "payload"), ANALYSIS_THAT_MUST_SURVIVE, ids=[c[0] for c in ANALYSIS_THAT_MUST_SURVIVE]
)
def test_analysis_output_is_not_mistaken_for_a_secret(label: str, payload: dict[str, Any]) -> None:
    """Measured before the value check: dotnet.il answered with call_tokens
    replaced by the mask, so the agent could not follow a single call, and
    nothing said the values had been suppressed rather than never found."""
    assert redact(payload) == payload, label


@pytest.mark.parametrize(
    ("label", "payload"), SECRETS_THAT_MUST_NOT_LEAK, ids=[c[0] for c in SECRETS_THAT_MUST_NOT_LEAK]
)
def test_a_credential_is_still_hidden(label: str, payload: dict[str, Any]) -> None:
    """The other direction, which is the whole point of the module."""
    redacted = redact(payload)
    assert redacted != payload, label
    assert "***REDACTED***" in str(redacted), label


# Every alternative _SECRET_KEY claims to match, each paired with a string value
# a real credential would live in. The list above only ever exercised
# token / api_key / password / credential / authorization, so dropping
# private_key, access_key, secret, passwd or providerApiKeys from the regex --
# the kind of thing a "tidy up the pattern" refactor does -- would silently
# shrink the credential net with every test still green. Pin the whole declared
# set so removing any one alternative fails its own row here. The `[_-]?` and
# case-insensitive `search` are pinned too (apiKey, x-api-key, access-key), so a
# regex tightened to word boundaries or exact case cannot quietly stop matching
# the header/camelCase spellings that actually appear in provider payloads.
DECLARED_SECRET_KEYS: list[tuple[str, str]] = [
    ("api_key", "sk-live-abcdef"),
    ("apiKey", "sk-live-abcdef"),
    ("x-api-key", "sk-live-abcdef"),
    ("private_key", "-----BEGIN PRIVATE KEY-----"),
    ("access_key", "AKIAEXAMPLE"),
    ("access-key", "AKIAEXAMPLE"),
    ("authorization", "Bearer abc.def"),
    ("token", "eyJhbGciOiJIUzI1NiJ9.abc.def"),
    ("refresh_token", "rt_abcdef"),
    ("secret", "shhh"),
    ("client_secret", "cs_abcdef"),
    ("password", "hunter2"),
    ("passwd", "hunter2"),
    ("credential", "cred-abcdef"),
    ("providerApiKeys", "sk-abcdef"),
]


@pytest.mark.parametrize(
    ("key", "value"), DECLARED_SECRET_KEYS, ids=[k for k, _ in DECLARED_SECRET_KEYS]
)
def test_every_declared_secret_key_is_redacted(key: str, value: str) -> None:
    """A string value under any declared secret key is fully masked."""
    assert is_secret_key(key), f"{key} should be recognised as a secret key"
    assert redact({key: value}) == {key: "***REDACTED***"}, key


def test_cookie_is_deliberately_not_treated_as_secret() -> None:
    """``cookie`` is kept OUT of the secret-key set on purpose.

    ``__security_cookie`` is the stack-canary global in almost every Windows
    binary, and ``cookie`` appears in countless other real symbols and fields;
    matching it would blank genuine analysis output (the same reason ``token``
    leans on the numeric guard rather than a blanket mask). The exclusion lived
    only in this file's module docstring -- so a well-meaning "add cookie to the
    credential net" change would corrupt RE output for every PE while every test
    above stayed green. Pin the exclusion here in both directions: the key is not
    classified secret, and a string value under it survives redaction untouched.
    """
    assert is_secret_key("cookie") is False
    assert is_secret_key("__security_cookie") is False
    assert redact({"cookie": "GS_HANDLER_CHECK"}) == {"cookie": "GS_HANDLER_CHECK"}
    assert redact({"__security_cookie": "0x140001000"}) == {
        "__security_cookie": "0x140001000"
    }


def test_a_bearer_inside_a_string_is_still_masked() -> None:
    """Value matching stays limited to this one shape, which cannot be a symbol."""
    assert redact({"header": "Authorization: Bearer abc.def"}) == {
        "header": "Authorization: Bearer ***REDACTED***"
    }


def test_a_structure_too_deep_to_walk_is_marked_rather_than_raising() -> None:
    """This runs over every tool argument and every tool result, and it recurses.

    Python gives up at 1000 frames. A structure two thousand deep encodes in
    14 KB, comfortably inside the argument size bound, and raised RecursionError
    from inside the store transaction, failing the run with nothing to explain
    it. Real payloads are nowhere near: the whole 263-tool schema export is 12
    deep and a detection report is 7.
    """
    import sys

    def build(levels: int) -> Any:
        sys.setrecursionlimit(20_000)
        try:
            value: Any = "leaf"
            for _ in range(levels):
                value = {"a": value}
            return value
        finally:
            sys.setrecursionlimit(1_000)

    shallow = redact(build(12))
    assert "redaction_depth_exceeded" not in str(shallow), "ordinary payloads are untouched"

    deep = redact(build(2_000))
    assert "redaction_depth_exceeded" in str(deep), "and the cut is stated, not silent"


def test_a_secret_below_a_few_levels_is_still_found() -> None:
    """The depth bound must not become a way to smuggle a credential past it."""
    nested: Any = {"api_key": "sk-live-abcdef"}
    for _ in range(20):
        nested = {"wrapper": nested}

    assert "sk-live-abcdef" not in str(redact(nested))


def test_the_credential_test_itself_cannot_be_made_to_recurse_away() -> None:
    """Deciding whether a value could be a credential walks the value too.

    That walk is separate from redact's own depth counter, so it needed its own
    bound: a secret key holding a list nested three thousand deep raised
    RecursionError here while the same list under an ordinary key was fine.
    Too deep to inspect resolves to masked, which is the safe answer for
    something already sitting under a credential's name.
    """
    import sys

    sys.setrecursionlimit(20_000)
    try:
        deep: Any = "leaf"
        for _ in range(3_000):
            deep = [deep]
    finally:
        sys.setrecursionlimit(1_000)

    assert "***REDACTED***" in str(redact({"api_key": deep})), "a deep value under a secret name"
    assert "***REDACTED***" not in str(redact({"harmless": deep})), "but not under an ordinary one"
    assert redact({"call_tokens": [1, 2, 3]}) == {"call_tokens": [1, 2, 3]}
