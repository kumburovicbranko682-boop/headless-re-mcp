"""Redaction has to hide credentials without deleting the analysis.

It runs over tool results, and those carry what the run was started to find.
The module already excludes "cookie" because __security_cookie is a real symbol
in almost every Windows binary; "token" needed the same care, since a .NET
metadata token is exactly the sort of thing a binary is described with.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.agent.redaction import redact

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


def test_a_bearer_inside_a_string_is_still_masked() -> None:
    """Value matching stays limited to this one shape, which cannot be a symbol."""
    assert redact({"header": "Authorization: Bearer abc.def"}) == {
        "header": "Authorization: Bearer ***REDACTED***"
    }
