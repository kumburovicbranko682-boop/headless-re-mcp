"""frida.hook.template's schema enum must equal the templates the backend serves.

``frida.hook.template`` loads a *code-injection* script chosen by name. Three
surfaces must agree on the set of names, or an agent is misled about what it may
inject:

* the tool schema advertises the choices as a regex enum ``^(a|b|c)$``;
* the backend serves them from ``_HOOK_TEMPLATES`` and runs whatever it finds;
* on a miss the backend rejects with ``invalid_params`` and
  ``allowed=sorted(_HOOK_TEMPLATES)`` as the caller's self-correction hint.

The earlier test pinned the schema pattern and checked the canned names were
*present* in the registry source text. That ``present in`` check is one-directional:
a template added to ``_HOOK_TEMPLATES`` without widening the schema (an injectable
capability the agent can never reach), or -- read the other way -- a name the
schema still advertises after the backend dropped it, slips straight through. This
pins the two live sets *equal*, ties the rejection hint to the same set, and locks
all of it to an explicit reviewed set so adding an injectable template is a
conscious three-way change, not a silent dict edit.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import _HOOK_TEMPLATES, FridaClient, FridaError
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.frida import build_frida_tools

# The canned frida hook templates, listed explicitly so adding or removing an
# injectable script is a deliberate edit here (a reviewer's checkpoint), not a
# dict key that quietly changes what an agent can inject into a process.
_EXPECTED_TEMPLATES = frozenset(
    {"noop", "android_ssl_unpin", "android_crypto_monitor", "android_root_bypass"}
)


def _schema_template_names() -> frozenset[str]:
    handler = next(
        binding.handler
        for binding in build_frida_tools(object())  # type: ignore[arg-type]
        if binding.name == "frida.hook.template"
    )
    pattern = input_schema_for(handler)["properties"]["template"]["pattern"]
    # The enum is a plain ``^(name|name|...)$`` alternation of [a-z_] names, so a
    # bare split recovers the advertised set exactly.
    assert pattern.startswith("^(") and pattern.endswith(")$"), pattern
    return frozenset(pattern[2:-2].split("|"))


def test_the_schema_enum_equals_the_backend_template_registry() -> None:
    assert _schema_template_names() == set(_HOOK_TEMPLATES), (
        "frida.hook.template's schema enum and the backend _HOOK_TEMPLATES "
        "registry name different templates: a schema-valid name the backend will "
        "not run, or an injectable template the agent cannot reach through the schema"
    )


def test_the_schema_and_registry_match_the_reviewed_expected_set() -> None:
    # A new injectable template fails all three until reconciled here, so the
    # capability an agent can reach never drifts from the one a reviewer approved.
    assert set(_HOOK_TEMPLATES) == _EXPECTED_TEMPLATES
    assert _schema_template_names() == _EXPECTED_TEMPLATES


def test_the_rejection_hint_offers_exactly_the_served_templates() -> None:
    # The ``allowed`` self-correction hint the backend returns on an unknown name
    # must be the very set it serves -- an agent that retries from a stale hint
    # would keep missing. The lookup that builds ``allowed`` runs before any
    # attach, so arm availability (skip the "frida not installed" gate) without
    # needing the real module or a live process.
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as info:
        client.hook_template(4242, "definitely-not-a-template", allowed_pid=4242)
    assert info.value.code == "invalid_params"
    assert set(info.value.details["allowed"]) == set(_HOOK_TEMPLATES)
