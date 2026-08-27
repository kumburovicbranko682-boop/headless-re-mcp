"""web.click / web.type: bounded interaction, never arbitrary execution.

The web line could observe a page but not act on it, so it could not drive a
multi-step flow (log in, submit, page through). web.click and web.type close
that gap while staying inside the same envelope as the rest of the surface:

- a selector is the only handle accepted, never a script, so this is not a
  back door to the ``web.evaluate`` the surface deliberately withholds;
- selector and text are caller input, so both are size-bounded and an empty
  selector is refused up front rather than surfacing as a late actionability
  timeout after a browser thread was already spent on it;
- the caller timeout is clamped exactly like navigate's, because the agent
  transport invokes handlers straight from model arguments with no schema
  enforcement -- a non-positive value would reach ``Future.result(timeout<=0)``
  and flip the runner to ``_wedged``, bricking a live session;
- web.type returns only the *length* of what it entered, never the text, so a
  typed password or token does not land in the result envelope.

These pin those properties directly, with a fake page (no browser) driven on a
real runner, so the guarantees hold without Playwright's browsers installed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web.client import (
    _MAX_NAV_TIMEOUT_S,
    _MAX_SELECTOR_BYTES,
    _MAX_TYPE_TEXT_BYTES,
    _require_selector,
    _require_type_text,
    _Runner,
)
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, ToolEffect


class _FakeActionPage:
    """Records the click/fill a real page would have received, no browser."""

    def __init__(self, *, fail: bool = False) -> None:
        self.url = "https://app/"
        self.clicks: list[tuple[str, float]] = []
        self.fills: list[tuple[str, str, float]] = []
        self._fail = fail

    def click(self, selector: str, timeout: float = 0.0) -> None:
        if self._fail:
            raise RuntimeError("Timeout: element is not visible")
        self.clicks.append((selector, timeout))
        self.url = "https://app/next"

    def fill(self, selector: str, value: str, timeout: float = 0.0) -> None:
        if self._fail:
            raise RuntimeError("Element is not an <input>, <textarea> or [contenteditable]")
        self.fills.append((selector, value, timeout))

    def title(self) -> str:
        return "Example"


class TestSelectorGuard:
    def test_an_empty_or_whitespace_selector_is_refused(self) -> None:
        for bad in ("", "   ", "\t"):
            with pytest.raises(WebError) as info:
                _require_selector(bad)
            assert info.value.code == "invalid_params"

    def test_an_over_long_selector_is_refused(self) -> None:
        with pytest.raises(WebError) as info:
            _require_selector("a" * (_MAX_SELECTOR_BYTES + 1))
        assert info.value.code == "invalid_params"

    def test_a_normal_selector_is_accepted_and_trimmed(self) -> None:
        assert _require_selector("  #login > button  ") == "#login > button"


class TestTypeTextGuard:
    def test_over_long_text_is_refused_by_byte_size(self) -> None:
        with pytest.raises(WebError) as info:
            _require_type_text("x" * (_MAX_TYPE_TEXT_BYTES + 1))
        assert info.value.code == "invalid_params"

    def test_text_at_the_cap_is_accepted_and_returned_verbatim(self) -> None:
        value = "y" * _MAX_TYPE_TEXT_BYTES
        assert _require_type_text(value) == value

    def test_none_becomes_empty_rather_than_the_string_none(self) -> None:
        assert _require_type_text(None) == ""  # type: ignore[arg-type]


class TestClickIsBounded:
    def test_a_bad_selector_is_refused_before_the_session_is_touched(self) -> None:
        """The refusal must land before _get, so no session work is spent on it."""
        backend = WebBackend()

        def poisoned(_session_id: str) -> Any:
            raise AssertionError("a rejected selector must not reach the session")

        backend._get = poisoned  # type: ignore[method-assign]
        with pytest.raises(WebError) as info:
            backend.click("s", "")
        assert info.value.code == "invalid_params"

    def test_a_negative_timeout_does_not_wedge_a_live_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-click-neg")
        try:
            page = _FakeActionPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            with pytest.raises(WebError) as info:
                backend.click("s", "#btn", timeout=-1.0)
            assert info.value.code == "invalid_params"
            # The runner never saw the doomed wait, so the session is still usable.
            assert runner.wedged is False
            assert page.clicks == []

            payload = backend.click("s", "#btn", timeout=5.0)
            assert payload["clicked"] is True
            assert runner.wedged is False
        finally:
            runner.shutdown()

    def test_a_huge_timeout_is_capped_to_the_schema_max(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-click-cap")
        try:
            page = _FakeActionPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            backend.click("s", "#btn", timeout=10**9)
            # click receives milliseconds, capped at the schema ceiling.
            assert page.clicks == [("#btn", _MAX_NAV_TIMEOUT_S * 1000.0)]
        finally:
            runner.shutdown()

    def test_a_click_reports_the_page_it_landed_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-click-ok")
        try:
            page = _FakeActionPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            payload = backend.click("s", "#go", timeout=5.0)
            assert payload == {
                "clicked": True,
                "selector": "#go",
                "url": "https://app/next",
                "title": "Example",
            }
        finally:
            runner.shutdown()

    def test_an_unactionable_element_surfaces_as_backend_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-click-fail")
        try:
            page = _FakeActionPage(fail=True)
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            with pytest.raises(WebError) as info:
                backend.click("s", "#missing", timeout=5.0)
            assert info.value.code == "backend_error"
        finally:
            runner.shutdown()


class TestTypeIsBoundedAndDoesNotEchoText:
    def test_type_returns_only_the_length_never_the_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A typed secret must not come back in the envelope.

        The field is filled, but the result carries the length alone -- so a
        password or token entered here cannot be read back out of the transcript
        by anything that logs tool results.
        """
        backend = WebBackend()
        runner = _Runner("test-type-secret")
        try:
            page = _FakeActionPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            secret = "hunter2-do-not-echo"
            payload = backend.type_text("s", "#password", secret, timeout=5.0)
            assert payload == {"typed": True, "selector": "#password", "length": len(secret)}
            # The value reached the page but not the result envelope.
            assert page.fills == [("#password", secret, 5.0 * 1000.0)]
            assert secret not in json.dumps(payload)
        finally:
            runner.shutdown()

    def test_over_long_text_is_refused_before_the_session_is_touched(self) -> None:
        backend = WebBackend()

        def poisoned(_session_id: str) -> Any:
            raise AssertionError("over-cap text must not reach the session")

        backend._get = poisoned  # type: ignore[method-assign]
        with pytest.raises(WebError) as info:
            backend.type_text("s", "#field", "x" * (_MAX_TYPE_TEXT_BYTES + 1))
        assert info.value.code == "invalid_params"

    def test_a_non_editable_target_surfaces_as_backend_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-type-fail")
        try:
            page = _FakeActionPage(fail=True)
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            with pytest.raises(WebError) as info:
                backend.type_text("s", "#div", "hi", timeout=5.0)
            assert info.value.code == "backend_error"
        finally:
            runner.shutdown()


class TestInteractionToolSurface:
    def test_click_and_type_are_writes_that_do_not_auto_execute(self) -> None:
        for name in ("web.click", "web.type"):
            spec = COMMAND_CATALOG.require(name)
            assert spec.write is True
            assert spec.agent_auto_execute is False
            assert spec.effects == frozenset({ToolEffect.STATE_CHANGE})

    def test_interaction_is_selector_based_not_a_script_evaluator(self) -> None:
        """The new tools must not reopen the door web.evaluate keeps shut."""
        public = {name for name in dir(WebBackend) if not name.startswith("_")}
        assert {"click", "type_text"} <= public
        assert not {"evaluate", "eval", "run_code"} & public
