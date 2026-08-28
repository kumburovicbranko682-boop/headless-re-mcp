from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# This gate exercises the web workbench end to end, so it needs the full optional
# web stack: playwright (the ``browser`` extra) plus uvicorn and
# ``headless_re_mcp.web.app`` (the ``web`` extra, which imports fastapi). A bare
# top-level import of any of them turns a partial install into a collection
# *error*, and pytest treats a single collection error as fatal: it aborts
# collection of the whole tests/integration tree and runs nothing, so a machine
# missing one extra loses every other backend gate too. Guarding only playwright
# is not enough -- an eager ``import uvicorn`` or ``from ...web.app import
# create_app`` still errors when the web extra is absent. Route every optional
# dependency through importorskip so a missing extra skips just this module
# ("skip != pass"), matching every other backend gate.
_playwright_sync = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright not installed — browser workbench Gate not run (skip != pass)",
)
Response = _playwright_sync.Response
expect = _playwright_sync.expect
sync_playwright = _playwright_sync.sync_playwright

uvicorn = pytest.importorskip(
    "uvicorn",
    reason="uvicorn not installed — browser workbench Gate needs the web extra (skip != pass)",
)
create_app = pytest.importorskip(
    "headless_re_mcp.web.app",
    reason="web extra not installed — browser workbench Gate not run (skip != pass)",
).create_app

JsonObject = dict[str, Any]


class BrowserFakeProvider:
    def stream_chat(
        self,
        *,
        messages: Sequence[JsonObject],
        tools: Sequence[JsonObject],
        model: str,
        enable_thinking: bool = False,
        reasoning_effort: str | None = None,
    ) -> AsyncIterator[ProviderEvent]:
        del tools, model, enable_thinking, reasoning_effort
        return self._stream(messages)

    async def _stream(self, messages: Sequence[JsonObject]) -> AsyncIterator[ProviderEvent]:
        last_user = max((index for index, item in enumerate(messages) if item.get("role") == "user"), default=-1)
        user = str(messages[last_user].get("content", "")) if last_user >= 0 else ""
        tool_after_user = any(item.get("role") == "tool" for item in messages[last_user + 1 :])
        if tool_after_user:
            yield ProviderEvent("text_delta", text="tool round finished")
            yield ProviderEvent("completed")
            return
        if "read" in user:
            yield ProviderEvent("text_delta", text="running read-only check")
            yield ProviderEvent("completed", tool_calls=(ProviderToolCall("read-call", "doctor", {}),))
            return
        yield ProviderEvent("text_delta", text="dangerous operation proposed")
        yield ProviderEvent(
            "completed",
            tool_calls=(ProviderToolCall("danger-call", "workflow.cancel", {"session_id": "missing-session"}),),
        )

    async def list_models(self) -> list[str]:
        return ["browser-fake"]


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# Each wait below covers a real round trip -- SSE, a run, and for the read-only
# case an actual `doctor` execution that stats every configured backend path.
# Alone that takes a few seconds; in a loaded full-suite run it has exceeded 15s
# and failed a test that was working, which is worse than a slow failure.
_ROUND_TRIP_MS = 45_000


@pytest.mark.integration
def test_browser_agent_workbench_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    token = "browser-web-token-0123456789"
    app = create_app(AnalysisService(settings), token=token, settings=settings)
    app.state.agent_orchestrator.provider_factory = lambda _profile: BrowserFakeProvider()
    port = _port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started

    response_bodies: list[str] = []
    sse_urls: list[str] = []
    secret = "browser-provider-secret-value"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                args=["--disable-gpu", "--no-first-run"],
            )
            page = browser.new_page()

            def capture(response: Response) -> None:
                if "/api/" not in response.url:
                    return
                if "/events?" in response.url:
                    sse_urls.append(response.url)
                    return
                with suppress(Exception):
                    response_bodies.append(response.text())

            page.on("response", capture)
            # A fresh profile lands on the work-direction screen first.
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="你想逆向什么？")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="Agent analysis")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("Message").fill("run read-only tool")
            page.get_by_role("button", name="Send").click()
            expect(page.get_by_text("tool round finished")).to_be_visible(timeout=_ROUND_TRIP_MS)
            expect(page.get_by_text("tool.completed").first).to_be_visible()

            page.get_by_role("button", name="Provider & setup").click()
            page.get_by_label("Base URL").fill("https://example.invalid/v1")
            page.get_by_label("Model").fill("browser-fake")
            page.get_by_label("API key").fill(secret)
            page.get_by_role("button", name="Save server-side").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()

            page.get_by_label("Message").fill("danger approve")
            page.get_by_role("button", name="Send").click()
            expect(page.get_by_role("button", name="Approve once")).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            page.reload()
            expect(page.get_by_role("button", name="Approve once")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            page.get_by_role("button", name="Approve once").click()
            expect(page.get_by_text("tool round finished")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls)

            page.get_by_label("Message").fill("danger reject")
            page.get_by_role("button", name="Send").click()
            expect(page.get_by_role("button", name="Reject", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="Reject", exact=True).click()
            assert rejected_response.value.status == 200
            expect(page.get_by_text("run.rejected")).to_be_visible(timeout=_ROUND_TRIP_MS)

            providers = page.evaluate(
                """async ({token}) => (await fetch('/api/providers', {headers:{Authorization:`Bearer ${token}`}})).text()""",
                {"token": token},
            )
            assert secret not in providers
            dom = page.locator("html").inner_text()
            assert secret not in dom and token not in dom
            storage = page.evaluate(
                "({local:Object.values(localStorage), session:Object.values(sessionStorage), url:location.href})"
            )
            assert secret not in json.dumps(storage)
            assert token not in json.dumps(storage)
            assert all(secret not in body for body in response_bodies)
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        assert not thread.is_alive()
