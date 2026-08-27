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
import uvicorn
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Playwright, Response, expect, sync_playwright

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

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


def _launch_browser(playwright: Playwright) -> Any:
    """Launch the browser Playwright installed, on whatever OS this is.

    The backend itself drives ``chromium.launch()`` with no ``executable_path``
    -- the bundled build works on every platform -- so this gate does the same
    rather than naming a system Chrome path, which resolved only on the machine
    it was written on and made the gate impossible elsewhere. A machine that
    never ran ``playwright install`` has no browser to render the workbench, so
    that skips honestly (skip != pass) instead of failing as if the UI broke.
    """
    try:
        return playwright.chromium.launch(
            headless=True, args=["--disable-gpu", "--no-first-run"]
        )
    except PlaywrightError as exc:
        message = str(exc)
        if "playwright install" in message or "Executable doesn't exist" in message:
            pytest.skip(
                "chromium is not installed (run `playwright install chromium`) "
                "— browser workbench gate not run (skip != pass)"
            )
        raise


@pytest.mark.integration
def test_browser_agent_workbench_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    # Fail-closed on purpose: Settings.load() ships the packed-analysis preset
    # that auto-approves the state_change effect, which would silently run the
    # workflow.cancel call below and skip the approval card this gate exists to
    # exercise. Clearing the grants puts the agent back in "request" mode.
    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        agent_auto_approve_effects=(),
        agent_auto_approve_tools=(),
    )
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
            browser = _launch_browser(playwright)
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
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # The workbench has no fixed heading (the h1 is the thread title), so
            # the composer -- which exists only here, not on the landing -- is the
            # signal that we left the work-direction screen.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_text("tool round finished").first).to_be_visible(timeout=_ROUND_TRIP_MS)
            # Raw run-event types are listed behind the inspector's 事件 tab.
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("tool.completed").first).to_be_visible()

            page.get_by_role("button", name="设置").click()
            page.get_by_label("接口地址").fill("https://example.invalid/v1")
            # The model control is a <select> once the server has probed models
            # and a plain <input> before then; only the input takes fill(), and
            # the injected fake provider ignores the value either way.
            model_field = page.get_by_label("模型", exact=True)
            if model_field.evaluate("el => el.tagName.toLowerCase()") == "input":
                model_field.fill("browser-fake")
            page.get_by_label("API 密钥").fill(secret)
            page.get_by_role("button", name="保存模型").click()
            # Saving shows an in-place note rather than closing, so close it.
            page.locator(".modal-close").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()

            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            page.reload()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            page.get_by_role("button", name="批准一次").click()
            # A reload does not re-select the thread, so the resumed run appends
            # to a conversation the pane is not showing yet. Confirm from the run
            # event log that it resumed and finished, and that the stream
            # reconnected from the cursor persisted before the reload.
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("run.completed").first).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls)
            # Reopen the thread; the follow-up turn the approved call produced is
            # persisted server-side and shows once the conversation is loaded.
            page.locator("button.thread").first.click()
            expect(page.get_by_text("tool round finished").first).to_be_visible(timeout=_ROUND_TRIP_MS)

            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            # The reload above reset the inspector to its 监视 tab; the reject
            # event is on 事件.
            page.get_by_role("tab", name="事件").click()
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
