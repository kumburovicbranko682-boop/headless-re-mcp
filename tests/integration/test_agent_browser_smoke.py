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
from playwright.sync_api import Response, expect, sync_playwright

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


@pytest.mark.integration
def test_browser_agent_workbench_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    # Fail-closed autonomy so the danger tool actually parks for a human. The
    # shipped default applies the packed-analysis preset, which auto-approves
    # the state_change effect (and workflow.cancel is a state_change tool), so
    # without this the approval card never appears and the flow can't be tested.
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
            # Playwright's own bundled chromium, the same one WebBackend
            # launches (pw.chromium.launch(headless=...)). Pinning a system
            # Chrome path made this gate Windows-only and pass/fail on whether
            # a machine happened to have Chrome installed at that path; the
            # bundled browser is what `playwright install chromium` provides.
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except PlaywrightError as exc:
                pytest.skip(
                    f"chromium not installed for playwright ({exc}) — skip != pass"
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
            # A fresh profile lands on the work-direction screen first. The SPA
            # ships as a prebuilt bundle under src/.../web/spa, and its whole
            # surface is Chinese now, so these selectors track the served UI.
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # No thread is selected yet, so the conversation header reads 新对话.
            expect(page.get_by_role("heading", name="新对话")).to_be_visible()
            assert "token=" not in page.url

            # Raw event names (tool.completed, run.rejected) only render inside
            # the inspector's 事件 tab; it starts on 监视 and every reload remounts
            # the SPA and resets it, so re-select the tab before each check.
            def show_events() -> None:
                page.get_by_role("tab", name="事件").click()

            show_events()
            page.get_by_label("消息", exact=True).fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_text("tool round finished", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            expect(page.get_by_text("tool.completed").first).to_be_visible()

            # The settings modal keeps itself open after a save (it shows a
            # confirmation note instead of closing), so close it explicitly and
            # confirm it is gone before moving on.
            page.get_by_role("button", name="设置", exact=True).click()
            page.get_by_label("接口地址", exact=True).fill("https://example.invalid/v1")
            page.get_by_label("模型", exact=True).fill("browser-fake")
            page.get_by_label("API 密钥").fill(secret)
            page.get_by_role("button", name="保存模型").click()
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible()
            page.locator(".modal-close").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()

            page.get_by_label("消息", exact=True).fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            page.reload()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            page.get_by_role("button", name="批准一次").click()
            # After a reload-resume the SPA does not re-select the thread, so the
            # second-round assistant text only flashes as transient streaming
            # text and is never persisted into the transcript. The durable proof
            # the approved round ran to completion is the run.completed event,
            # plus the resumed SSE stream reconnecting after the pre-reload seq.
            show_events()
            expect(page.get_by_text("run.completed").first).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls)

            page.get_by_label("消息", exact=True).fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            show_events()
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
