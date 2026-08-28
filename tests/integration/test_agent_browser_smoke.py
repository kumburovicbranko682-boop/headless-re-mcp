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

# Skip the whole module (rather than error at collection) when playwright is not
# installed, exactly like the other web gates degrade. This keeps a bare machine
# -- or the Linux quality runner without the browser extra -- from turning a
# missing optional backend into a hard collection error for tests/integration.
_playwright = pytest.importorskip("playwright.sync_api")
Response = _playwright.Response
expect = _playwright.expect
sync_playwright = _playwright.sync_playwright

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall  # noqa: E402
from headless_re_mcp.config import Settings  # noqa: E402
from headless_re_mcp.core.service import AnalysisService  # noqa: E402
from headless_re_mcp.web.app import create_app  # noqa: E402

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
    # Pin fail-closed autonomy. The machine default now auto-approves the
    # state_change effect (packed-PE analysis preset), which would let the
    # "danger" tool below run unattended and never raise the approval card this
    # gate exercises. Empty allowlists restore the read-only-only baseline.
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
            # Playwright's own managed Chromium (installed via
            # ``playwright install chromium``) rather than a hardcoded system
            # path: the old absolute ``C:\Program Files\...\chrome.exe`` could
            # only ever launch on a Windows box with Chrome installed there, so
            # the agent-workbench smoke never ran on Linux. The managed browser
            # is portable across both runners.
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"chromium could not launch ({exc}) — Gate not run (skip != pass)")
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
            # A fresh profile lands on the work-direction screen first
            # (WorkspaceLanding, heading 开始一段分析).
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # The workbench composer is the stable "we are past the landing"
            # anchor; the chat heading is the (empty) thread title, not fixed copy.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            # exact=True so this matches the chat bubble <p>, not the event
            # JSON <pre> that also embeds the delta text in the 事件 tab.
            expect(
                page.get_by_text("tool round finished", exact=True)
            ).to_be_visible(timeout=_ROUND_TRIP_MS)
            # Raw event kinds live in the inspector's 事件 (events) tab.
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("tool.completed").first).to_be_visible()

            # One "模型与设置" dialog holds provider + backend setup; save it
            # server-side, then close it (saving does not auto-dismiss).
            page.get_by_role("button", name="设置").click()
            page.get_by_label("接口地址", exact=True).fill("https://example.invalid/v1")
            page.get_by_label("模型", exact=True).fill("browser-fake")
            page.get_by_label("API 密钥").fill(secret)
            page.get_by_role("button", name="保存模型").click()
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible(timeout=_ROUND_TRIP_MS)
            page.get_by_role("button", name="×").click()
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
            # After the reload the workbench resumes the run but not the thread
            # selection, so the finished assistant bubble is never reloaded into
            # the transcript. Assert the run itself reached completion through the
            # resumed event stream instead (events tab).
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("run.completed").first).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls)

            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            # The reload above reset the inspector to its 监视 tab; reopen 事件
            # to read the terminal run.rejected event kind.
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
