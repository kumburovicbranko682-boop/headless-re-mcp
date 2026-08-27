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
    # Fail-closed autonomy so the write tool this gate proposes actually pauses
    # for approval. The packed-PE default auto-approves state_change, which would
    # run workflow.cancel outright and the approval card -- the whole point of the
    # approve/reject legs below -- would never appear.
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
            # Drive the Playwright-managed Chromium, the same build the WebBackend
            # launches. Pinning an absolute system-Chrome path made this gate
            # Windows-only by accident: it could never find a browser on Linux CI,
            # which is exactly where the portable Web line most needs proving.
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except PlaywrightError as exc:
                # The pip package can be present while the browser binary is not
                # (it is a separate `playwright install chromium` download). Skip
                # cleanly like every other backend gate rather than hard-failing
                # with a launch error that reads like a real regression.
                message = str(exc)
                if "Executable doesn't exist" in message or "playwright install" in message:
                    pytest.skip(
                        "Playwright Chromium not installed — run 'playwright install "
                        "chromium' (skip != pass)"
                    )
                raise
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
            # Past the landing, the workbench composer is what proves the agent
            # view mounted; it carries a stable aria-label the redesign kept.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            # The read-only tool auto-runs and the fake provider closes the round
            # with this line, which is the visible proof the tool round completed.
            # exact=True so the assistant paragraph is matched, not the raw event
            # JSON ({"delta": "tool round finished"}) the inspector also renders.
            expect(
                page.get_by_text("tool round finished", exact=True).last
            ).to_be_visible(timeout=_ROUND_TRIP_MS)

            page.get_by_role("button", name="设置").click()
            page.get_by_label("接口地址").fill("https://example.invalid/v1")
            # exact=True: the dialog's own aria-label ("模型与设置") also contains 模型.
            page.get_by_label("模型", exact=True).fill("browser-fake")
            page.get_by_label("API 密钥").fill(secret)
            page.get_by_role("button", name="保存模型").click()
            # The provider form saves in place rather than dismissing the modal,
            # so wait for the saved-note and close it explicitly.
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible(timeout=_ROUND_TRIP_MS)
            page.locator(".modal-close").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()

            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            # The pending approval must survive a reload: the run lives server-side,
            # so the card returns from replayed history rather than a fresh proposal.
            page.reload()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            with page.expect_response(
                lambda response: response.url.endswith("/approve"), timeout=_ROUND_TRIP_MS
            ) as approved_response:
                page.get_by_role("button", name="批准一次").click()
            assert approved_response.value.status == 200
            # Approving resolves the card, and the resumed stream continues from the
            # cursor the reload carried rather than replaying the run from zero.
            expect(page.get_by_role("button", name="批准一次")).not_to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            assert any(f"after={prior_seq}" in url for url in sse_urls)

            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            # The rejected tool call resolves the approval, so its card -- and the
            # reject button with it -- comes off the transcript.
            expect(page.get_by_role("button", name="拒绝", exact=True)).not_to_be_visible(
                timeout=_ROUND_TRIP_MS
            )

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
