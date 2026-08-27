from __future__ import annotations

import json
import os
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
from playwright.sync_api import Browser, Playwright, Response, expect, sync_playwright
from playwright.sync_api import Error as PlaywrightError

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
        last_user = max(
            (index for index, item in enumerate(messages) if item.get("role") == "user"), default=-1
        )
        user = str(messages[last_user].get("content", "")) if last_user >= 0 else ""
        tool_after_user = any(item.get("role") == "tool" for item in messages[last_user + 1 :])
        if tool_after_user:
            yield ProviderEvent("text_delta", text="tool round finished")
            yield ProviderEvent("completed")
            return
        if "read" in user:
            yield ProviderEvent("text_delta", text="running read-only check")
            yield ProviderEvent(
                "completed", tool_calls=(ProviderToolCall("read-call", "doctor", {}),)
            )
            return
        # patches.apply carries FILE_WRITE + STATE_CHANGE and is on the default
        # policy's excluded list, so it parks for approval even under the packed
        # analysis preset (unlike a bare state_change tool, which auto-approves).
        yield ProviderEvent("text_delta", text="dangerous operation proposed")
        yield ProviderEvent(
            "completed",
            tool_calls=(
                ProviderToolCall("danger-call", "patches.apply", {"session_id": "missing-session"}),
            ),
        )

    async def list_models(self) -> list[str]:
        return ["browser-fake"]


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _launch_chromium(playwright: Playwright) -> Browser:
    """Launch a headless Chromium for the smoke test, portably.

    The web backend drives Playwright's bundled Chromium
    (``pw.chromium.launch``), so this gate does the same instead of pinning a
    machine-specific ``chrome.exe`` path, which made the test hard-fail on any
    host without Chrome at that exact Windows location. Preference order:

    1. an explicit executable from ``HEADLESS_RE_TEST_CHROME`` (escape hatch),
    2. Playwright's bundled Chromium (matches the backend; present after
       ``playwright install chromium``),
    3. an installed system Chrome via the ``chrome`` channel (Playwright
       resolves the per-OS install path).

    When none is available the gate *skips* -- a missing browser is an
    environment gap, not a product regression, and "skip != pass" is honoured
    by reporting the reason.
    """
    args = ["--disable-gpu", "--no-first-run"]
    attempts: list[dict[str, Any]] = []
    override = os.environ.get("HEADLESS_RE_TEST_CHROME")
    if override:
        attempts.append({"executable_path": override})
    attempts.append({})
    attempts.append({"channel": "chrome"})

    last_error: PlaywrightError | None = None
    for extra in attempts:
        try:
            return playwright.chromium.launch(headless=True, args=args, **extra)
        except PlaywrightError as exc:
            last_error = exc
    pytest.skip(f"no Chromium/Chrome available for Playwright: {last_error}")


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
            browser = _launch_chromium(playwright)
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
            # The agent workbench is anchored by its composer; the message box
            # is only present once past the landing screen.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            # Scope the round-completion marker to the visible transcript: the
            # inspector's events tab also renders each message.delta as a hidden
            # <pre>, so an unscoped `.last` would lock onto that hidden node.
            finished = page.locator(".transcript").get_by_text("tool round finished")

            # A read-only tool call is auto-approved and executed; the fake
            # provider's second round emits this once the tool result comes back.
            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            expect(finished).to_have_count(1, timeout=_ROUND_TRIP_MS)

            # Store a provider secret server-side through the settings modal.
            page.get_by_role("button", name="设置").click()
            dialog = page.get_by_role("dialog")
            expect(dialog).to_be_visible()
            dialog.get_by_label("接口地址").fill("https://example.invalid/v1")
            dialog.get_by_label("模型").fill("browser-fake")
            dialog.get_by_label("API 密钥").fill(secret)
            dialog.get_by_role("button", name="保存模型").click()
            page.get_by_role("button", name="×").click()
            expect(dialog).not_to_be_visible()

            # A write-effect tool must pause for approval instead of running.
            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            # The paused run survives a reload and resumes its event stream from
            # the persisted cursor rather than replaying from zero.
            page.reload()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            assert "token=" not in page.url
            # The resumed stream picks up from the persisted cursor, not zero.
            assert any(f"after={prior_seq}" in url for url in sse_urls)
            # Approving clears the card and lets the paused run advance.
            page.get_by_role("button", name="批准一次").click()
            expect(page.get_by_role("button", name="批准一次")).not_to_be_visible(
                timeout=_ROUND_TRIP_MS
            )

            # Rejecting a write-effect tool posts to the reject endpoint and
            # clears the approval card without running the tool.
            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
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
