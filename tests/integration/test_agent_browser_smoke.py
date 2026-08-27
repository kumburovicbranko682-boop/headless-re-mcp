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
from typing import TYPE_CHECKING, Any

import pytest
import uvicorn

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

if TYPE_CHECKING:
    from playwright.sync_api import Response

# importorskip, not a plain import: on a machine without the optional browser
# extra a hard import errors the whole file at collection time, which reads as
# a broken suite instead of an honest "backend absent" skip.
_playwright_api = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright not installed — browser smoke Gate not run (skip != pass)",
)
expect = _playwright_api.expect
sync_playwright = _playwright_api.sync_playwright

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
        # patches.apply is on the never-auto-approve side of the default
        # policy (state_change and most file_writes are waved through on a
        # fresh machine), so this is guaranteed to raise an approval card.
        yield ProviderEvent(
            "completed",
            tool_calls=(ProviderToolCall("danger-call", "patches.apply", {"session_id": "missing-session"}),),
        )

    async def list_models(self) -> list[str]:
        return ["browser-fake"]


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


_WINDOWS_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


def _launch_chromium(playwright: Any) -> Any:
    """System Chrome on Windows when present, else playwright's own chromium.

    The fallback is what production (`WebBackend.open`) launches, so it is the
    path that must work on Linux; the system-Chrome branch keeps the Windows
    dev machines working without a `playwright install` download.
    """
    kwargs: dict[str, Any] = {"headless": True, "args": ["--disable-gpu", "--no-first-run"]}
    if os.name == "nt" and _WINDOWS_CHROME.is_file():
        kwargs["executable_path"] = str(_WINDOWS_CHROME)
    try:
        return playwright.chromium.launch(**kwargs)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"chromium could not launch ({exc}) — browser smoke Gate not run (skip != pass)")


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
            expect(page.get_by_role("heading", name="新对话")).to_be_visible()
            assert "token=" not in page.url

            # Scoped to the transcript: the inspector keeps a hidden raw-event
            # drawer that also contains every streamed string.
            transcript = page.locator(".transcript")
            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            expect(transcript.get_by_text("tool round finished")).to_be_visible(timeout=_ROUND_TRIP_MS)
            # The transcript must show the tool round itself (role label 工具),
            # not just the model's closing words.
            expect(transcript.get_by_text("工具", exact=True).first).to_be_visible()

            page.get_by_role("button", name="设置", exact=True).click()
            dialog = page.get_by_role("dialog", name="模型与设置")
            dialog.get_by_label("接口地址").fill("https://example.invalid/v1")
            dialog.get_by_label("模型", exact=True).fill("browser-fake")
            dialog.get_by_label("API 密钥").fill(secret)
            dialog.get_by_role("button", name="保存模型").click()
            expect(dialog.get_by_text("模型设置已保存到本机服务。")).to_be_visible()
            dialog.get_by_role("button", name="×").click()
            expect(page.get_by_role("dialog", name="模型与设置")).not_to_be_visible()

            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            page.reload()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            page.get_by_role("button", name="批准一次").click()
            # The reload dropped the thread selection, so pick the conversation
            # back up from the rail. Selecting is race-free with the resumed
            # run: the message list is refetched again when its stream ends.
            page.locator(".thread-row .thread").first.click()
            # A second closing line, not just the surviving first one.
            expect(transcript.get_by_text("tool round finished")).to_have_count(
                2, timeout=_ROUND_TRIP_MS
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
            expect(page.get_by_text("本轮已停")).to_be_visible(timeout=_ROUND_TRIP_MS)

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
