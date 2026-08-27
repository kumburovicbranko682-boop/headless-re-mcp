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

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

# A top-level ``from playwright.sync_api import ...`` made this module fail to
# import on any machine without playwright, which aborts collection of the
# whole tests/integration directory rather than skipping this one gate -- worse
# than the "skip != pass" contract every other backend follows. importorskip
# turns a missing playwright into a clean module skip instead.
_playwright_sync = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright not installed — browser workbench Gate not run (skip != pass)",
)
Response = _playwright_sync.Response
expect = _playwright_sync.expect
sync_playwright = _playwright_sync.sync_playwright

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
    secret = "browser-provider-secret-value"
    try:
        with sync_playwright() as playwright:
            # Playwright's bundled Chromium, matching WebBackend.open, instead of
            # a hardcoded system Chrome path: the old absolute Windows path meant
            # this gate could never run anywhere else even with playwright
            # present. A machine that installed playwright but not the browser
            # skips honestly rather than erroring.
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except Exception as exc:  # noqa: BLE001
                pytest.skip(
                    "chromium could not launch (run 'playwright install chromium'?): "
                    f"{exc} — skip != pass"
                )
            page = browser.new_page()

            def capture(response: Response) -> None:
                # SSE bodies never resolve to text(); skip them and keep every
                # other API reply so the secret-leak check sees them all.
                if "/api/" not in response.url or "/events?" in response.url:
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
            # The agent workbench is identified by its composer. The token must
            # not linger in the URL once the SPA has read it into a header.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            # One full read-only round trip over SSE: the fake provider streams
            # text, proposes a read-only tool (doctor, which auto-runs), and is
            # called again with the tool result, ending with this line. Its
            # arrival proves the browser drove a whole run end to end -- SSE,
            # a run, and a real tool execution -- not just that the page loaded.
            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            expect(
                page.get_by_text("tool round finished", exact=True)
            ).to_be_visible(timeout=_ROUND_TRIP_MS)

            # Saving a provider writes a secret to the loopback service; it must
            # never come back to the page. The dialog stays open on save (it
            # shows a confirmation note), so close it explicitly before reading
            # the DOM back. The approval UI that used to follow here is covered
            # by webui component tests; the default autonomy now auto-runs the
            # state-change tool this smoke test used to prompt on, so driving an
            # approval card in-browser would need bespoke fail-closed setup.
            page.get_by_role("button", name="设置").click()
            dialog = page.get_by_role("dialog", name="模型与设置")
            expect(dialog).to_be_visible()
            dialog.get_by_label("接口地址").fill("https://example.invalid/v1")
            dialog.get_by_label("模型", exact=True).fill("browser-fake")
            dialog.locator("input[type=password]").fill(secret)
            dialog.get_by_role("button", name="保存模型").click()
            expect(
                page.get_by_text("模型设置已保存到本机服务。")
            ).to_be_visible(timeout=_ROUND_TRIP_MS)
            dialog.get_by_role("button", name="×").click()
            expect(page.get_by_role("dialog")).to_have_count(0)

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
