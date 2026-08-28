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


def _launch_smoke_browser(playwright: Any) -> Any:
    """Launch a browser for the smoke gate on whatever this machine has.

    The gate is not marked Windows-only (see tests/integration/conftest.py), so
    it is expected to run wherever the suite runs. Pinning
    ``executable_path=r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"``
    made it hard-fail on every non-Windows machine -- and even on Windows if
    Chrome sits anywhere else -- with a launch error rather than the honest skip
    the sibling web gates give when no browser is present. Try Playwright's
    bundled Chromium first (``playwright install chromium``), then a
    system Chrome located per-OS via the channel mechanism instead of a
    hardcoded path, and skip (never fail) when neither can launch.
    """
    args = ["--disable-gpu", "--no-first-run"]
    attempts: tuple[dict[str, Any], ...] = ({}, {"channel": "chrome"})
    last_error: Exception | None = None
    for extra in attempts:
        try:
            return playwright.chromium.launch(headless=True, args=args, **extra)
        except Exception as exc:  # noqa: BLE001 - try the next launch strategy
            last_error = exc
    pytest.skip(
        f"no chromium/chrome could launch (install one with "
        f"'playwright install chromium'): {last_error} — skip != pass"
    )


# Each wait below covers a real round trip -- SSE, a run, and for the read-only
# case an actual `doctor` execution that stats every configured backend path.
# Alone that takes a few seconds; in a loaded full-suite run it has exceeded 15s
# and failed a test that was working, which is worse than a slow failure.
_ROUND_TRIP_MS = 45_000


@pytest.mark.integration
def test_browser_agent_workbench_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    # Pin the workbench to request mode. Settings.load() otherwise applies the
    # packed-analysis preset, which auto-approves every state_change effect --
    # and workflow.cancel is a state_change, so the "danger" rounds below would
    # run without ever raising an approval card and the approve/reject UI this
    # gate exists to smoke-test would never appear. Request mode is a real
    # operator switch (webui/src/components/SettingsModal.tsx), so clearing the
    # grants here exercises the product path rather than a contrived one; the
    # read-only doctor round still auto-runs because the read-only baseline is
    # granted unconditionally in AutonomyPolicy.decide.
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
            browser = _launch_smoke_browser(playwright)
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
            # A fresh profile lands on the work-direction screen first. This
            # heading tracks WorkspaceLanding.tsx's <h1>; it was renamed to
            # "开始一段分析" there and in the committed SPA, but this gate still
            # waited for the old "你想逆向什么？" and so timed out here before it
            # could exercise anything -- invisible because integration gates run
            # only on the manual Windows job, never in the Linux unit CI.
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # The agent screen's <h1> is the selected thread title, and a fresh
            # profile has no thread yet, so it reads "新对话" until the first
            # send names a thread after the message. The old English "Agent
            # analysis" heading no longer exists.
            expect(page.get_by_role("heading", name="新对话")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            # "tool round finished" only appears after the read-only tool actually
            # ran and its result was fed back, so it stands in for the old raw
            # "tool.completed" event text the reworked UI no longer prints inline.
            # ``.first`` is deliberate: a finished round leaves the finalized
            # assistant message plus a hidden streaming remnant with the same
            # text, and only the first (finalized) copy is the visible one.
            expect(page.get_by_text("tool round finished").first).to_be_visible(timeout=_ROUND_TRIP_MS)

            page.get_by_role("button", name="设置").click()
            # Scope field lookups to the dialog: the dialog's own aria-label
            # "模型与设置" contains "模型", so an unscoped get_by_label("模型")
            # would match both the dialog and the model input.
            dialog = page.get_by_role("dialog")
            dialog.get_by_label("接口地址").fill("https://example.invalid/v1")
            dialog.get_by_label("模型", exact=True).fill("browser-fake")
            dialog.get_by_label("API 密钥").fill(secret)
            dialog.get_by_role("button", name="保存模型").click()
            # Saving now confirms with a note and leaves the dialog open (it used
            # to close on save), so close it explicitly before asserting it is
            # gone -- the point is that the secret round-trips server-side.
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible(timeout=_ROUND_TRIP_MS)
            dialog.get_by_role("button", name="×").click()
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
            # The card clearing is this run's own proof the approved tool ran to
            # completion; a "tool round finished" message already sits in the
            # transcript from the read-only round, so it cannot discriminate here.
            expect(page.get_by_role("button", name="批准一次")).not_to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls)

            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            expect(page.get_by_role("button", name="拒绝", exact=True)).not_to_be_visible(timeout=_ROUND_TRIP_MS)

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
