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

# playwright ships in the [browser] extra and uvicorn/FastAPI in [web]; both
# are optional. Importing them unguarded at module level turns a partial
# install into a collection *error* that aborts the entire tests/integration
# run — no other gate can even start — instead of the per-module skip every
# sibling gate degrades to when its tool is absent (skip != pass, but a
# collection abort is neither).
pytest.importorskip(
    "playwright.sync_api",
    reason="playwright is not installed (pip install -e '.[browser]') — browser smoke gate skipped",
)
pytest.importorskip(
    "uvicorn",
    reason="uvicorn is not installed (pip install -e '.[web]') — browser smoke gate skipped",
)
pytest.importorskip(
    "headless_re_mcp.web.app",
    reason="web extra is not installed (pip install -e '.[web]') — browser smoke gate skipped",
)

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
        # report.generate is FILE_WRITE, which the shipped packed-analysis default
        # preset (agent_auto_approve_effects = state_change) still routes to a
        # human. A state-change tool such as workflow.cancel would now be
        # auto-approved by that preset, so it can no longer drive the approval UI
        # this gate exists to exercise. The args need only reach the approval
        # gate; execution afterward may fail harmlessly (missing session).
        yield ProviderEvent(
            "completed",
            tool_calls=(ProviderToolCall("danger-call", "report.generate", {"session_id": "missing-session"}),),
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
            # Launch Playwright's bundled Chromium exactly the way the product
            # does (WebBackend.open -> pw.chromium.launch(headless=...)). The
            # test used to pin executable_path to an absolute Windows Chrome path
            # (C:\Program Files\Google\Chrome\...), so it hard-failed with
            # "executable doesn't exist" on Linux/macOS -- and on any Windows box
            # where Chrome was installed elsewhere or not at all -- instead of
            # running or skipping. It also meant the smoke test exercised system
            # Chrome rather than the browser the product actually ships. Skip
            # honestly (skip != pass) when the bundled browser is not installed.
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except PlaywrightError as exc:
                pytest.skip(
                    "bundled Chromium is not installed (run 'playwright install "
                    f"chromium') — browser smoke Gate not run (skip != pass): {exc}"
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
            # A fresh profile lands on the work-direction screen first. The
            # selectors below track the shipped (Chinese) SPA: the landing
            # heading is "开始一段分析", the composer field is aria-label "消息",
            # etc. These had rotted to an older English UI, but the test never
            # caught it because it hard-failed at browser launch first.
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # The composer is the stable workbench marker: it only renders once
            # the landing has been skipped for a chosen profile.
            expect(page.get_by_label("消息")).to_be_visible()
            assert "token=" not in page.url

            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            # exact=True targets the rendered assistant paragraph; the same text
            # also appears inside a raw SSE-delta <pre> in the run event log, so a
            # substring match is a strict-mode violation.
            expect(page.get_by_text("tool round finished", exact=True)).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            # Raw run events (tool.completed, run.rejected below) render in the
            # Inspector's "事件" tab, which is not the default "监视" tab, so the
            # event log is present-but-hidden until we switch to it. The Inspector
            # is a separate aside, so this does not disturb the center composer or
            # the approval cards. The tab stays selected for the rest of the run.
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("tool.completed").first).to_be_visible(timeout=_ROUND_TRIP_MS)

            page.get_by_role("button", name="设置").click()
            page.get_by_label("接口地址").fill("https://example.invalid/v1")
            page.get_by_label("模型", exact=True).fill("browser-fake")
            page.get_by_label("API 密钥", exact=False).fill(secret)
            page.get_by_role("button", name="保存模型").click()
            # Saving keeps the modal open and shows a success note rather than
            # dismissing the dialog, so confirm the round trip landed and then
            # close explicitly via the × control.
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible(timeout=_ROUND_TRIP_MS)
            page.locator("button.modal-close").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()

            # Approve path (no reload): the file-write tool parks for a human,
            # and approving it runs the tool and lets the run continue to its
            # next assistant turn.
            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="批准一次")).to_be_visible(timeout=_ROUND_TRIP_MS)
            page.get_by_role("button", name="批准一次").click()
            expect(page.get_by_text("tool round finished", exact=True).first).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )

            # Reject path, exercised across a reload: a pending approval is
            # security-relevant, so it must survive a page refresh (never
            # auto-fire, never vanish) and the run must resume from the recorded
            # sequence rather than replaying from zero. Reject is terminal via a
            # POST, so it is the robust place to assert the resume: it does not
            # depend on a fresh assistant turn streaming back after the reload.
            page.get_by_label("消息").fill("danger reject")
            page.get_by_role("button", name="发送").click()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0
            page.reload()
            expect(page.get_by_role("button", name="拒绝", exact=True)).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert "token=" not in page.url
            assert any(f"after={prior_seq}" in url for url in sse_urls)
            with page.expect_response(
                lambda response: response.url.endswith("/reject"), timeout=_ROUND_TRIP_MS
            ) as rejected_response:
                page.get_by_role("button", name="拒绝", exact=True).click()
            assert rejected_response.value.status == 200
            # The reload reset the Inspector back to its default "监视" tab, so
            # re-open the "事件" tab to read the terminal run event.
            page.get_by_role("tab", name="事件").click()
            expect(page.get_by_text("run.rejected").first).to_be_visible(timeout=_ROUND_TRIP_MS)

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
