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


# Each wait below covers a real round trip -- SSE, a run, and for the read-only
# case an actual `doctor` execution that stats every configured backend path.
# Alone that takes a few seconds; in a loaded full-suite run it has exceeded 15s
# and failed a test that was working, which is worse than a slow failure.
_ROUND_TRIP_MS = 45_000


def _launch_smoke_browser(playwright: Any) -> Any:
    """Launch a browser portably, or skip when none is installed.

    The gate drives the real web workbench, so it needs a real browser -- but
    which one is not the point. Prefer an installed Chrome via the
    cross-platform ``channel`` (what a hardcoded ``C:\\...\\chrome.exe`` path was
    reaching for, minus the OS assumption), fall back to Playwright's bundled
    Chromium, and skip rather than fail when neither can start: a machine with
    no browser is a missing backend, not a regression. Hardcoding one absolute
    path turned every machine that lacked *that* file into a red gate instead of
    an honest skip.
    """
    args = ["--disable-gpu", "--no-first-run"]
    last_error: Exception | None = None
    for kwargs in ({"channel": "chrome"}, {}):
        try:
            return playwright.chromium.launch(headless=True, args=args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - try the next option, skip if none work
            last_error = exc
    pytest.skip(
        "no Chrome/Chromium browser available for the workbench smoke Gate "
        f"(skip != pass): {last_error}"
    )


@pytest.mark.integration
def test_browser_agent_workbench_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    # Fail-closed autonomy so the danger tool actually prompts. The default
    # policy auto-approves state_change for packed-PE analysis, which would
    # silently execute workflow.cancel (a state_change write) and skip the
    # approval card this gate is here to exercise. Explicit empty lists opt out.
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
            # heading tracks WorkspaceLanding.tsx (the committed SPA renders it);
            # keep it in sync there rather than guessing older copy here.
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()

            # Skip past it for the agent flow. Seeding the stored choice rather
            # than clicking keeps this gate from persisting a workspace profile
            # into the real user config; the choice itself is covered by
            # webui/src/components/WorkspaceLanding.test.tsx.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            # The workbench chat header shows the (empty) thread title. Selectors
            # below track App.tsx / SettingsModal.tsx / ApprovalCard.tsx; the UI
            # is Chinese, so match its copy rather than older English strings.
            expect(page.get_by_role("heading", name="新对话")).to_be_visible()
            assert "token=" not in page.url

            # Scope text to the transcript: the Inspector's (hidden) events tab
            # also renders the raw {"delta": ...} payloads, so an unscoped
            # get_by_text resolves to a hidden node instead of the chat bubble.
            transcript = page.locator(".transcript")
            page.get_by_label("消息").fill("run read-only tool")
            page.get_by_role("button", name="发送").click()
            # "tool round finished" is the fake provider's second-round text, so
            # it only appears once a tool round actually completed. .last keeps
            # the assertion valid after later rounds add more of the same text.
            expect(transcript.get_by_text("tool round finished").last).to_be_visible(timeout=_ROUND_TRIP_MS)

            # Settings loads the provider/setup/persona state before populating
            # the fields; wait for that so the async load cannot overwrite what
            # we type. setup/status runs doctor, so it is the slowest of the three.
            with page.expect_response(
                lambda response: "/api/setup/status" in response.url, timeout=_ROUND_TRIP_MS
            ):
                page.get_by_role("button", name="设置").click()
            expect(page.get_by_role("dialog", name="模型与设置")).to_be_visible()
            page.get_by_label("接口地址").fill("https://example.invalid/v1")
            # exact: the dialog's own aria-label "模型与设置" also contains "模型".
            page.get_by_label("模型", exact=True).fill("browser-fake")
            page.get_by_label("API 密钥").fill(secret)
            page.get_by_role("button", name="保存模型").click()
            # Saving keeps the modal open and shows a note; close it explicitly.
            expect(page.get_by_text("模型设置已保存到本机服务。")).to_be_visible(timeout=_ROUND_TRIP_MS)
            page.locator("button.modal-close").click()
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
            # After a reload the run resumes without a selected thread, so its
            # final assistant text is only shown while streaming and is not
            # committed to the transcript. What this sub-test proves is that the
            # approval survived the reload and the decision was accepted (card
            # gone) and that the SSE reconnected from the saved cursor (after=).
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
            # run.rejected is surfaced as a run-outcome hint (state.ts
            # runFailureHint), not as the raw event name the old UI printed.
            expect(transcript.get_by_text("本轮已停").last).to_be_visible(timeout=_ROUND_TRIP_MS)

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
