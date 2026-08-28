"""Reload-resume gate: a run must stream back into a reloaded client.

A run is a detached server-side task -- the orchestrator polls the store for
approval decisions, not the SSE connection -- so a page reload cannot kill it.
The reloaded SPA resumes the event stream from ``history.state``, but it used
to do so with no thread selected, and ``consume()``'s end-of-stream message
reconciliation was gated on a selected thread: terminal events clear
streamingText without committing it, so everything the run said *after* the
reload vanished and the transcript stayed empty. Observed live before the fix:
reload while a tool approval was pending, click approve, and the continued
assistant turn never appeared.

This gate drives the exact scenario end to end against the shipped SPA and a
real (bundled) Chromium: send a message that parks on a file-write approval,
reload, verify the approval card and the replayed round text survive and the
SSE resumes from the recorded cursor, approve, and require the continued run
to stream back and to remain in the transcript after the run has fully ended,
with the pre-reload conversation restored alongside it. skip != pass -- it
skips honestly when the bundled browser is not installed.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

from headless_re_mcp.agent.providers.base import ProviderEvent, ProviderToolCall
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

JsonObject = dict[str, Any]

# Every wait covers a real round trip (SSE, a run, tool execution); in a loaded
# full-suite run these have exceeded 15s, which is worse than a slow failure.
_ROUND_TRIP_MS = 45_000


class ReloadFakeProvider:
    """First turn parks on a human approval; the turn after the tool finishes."""

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
        if any(item.get("role") == "tool" for item in messages):
            yield ProviderEvent("text_delta", text="tool round finished")
            yield ProviderEvent("completed")
            return
        yield ProviderEvent("text_delta", text="dangerous operation proposed")
        # report.generate is FILE_WRITE, which the shipped packed-analysis
        # default preset still routes to a human, so the run parks awaiting
        # approval. The args need only reach the approval gate; execution
        # afterwards may fail harmlessly (missing session).
        yield ProviderEvent(
            "completed",
            tool_calls=(
                ProviderToolCall(
                    "danger-call", "report.generate", {"session_id": "missing-session"}
                ),
            ),
        )

    async def list_models(self) -> list[str]:
        return ["reload-fake"]


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.integration
def test_run_resumed_after_reload_streams_its_continuation_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    token = "reload-web-token-0123456789"
    app = create_app(AnalysisService(settings), token=token, settings=settings)
    app.state.agent_orchestrator.provider_factory = lambda _profile: ReloadFakeProvider()
    port = _port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started

    sse_urls: list[str] = []
    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-gpu", "--no-first-run"],
                )
            except PlaywrightError as exc:
                pytest.skip(
                    "bundled Chromium is not installed (run 'playwright install "
                    f"chromium') — reload-resume Gate not run (skip != pass): {exc}"
                )
            page = browser.new_page()
            def capture(response: Any) -> None:
                if "/events?" in response.url:
                    sse_urls.append(response.url)

            page.on("response", capture)

            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_role("heading", name="开始一段分析")).to_be_visible()
            # Seed the stored profile choice instead of clicking so this gate
            # does not persist a workspace profile into the real user config.
            page.evaluate("localStorage.setItem('headless_ws_profile','full')")
            page.goto(f"http://127.0.0.1:{port}/?token={token}")
            expect(page.get_by_label("消息")).to_be_visible()

            page.get_by_label("消息").fill("danger approve")
            page.get_by_role("button", name="发送").click()
            approve_once = page.get_by_role("button", name="批准一次")
            expect(approve_once).to_be_visible(timeout=_ROUND_TRIP_MS)
            prior_seq = int(page.evaluate("window.history.state.runSeq"))
            assert prior_seq > 0

            page.reload()
            # The pending approval and the replayed round text survive the
            # reload; the stream resumes from the recorded cursor, not zero.
            approve_once = page.get_by_role("button", name="批准一次")
            expect(approve_once).to_be_visible(timeout=_ROUND_TRIP_MS)
            expect(
                page.get_by_text("dangerous operation proposed", exact=True).first
            ).to_be_visible(timeout=_ROUND_TRIP_MS)
            assert any(f"after={prior_seq}" in url for url in sse_urls), sse_urls

            # Approve: the continued run must stream back to THIS reloaded
            # client -- the assertion that failed before the fix.
            page.get_by_role("button", name="批准一次").click()
            expect(page.get_by_text("tool round finished", exact=True).first).to_be_visible(
                timeout=_ROUND_TRIP_MS
            )
            # Durability: a reconciled message, not a streamingText flash that
            # the terminal event wipes. The user's own message coming back as a
            # transcript paragraph (and naming the thread in the rail) is proof
            # the run's thread got selected again.
            page.wait_for_timeout(1500)
            expect(page.get_by_text("tool round finished", exact=True).first).to_be_visible()
            expect(page.get_by_role("paragraph").filter(has_text="danger approve")).to_be_visible()
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        assert not thread.is_alive()
