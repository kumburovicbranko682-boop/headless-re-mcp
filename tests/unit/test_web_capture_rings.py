"""The web capture rings: bounded growth, honest dropped counts, truncation flags.

_wire_events registers four CDP handlers that fill the per-session capture rings
(requests, scripts, console) and set the eviction counters web.status and the
HAR exports now report. Those handlers only ran when a real browser drove CDP
events, so their eviction and truncation branches were untested -- yet the
dropped counters are the honesty signal an operator reads to know a ring has
begun shedding history. These drive the handlers directly through a fake CDP
that captures the registered callbacks, feeding synthetic events to pin: each
ring evicts its oldest entry past the cap and increments its dropped counter by
exactly the number shed; a response updates its matching request and silently
ignores one for a request never seen; and an oversized url/method/mime/console
field is flagged rather than stored whole.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE,
    _MAX_CONSOLE_TEXT,
    _MAX_METADATA_BYTES,
    _MAX_REQUESTS,
    _MAX_SCRIPTS,
    _MAX_URL_BYTES,
    WebBackend,
    _playwright_driver_pid,
    _reap_driver_pid,
    _reap_web_session,
    _WebSession,
)

JsonObject = dict[str, Any]


class _FakeCdp:
    """Records send() calls and captures the handlers _wire_events registers."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, *_args: Any, **_kwargs: Any) -> None:
        self.sent.append(method)

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired() -> tuple[_WebSession, dict[str, Any]]:
    cdp = _FakeCdp()
    handle = _WebSession(None, None, None, None, cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp.handlers


def test_wire_events_enables_the_domains_it_reads() -> None:
    _handle, handlers = _wired()
    assert set(handlers) == {
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Debugger.scriptParsed",
        "Runtime.consoleAPICalled",
    }


def test_request_ring_evicts_oldest_and_counts_exactly_what_it_shed() -> None:
    handle, handlers = _wired()
    on_request = handlers["Network.requestWillBeSent"]
    overflow = 3
    for index in range(_MAX_REQUESTS + overflow):
        on_request(
            {
                "requestId": f"r{index}",
                "request": {"url": f"https://x/{index}", "method": "GET"},
                "type": "Document",
            }
        )
    assert len(handle.requests) == _MAX_REQUESTS
    assert handle.requests_dropped == overflow
    # The oldest ids are the ones gone; the newest survive.
    assert "r0" not in handle.requests
    assert f"r{_MAX_REQUESTS + overflow - 1}" in handle.requests


def test_response_updates_its_request_and_ignores_an_unknown_one() -> None:
    handle, handlers = _wired()
    handlers["Network.requestWillBeSent"](
        {"requestId": "r1", "request": {"url": "https://x/1", "method": "GET"}, "type": "XHR"}
    )
    handlers["Network.responseReceived"](
        {"requestId": "r1", "response": {"status": 200, "mimeType": "application/json"}}
    )
    assert handle.requests["r1"]["status"] == 200
    assert handle.requests["r1"]["mimeType"] == "application/json"

    # A response for a request that was never (or no longer) recorded must be a
    # no-op, not a crash or a phantom entry.
    handlers["Network.responseReceived"](
        {"requestId": "ghost", "response": {"status": 500, "mimeType": "text/html"}}
    )
    assert "ghost" not in handle.requests


def test_script_ring_evicts_oldest_and_counts_exactly_what_it_shed() -> None:
    handle, handlers = _wired()
    on_script = handlers["Debugger.scriptParsed"]
    overflow = 4
    for index in range(_MAX_SCRIPTS + overflow):
        on_script({"scriptId": f"s{index}", "url": f"https://x/{index}.js"})
    assert len(handle.scripts) == _MAX_SCRIPTS
    assert handle.scripts_dropped == overflow


def test_console_ring_evicts_oldest_and_counts_exactly_what_it_shed() -> None:
    handle, handlers = _wired()
    on_console = handlers["Runtime.consoleAPICalled"]
    overflow = 5
    for index in range(_MAX_CONSOLE + overflow):
        on_console({"type": "log", "args": [{"value": f"line {index}"}]})
    assert len(handle.console) == _MAX_CONSOLE
    assert handle.console_dropped == overflow


def test_oversized_request_fields_are_flagged_not_stored_whole() -> None:
    handle, handlers = _wired()
    handlers["Network.requestWillBeSent"](
        {
            "requestId": "big",
            "request": {
                "url": "https://x/" + ("u" * (_MAX_URL_BYTES + 50)),
                "method": "M" * (_MAX_METADATA_BYTES + 50),
            },
            "type": "Document",
        }
    )
    entry = handle.requests["big"]
    assert entry["metadata_truncated"] is True
    assert len(entry["url"].encode("utf-8")) <= _MAX_URL_BYTES
    assert len(entry["method"].encode("utf-8")) <= _MAX_METADATA_BYTES


def test_a_request_with_ordinary_fields_carries_no_truncation_flag() -> None:
    handle, handlers = _wired()
    handlers["Network.requestWillBeSent"](
        {"requestId": "ok", "request": {"url": "https://x/ok", "method": "GET"}, "type": "Fetch"}
    )
    assert "metadata_truncated" not in handle.requests["ok"]


def test_oversized_response_mime_flags_the_existing_entry() -> None:
    handle, handlers = _wired()
    handlers["Network.requestWillBeSent"](
        {"requestId": "r", "request": {"url": "https://x/r", "method": "GET"}, "type": "XHR"}
    )
    handlers["Network.responseReceived"](
        {"requestId": "r", "response": {"status": 200, "mimeType": "z" * (_MAX_METADATA_BYTES + 5)}}
    )
    assert handle.requests["r"]["metadata_truncated"] is True


def test_oversized_script_url_is_flagged_not_stored_whole() -> None:
    handle, handlers = _wired()
    handlers["Debugger.scriptParsed"](
        {"scriptId": "big", "url": "https://x/" + ("u" * (_MAX_URL_BYTES + 50))}
    )
    entry = handle.scripts["big"]
    assert entry["metadata_truncated"] is True
    assert len(entry["url"].encode("utf-8")) <= _MAX_URL_BYTES


def test_an_ordinary_script_carries_no_truncation_flag() -> None:
    handle, handlers = _wired()
    handlers["Debugger.scriptParsed"]({"scriptId": "s", "url": "https://x/s.js"})
    assert "metadata_truncated" not in handle.scripts["s"]


def test_oversized_console_text_is_flagged_truncated() -> None:
    handle, handlers = _wired()
    handlers["Runtime.consoleAPICalled"](
        {"type": "error", "args": [{"value": "z" * (_MAX_CONSOLE_TEXT + 100)}]}
    )
    entry = handle.console[-1]
    assert entry["text_truncated"] is True
    assert len(entry["text"]) <= _MAX_CONSOLE_TEXT


def test_ordinary_console_text_carries_no_flag() -> None:
    handle, handlers = _wired()
    handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "hello"}]})
    assert "text_truncated" not in handle.console[-1]


def _pid_chain(pid: Any) -> SimpleNamespace:
    """A stand-in for playwright's private _impl_obj._connection._transport._proc
    chain, the only handle a wedged session has to the driver process."""
    return SimpleNamespace(
        _impl_obj=SimpleNamespace(
            _connection=SimpleNamespace(
                _transport=SimpleNamespace(_proc=SimpleNamespace(pid=pid))
            )
        )
    )


def test_driver_pid_walks_the_private_chain_to_the_proc() -> None:
    assert _playwright_driver_pid(_pid_chain(4321)) == 4321


def test_driver_pid_is_none_when_the_private_chain_breaks() -> None:
    """A playwright build that renamed or dropped a link in the chain must yield
    None, not raise -- reaping simply has no pid to act on."""
    broken = SimpleNamespace(_impl_obj=SimpleNamespace())  # no _connection beyond here
    assert _playwright_driver_pid(broken) is None


@pytest.mark.parametrize("bad_pid", [0, -1, "1234", None])
def test_driver_pid_rejects_a_non_positive_or_non_int_pid(bad_pid: Any) -> None:
    assert _playwright_driver_pid(_pid_chain(bad_pid)) is None


def test_reap_driver_pid_ignores_a_non_positive_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must short-circuit before it ever asks the OS about the pid --
    a 0/negative/None pid is not a process to inspect, let alone kill."""
    looked_up: list[Any] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: looked_up.append(pid))
    for bad in (0, -5, None):
        _reap_driver_pid(bad)  # type: ignore[arg-type]
    assert looked_up == []


def test_reap_driver_pid_spares_a_pid_whose_image_is_not_a_driver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pids are recycled; killing a tree by number alone could take out an
    unrelated process. Only an image that looks like the node/chromium driver is
    terminated -- a plain python process is left alone."""
    terminated: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/usr/bin/python3")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: terminated.append(pid))
    _reap_driver_pid(12345)
    assert terminated == []


def test_reap_driver_pid_terminates_a_matching_driver_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "/opt/node/bin/node")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: terminated.append(pid))
    _reap_driver_pid(999)
    assert terminated == [999]


def test_reap_web_session_reaps_the_handles_driver_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []
    monkeypatch.setattr(web_client, "process_image_path", lambda pid: "chromium")
    monkeypatch.setattr(web_client, "terminate_pid_tree", lambda pid: terminated.append(pid))
    _reap_web_session(SimpleNamespace(driver_pid=777))  # type: ignore[arg-type]
    assert terminated == [777]
