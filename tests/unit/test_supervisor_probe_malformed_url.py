"""A malformed readiness URL must report unreachable, not raise out of the probe.

``probe_ready``'s contract is that "anything that stops the request from
completing is reported as unreachable" -- it returns ``(False, ...)`` for a bad
scheme or a missing host and even spells the detail ``unreachable: ValueError``
for them, so the intent is that a URL it cannot use is a failed probe, never an
exception. But ``urllib.parse.urlsplit`` raises ``ValueError`` on a malformed
authority (an unclosed IPv6 literal, ``http://[::1``) *before* that guard runs,
and the readiness URL is built straight from the operator's ``--host`` value
(``http://{host}:{port}/readyz``), so a half-bracketed IPv6 host reaches it.

Before the fix the parse error escaped ``probe_ready``; the supervisor's own
``_probe_once`` wrapper happened to catch it and relabel it ``probe raised:
ValueError``, but any other caller of this public helper got an exception where
the docstring promises a verdict. These tests pin the verdict at the source.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.supervisor import probe_ready


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1/readyz",  # unclosed IPv6 bracket -> urlsplit raises
        "http://[::1]extra:9100/readyz",  # junk after the IPv6 literal
    ],
)
def test_a_malformed_url_is_unreachable_not_an_exception(url: str) -> None:
    ok, detail = probe_ready(url, timeout=0.1)
    assert ok is False
    assert detail == "unreachable: ValueError"


def test_a_bracketless_ipv6_host_is_still_unreachable() -> None:
    # http://::1:9100/readyz does not raise but leaves hostname empty; the
    # scheme/hostname guard already turns that into the same verdict, so the two
    # malformed-host shapes an operator can produce agree.
    ok, detail = probe_ready("http://::1:9100/readyz", timeout=0.1)
    assert ok is False
    assert detail == "unreachable: ValueError"
