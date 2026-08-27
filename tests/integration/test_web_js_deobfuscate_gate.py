"""Live webcrack gate: deobfuscate a real obfuscator.io-style script.

The bundle-graph gate proves webcrack's *unpack_bundle* path (splitting a webpack
bundle), but the deobfuscate path -- the one that matters for triaging packed or
malicious JavaScript -- is never fed genuinely obfuscated input. This gate feeds
a committed obfuscator.io payload (string-array + rotation IIFE + base64
string-array encoding, produced by javascript-obfuscator) in which the payload
string is *not* present as plaintext, and asserts webcrack recovers it.

The fixture is checked first, without webcrack, to prove it is really obfuscated:
the readable marker is absent from the input while the string-array rotation
machinery is present. Then JsClient.deobfuscate must surface the marker as a
plain literal, restore ``console.log`` and the ``reveal`` function, and strip
the rotation machinery -- i.e. actually decode a hidden string, not merely
reformat. beautify() (the same webcrack pass under a formatting name) is exercised
too. Skips honestly when webcrack is not installed. skip != pass.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsClient

_MARKER = "H3adl3ss-deob-marker-4d2"
# Produced by: javascript-obfuscator src.js --string-array true
#   --string-array-threshold 1 --string-array-encoding base64
#   --string-array-rotate true --string-array-index-shift true --compact true
# where src.js was: function reveal(){var marker='H3adl3ss-deob-marker-4d2';
#   console.log(marker);return marker;} reveal();
# Stored base64-encoded (the raw payload is one long minified line and the
# marker is itself base64 inside the string array); decoded below it never
# appears as plaintext, which the test verifies before trusting webcrack.
_OBFUSCATED_B64 = (
    "KGZ1bmN0aW9uKF8weDExZGExNCxfMHg1OWNmY2Epe3ZhciBfMHg0YWUzNmU9YTBfMHgyNTQxLF8weDQwNzM2OT1f"
    "MHgxMWRhMTQoKTt3aGlsZSghIVtdKXt0cnl7dmFyIF8weDZkNTBlYj0tcGFyc2VJbnQoXzB4NGFlMzZlKDB4MTQy"
    "KSkvMHgxKy1wYXJzZUludChfMHg0YWUzNmUoMHgxNDApKS8weDIqKC1wYXJzZUludChfMHg0YWUzNmUoMHgxM2Yp"
    "KS8weDMpK3BhcnNlSW50KF8weDRhZTM2ZSgweDEzYykpLzB4NCooLXBhcnNlSW50KF8weDRhZTM2ZSgweDE0MSkp"
    "LzB4NSkrLXBhcnNlSW50KF8weDRhZTM2ZSgweDE0NikpLzB4NiooLXBhcnNlSW50KF8weDRhZTM2ZSgweDE0NCkp"
    "LzB4NykrLXBhcnNlSW50KF8weDRhZTM2ZSgweDE0NSkpLzB4OCooLXBhcnNlSW50KF8weDRhZTM2ZSgweDE0Mykp"
    "LzB4OSkrcGFyc2VJbnQoXzB4NGFlMzZlKDB4MTNhKSkvMHhhKigtcGFyc2VJbnQoXzB4NGFlMzZlKDB4MTM5KSkv"
    "MHhiKStwYXJzZUludChfMHg0YWUzNmUoMHgxM2QpKS8weGMqKC1wYXJzZUludChfMHg0YWUzNmUoMHgxM2IpKS8w"
    "eGQpO2lmKF8weDZkNTBlYj09PV8weDU5Y2ZjYSlicmVhaztlbHNlIF8weDQwNzM2OVsncHVzaCddKF8weDQwNzM2"
    "OVsnc2hpZnQnXSgpKTt9Y2F0Y2goXzB4NTg2YWExKXtfMHg0MDczNjlbJ3B1c2gnXShfMHg0MDczNjlbJ3NoaWZ0"
    "J10oKSk7fX19KGEwXzB4MzRhYSwweGFiMjcwKSk7ZnVuY3Rpb24gYTBfMHgyNTQxKF8weDQ2ZDFjMSxfMHg0MThh"
    "NTUpe18weDQ2ZDFjMT1fMHg0NmQxYzEtMHgxMzk7dmFyIF8weDM0YWE0MD1hMF8weDM0YWEoKTt2YXIgXzB4MjU0"
    "MWFmPV8weDM0YWE0MFtfMHg0NmQxYzFdO2lmKGEwXzB4MjU0MVsnaVdvWkl5J109PT11bmRlZmluZWQpe3ZhciBf"
    "MHgzNGM5YmI9ZnVuY3Rpb24oXzB4ODM0YWIxKXt2YXIgXzB4MjZhMTZkPSdhYmNkZWZnaGlqa2xtbm9wcXJzdHV2"
    "d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMDEyMzQ1Njc4OSsvPSc7dmFyIF8weDYyMDA0OD0nJyxfMHhl"
    "ZDIzMjg9Jyc7Zm9yKHZhciBfMHgzZmIxMTE9MHgwLF8weDE2Mjc0YyxfMHg0MmMzZjUsXzB4MjlkY2MyPTB4MDtf"
    "MHg0MmMzZjU9XzB4ODM0YWIxWydjaGFyQXQnXShfMHgyOWRjYzIrKyk7fl8weDQyYzNmNSYmKF8weDE2Mjc0Yz1f"
    "MHgzZmIxMTElMHg0P18weDE2Mjc0YyoweDQwK18weDQyYzNmNTpfMHg0MmMzZjUsXzB4M2ZiMTExKyslMHg0KT9f"
    "MHg2MjAwNDgrPVN0cmluZ1snZnJvbUNoYXJDb2RlJ10oMHhmZiZfMHgxNjI3NGM+PigtMHgyKl8weDNmYjExMSYw"
    "eDYpKToweDApe18weDQyYzNmNT1fMHgyNmExNmRbJ2luZGV4T2YnXShfMHg0MmMzZjUpO31mb3IodmFyIF8weDUz"
    "ZjllYz0weDAsXzB4NDFkYjllPV8weDYyMDA0OFsnbGVuZ3RoJ107XzB4NTNmOWVjPF8weDQxZGI5ZTtfMHg1M2Y5"
    "ZWMrKyl7XzB4ZWQyMzI4Kz0nJScrKCcwMCcrXzB4NjIwMDQ4WydjaGFyQ29kZUF0J10oXzB4NTNmOWVjKVsndG9T"
    "dHJpbmcnXSgweDEwKSlbJ3NsaWNlJ10oLTB4Mik7fXJldHVybiBkZWNvZGVVUklDb21wb25lbnQoXzB4ZWQyMzI4"
    "KTt9O2EwXzB4MjU0MVsnZ1h1d3N6J109XzB4MzRjOWJiLGEwXzB4MjU0MVsnUWNIeFNwJ109e30sYTBfMHgyNTQx"
    "WydpV29aSXknXT0hIVtdO312YXIgXzB4MzNiNzQyPV8weDM0YWE0MFsweDBdO2EwXzB4MjU0MVsndW1Mc1RGJ10h"
    "PT1fMHgzM2I3NDImJihhMF8weDI1NDFbJ1FjSHhTcCddPXt9LGEwXzB4MjU0MVsndW1Mc1RGJ109XzB4MzNiNzQy"
    "KTt2YXIgXzB4MTNlNzM3PWEwXzB4MjU0MVsnUWNIeFNwJ11bXzB4NDZkMWMxXTtyZXR1cm4gXzB4MTNlNzM3PT09"
    "dW5kZWZpbmVkPyhfMHgyNTQxYWY9YTBfMHgyNTQxWydnWHV3c3onXShfMHgyNTQxYWYpLGEwXzB4MjU0MVsnUWNI"
    "eFNwJ11bXzB4NDZkMWMxXT1fMHgyNTQxYWYpOl8weDI1NDFhZj1fMHgxM2U3MzcsXzB4MjU0MWFmO31mdW5jdGlv"
    "biByZXZlYWwoKXt2YXIgXzB4MjYwOWIyPWEwXzB4MjU0MSxfMHhlZDIzMjg9XzB4MjYwOWIyKDB4MTNlKTtyZXR1"
    "cm4gY29uc29sZVtfMHgyNjA5YjIoMHgxNDcpXShfMHhlZDIzMjgpLF8weGVkMjMyODt9ZnVuY3Rpb24gYTBfMHgz"
    "NGFhKCl7dmFyIF8weDQzNzhjZj1bJ3Nkbkh6Z1daQzNtVHpndlZ5STFUeXhqUnp4aVRuZ3FZJywnb2RtM20wVHdC"
    "aGpaREcnLCduZGFZdEtEdkFNRFgnLCdudG0xbmRiZHV3WE15MG0nLCduWnVXb2RLNXZ1MVpDMlBrJywnbUpxV25k"
    "bTFveEQxdXhqTkRHJywnbnR6bUFoblB6dUsnLCdtdHpKdTJEbUV1UycsJ29kYVdtWmk0QTJ2ekN4SEonLCdCZzlO"
    "JywnbmRhMW50RDNxMWZ1c3d1JywnbnRtV3VnNXJ2dnJjJywnbVpMVXYweldzTUMnLCduSnJ5QU1MUUN2ZScsJ210"
    "bTNuZEczbktQT3FLenlyYSddO2EwXzB4MzRhYT1mdW5jdGlvbigpe3JldHVybiBfMHg0Mzc4Y2Y7fTtyZXR1cm4g"
    "YTBfMHgzNGFhKCk7fXJldmVhbCgpOw=="
)
_OBFUSCATED = base64.b64decode(_OBFUSCATED_B64).decode("utf-8")


@pytest.mark.integration
def test_web_js_deobfuscate_recovers_hidden_string_and_structure(tmp_path: Path) -> None:
    client = JsClient()
    if not client.available:
        pytest.skip("webcrack not installed — deobfuscate Gate not run (skip != pass)")

    # The fixture really is obfuscated: the marker is hidden (base64 in the
    # string array, not plaintext) and the rotation machinery is present.
    assert _MARKER not in _OBFUSCATED, "fixture is not actually obfuscated"
    assert "['shift']" in _OBFUSCATED and "_0x" in _OBFUSCATED, "fixture lacks obfuscation markers"

    source = tmp_path / "obf.js"
    source.write_text(_OBFUSCATED, encoding="utf-8")

    result = client.deobfuscate(source, timeout=120.0)
    code = str(result.get("code", ""))
    assert code.strip(), result

    # Decoded, not merely reformatted: the hidden string is now a plain literal.
    assert _MARKER in code, code[:600]
    # Original structure is restored: the function and the console.log call.
    assert "function reveal" in code, code[:600]
    assert "console" in code and "log" in code, code[:600]
    assert "return" in code, code[:600]
    # The string-array rotation machinery is gone -- webcrack consumed it rather
    # than leaving the encoded array and shift/push rotation behind.
    assert "['shift']" not in code, code[:600]
    assert "a0_0x34aa" not in code, code[:600]

    # beautify() is the same webcrack pass under a formatting-focused name; it
    # must recover the marker too (this exercises that ungated alias).
    beautified = client.beautify(source, timeout=120.0)
    assert _MARKER in str(beautified.get("code", "")), beautified
