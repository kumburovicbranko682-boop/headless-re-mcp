"""Shared, dependency-free credential detectors used across analysis lines.

The same "did this artefact hardcode a key/token" question is the top-of-funnel
for a JS bundle (js.secrets, over string literals) and an Android app (apk.secrets,
over the DEX string pool). Both run the *same* set of high-precision detectors, so
the pattern table lives here once rather than being copied per backend: a new
detector or a tightened pattern lands in one place and every line inherits it.

This module owns only the per-text matching primitive -- the detectors, the
opt-in high-entropy catch-all, and the generic-skips-a-claimed-literal rule.
Aggregation (dedup, occurrence counting, the reference each finding carries --
a char offset for JS, the containing DEX constant for APK -- filtering, sorting,
paging and the collect cap) stays in each caller, because those differ per line.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator

# A whole-literal token at least this long, all base64/hex-ish and high-entropy,
# is reported as a generic secret when include_generic is set. Below this it is
# too short to be a credible key and too likely an ordinary identifier.
GENERIC_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")
# Shannon entropy floor (bits/char) for a generic token: random base64/hex sits
# near 4-6; a repetitive or word-like blob falls below and is not flagged.
GENERIC_ENTROPY_MIN = 3.5

# High-precision credential detectors, each anchored so an ordinary word or
# identifier does not trip it: a secrets pass is only useful with a low
# false-positive rate, so a generic "long random-looking string" is *not* folded
# in here -- it is gated behind include_generic below. Patterns are all linear
# (bounded character classes) so a hostile text cannot cause backtracking.
SECRET_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # AWS key ids carry a fixed 4-char resource prefix + 16 base32 chars.
    (
        "aws_access_key_id",
        re.compile(
            r"\b(?:AKIA|ASIA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA|ABIA|ACCA|ASCA)[0-9A-Z]{16}\b"
        ),
    ),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google_oauth_token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,251}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/\-]+", re.IGNORECASE),
    ),
    ("stripe_secret_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b")),
    ("twilio_api_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("twilio_account_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("mailgun_api_key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("npm_token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    # A URL that carries userinfo (user:pass@host) is a leaked credential.
    (
        "basic_auth_url",
        re.compile(
            r"(?:https?|ftp)://[^\s:@/]{1,64}:[^\s:@/]{1,64}@[^\s/\"'`<>]{1,255}",
            re.IGNORECASE,
        ),
    ),
)


def shannon_entropy(text: str) -> float:
    """Bits/char Shannon entropy of ``text`` (0.0 for empty)."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_secret_matches(text: str, *, include_generic: bool = False) -> Iterator[tuple[str, str]]:
    """Yield ``(detector, value)`` for every credential match in ``text``.

    Specific detectors run first, in table order, then -- only when
    include_generic is set and no specific detector claimed this text -- a single
    generic_high_entropy match for a whole-text base64/hex token above the
    entropy floor. The generic pass is suppressed for a text a specific detector
    already matched, so a known key is not also reported as a generic blob.
    """
    literal_hit = False
    for detector, pattern in SECRET_DETECTORS:
        for match in pattern.finditer(text):
            literal_hit = True
            yield detector, match.group(0)
    if include_generic and not literal_hit:
        token = text.strip()
        if GENERIC_TOKEN_RE.match(token) and shannon_entropy(token) >= GENERIC_ENTROPY_MIN:
            yield "generic_high_entropy", token
