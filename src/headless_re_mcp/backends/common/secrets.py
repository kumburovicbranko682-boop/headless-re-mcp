"""Shared hard-coded-credential classifier (pure Python, no dependencies).

One credential table, used by more than one backend: js.secrets feeds it the
decoded values of a script's string literals, apk.secrets feeds it the DEX
string-constant pool. Keeping the table here means a new provider pattern is
added once and both lines gain it.

Precision over recall: every pattern below has a distinctive fixed prefix or
structure (AKIA..., ghp_..., a three-segment JWT, a PEM header) rather than
"a long random string", so the false-positive rate stays low on real code.
The matched secret is always redacted in the output -- the provider-naming
prefix and length are kept, the middle masked -- so a transcript never carries
a live value. This is a lexical scan: it cannot catch a secret assembled at
runtime from fragments, and a test/example key still matches.
"""

from __future__ import annotations

import re
from collections import Counter, OrderedDict
from collections.abc import Iterable
from typing import Any

JsonObject = dict[str, Any]

# Bounds: distinct findings collected, sample locations kept per finding, and the
# page size. Callers bound how many input strings they feed in.
_MAX_SECRETS_COLLECT = 5000
_MAX_SECRET_SAMPLE_LINES = 5
_MAX_SECRETS_PAGE = 2000

# High-precision credential patterns. (kind, severity, pattern). Severity is
# high for a live/private credential, medium for a publishable/test/JWT one.
_SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", "high", re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}\b")),
    ("google_api_key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google_oauth_token", "high", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("firebase_database_url", "medium", re.compile(r"https://[a-z0-9.\-]+\.firebaseio\.com")),
    ("github_token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("github_pat", "high", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("gitlab_token", "high", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack_webhook", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
    ("stripe_secret_key", "high", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b")),
    ("stripe_test_key", "medium", re.compile(r"\b[sr]k_test_[0-9A-Za-z]{16,}\b")),
    ("stripe_publishable_key", "medium", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("twilio_account_sid", "medium", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("twilio_api_key", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid_api_key", "high", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    ("npm_token", "high", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    (
        "jwt",
        "medium",
        re.compile(r"\beyJ[0-9A-Za-z_\-]{6,}\.eyJ[0-9A-Za-z_\-]{6,}\.[0-9A-Za-z_\-]{6,}"),
    ),
    (
        "private_key",
        "high",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
)

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def redact_secret(secret: str) -> str:
    """Mask the middle of a matched credential, keeping enough to identify it.

    Full secrets must never be echoed into a transcript, but the prefix (which
    is what names the provider) and length are what a triage needs.
    """
    length = len(secret)
    if length <= 8:
        head = secret[:2]
        return f"{head}{'*' * max(1, length - 2)} (len {length})"
    return f"{secret[:4]}{'*' * 4}{secret[-2:]} (len {length})"


def _clamp_page(offset: int, limit: int) -> tuple[int, int]:
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_SECRETS_PAGE))
    return start, cap


def classify_secrets(
    items: Iterable[tuple[str, int | None]],
    *,
    offset: int = 0,
    limit: int = 200,
    scan_capped: bool = False,
) -> JsonObject:
    """Classify string values against the credential table, deduped and redacted.

    ``items`` yields ``(value, location)`` pairs where ``location`` is a 1-based
    line number (JS) or None (a source with no line info, e.g. a DEX string
    pool). Identical secrets are folded together, keeping an occurrence count and
    up to five sample locations. ``scan_capped`` is seeded by the caller (whose
    own input scan may have truncated) and additionally set here if the distinct
    finding set overflows. Returns findings (paged, high severity first then
    kind), count/total/offset/has_more, a kinds tally, total_findings and
    scan_capped.
    """
    found: OrderedDict[tuple[str, str], JsonObject] = OrderedDict()
    kinds: Counter[str] = Counter()
    for value, location in items:
        for kind, severity, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(value):
                secret = match.group(0)
                key = (kind, secret)
                row = found.get(key)
                if row is None:
                    if len(found) >= _MAX_SECRETS_COLLECT:
                        scan_capped = True
                        continue
                    row = {
                        "kind": kind,
                        "severity": severity,
                        "preview": redact_secret(secret),
                        "length": len(secret),
                        "count": 0,
                        "lines": [],
                    }
                    found[key] = row
                    kinds[kind] += 1
                row["count"] = int(row["count"]) + 1
                lines_list: list[int] = row["lines"]
                if (
                    location is not None
                    and location not in lines_list
                    and len(lines_list) < _MAX_SECRET_SAMPLE_LINES
                ):
                    lines_list.append(location)

    rows = sorted(
        found.values(),
        key=lambda r: (
            _SEVERITY_RANK.get(str(r["severity"]), 3),
            str(r["kind"]),
            str(r["preview"]),
        ),
    )
    start, cap = _clamp_page(offset, limit)
    window = rows[start : start + cap]
    return {
        "findings": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "kinds": dict(kinds),
        "total_findings": sum(int(r["count"]) for r in rows),
        "scan_capped": scan_capped,
    }
