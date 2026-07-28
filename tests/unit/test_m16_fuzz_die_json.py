from __future__ import annotations

import json

import pytest

from headless_re_mcp.detection.die import DieScanError, _normalize_json


@pytest.mark.parametrize(
    "payload",
    [
        None,
        1,
        "x",
        [],
        {},
        {"detects": "nope"},
        {"detects": [{"values": "bad"}]},
        {"detects": [{"type": "x" * 100000}]},
    ],
)
def test_die_normalize_handles_garbage(payload: object) -> None:
    try:
        findings, raw = _normalize_json(payload)
    except DieScanError:
        return
    assert isinstance(findings, tuple)
    assert isinstance(raw, dict)


def test_die_normalize_accepts_minimal() -> None:
    findings, raw = _normalize_json(
        {
            "detects": [
                {
                    "filetype": "PE64",
                    "values": [
                        {
                            "type": "Packer",
                            "name": "UPX",
                            "string": "UPX",
                            "version": "4",
                            "info": "",
                        }
                    ],
                }
            ]
        }
    )
    assert isinstance(findings, tuple)
    assert "detects" in json.dumps(raw)
