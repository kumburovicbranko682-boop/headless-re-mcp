"""apk.repack / apk.sign must refuse a non-string path argument as invalid_params.

``decoded_dir`` (repack) and ``apk_path``/``keystore`` (sign) are schema-typed as
strings, but the agent and OpenAI-bridge transports bind handler kwargs straight
from model output with no pydantic coercion. A non-string value reached the
``(arg).strip()`` normalization and raised a raw AttributeError (or, for bytes, a
TypeError from the following ``Path(arg)``) that the service filed as a logged
internal_error incident instead of the invalid_params a caller can act on.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def _apk_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None, created.error
    return service, str(created.data["session"]["id"])


@pytest.mark.parametrize("decoded_dir", [123, ["/x"], {"d": "/x"}, 1.5, b"/x", True])
def test_apk_repack_refuses_a_non_string_decoded_dir(
    tmp_path: Path, decoded_dir: object
) -> None:
    service, session_id = _apk_session(tmp_path)
    try:
        result = service.apk_repack(session_id, decoded_dir=cast(Any, decoded_dir))
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("apk_path", "keystore"),
    [
        (123, ""),
        (["/x"], ""),
        (1.5, ""),
        (b"/x", ""),
        ("", 123),
        ("", ["/x"]),
        ("", {"k": "v"}),
    ],
)
def test_apk_sign_refuses_a_non_string_path_arg(
    tmp_path: Path, apk_path: object, keystore: object
) -> None:
    service, session_id = _apk_session(tmp_path)
    try:
        result = service.apk_sign(
            session_id, apk_path=cast(Any, apk_path), keystore=cast(Any, keystore)
        )
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()
