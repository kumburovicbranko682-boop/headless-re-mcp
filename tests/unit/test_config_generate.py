from __future__ import annotations

import json
from pathlib import Path

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings, ida_library_names
from headless_re_mcp.config_generate import (
    build_stdio_server_config,
    generate_config_bundle,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def test_stdio_config_has_no_secret_fields(tmp_path: Path) -> None:
    server = build_stdio_server_config(
        python_path=Path(tmp_path / "python.exe"),
        config_path=tmp_path / "config.json",
    )
    blob = json.dumps(server)
    assert "token" not in blob.casefold()
    assert "license" not in blob.casefold()
    assert server["args"][:2] == ["-m", "headless_re_mcp"]
    assert "serve" in server["args"]


def test_strip_secrets_reaches_dicts_nested_in_lists() -> None:
    """The doctor report keeps every probe inside a list.

    A dict-only walk stripped a top-level "token" but let the identical key
    pass through untouched one level down inside ``probes``, so the exported
    bundle carried whatever a probe had put under a secret-named detail.
    """
    from headless_re_mcp.config_generate import _strip_secrets

    doctor = {
        "ready": True,
        "token": "topsecret",
        "probes": [
            {
                "name": "x",
                "details": {
                    "rpc_token": "SUPERSECRET",
                    "license": "IDA-ABC-123",
                    "executable": "C:/tools/x.exe",
                },
            }
        ],
    }
    cleaned = _strip_secrets(doctor)
    blob = json.dumps(cleaned)
    assert "SUPERSECRET" not in blob
    assert "IDA-ABC-123" not in blob
    assert "topsecret" not in blob
    # Non-secret detail survives untouched.
    assert cleaned["probes"][0]["details"]["executable"] == "C:/tools/x.exe"


def test_exported_doctor_snapshot_carries_no_secret_probe_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a secret-keyed probe detail must not reach the export."""
    import headless_re_mcp.config_generate as config_generate

    class _FakeReport:
        ready = True

        @staticmethod
        def to_json() -> str:
            return json.dumps(
                {
                    "ready": True,
                    "probes": [
                        {
                            "name": "ida_idalib",
                            "status": "ready",
                            "summary": "ok",
                            "details": {"license": "IDA-ABC-123", "home": "C:/IDA"},
                            "remediation": None,
                        }
                    ],
                }
            )

    monkeypatch.setattr(config_generate, "run_doctor", lambda _settings: _FakeReport())
    bundle = generate_config_bundle(
        _settings(tmp_path),
        python_path=Path("python"),
        config_path=tmp_path / "config.json",
        run_doctor_check=False,
        include_examples=False,
        embed_discovered_env=True,
    )
    assert bundle["ok"] is True
    blob = json.dumps(bundle["doctor"])
    assert "IDA-ABC-123" not in blob
    assert bundle["doctor"]["probes"][0]["details"]["home"] == "C:/IDA"


def test_generate_skips_doctor_when_requested(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    bundle = generate_config_bundle(
        settings,
        python_path=Path("python"),
        config_path=tmp_path / "config.json",
        run_doctor_check=False,
        include_examples=True,
    )
    assert bundle["ok"] is True
    assert "cursor" in bundle["examples"]
    assert "vscode" in bundle["examples"]
    assert "claude_desktop" in bundle["examples"]


def test_embed_discovered_env_uses_real_paths(tmp_path: Path) -> None:
    from headless_re_mcp.config_generate import export_mcp_environment

    headless = tmp_path / "headless.exe"
    headless.write_bytes(b"MZ")
    ida = tmp_path / "IDA"
    ida.mkdir()
    (ida / ida_library_names()[0]).write_bytes(b"MZ")
    settings = Settings(
        ida_home=ida,
        x64dbg_source=None,
        x64dbg_headless_x64=headless,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "artifacts").mkdir()
    export = export_mcp_environment(
        settings,
        python_path=tmp_path / "python.exe",
        config_path=tmp_path / "config.json",
        persist=True,
        output_dir=tmp_path / "out",
    )
    assert export["ok"] is True
    env = export["stdio"]["env"]
    assert env["HEADLESS_RE_X64DBG_HEADLESS_X64"] == str(headless.resolve())
    assert env["HEADLESS_RE_IDA_HOME"] == str(ida.resolve())
    assert "HEADLESS_RE_CONFIG" in env
    cursor = export["examples"]["cursor"]["mcpServers"]["headless-re-mcp"]
    assert cursor["env"]["HEADLESS_RE_IDA_HOME"] == str(ida.resolve())
    assert (tmp_path / "out" / "mcp.cursor.json").is_file()
    assert "rpc_token" not in json.dumps(export["stdio"]).casefold()


def test_settings_env_map_only_names_real_settings_fields() -> None:
    """A rename in Settings would silently drop a path from generated configs.

    build_discovered_env reads each mapped field with getattr(..., None); if the
    field were renamed, discovery would return None and the HEADLESS_RE_* entry
    would just vanish from the emitted MCP config, with no error. Pin the map to
    the dataclass so a rename fails here instead.
    """
    from headless_re_mcp.config_generate import _SETTINGS_ENV_MAP

    fields = set(Settings.__dataclass_fields__)
    unknown = {name for name, _env in _SETTINGS_ENV_MAP if name not in fields}
    assert not unknown, f"_SETTINGS_ENV_MAP names non-existent Settings fields: {unknown}"

    # And every mapped env var is a distinct HEADLESS_RE_* key.
    env_keys = [env for _name, env in _SETTINGS_ENV_MAP]
    assert all(key.startswith("HEADLESS_RE_") for key in env_keys)
    assert len(env_keys) == len(set(env_keys)), "duplicate env key in _SETTINGS_ENV_MAP"


def test_strip_secrets_drops_secret_keys_recursively_and_case_insensitively() -> None:
    """MCP config bundles are copy-pasted, so no secret-named key may survive."""
    from headless_re_mcp.config_generate import _SECRET_KEYS, _strip_secrets

    payload = {
        "token": "abc",
        "Api_Key": "shhh",
        "APIKEY": "shhh",
        "keep": "ok",
        "token_count": 3,  # not an exact secret key -- must survive
        "nested": {
            "password": "p",
            "IDA_License": "lic",
            "still_here": 1,
            "deeper": {"secret": "s", "fine": True},
        },
    }
    cleaned = _strip_secrets(payload)

    # Every exact secret key is gone at every depth.
    assert "token" not in cleaned
    assert "Api_Key" not in cleaned and "APIKEY" not in cleaned
    assert "password" not in cleaned["nested"]
    assert "IDA_License" not in cleaned["nested"]
    assert "secret" not in cleaned["nested"]["deeper"]
    # Non-secret keys (including a near-miss) are untouched.
    assert cleaned["keep"] == "ok"
    assert cleaned["token_count"] == 3
    assert cleaned["nested"]["still_here"] == 1
    assert cleaned["nested"]["deeper"]["fine"] is True
    # The guard matches on casefold against the frozen key set.
    assert {"token", "password", "secret", "api_key", "apikey"} <= _SECRET_KEYS


def test_strip_secrets_covers_the_full_credential_vocabulary() -> None:
    """config_generate must hide every key the redaction module calls a secret.

    The two secret definitions are independent (this one is exact-key, the
    redaction module is a substring regex); if a doctor probe emitted a detail
    named authorization/credential/passwd/private_key/access_key, the redaction
    module would hide it everywhere else but this copy-pasted config bundle
    would not. Pin the added vocabulary as stripped, both spellings.
    """
    from headless_re_mcp.config_generate import _strip_secrets

    payload = {
        "Authorization": "Bearer x",
        "credential": "c",
        "PASSWD": "p",
        "private_key": "-----BEGIN-----",
        "PrivateKey": "-----BEGIN-----",
        "access_key": "AKIA",
        "AccessKey": "AKIA",
        # A near-miss that must still survive the exact-key rule.
        "credentials_checked": 2,
    }
    cleaned = _strip_secrets(payload)

    assert cleaned == {"credentials_checked": 2}


def _poisoned_report(*, ready: bool):
    from headless_re_mcp.doctor import DoctorReport, Probe, ProbeStatus

    leaky = Probe(
        "ida_idalib",
        ProbeStatus.READY,
        "ready",
        details={"api_key": "leaked-secret-value", "path": "/opt/ida"},
    )
    if not ready:
        return DoctorReport(probes=(leaky,))
    # Ready needs every required probe present and READY. The required set is
    # platform-dependent (Linux drops x64dbg) but always includes "platform",
    # so include it or the report is never ready on either OS.
    return DoctorReport(
        probes=(
            leaky,
            Probe("platform", ProbeStatus.READY, "ready"),
            Probe("python", ProbeStatus.READY, "ready"),
            Probe("x64dbg_headless_binaries", ProbeStatus.READY, "ready"),
        )
    )


def test_generated_bundle_scrubs_a_secret_from_the_doctor_report_when_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import headless_re_mcp.config_generate as cg

    monkeypatch.setattr(cg, "run_doctor", lambda settings=None: _poisoned_report(ready=True))
    bundle = generate_config_bundle(
        _settings(tmp_path),
        python_path=Path("python"),
        config_path=tmp_path / "config.json",
        run_doctor_check=True,
        include_examples=False,
    )
    assert bundle["ok"] is True
    blob = json.dumps(bundle)
    assert "leaked-secret-value" not in blob
    assert "api_key" not in blob.casefold()


def test_doctor_not_ready_failure_body_also_scrubs_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The early not-ready return used to send the doctor report back unstripped."""
    import headless_re_mcp.config_generate as cg

    monkeypatch.setattr(cg, "run_doctor", lambda settings=None: _poisoned_report(ready=False))
    bundle = generate_config_bundle(
        _settings(tmp_path),
        python_path=Path("python"),
        config_path=tmp_path / "config.json",
        run_doctor_check=True,
        include_examples=False,
    )
    assert bundle["ok"] is False
    assert bundle["error"]["code"] == "doctor_not_ready"
    blob = json.dumps(bundle)
    assert "leaked-secret-value" not in blob
    assert "api_key" not in blob.casefold()


def test_cli_config_generate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(cli_module.Settings, "load", lambda _path=None: settings)
    code = cli_module.main(
        ["config", "generate", "--skip-doctor", "--no-examples", "--python", "python"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert "examples" not in payload
