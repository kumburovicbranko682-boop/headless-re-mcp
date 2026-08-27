"""Routes that rewrite providers.json must not bake the env API key into it.

``HEADLESS_RE_PROVIDER_API_KEY`` is the supported way to keep the provider
credential out of providers.json entirely (pinned in
test_provider_secret_surface). Two routes read a profile and save it back:
the model probe warms the ``known_models`` dropdown cache, and the provider
PUT falls back to the existing profile for fields the body omits. Both used
the effective (env-merged) view for that round trip, so one successful probe
— or one settings-panel save, which never sends api_key when unchanged —
silently copied the environment's secret onto disk.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

ENV_KEY = "env-secret-key-123456"


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_API_KEY", ENV_KEY)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    return TestClient(app)


def _seed_keyless_profile(client: TestClient) -> None:
    client.app.state.provider_configs.save(
        ProviderProfile(
            id="default",
            base_url="https://api.example.com/v1",
            model="gpt-4.1-mini",
            api_key=None,
        )
    )


def test_a_model_probe_does_not_write_the_env_key_into_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def listed(self: OpenAICompatibleProvider) -> list[str]:
        return ["model-a", "model-b"]

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", listed)
    headers = {"Authorization": "Bearer web-secret"}
    with _client(tmp_path, monkeypatch) as client:
        _seed_keyless_profile(client)

        probed = client.post("/api/providers/default/models", headers=headers)
        assert probed.status_code == 200
        assert probed.json()["models"] == ["model-a", "model-b"]

        text = (tmp_path / "providers.json").read_text(encoding="utf-8")
        assert ENV_KEY not in text
        # The cache itself did land.
        assert "model-a" in text


def test_a_partial_provider_put_does_not_write_the_env_key_into_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {"Authorization": "Bearer web-secret"}
    with _client(tmp_path, monkeypatch) as client:
        _seed_keyless_profile(client)

        # The settings panel's save: base_url + model, api_key omitted.
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={"base_url": "https://api.example.com/v1", "model": "gpt-4.1-mini"},
        )
        assert saved.status_code == 200

        text = (tmp_path / "providers.json").read_text(encoding="utf-8")
        assert ENV_KEY not in text
        # The environment key still configures the effective profile.
        listed = client.get("/api/providers", headers=headers).json()
        default = next(p for p in listed["profiles"] if p["id"] == "default")
        assert default["configured"] is True
        assert ENV_KEY not in str(listed)


def test_an_explicit_api_key_in_the_put_body_is_still_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {"Authorization": "Bearer web-secret"}
    with _client(tmp_path, monkeypatch) as client:
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={
                "base_url": "https://api.example.com/v1",
                "model": "gpt-4.1-mini",
                "api_key": "sk-typed-by-hand-0123456789",
            },
        )
        assert saved.status_code == 200
        text = (tmp_path / "providers.json").read_text(encoding="utf-8")
        assert "sk-typed-by-hand-0123456789" in text
