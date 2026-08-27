"""A failed provider probe must keep the provider's error body."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app


@pytest.mark.asyncio
async def test_list_models_attaches_the_provider_error_body() -> None:
    """raise_for_status on a stream used to keep only the status line.

    Measured: a 429 whose body said quota exceeded retry after 30s raised
    HTTPStatusError whose str was Client error '429 Too Many Requests'...
    and did not contain quota exceeded. An unattended probe then cannot
    tell a quota wait from a bad key.
    """

    def quota(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            text='{"error":{"message":"quota exceeded retry after 30s"}}',
        )

    provider = OpenAICompatibleProvider(
        ProviderProfile("p", "https://provider.example/v1", "m", api_key="k"),
        transport=httpx.MockTransport(quota),
    )
    with pytest.raises(httpx.HTTPStatusError, match="quota exceeded retry after 30s"):
        await provider.list_models()


def test_probe_models_keeps_the_provider_error_in_the_502(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The route used to answer provider_probe_failed:HTTPStatusError only."""

    async def boom(self: OpenAICompatibleProvider) -> list[str]:
        raise RuntimeError("quota exceeded retry after 30s")

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", boom)
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    with TestClient(app) as client:
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
        )
        assert saved.status_code == 200
        probed = client.post("/api/providers/default/models", headers=headers)
        assert probed.status_code == 502
        detail = probed.json()["detail"]
        assert detail.startswith("provider_probe_failed:RuntimeError:")
        assert "quota exceeded retry after 30s" in detail


def test_probe_models_returns_the_list_when_only_the_cache_write_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A read-only providers.json must not turn a successful probe into a 502.

    Persisting known_models only warms the settings dropdown for the next
    open. The write used to share the probe's try block, so its OSError was
    reported as provider_probe_failed — sending the user to debug their key
    and network while the provider had answered — and the fetched list was
    discarded instead of returned.
    """

    async def listed(self: OpenAICompatibleProvider) -> list[str]:
        return ["model-a", "model-b"]

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", listed)
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    with TestClient(app) as client:
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
        )
        assert saved.status_code == 200

        def refuse_save(profile: Any, *, make_current: bool = True) -> dict[str, Any]:
            raise OSError("providers.json is read-only")

        store = app.state.provider_configs
        monkeypatch.setattr(store, "save", refuse_save)

        probed = client.post("/api/providers/default/models", headers=headers)
        assert probed.status_code == 200
        body = probed.json()
        assert body["ok"] is True
        assert body["models"] == ["model-a", "model-b"]
        assert "read-only" in body["cache_error"]


def test_probe_models_still_persists_the_cache_when_it_can(
    tmp_path: Path, monkeypatch: Any
) -> None:
    async def listed(self: OpenAICompatibleProvider) -> list[str]:
        return ["model-a", "model-b"]

    monkeypatch.setattr(OpenAICompatibleProvider, "list_models", listed)
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token="web-secret", settings=settings)
    headers = {"Authorization": "Bearer web-secret"}
    with TestClient(app) as client:
        saved = client.put(
            "/api/providers/default",
            headers=headers,
            json={"base_url": "https://example.invalid/v1", "model": "fake", "api_key": "k"},
        )
        assert saved.status_code == 200

        probed = client.post("/api/providers/default/models", headers=headers)
        assert probed.status_code == 200
        body = probed.json()
        assert body["models"] == ["model-a", "model-b"]
        assert "cache_error" not in body

        listed_profiles = client.get("/api/providers", headers=headers).json()
        default = next(p for p in listed_profiles["profiles"] if p["id"] == "default")
        assert default["known_models"] == ["model-a", "model-b"]
