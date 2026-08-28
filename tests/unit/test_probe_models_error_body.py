"""A failed provider probe must keep the provider's error body."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from headless_re_mcp.agent.config import ProviderProfile
from headless_re_mcp.agent.providers.openai_compatible import OpenAICompatibleProvider
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# fastapi and the web app it powers are the optional ``web`` extra. Skip this
# module (rather than erroring out the whole tests/unit collection) when it is
# absent, matching the skip-!=-pass contract the backend gates follow.
TestClient = pytest.importorskip(
    "fastapi.testclient", reason="fastapi (web extra) not installed (skip != pass)"
).TestClient
create_app = pytest.importorskip("headless_re_mcp.web.app").create_app


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
