from __future__ import annotations

import pytest

from headless_re_mcp.agent.config import ProviderProfile, normalize_base_url


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@provider.example/v1",
        "https://access-token@provider.example",
        "http://:password@127.0.0.1:8000/v1",
    ],
)
def test_provider_base_url_rejects_embedded_credentials(url: str) -> None:
    with pytest.raises(ValueError, match="must not include credentials"):
        normalize_base_url(url)

    with pytest.raises(ValueError, match="must not include credentials"):
        ProviderProfile("unsafe", url, "model")


def test_provider_base_url_still_normalizes_safe_urls() -> None:
    assert normalize_base_url("HTTPS://provider.example:8443/api/") == (
        "https://provider.example:8443/api/v1"
    )
