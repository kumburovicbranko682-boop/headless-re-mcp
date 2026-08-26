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


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.example/v1",
        "http://192.0.2.10:8000",
    ],
)
def test_provider_api_keys_are_not_sent_over_remote_plaintext(url: str) -> None:
    with pytest.raises(ValueError, match="API keys require HTTPS"):
        ProviderProfile("unsafe", url, "model", api_key="secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000",
    ],
)
def test_provider_api_keys_may_use_local_plaintext(url: str) -> None:
    profile = ProviderProfile("local", url, "model", api_key="secret")
    assert profile.base_url.startswith("http://")


def test_remote_plaintext_without_a_secret_remains_supported() -> None:
    profile = ProviderProfile("public", "http://provider.example", "model")
    assert profile.base_url == "http://provider.example/v1"
