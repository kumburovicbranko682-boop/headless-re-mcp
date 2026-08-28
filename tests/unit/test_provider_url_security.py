from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent import config as provider_config
from headless_re_mcp.agent.config import (
    ProviderConfigStore,
    ProviderProfile,
    normalize_base_url,
)


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


def test_provider_config_is_rejected_before_an_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 64)
    path = tmp_path / "providers.json"
    path.write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(ValueError, match="provider config exceeds 64 bytes"):
        ProviderConfigStore(path).list_public()


@pytest.mark.parametrize(
    "bad", [{}, [], "abc", "12.5", float("inf"), float("nan"), True]
)
def test_zerofall_import_rejects_a_malformed_threshold_as_a_client_error(
    tmp_path: Path, bad: object
) -> None:
    # The Zerofall body is client JSON, so this field can be an object, array,
    # non-numeric string, a non-finite float (json parses 1e400 to inf), or a
    # bool. int() raises TypeError on the containers and OverflowError on inf,
    # and the import route only catches ValueError -- so those used to surface
    # as a 500. It must be one invalid-field ValueError (a 400) either way.
    store = ProviderConfigStore(tmp_path / "providers.json")
    with pytest.raises(ValueError, match="contextCompressionThresholdPercent"):
        store.import_zerofall(
            {"contextCompressionThresholdPercent": bad}, confirm=True
        )


def test_zerofall_import_treats_an_absent_or_null_threshold_as_the_default(
    tmp_path: Path,
) -> None:
    store = ProviderConfigStore(tmp_path / "providers.json")
    absent = store.import_zerofall({"model": "m"}, confirm=True)
    explicit_null = store.import_zerofall(
        {"model": "m", "contextCompressionThresholdPercent": None}, confirm=True
    )
    assert absent["context_compression_threshold_percent"] == 75
    assert explicit_null["context_compression_threshold_percent"] == 75


@pytest.mark.parametrize("field", ["knownModels", "modelCatalogs"])
def test_zerofall_import_drops_a_non_array_list_field_instead_of_crashing(
    tmp_path: Path, field: str
) -> None:
    # ``knownModels: 5`` used to raise "int object is not iterable" out of the
    # comprehension and reach the route as a 500. A non-array is unusable, so it
    # is dropped like a bad entry rather than aborting the import.
    store = ProviderConfigStore(tmp_path / "providers.json")
    profile = store.import_zerofall({"model": "m", field: 5}, confirm=True)
    assert profile["known_models"] == []
    assert profile["model_catalogs"] == []


def test_zerofall_import_keeps_only_the_well_typed_list_entries(tmp_path: Path) -> None:
    store = ProviderConfigStore(tmp_path / "providers.json")
    profile = store.import_zerofall(
        {"model": "m", "knownModels": ["gpt-x", 3, None], "modelCatalogs": [{"a": 1}, "skip"]},
        confirm=True,
    )
    assert profile["known_models"] == ["gpt-x"]
    assert profile["model_catalogs"] == [{"a": 1}]


def test_provider_config_refuses_writes_that_it_could_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 1024)
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(ProviderProfile("default", "https://provider.example", "small"))
    original = path.read_bytes()

    with pytest.raises(ValueError, match="provider config exceeds 1024 bytes"):
        store.save(
            ProviderProfile(
                "oversized",
                "https://provider.example",
                "x" * 2048,
            )
        )

    assert path.read_bytes() == original
