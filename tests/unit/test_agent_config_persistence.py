from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile


def _profile(*, api_key: str = "provider-secret") -> ProviderProfile:
    return ProviderProfile(
        id="default",
        base_url="https://provider.example/v1",
        model="example-model",
        api_key=api_key,
    )


def test_provider_config_save_is_atomic_and_leaves_no_temporary_secret(
    tmp_path: Path,
) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)

    public = store.save(_profile())

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert public["configured"] is True
    assert saved["profiles"]["default"]["api_key"] == "provider-secret"
    assert list(tmp_path.glob(".providers.json-*.tmp")) == []


def test_provider_config_preserves_original_if_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "providers.json"
    original = '{"profiles": {}, "current": null}'
    path.write_text(original, encoding="utf-8")
    store = ProviderConfigStore(path)

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        temporary = Path(source)
        assert temporary.is_file()
        assert "new-provider-secret" in temporary.read_text(encoding="utf-8")
        assert Path(destination) == path
        if os.name != "nt":
            assert temporary.stat().st_mode & 0o777 == 0o600
        raise OSError("replace failed")

    monkeypatch.setattr("headless_re_mcp.agent.config.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        store.save(_profile(api_key="new-provider-secret"))

    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".providers.json-*.tmp")) == []


def test_list_public_skips_a_malformed_profile_instead_of_failing_the_endpoint(
    tmp_path: Path,
) -> None:
    """One bad stored profile must not take down the whole provider listing.

    ``list_public`` builds a ``ProviderProfile`` per stored entry, and its
    ``__post_init__`` rejects an out-of-range compression threshold. Because the
    config file is hand-editable (and can predate a stricter schema), a single
    bad entry made ``GET /api/providers`` raise ``ValueError`` -> 500, so the
    console could not show even the profiles that were fine. The good profile
    must still be listed and the bad one simply skipped.
    """
    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps(
            {
                "current": "good",
                "profiles": {
                    "good": {
                        "base_url": "https://provider.example/v1",
                        "model": "example-model",
                    },
                    # 999 is outside the 10..95 band ProviderProfile enforces.
                    "bad": {
                        "base_url": "https://provider.example/v1",
                        "model": "example-model",
                        "context_compression_threshold_percent": 999,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    store = ProviderConfigStore(path)

    result = store.list_public()

    assert result["current"] == "good"
    assert [profile["id"] for profile in result["profiles"]] == ["good"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_provider_config_is_private_on_posix(tmp_path: Path) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)

    store.save(_profile())

    assert path.stat().st_mode & 0o777 == 0o600
