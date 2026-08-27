"""device.packages / device.properties are stable sorted paginated readers.

Both capped at a limit and raised has_more with no offset, so entries past the
first page were unreachable -- and packages kept the first N in ``pm`` order
before sorting those N, so the "sorted" page was a sorted view of an arbitrary
subset. They now collect the whole set, sort, then slice, and report
total/offset like apk.classes and the jadx source listing.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.device import build_device_tools


def _backend(raw: str) -> AdbBackend:
    class Dev:
        def shell(self, args: Any, timeout: float | None = None) -> str:
            del args, timeout
            return raw

    backend = AdbBackend()
    backend._device = lambda serial: Dev()  # type: ignore[method-assign]
    return backend


def test_packages_pages_are_a_stable_sorted_partition() -> None:
    names = [f"com.app{index:02d}" for index in range(7)]
    raw = "\n".join(f"package:{name}" for name in names)
    backend = _backend(raw)
    expected = sorted(names)

    seen: list[str] = []
    for start in (0, 3, 6):
        result = backend.packages("emulator-5554", offset=start, limit=3)
        assert result["offset"] == start
        assert result["total"] == 7
        assert result["count"] == len(result["packages"])
        assert result["packages"] == expected[start : start + 3]
        seen.extend(result["packages"])
    assert seen == expected
    assert backend.packages("emulator-5554", offset=6, limit=3)["has_more"] is False
    assert backend.packages("emulator-5554", offset=0, limit=3)["has_more"] is True


def test_packages_offset_past_the_end_is_an_empty_page() -> None:
    raw = "\n".join(f"package:com.app{index}" for index in range(4))
    result = _backend(raw).packages("emulator-5554", offset=100, limit=10)
    assert result["packages"] == []
    assert result["count"] == 0
    assert result["offset"] == 100
    assert result["total"] == 4
    assert result["has_more"] is False


def test_properties_pages_are_a_stable_sorted_partition() -> None:
    raw = "\n".join(f"[ro.k{index:02d}]: [{index}]" for index in range(6))
    backend = _backend(raw)
    expected_keys = sorted(f"ro.k{index:02d}" for index in range(6))

    seen: list[str] = []
    for start in (0, 2, 4):
        result = backend.properties("emulator-5554", offset=start, limit=2)
        assert result["offset"] == start
        assert result["total"] == 6
        keys = list(result["properties"].keys())
        assert result["count"] == len(keys)
        assert keys == expected_keys[start : start + 2]
        seen.extend(keys)
    assert seen == expected_keys
    assert backend.properties("emulator-5554", offset=4, limit=2)["has_more"] is False
    assert backend.properties("emulator-5554", offset=0, limit=2)["has_more"] is True


def _schema(name: str, field: str) -> dict[str, Any]:
    handler = next(
        binding.handler
        for binding in build_device_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    field_schema: dict[str, Any] = input_schema_for(handler)["properties"][field]
    return field_schema


def test_device_readers_schema_bounds_offset_and_limit() -> None:
    for name in ("device.packages", "device.properties"):
        offset = _schema(name, "offset")
        assert offset.get("type") == "integer"
        assert offset.get("minimum") == 0
        assert "maximum" not in offset

        limit = _schema(name, "limit")
        assert limit.get("type") == "integer"
        assert limit.get("minimum") == 1
        assert limit.get("maximum") == 2000
