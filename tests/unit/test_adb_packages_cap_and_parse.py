"""``device.packages`` caps the device-order stream, then sorts the kept page.

``AdbBackend.packages`` parses ``pm list packages`` line by line and stops once
it has kept ``limit`` names:

    for line in text.splitlines():
        if not line.startswith("package:"):
            continue
        name = line.split(":", 1)[1].strip()
        if not name:
            continue
        if len(pkgs) >= capped:
            has_more = True
            break
        pkgs.append(name)
    pkgs.sort()

Two behaviours here are load-bearing and neither is pinned by
``test_adb_device_readouts``:

* **Cap before sort.** ``pm list packages`` emits in the device's own order (not
  alphabetical), and the cap is applied to that stream *before* ``pkgs.sort()``,
  which only orders the kept page for display. So a truncated page is the first
  ``limit`` packages the device listed, sorted -- **not** the ``limit``
  alphabetically-smallest, and ``has_more`` means "the device listed more than
  the cap." The existing test feeds a reverse-sorted listing but asserts only
  ``set(page) <= {all names}``, which a sort-*before*-cap implementation
  (returning the alphabetical bottom of the list) would satisfy just as well.
  This pins *which* names come back, so that "fix it to sort then cap" refactor
  cannot silently change the truncated page.

* **Parse skips, and they do not consume the cap.** Lines that are not
  ``package:...`` (pm banners, warnings) and ``package:`` lines with no name are
  dropped, and the ``package:`` prefix is stripped with ``split(":", 1)`` so a
  name that itself contains a colon survives intact. The existing tests feed only
  clean ``package:name`` lines, so every skip branch is inert; drop the
  ``startswith`` guard or the empty-name guard and nothing there fails.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend


class _ScriptedDev:
    """A device whose ``shell`` returns one canned dump and records its argv."""

    def __init__(self, output: str) -> None:
        self._output = output
        self.calls: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        return self._output


def _backend_with(dev: _ScriptedDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_truncated_page_is_the_device_order_prefix_then_sorted() -> None:
    """limit=3 over a reverse-sorted listing keeps the first three, then sorts.

    Device order is ``com.e, com.d, com.c, com.b, com.a``. Cap-before-sort keeps
    ``com.e, com.d, com.c`` (the first three the device listed) and sorts them to
    ``[com.c, com.d, com.e]``. A sort-before-cap implementation would instead
    return the alphabetical bottom ``[com.a, com.b, com.c]`` -- so this exact
    assertion is what tells the two apart.
    """
    listing = "\n".join(
        f"package:{name}" for name in ("com.e", "com.d", "com.c", "com.b", "com.a")
    )
    payload = _backend_with(_ScriptedDev(listing)).packages("emulator-5554", limit=3)
    assert payload["packages"] == ["com.c", "com.d", "com.e"]
    assert payload["has_more"] is True
    assert payload["count"] == 3


def test_non_package_lines_and_empty_names_are_dropped() -> None:
    """Banners, noise and nameless ``package:`` lines never become entries.

    A name that contains a colon (``com.mid:weird``) must survive, proving the
    prefix is stripped with a single split rather than by cutting at every colon.
    """
    listing = "\n".join(
        [
            "warning: pm is deprecated",
            "package:com.zeta",
            "package:",
            "random noise line",
            "package:com.alpha",
            "package:com.mid:weird",
        ]
    )
    payload = _backend_with(_ScriptedDev(listing)).packages("emulator-5554", limit=500)
    assert payload["packages"] == ["com.alpha", "com.mid:weird", "com.zeta"]
    assert payload["count"] == 3
    assert payload["has_more"] is False


def test_skipped_lines_do_not_consume_the_cap() -> None:
    """The cap counts kept packages, not raw lines, and sits after the skips.

    With noise interleaved and limit=2, the two real packages seen first fill the
    cap and the third trips has_more; the banners between them must not count
    toward the limit or the page would come back short.
    """
    listing = "\n".join(
        [
            "warning: header",
            "package:com.b",
            "noise",
            "package:com.a",
            "warning: footer",
            "package:com.c",
        ]
    )
    payload = _backend_with(_ScriptedDev(listing)).packages("emulator-5554", limit=2)
    assert payload["count"] == 2
    assert payload["packages"] == ["com.a", "com.b"]
    assert payload["has_more"] is True
