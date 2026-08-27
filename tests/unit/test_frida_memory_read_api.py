"""frida.memory.read must use the NativePointer API, not the removed global.

frida 17 dropped the legacy ``Memory.read*`` free functions. The enumeration
script's ``read`` used ``Memory.readByteArray(ptr(address), size)``, which then
raised "TypeError: not a function" and broke ``frida.memory.read`` on every
modern runtime -- verified live against frida 17.17 attaching to a local
process. The NativePointer method ``ptr(address).readByteArray(size)`` has
existed since frida 12, so it works across the whole ``>=16.5`` range the
android extra pins. The frida native runtime cannot run in CI, so this guards
the script content statically, the way the hook-template schema test does.
"""

from __future__ import annotations

from headless_re_mcp.backends.frida.client import _ENUM_SCRIPT


def test_read_uses_the_pointer_method_not_the_removed_memory_global() -> None:
    assert "ptr(address).readByteArray(size)" in _ENUM_SCRIPT
    # The legacy global is gone in frida 17; a reference would break memory.read
    # again the moment the pinned runtime is the modern one.
    assert "Memory.readByteArray" not in _ENUM_SCRIPT
