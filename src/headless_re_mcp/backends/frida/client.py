from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

_HOOK_TEMPLATES = {
    "noop": "rpc.exports = { ping: function () { return 'pong'; } };",
}

_ENUM_SCRIPT = """
rpc.exports = {
  modules: function () {
    return Process.enumerateModules().map(function (m) {
      return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
    });
  },
  exports: function (moduleName, limit) {
    var mod = Process.findModuleByName(moduleName);
    if (mod === null) {
      return {found: false, exports: []};
    }
    var items = mod.enumerateExports().slice(0, limit).map(function (e) {
      return {name: e.name, address: e.address.toString(), type: e.type};
    });
    return {found: true, module: mod.name, base: mod.base.toString(), exports: items};
  },
  read: function (address, size) {
    return Array.from(new Uint8Array(Memory.readByteArray(ptr(address), size)));
  }
};
"""


class FridaError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class FridaClient:
    def __init__(self) -> None:
        self._frida: Any = None
        self._available = False
        try:
            import frida

            self._frida = frida
            self._available = True
        except Exception:
            self._frida = None
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def attach(self, pid: int, *, allowed_pid: int) -> JsonObject:
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")
        if type(pid) is not int or pid <= 0:
            raise FridaError("invalid_params", "pid must be a positive integer")
        if pid != allowed_pid:
            raise FridaError(
                "permission_denied",
                "frida attach limited to session debuggee pid",
                pid=pid,
                allowed_pid=allowed_pid,
            )
        session = self._frida.attach(pid)
        try:
            return {
                "pid": pid,
                "attached": True,
                "device": "local",
                "note": "probe attach; detached immediately",
            }
        finally:
            session.detach()

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> JsonObject:
        self._require(pid, allowed_pid)
        session = self._frida.attach(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            mods = list(script.exports_sync.modules())
            capped = max(1, min(int(limit), 256))
            items = [
                {
                    "name": str(item.get("name", "")),
                    "base": str(item.get("base", "")),
                    "size": int(item.get("size", 0) or 0),
                    "path": str(item.get("path", "")),
                }
                for item in mods[:capped]
            ]
            return {"modules": items, "count": len(items), "total": len(mods)}
        finally:
            session.detach()

    def exports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        limit: int = 64,
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if not isinstance(module_name, str) or not module_name.strip():
            raise FridaError("invalid_params", "module_name is required")
        capped = max(1, min(int(limit), 512))
        session = self._frida.attach(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            raw = script.exports_sync.exports(module_name.strip(), capped)
            if not isinstance(raw, dict):
                raise FridaError("backend_error", "unexpected frida exports payload")
            items = []
            for item in list(raw.get("exports") or [])[:capped]:
                if not isinstance(item, dict):
                    continue
                items.append(
                    {
                        "name": str(item.get("name", "")),
                        "address": str(item.get("address", "")),
                        "type": str(item.get("type", "")),
                    }
                )
            return {
                "found": bool(raw.get("found")),
                "module": str(raw.get("module") or module_name),
                "base": str(raw.get("base") or ""),
                "exports": items,
                "count": len(items),
            }
        finally:
            session.detach()

    def memory_read(
        self, pid: int, address: int, size: int, *, allowed_pid: int
    ) -> JsonObject:
        self._require(pid, allowed_pid)
        if type(size) is not int or not 1 <= size <= 256 * 1024:
            raise FridaError("invalid_params", "size must be 1..262144")
        session = self._frida.attach(pid)
        try:
            script = session.create_script(_ENUM_SCRIPT)
            script.load()
            data = bytes(script.exports_sync.read(int(address), int(size)))
            return {
                "address": address,
                "size": size,
                "encoding": "hex",
                "data": data.hex(),
            }
        finally:
            session.detach()

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> JsonObject:
        self._require(pid, allowed_pid)
        source = _HOOK_TEMPLATES.get(template)
        if source is None:
            raise FridaError(
                "invalid_params",
                "unknown hook template",
                template=template,
                allowed=sorted(_HOOK_TEMPLATES),
            )
        session = self._frida.attach(pid)
        try:
            script = session.create_script(source)
            script.load()
            return {"pid": pid, "template": template, "loaded": True}
        finally:
            session.detach()

    def _require(self, pid: int, allowed_pid: int) -> None:
        if pid != allowed_pid:
            raise FridaError("permission_denied", "pid not allowed", pid=pid)
        if not self._available or self._frida is None:
            raise FridaError("capability_unavailable", "frida Python module is not installed")
