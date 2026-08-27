"""device.* state changes must land in the global (session-less) audit log.

Device operations are keyed by serial, not a session, so unlike apk.* / frida.* /
web.* they have no per-session timeline. Two groups therefore used to leave no
trace: the mutations (connect, install, uninstall, launch, force-stop, push,
forward), so an operator had no record the agent installed/removed an app or
forwarded a port; and the captures (pull, screenshot), whose files are never
registered in the artifact table (it needs a session_id these ops lack), so a
pulled file or screenshot had zero provenance. These pin that each such operation
now records an audit entry with session_id null (visible through audit.list's
unfiltered listing), that a failure is still recorded with its error code, that
pure reads are not audited, and that an audit-write failure never fails the op.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeAdb(AdbBackend):
    """An AdbBackend stand-in: records calls, returns backend-shaped dicts.

    Subclasses AdbBackend (skipping its adbutils import) so the mixin's
    isinstance check in _backend() accepts it as the owned backend.
    """

    def __init__(self) -> None:
        # Initialise the real backend so inherited cleanup (release_forwards /
        # close_all) still has its lock and forward list; adbutils being absent
        # just leaves it unavailable, which the overridden ops do not consult.
        super().__init__()
        self.calls: list[str] = []
        self.fail: set[str] = set()

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> JsonObject:
        self.calls.append("connect")
        if "connect" in self.fail:
            raise AdbError("backend_error", "connect failed", endpoint=f"{host}:{port}")
        return {"endpoint": f"{host}:{port}", "result": "connected to device", "connected": True}

    def install(self, serial: str, apk_path: str, reinstall: bool = True) -> JsonObject:
        self.calls.append("install")
        if "install" in self.fail:
            raise AdbError("backend_error", "install failed", path=apk_path)
        return {"installed": True, "package": "com.example.app", "path": apk_path, "serial": serial}

    def uninstall(self, serial: str, package: str) -> JsonObject:
        self.calls.append("uninstall")
        return {"uninstalled": True, "package": package}

    def launch(self, serial: str, package: str) -> JsonObject:
        self.calls.append("launch")
        return {"launched": True, "package": package, "foreground": package}

    def force_stop(self, serial: str, package: str) -> JsonObject:
        self.calls.append("force_stop")
        return {"stopped": True, "package": package, "remaining_pids": []}

    def push(self, serial: str, local_path: str, remote_path: str) -> JsonObject:
        self.calls.append("push")
        return {"local": local_path, "remote": remote_path, "size": 7}

    def forward(self, serial: str, local: str, remote: str) -> JsonObject:
        self.calls.append("forward")
        return {"local": local, "remote": remote}

    def screenshot(self, serial: str, out_path: Any) -> JsonObject:
        self.calls.append("screenshot")
        return {"path": str(out_path), "serial": serial, "size": 123}

    def pull(self, serial: str, remote_path: str, local_path: Any) -> JsonObject:
        self.calls.append("pull")
        return {"remote": remote_path, "local": str(local_path), "size": 456}

    def info(self, serial: str) -> JsonObject:
        self.calls.append("info")
        return {"serial": serial, "state": "device"}

    def logcat(self, serial: str, lines: int = 200) -> JsonObject:
        self.calls.append("logcat")
        return {"lines": [], "count": 0, "requested": lines, "truncated": False}


def _service(tmp_path: Path) -> tuple[AnalysisService, _FakeAdb]:
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    fake = _FakeAdb()
    service._adb_backend = fake
    return service, fake


def _entries(service: AnalysisService) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return list(result.data["entries"])


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    return [e for e in _entries(service) if e["action"] == action]


def test_every_device_mutation_records_a_session_less_audit_entry(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        service.device_connect("127.0.0.1", 5555)
        service.device_install("emulator-5554", str(tmp_path / "app.apk"))
        service.device_uninstall("emulator-5554", "com.example.app")
        service.device_launch("emulator-5554", "com.example.app")
        service.device_force_stop("emulator-5554", "com.example.app")
        service.device_push("emulator-5554", str(tmp_path / "f"), "/data/local/tmp/f")
        service.device_forward("emulator-5554", "tcp:8080", "tcp:80")

        actions = {e["action"] for e in _entries(service)}
        for expected in (
            "device.connect",
            "device.install",
            "device.uninstall",
            "device.launch",
            "device.force_stop",
            "device.push",
            "device.forward",
        ):
            assert expected in actions, expected
        # All device entries are serial-scoped, so they carry no session id.
        device_rows = [e for e in _entries(service) if str(e["action"]).startswith("device.")]
        assert device_rows
        assert all(e["session_id"] is None for e in device_rows)
        assert all(e["ok"] == 1 for e in device_rows)
    finally:
        service.close_all()


def test_install_audit_names_the_verified_package(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        service.device_install("emulator-5554", str(tmp_path / "app.apk"))
        entry = _by_action(service, "device.install")[0]
        assert entry["params_summary"] == {"serial": "emulator-5554"}
        assert entry["result_summary"]["installed"] is True
        assert entry["result_summary"]["package"] == "com.example.app"
    finally:
        service.close_all()


def test_forward_audit_records_both_ports(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        service.device_forward("emulator-5554", "tcp:8080", "tcp:80")
        entry = _by_action(service, "device.forward")[0]
        assert entry["params_summary"] == {
            "serial": "emulator-5554",
            "local": "tcp:8080",
            "remote": "tcp:80",
        }
        assert entry["result_summary"] == {"local": "tcp:8080", "remote": "tcp:80"}
    finally:
        service.close_all()


def test_a_failed_mutation_is_still_audited_with_its_error_code(tmp_path: Path) -> None:
    service, fake = _service(tmp_path)
    try:
        fake.fail.add("install")
        result = service.device_install("emulator-5554", str(tmp_path / "app.apk"))
        assert result.ok is False
        entry = _by_action(service, "device.install")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_a_connect_downgraded_to_failure_is_audited_as_not_ok(tmp_path: Path) -> None:
    """adb can answer connect with a status string and no exception.

    The service downgrades a not-connected reply to a failure; the audit must
    follow the final outcome, not the raw ok=True the backend first returned.
    """
    service, fake = _service(tmp_path)
    try:
        fake.connect = lambda host="127.0.0.1", port=5555: {  # type: ignore[method-assign]
            "endpoint": f"{host}:{port}",
            "result": "unable to connect",
            "connected": False,
        }
        result = service.device_connect("127.0.0.1", 5555)
        assert result.ok is False
        entry = _by_action(service, "device.connect")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_captures_are_audited_with_their_provenance(tmp_path: Path) -> None:
    """pull/screenshot files are never registered in the artifact table (they
    key by serial), so the audit entry is their only record."""
    service, _fake = _service(tmp_path)
    try:
        service.device_screenshot("emulator-5554")
        service.device_pull("emulator-5554", "/data/local/tmp/f.bin")

        shot = _by_action(service, "device.screenshot")[0]
        assert shot["session_id"] is None
        assert shot["ok"] == 1
        assert shot["params_summary"] == {"serial": "emulator-5554"}
        assert shot["result_summary"]["size"] == 123
        assert shot["result_summary"]["path"]  # a concrete local path was recorded

        pulled = _by_action(service, "device.pull")[0]
        assert pulled["session_id"] is None
        assert pulled["ok"] == 1
        assert pulled["result_summary"]["remote"] == "/data/local/tmp/f.bin"
        assert pulled["result_summary"]["size"] == 456
        assert pulled["result_summary"]["local"]
    finally:
        service.close_all()


def test_a_capture_that_overflows_the_cap_is_audited_as_too_large(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A capture that hit disk, exceeded the cap and was deleted must audit the
    too_large outcome, not the raw ok the backend first returned."""
    from headless_re_mcp.core.models import Result, RpcError

    service, _fake = _service(tmp_path)
    try:
        monkeypatch.setattr(
            "headless_re_mcp.core.service_device.refuse_oversized_device_file",
            lambda out: Result(
                ok=False,
                error=RpcError(code="output_too_large", message="too big", details={}),
            ),
        )
        result = service.device_screenshot("emulator-5554")
        assert result.ok is False
        entry = _by_action(service, "device.screenshot")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "output_too_large"}
    finally:
        service.close_all()


def test_pure_read_device_ops_are_not_audited(tmp_path: Path) -> None:
    """info/logcat return data and touch nothing, so unlike the captures they
    leave no audit entry."""
    service, _fake = _service(tmp_path)
    try:
        service.device_info("emulator-5554")
        service.device_logcat("emulator-5554")
        assert _entries(service) == []
    finally:
        service.close_all()


def test_device_audit_is_absent_from_a_session_scoped_listing(tmp_path: Path) -> None:
    """A serial-scoped entry is only visible in the unfiltered audit listing.

    audit.list filtered by a session id must not surface device mutations,
    which belong to no session; passing no session id is how they are seen.
    """
    service, _fake = _service(tmp_path)
    try:
        service.device_uninstall("emulator-5554", "com.example.app")
        scoped = service.audit_list("some-session-id")
        assert scoped.ok and scoped.data is not None
        assert all(e["action"] != "device.uninstall" for e in scoped.data["entries"])
        unscoped = service.audit_list(None)
        assert unscoped.ok and unscoped.data is not None
        assert any(e["action"] == "device.uninstall" for e in unscoped.data["entries"])
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_device_op(tmp_path: Path) -> None:
    """The mutation already happened on the device; a bookkeeping failure here
    must not turn a successful install into a failed tool call."""
    service, _fake = _service(tmp_path)
    original_repo = getattr(service, "repository", None)

    class _RaisingRepo:
        def append_audit(self, **kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

    try:
        service.repository = _RaisingRepo()  # type: ignore[assignment]
        result = service.device_install("emulator-5554", str(tmp_path / "app.apk"))
        assert result.ok is True
        assert result.data is not None
        assert result.data["installed"] is True
    finally:
        service.repository = original_repo  # type: ignore[assignment]
        service.close_all()
