"""Coverage for the PySide6 native launcher without installing Qt.

A minimal fake ``PySide6`` module tree is placed in ``sys.modules`` before
``native_app.gui`` is (re)imported, so the real window wiring, save/doctor
flows, and process lifecycle run against recording widgets. The gui module is
removed from ``sys.modules`` after each test so the bootstrap collection guard
(`test_native_bootstrap`) keeps seeing a Qt-free interpreter.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

import headless_re_mcp.config_generate as config_generate
import headless_re_mcp.native_app as native_app_pkg
import headless_re_mcp.native_app.__main__ as native_main
import headless_re_mcp.native_app.bootstrap as bootstrap
import headless_re_mcp.process_group as process_group

_GUI_MODULE = "headless_re_mcp.native_app.gui"


# --------------------------------------------------------------------------
# fake Qt widget tree
# --------------------------------------------------------------------------


class _Signal:
    def __init__(self) -> None:
        self._handlers: list[Any] = []

    def connect(self, handler: Any) -> None:
        self._handlers.append(handler)

    def emit(self) -> None:
        for handler in list(self._handlers):
            handler()


class _Base:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.object_name = ""

    def setObjectName(self, name: str) -> None:
        self.object_name = name


class _Layout(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.items: list[Any] = []

    def setContentsMargins(self, *margins: int) -> None:
        pass

    def setSpacing(self, value: int) -> None:
        pass

    def addWidget(self, widget: Any, stretch: int = 0) -> None:
        self.items.append(widget)

    def addLayout(self, layout: Any) -> None:
        self.items.append(layout)

    def addStretch(self, value: int = 0) -> None:
        pass


class _FormLayout(_Layout):
    def setLabelAlignment(self, flag: Any) -> None:
        pass

    def addRow(self, label: str, widget: Any) -> None:
        self.items.append((label, widget))


class _LineEdit(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._text = ""

    def setPlaceholderText(self, text: str) -> None:
        pass

    def text(self) -> str:
        return self._text

    def setText(self, value: str) -> None:
        self._text = value


class _PushButton(_Base):
    def __init__(self, label: str = "") -> None:
        super().__init__()
        self.label = label
        self.clicked = _Signal()

    def setFixedWidth(self, width: int) -> None:
        pass


class _CheckBox(_Base):
    def __init__(self, label: str = "") -> None:
        super().__init__()
        self._checked = False

    def setChecked(self, value: bool) -> None:
        self._checked = bool(value)

    def isChecked(self) -> bool:
        return self._checked


class _PlainTextEdit(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._text = ""

    def setReadOnly(self, value: bool) -> None:
        pass

    def setPlaceholderText(self, text: str) -> None:
        pass

    def appendPlainText(self, line: str) -> None:
        self._text += line + "\n"

    def setPlainText(self, text: str) -> None:
        self._text = text

    def toPlainText(self) -> str:
        return self._text


class _TabWidget(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.tabs: list[tuple[str, Any]] = []

    def addTab(self, page: Any, name: str) -> None:
        self.tabs.append((name, page))


class _Splitter(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.widgets: list[Any] = []

    def addWidget(self, widget: Any) -> None:
        self.widgets.append(widget)

    def setSizes(self, sizes: list[int]) -> None:
        pass


class _MainWindow(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.shown = False
        self.base_close_events: list[Any] = []

    def setWindowTitle(self, title: str) -> None:
        self.window_title = title

    def resize(self, width: int, height: int) -> None:
        pass

    def setMinimumSize(self, width: int, height: int) -> None:
        pass

    def setCentralWidget(self, widget: Any) -> None:
        self.central = widget

    def show(self) -> None:
        self.shown = True

    def closeEvent(self, event: Any) -> None:
        self.base_close_events.append(event)


class _FileDialog:
    @staticmethod
    def getExistingDirectory(parent: Any, caption: str) -> str:
        return ""

    @staticmethod
    def getOpenFileName(parent: Any, caption: str, start: str, filt: str) -> tuple[str, str]:
        return "", ""


class _MessageBox:
    calls: ClassVar[list[tuple[str, str, str]]] = []

    @classmethod
    def warning(cls, parent: Any, title: str, text: str) -> None:
        cls.calls.append(("warning", title, text))

    @classmethod
    def information(cls, parent: Any, title: str, text: str) -> None:
        cls.calls.append(("information", title, text))

    @classmethod
    def critical(cls, parent: Any, title: str, text: str) -> None:
        cls.calls.append(("critical", title, text))


class _Clipboard:
    def __init__(self) -> None:
        self.texts: list[str] = []

    def setText(self, text: str) -> None:
        self.texts.append(text)


class _GuiApplication:
    the_clipboard: ClassVar[_Clipboard] = _Clipboard()

    @classmethod
    def clipboard(cls) -> _Clipboard:
        return cls.the_clipboard


class _Application(_Base):
    the_instance: ClassVar[Any] = None
    created: ClassVar[int] = 0
    exec_result: ClassVar[int] = 0

    def __init__(self, argv: list[str] | None = None) -> None:
        super().__init__()
        type(self).created += 1

    def setStyle(self, name: str) -> None:
        pass

    def setStyleSheet(self, sheet: str) -> None:
        pass

    def setFont(self, font: Any) -> None:
        pass

    def exec(self) -> int:
        return type(self).exec_result

    @classmethod
    def instance(cls) -> Any:
        return cls.the_instance


class _Font:
    def __init__(self, *args: Any) -> None:
        pass


def _qt_modules() -> dict[str, types.ModuleType]:
    pyside = types.ModuleType("PySide6")
    qtcore = types.ModuleType("PySide6.QtCore")
    qtgui = types.ModuleType("PySide6.QtGui")
    qtwidgets = types.ModuleType("PySide6.QtWidgets")
    qtcore.Qt = SimpleNamespace(  # type: ignore[attr-defined]
        Orientation=SimpleNamespace(Horizontal=1),
        AlignmentFlag=SimpleNamespace(AlignRight=2),
    )
    qtgui.QFont = _Font  # type: ignore[attr-defined]
    qtgui.QGuiApplication = _GuiApplication  # type: ignore[attr-defined]
    widget_classes = {
        "QApplication": _Application,
        "QCheckBox": _CheckBox,
        "QFileDialog": _FileDialog,
        "QFormLayout": _FormLayout,
        "QFrame": _Base,
        "QHBoxLayout": _Layout,
        "QLabel": _Base,
        "QLineEdit": _LineEdit,
        "QMainWindow": _MainWindow,
        "QMessageBox": _MessageBox,
        "QPlainTextEdit": _PlainTextEdit,
        "QPushButton": _PushButton,
        "QSplitter": _Splitter,
        "QTabWidget": _TabWidget,
        "QVBoxLayout": _Layout,
        "QWidget": _Base,
    }
    for name, cls in widget_classes.items():
        setattr(qtwidgets, name, cls)
    pyside.QtCore = qtcore  # type: ignore[attr-defined]
    pyside.QtGui = qtgui  # type: ignore[attr-defined]
    pyside.QtWidgets = qtwidgets  # type: ignore[attr-defined]
    return {
        "PySide6": pyside,
        "PySide6.QtCore": qtcore,
        "PySide6.QtGui": qtgui,
        "PySide6.QtWidgets": qtwidgets,
    }


@pytest.fixture
def gui(monkeypatch: pytest.MonkeyPatch) -> Any:
    _MessageBox.calls.clear()
    _GuiApplication.the_clipboard = _Clipboard()
    _Application.the_instance = None
    _Application.created = 0
    _Application.exec_result = 0
    for name, module in _qt_modules().items():
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules.pop(_GUI_MODULE, None)
    module = importlib.import_module(_GUI_MODULE)
    yield module
    sys.modules.pop(_GUI_MODULE, None)


def _window(gui_mod: Any, monkeypatch: pytest.MonkeyPatch, **defaults: str) -> Any:
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: Path("/repo"))
    monkeypatch.setattr(bootstrap, "discover_defaults", lambda: dict(defaults))
    return gui_mod.NativeLauncherWindow()


class _Proc:
    def __init__(self, pid: int = 321, running: bool = True) -> None:
        self.pid = pid
        self._running = running

    def poll(self) -> int | None:
        return None if self._running else 0


# --------------------------------------------------------------------------
# PathRow
# --------------------------------------------------------------------------


def test_path_row_browses_for_a_directory(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    row = gui.PathRow("IDA home", directory=True)
    monkeypatch.setattr(_FileDialog, "getExistingDirectory", lambda parent, caption: "/opt/ida")
    row._browse()
    assert row.text() == "/opt/ida"


def test_path_row_browses_for_a_file(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    row = gui.PathRow("headless.exe")
    monkeypatch.setattr(
        _FileDialog,
        "getOpenFileName",
        lambda parent, caption, start, filt: ("/bin/headless.exe", "Executable (*.exe)"),
    )
    row._browse()
    assert row.text() == "/bin/headless.exe"


def test_path_row_keeps_the_old_text_on_cancel(gui: Any) -> None:
    row = gui.PathRow("headless.exe")
    row.set_text("  kept  ")
    row._browse()
    assert row.text() == "kept"


# --------------------------------------------------------------------------
# window construction and helpers
# --------------------------------------------------------------------------


def test_window_fills_defaults_and_logs_the_repo(
    gui: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    window = _window(gui, monkeypatch, ida_home="/opt/ida", upx="")
    assert window.ida.text() == "/opt/ida"
    assert window.upx.text() == ""  # falsy default is skipped
    assert "/repo" in window.log.toPlainText()
    assert "/repo" in capsys.readouterr().out


def test_collect_maps_empty_rows_to_none(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    window.ida.set_text("/opt/ida")
    data = window._collect()
    assert data["ida_home"] == "/opt/ida"
    assert data["x64dbg_headless_x64"] is None


def test_set_mcp_json_renders_into_the_view(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    window._set_mcp_json({"mcpServers": {}})
    assert '"mcpServers"' in window.mcp_view.toPlainText()


# --------------------------------------------------------------------------
# save_config
# --------------------------------------------------------------------------


def _fill_required(window: Any) -> None:
    window.ida.set_text("/opt/ida")
    window.x64.set_text("/x64/headless.exe")
    window.x86.set_text("/x86/headless.exe")


def test_save_config_requires_the_mandatory_paths(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    window.ida.set_text("/opt/ida")
    window.save_config()
    assert _MessageBox.calls == [("warning", "缺少路径", "IDA 与 x64/x86 headless.exe 为必需。")]


def test_save_config_saves_and_renders_the_cursor_payload(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    _fill_required(window)
    seen: dict[str, Any] = {}

    def apply_paths(data: dict[str, Any], *, activate_ida: bool) -> dict[str, Any]:
        seen["data"] = data
        seen["activate_ida"] = activate_ida
        return {"config_path": "/cfg/config.json"}

    monkeypatch.setattr(bootstrap, "apply_paths", apply_paths)
    monkeypatch.setattr(
        bootstrap,
        "sync_and_probe",
        lambda: [{"ok": True, "step": "sync"}, {"ok": False, "step": "probe"}],
    )
    monkeypatch.setattr(
        bootstrap,
        "export_mcp_files",
        lambda root: {"cursor_mcp": "/cfg/mcp.json", "cursor_payload": {"mcpServers": {}}},
    )
    window.save_config()
    assert seen["data"]["ida_home"] == "/opt/ida"
    assert seen["activate_ida"] is True
    log = window.log.toPlainText()
    assert "[OK] sync" in log and "[WARN] probe" in log
    assert "/cfg/mcp.json" in log
    assert '"mcpServers"' in window.mcp_view.toPlainText()
    assert _MessageBox.calls[-1][0] == "information"


def test_save_config_falls_back_to_a_fresh_export(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    _fill_required(window)
    monkeypatch.setattr(bootstrap, "apply_paths", lambda data, activate_ida: {"config_path": "p"})
    monkeypatch.setattr(bootstrap, "sync_and_probe", lambda: [])
    monkeypatch.setattr(bootstrap, "export_mcp_files", lambda root: {})
    monkeypatch.setattr(
        config_generate,
        "export_mcp_environment",
        lambda settings, persist, config_path: {"examples": {"cursor": {"mcpServers": {"a": 1}}}},
    )
    window.save_config()
    assert '"mcpServers"' in window.mcp_view.toPlainText()
    assert _MessageBox.calls[-1][0] == "information"


def test_save_config_skips_the_view_when_no_export_is_usable(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    _fill_required(window)
    monkeypatch.setattr(bootstrap, "apply_paths", lambda data, activate_ida: {"config_path": "p"})
    monkeypatch.setattr(bootstrap, "sync_and_probe", lambda: [])
    monkeypatch.setattr(bootstrap, "export_mcp_files", lambda root: {"cursor_payload": "nope"})
    monkeypatch.setattr(
        config_generate,
        "export_mcp_environment",
        lambda settings, persist, config_path: {"examples": {}},
    )
    window.save_config()
    assert window.mcp_view.toPlainText() == ""
    assert _MessageBox.calls[-1][0] == "information"


def test_save_config_reports_a_failure(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    _fill_required(window)

    def apply_paths(data: dict[str, Any], *, activate_ida: bool) -> dict[str, Any]:
        raise RuntimeError("disk is sealed")

    monkeypatch.setattr(bootstrap, "apply_paths", apply_paths)
    window.save_config()
    assert _MessageBox.calls == [("critical", "失败", "disk is sealed")]
    assert "ERROR: disk is sealed" in window.log.toPlainText()


# --------------------------------------------------------------------------
# copy_mcp / run_doctor
# --------------------------------------------------------------------------


def test_copy_mcp_requires_saved_output(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    window.copy_mcp()
    assert _MessageBox.calls[-1][0] == "information"
    assert _GuiApplication.the_clipboard.texts == []


def test_copy_mcp_puts_the_json_on_the_clipboard(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    window.mcp_view.setPlainText('{"mcpServers": {}}\n')
    window.copy_mcp()
    assert _GuiApplication.the_clipboard.texts == ['{"mcpServers": {}}']


def test_run_doctor_logs_the_probes(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    monkeypatch.setattr(
        bootstrap,
        "run_doctor_summary",
        lambda: {
            "ready": True,
            "probes": [{"status": "ok", "name": "ida", "summary": "found"}],
        },
    )
    window.run_doctor()
    log = window.log.toPlainText()
    assert "doctor.ready = True" in log
    assert "[ok] ida: found" in log


def test_run_doctor_reports_a_failure(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)

    def summary() -> dict[str, Any]:
        raise RuntimeError("doctor exploded")

    monkeypatch.setattr(bootstrap, "run_doctor_summary", summary)
    window.run_doctor()
    assert _MessageBox.calls == [("critical", "Doctor 失败", "doctor exploded")]


# --------------------------------------------------------------------------
# MCP / web process lifecycle
# --------------------------------------------------------------------------


def _arm_popen(
    gui_mod: Any, monkeypatch: pytest.MonkeyPatch, proc: _Proc
) -> tuple[list[Any], list[int]]:
    launched: list[Any] = []
    assigned: list[int] = []

    def popen(cmd: list[str], cwd: str | None = None, **kwargs: Any) -> _Proc:
        launched.append(cmd)
        return proc

    monkeypatch.setattr(gui_mod, "subprocess", SimpleNamespace(Popen=popen))
    monkeypatch.setattr(process_group, "assign_to_process_group", assigned.append)
    return launched, assigned


def test_start_mcp_launches_serve_once(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    launched, assigned = _arm_popen(gui, monkeypatch, _Proc(pid=77))
    window.start_mcp()
    assert launched[0][-2:] == ["headless_re_mcp", "serve"]
    assert assigned == [77]
    window.start_mcp()  # already running -> message box, no second Popen
    assert len(launched) == 1
    assert _MessageBox.calls[-1] == ("information", "MCP", "MCP serve 已在运行。")


def test_start_mcp_skips_group_assignment_without_a_pid(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    window.mcp_proc = _Proc(running=False)  # exited process does not block restarts
    launched, assigned = _arm_popen(gui, monkeypatch, _Proc(pid=0))
    window.start_mcp()
    assert len(launched) == 1
    assert assigned == []


def test_stop_mcp_only_stops_a_live_process(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    stopped: list[Any] = []
    monkeypatch.setattr(gui, "stop_owned_process", stopped.append)
    window.stop_mcp()  # nothing running
    live = _Proc()
    window.mcp_proc = live
    window.stop_mcp()
    assert stopped == [live]
    assert window.mcp_proc is None


def test_start_web_launches_serve_web_once(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    launched, assigned = _arm_popen(gui, monkeypatch, _Proc(pid=88))
    window.start_web()
    assert launched[0][-2:] == ["headless_re_mcp", "serve-web"]
    assert assigned == [88]
    window.start_web()
    assert len(launched) == 1
    assert _MessageBox.calls[-1] == ("information", "Web", "Web 控制台进程已在运行。")


def test_start_web_skips_group_assignment_without_a_pid(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _window(gui, monkeypatch)
    launched, assigned = _arm_popen(gui, monkeypatch, _Proc(pid=0))
    window.start_web()
    assert len(launched) == 1
    assert assigned == []


def test_close_event_stops_both_children(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window(gui, monkeypatch)
    stopped: list[Any] = []
    monkeypatch.setattr(gui, "stop_owned_process", stopped.append)
    mcp = _Proc(pid=1)
    web = _Proc(pid=2)
    window.mcp_proc = mcp
    window.web_proc = web
    event = object()
    window.closeEvent(event)
    assert stopped == [mcp, web]
    assert window.mcp_proc is None
    assert window.web_proc is None
    assert window.base_close_events == [event]


# --------------------------------------------------------------------------
# run_native_gui entrypoints
# --------------------------------------------------------------------------


def test_run_native_gui_builds_an_application(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: Path("/repo"))
    monkeypatch.setattr(bootstrap, "discover_defaults", lambda: {})
    _Application.exec_result = 5
    assert gui.run_native_gui() == 5
    assert _Application.created == 1


def test_run_native_gui_reuses_an_existing_application(
    gui: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap, "ensure_repo_on_path", lambda: Path("/repo"))
    monkeypatch.setattr(bootstrap, "discover_defaults", lambda: {})
    _Application.the_instance = _Application([])
    assert gui.run_native_gui() == 0
    assert _Application.created == 1  # only the pre-existing instance


def test_package_wrapper_defers_the_qt_import(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gui, "run_native_gui", lambda: 42)
    assert native_app_pkg.run_native_gui() == 42


# --------------------------------------------------------------------------
# native_app.__main__
# --------------------------------------------------------------------------


def test_main_cli_flag_runs_the_terminal_wizard(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def run_cli_setup(*, skip_pip: bool, non_interactive: bool, activate_ida: bool) -> int:
        seen.update(skip_pip=skip_pip, non_interactive=non_interactive, activate_ida=activate_ida)
        return 0

    monkeypatch.setattr(bootstrap, "run_cli_setup", run_cli_setup)
    assert native_main._main(["--cli", "--skip-pip", "--no-activate-ida"]) == 0
    assert seen == {"skip_pip": True, "non_interactive": False, "activate_ida": False}


def test_main_default_runs_the_gui(gui: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gui, "run_native_gui", lambda: 7)
    assert native_main._main([]) == 7


def test_main_wraps_the_cli_in_the_error_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.error_boundary as error_boundary

    seen: dict[str, Any] = {}

    def run_cli_safely(fn: Any, *, context: str) -> int:
        seen["context"] = context
        return 9

    monkeypatch.setattr(error_boundary, "run_cli_safely", run_cli_safely)
    assert native_main.main([]) == 9
    assert seen == {"context": "native-app"}
