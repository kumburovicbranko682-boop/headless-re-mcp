"""Modern native launcher (PySide6). No WebView / Electron chrome."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

# PySide6 is the optional `native` extra; mypy skips it so Qt types are Any
# on the quality job. unused-ignore keeps the subclass lines valid if a
# local run actually has the stubs.
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.native_app.bootstrap import stop_owned_process

STYLE = """
QMainWindow, QWidget {
    background: #0f1419;
    color: #e7ecf1;
    font-family: "Segoe UI";
    font-size: 13px;
}
QLabel#title {
    font-size: 20px;
    font-weight: 600;
    color: #f4f7fa;
}
QLabel#subtitle {
    color: #8b98a5;
    font-size: 12px;
}
QFrame#card {
    background: #171d25;
    border: 1px solid #273140;
    border-radius: 12px;
}
QLineEdit {
    background: #0c1015;
    border: 1px solid #2d3a4a;
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: #3d7eff;
}
QLineEdit:focus { border: 1px solid #4d8dff; }
QPlainTextEdit {
    background: #0a0e13;
    border: 1px solid #2d3a4a;
    border-radius: 10px;
    padding: 10px;
    color: #d7e0ea;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
}
QPushButton {
    background: #243041;
    border: 1px solid #334556;
    border-radius: 8px;
    padding: 8px 14px;
    color: #e7ecf1;
}
QPushButton:hover { background: #2c3b4f; }
QPushButton#primary {
    background: #2f6fed;
    border: 1px solid #2f6fed;
    font-weight: 600;
}
QPushButton#primary:hover { background: #3b7bff; }
QPushButton#danger {
    background: #5a2430;
    border: 1px solid #7a3342;
}
QTabWidget::pane {
    border: 1px solid #273140;
    border-radius: 10px;
    background: #171d25;
    top: -1px;
}
QTabBar::tab {
    background: #121820;
    color: #9aa8b6;
    padding: 8px 16px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
QTabBar::tab:selected {
    background: #171d25;
    color: #ffffff;
}
QCheckBox { spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid #3a4a5c; background: #0c1015;
}
QCheckBox::indicator:checked {
    background: #2f6fed; border-color: #2f6fed;
}
"""


class PathRow(QWidget):  # type: ignore[misc, unused-ignore]
    def __init__(self, label: str, *, directory: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.directory = directory
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(label)
        browse = QPushButton("浏览")
        browse.setFixedWidth(72)
        browse.clicked.connect(self._browse)
        layout.addWidget(self.edit, 1)
        layout.addWidget(browse)

    def _browse(self) -> None:
        if self.directory:
            path = QFileDialog.getExistingDirectory(self, "选择目录")
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "选择文件", "", "Executable (*.exe);;All (*.*)"
            )
        if path:
            self.edit.setText(path)

    def text(self) -> str:
        return str(self.edit.text()).strip()

    def set_text(self, value: str) -> None:
        self.edit.setText(value)


class NativeLauncherWindow(QMainWindow):  # type: ignore[misc, unused-ignore]
    def __init__(self) -> None:
        super().__init__()
        from headless_re_mcp.native_app.bootstrap import discover_defaults, ensure_repo_on_path

        self.repo_root = ensure_repo_on_path()
        self.defaults = discover_defaults()
        self.mcp_proc: subprocess.Popen[Any] | None = None
        self.web_proc: subprocess.Popen[Any] | None = None

        self.setWindowTitle("Headless RE-MCP")
        self.resize(980, 680)
        self.setMinimumSize(860, 600)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(14)

        title = QLabel("Headless RE-MCP")
        title.setObjectName("title")
        sub = QLabel("原生桌面配置 · 无浏览器套壳 · MCP JSON 可一键复制")
        sub.setObjectName("subtitle")
        outer.addWidget(title)
        outer.addWidget(sub)

        split = QSplitter(Qt.Orientation.Horizontal)
        outer.addWidget(split, 1)

        left_card = QFrame()
        left_card.setObjectName("card")
        left = QVBoxLayout(left_card)
        left.setContentsMargins(16, 16, 16, 16)
        left.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.ida = PathRow("IDA 9.x 安装目录", directory=True)
        self.x64 = PathRow("headless.exe (x64)")
        self.x86 = PathRow("headless.exe (x86)")
        self.upx = PathRow("UPX（可选）")
        self.diec = PathRow("diec（可选）")
        self.r2 = PathRow("Rizin/r2（可选）")
        self.cdb = PathRow("cdb（可选）")
        form.addRow("IDA", self.ida)
        form.addRow("x64 headless", self.x64)
        form.addRow("x86 headless", self.x86)
        form.addRow("UPX", self.upx)
        form.addRow("DIE", self.diec)
        form.addRow("R2", self.r2)
        form.addRow("CDB", self.cdb)
        left.addLayout(form)

        self.activate_ida = QCheckBox("保存时运行 IDA idalib 激活脚本")
        self.activate_ida.setChecked(True)
        left.addWidget(self.activate_ida)

        actions = QHBoxLayout()
        self.btn_save = QPushButton("保存配置并生成 MCP")
        self.btn_save.setObjectName("primary")
        self.btn_doctor = QPushButton("Doctor")
        self.btn_mcp = QPushButton("启动 MCP")
        self.btn_stop = QPushButton("停止 MCP")
        self.btn_stop.setObjectName("danger")
        self.btn_web = QPushButton("启动 Web 进程")
        for b in (self.btn_save, self.btn_doctor, self.btn_mcp, self.btn_stop, self.btn_web):
            actions.addWidget(b)
        left.addLayout(actions)
        left.addStretch(1)
        split.addWidget(left_card)

        right_card = QFrame()
        right_card.setObjectName("card")
        right = QVBoxLayout(right_card)
        right.setContentsMargins(12, 12, 12, 12)
        tabs = QTabWidget()
        right.addWidget(tabs)

        mcp_page = QWidget()
        mcp_layout = QVBoxLayout(mcp_page)
        mcp_layout.setContentsMargins(8, 8, 8, 8)
        mcp_bar = QHBoxLayout()
        mcp_bar.addWidget(QLabel("Cursor / MCP 客户端配置"))
        mcp_bar.addStretch(1)
        self.btn_copy = QPushButton("复制到剪贴板")
        self.btn_copy.setObjectName("primary")
        mcp_bar.addWidget(self.btn_copy)
        mcp_layout.addLayout(mcp_bar)
        self.mcp_view = QPlainTextEdit()
        self.mcp_view.setReadOnly(True)
        self.mcp_view.setPlaceholderText("点击「保存配置并生成 MCP」后，这里会贴出完整 JSON。")
        mcp_layout.addWidget(self.mcp_view, 1)
        tabs.addTab(mcp_page, "MCP 配置")

        log_page = QWidget()
        log_layout = QVBoxLayout(log_page)
        log_layout.setContentsMargins(8, 8, 8, 8)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        log_layout.addWidget(self.log)
        tabs.addTab(log_page, "控制台")
        split.addWidget(right_card)
        split.setSizes([420, 560])

        self._fill_defaults()
        self.btn_save.clicked.connect(self.save_config)
        self.btn_doctor.clicked.connect(self.run_doctor)
        self.btn_mcp.clicked.connect(self.start_mcp)
        self.btn_stop.clicked.connect(self.stop_mcp)
        self.btn_web.clicked.connect(self.start_web)
        self.btn_copy.clicked.connect(self.copy_mcp)

        self._append(f"仓库：{self.repo_root}")
        self._append("UI：PySide6 原生控件（非 WebView）。IDA 不捆绑。")

    def _fill_defaults(self) -> None:
        mapping = {
            self.ida: "ida_home",
            self.x64: "x64dbg_headless_x64",
            self.x86: "x64dbg_headless_x86",
            self.upx: "upx",
            self.diec: "diec",
            self.r2: "r2",
            self.cdb: "cdb",
        }
        for row, key in mapping.items():
            value = self.defaults.get(key)
            if value:
                row.set_text(str(value))

    def _append(self, msg: str) -> None:
        self.log.appendPlainText(msg)
        print(msg, flush=True)

    def _collect(self) -> dict[str, str | None]:
        def opt(row: PathRow) -> str | None:
            text = row.text()
            return text or None

        return {
            "ida_home": opt(self.ida),
            "x64dbg_headless_x64": opt(self.x64),
            "x64dbg_headless_x86": opt(self.x86),
            "upx": opt(self.upx),
            "diec": opt(self.diec),
            "r2": opt(self.r2),
            "cdb": opt(self.cdb),
        }

    def _set_mcp_json(self, payload: dict[str, Any]) -> None:
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        self.mcp_view.setPlainText(text)
        self._append("======== MCP 配置（可复制） ========")
        print(text, flush=True)
        self._append("======== MCP 配置结束 ========")

    def save_config(self) -> None:
        from headless_re_mcp.native_app.bootstrap import (
            apply_paths,
            export_mcp_files,
            sync_and_probe,
        )

        data = self._collect()
        if not data.get("ida_home") or not data.get("x64dbg_headless_x64") or not data.get(
            "x64dbg_headless_x86"
        ):
            QMessageBox.warning(self, "缺少路径", "IDA 与 x64/x86 headless.exe 为必需。")
            return
        try:
            result = apply_paths(data, activate_ida=self.activate_ida.isChecked())
            self._append(f"配置已写入：{result['config_path']}")
            for item in sync_and_probe():
                self._append(f"[{'OK' if item.get('ok') else 'WARN'}] {item.get('step')}")
            mcp = export_mcp_files(self.repo_root)
            if mcp.get("cursor_mcp"):
                self._append(f"已写入：{mcp['cursor_mcp']}")
            cursor = mcp.get("cursor_payload")
            if isinstance(cursor, dict):
                self._set_mcp_json(cursor)
            else:
                from headless_re_mcp.config import Settings, default_config_path
                from headless_re_mcp.config_generate import export_mcp_environment

                export = export_mcp_environment(
                    Settings.load(), persist=False, config_path=default_config_path()
                )
                cursor = (export.get("examples") or {}).get("cursor")
                if isinstance(cursor, dict):
                    self._set_mcp_json(cursor)
            QMessageBox.information(self, "完成", "配置已保存，右侧与控制台已贴出 MCP JSON。")
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))
            self._append(f"ERROR: {exc}")

    def copy_mcp(self) -> None:
        text = self.mcp_view.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "MCP", "还没有可复制的配置，请先保存。")
            return
        QGuiApplication.clipboard().setText(text)
        self._append("MCP JSON 已复制到剪贴板。")

    def run_doctor(self) -> None:
        from headless_re_mcp.native_app.bootstrap import run_doctor_summary

        try:
            doctor = run_doctor_summary()
            self._append(f"doctor.ready = {doctor['ready']}")
            for probe in doctor["probes"]:
                self._append(f"[{probe['status']}] {probe['name']}: {probe['summary']}")
        except Exception as exc:
            QMessageBox.critical(self, "Doctor 失败", str(exc))

    def start_mcp(self) -> None:
        if self.mcp_proc and self.mcp_proc.poll() is None:
            QMessageBox.information(self, "MCP", "MCP serve 已在运行。")
            return
        self.mcp_proc = subprocess.Popen(
            [sys.executable, "-m", "headless_re_mcp", "serve"],
            cwd=str(self.repo_root),
            **no_window_popen_kwargs(),
        )
        from headless_re_mcp.process_group import assign_to_process_group

        if self.mcp_proc.pid:
            assign_to_process_group(self.mcp_proc.pid)
        self._append(f"已启动 MCP serve pid={self.mcp_proc.pid}")

    def stop_mcp(self) -> None:
        if self.mcp_proc and self.mcp_proc.poll() is None:
            stop_owned_process(self.mcp_proc)
            self._append("已请求停止 MCP serve")
        self.mcp_proc = None

    def start_web(self) -> None:
        if self.web_proc and self.web_proc.poll() is None:
            QMessageBox.information(self, "Web", "Web 控制台进程已在运行。")
            return
        self.web_proc = subprocess.Popen(
            [sys.executable, "-m", "headless_re_mcp", "serve-web"],
            cwd=str(self.repo_root),
            **no_window_popen_kwargs(),
        )
        from headless_re_mcp.process_group import assign_to_process_group

        if self.web_proc.pid:
            assign_to_process_group(self.web_proc.pid)
        self._append(
            f"已启动 serve-web pid={self.web_proc.pid}（请用系统浏览器访问，窗口不内嵌）"
        )

    def closeEvent(self, event: Any) -> None:
        self.stop_mcp()
        stop_owned_process(self.web_proc)
        self.web_proc = None
        super().closeEvent(event)


def run_native_gui() -> int:
    # instance() is typed as the QCoreApplication base, which has no styling.
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    app.setFont(QFont("Segoe UI", 10))
    window = NativeLauncherWindow()
    window.show()
    return int(app.exec())
