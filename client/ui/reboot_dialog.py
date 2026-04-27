"""Reboot-Dialog mit Countdown.

Wird vom Tray angezeigt wenn der Proxy einen pending Reboot meldet.
Zeigt App-Icon, Meldung, visuellen Countdown mit Progressbar, und
Jetzt/Verschieben Buttons.
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QProgressBar,
    QFrame,
)
from PyQt5.QtCore import QTimer, Qt, QSize
from PyQt5.QtGui import QPixmap, QIcon


_STYLE = """
QDialog {
    background: #fafafa;
}
QLabel#title {
    font-size: 16px;
    font-weight: 700;
    color: #18181b;
    letter-spacing: -0.3px;
}
QLabel#message {
    font-size: 13px;
    color: #3f3f46;
    line-height: 1.5;
}
QLabel#countdown {
    font-size: 36px;
    font-weight: 700;
    color: #18181b;
    font-family: 'Segoe UI', 'Consolas', monospace;
}
QLabel#hint {
    font-size: 11px;
    color: #a1a1aa;
}
QProgressBar {
    border: none;
    background: #e4e4e7;
    border-radius: 3px;
    height: 6px;
    text-align: center;
}
QProgressBar::chunk {
    background: #ef4444;
    border-radius: 3px;
}
QPushButton#now_btn {
    background: #18181b;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 13px;
    font-weight: 600;
}
QPushButton#now_btn:hover {
    background: #27272a;
}
QPushButton#defer_btn {
    background: white;
    color: #3f3f46;
    border: 1px solid #e4e4e7;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton#defer_btn:hover {
    background: #f4f4f5;
    border-color: #d4d4d8;
}
QFrame#separator {
    background: #e4e4e7;
    max-height: 1px;
}
"""


class RebootDialog(QDialog):
    """Modaler Dialog: Neustart erforderlich mit visuellem Countdown."""

    def __init__(self, message: str, countdown: int, can_defer: bool,
                 app_name: str = "", icon_data: bytes | None = None,
                 parent=None):
        super().__init__(parent)
        self._app_name = app_name or "Software-Update"
        self.setWindowTitle(f"{self._app_name} \u2014 Neustart")
        self.setWindowFlags(
            Qt.Dialog
            | Qt.WindowStaysOnTopHint
            | Qt.CustomizeWindowHint
            | Qt.WindowTitleHint
        )
        self.setFixedWidth(440)
        self.setStyleSheet(_STYLE)
        self._total = max(countdown, 10)
        self._remaining = self._total
        self._result = None

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(0)

        # -- Icon + Title Row --
        header = QHBoxLayout()
        header.setSpacing(14)

        if icon_data:
            try:
                pm = QPixmap()
                pm.loadFromData(icon_data)
                icon_label = QLabel()
                icon_label.setPixmap(pm.scaled(
                    QSize(36, 36), Qt.KeepAspectRatio, Qt.SmoothTransformation
                ))
                icon_label.setFixedSize(36, 36)
                header.addWidget(icon_label)
            except Exception:
                pass

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("Neustart erforderlich")
        title.setObjectName("title")
        title_col.addWidget(title)

        subtitle = QLabel(self._app_name)
        subtitle.setStyleSheet("font-size: 11px; color: #71717a;")
        title_col.addWidget(subtitle)

        header.addLayout(title_col)
        header.addStretch()
        root.addLayout(header)

        # -- Separator --
        root.addSpacing(16)
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.HLine)
        root.addWidget(sep)
        root.addSpacing(16)

        # -- Message --
        msg = QLabel(message or "Es wurden Updates installiert die einen Neustart erfordern.")
        msg.setObjectName("message")
        msg.setWordWrap(True)
        root.addWidget(msg)

        root.addSpacing(20)

        # -- Countdown --
        self._countdown_label = QLabel()
        self._countdown_label.setObjectName("countdown")
        self._countdown_label.setAlignment(Qt.AlignCenter)
        root.addWidget(self._countdown_label)

        root.addSpacing(8)

        # -- Progress Bar --
        self._progress = QProgressBar()
        self._progress.setRange(0, self._total)
        self._progress.setValue(self._total)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(6)
        root.addWidget(self._progress)

        root.addSpacing(6)

        hint = QLabel("Automatischer Neustart wenn der Countdown abgelaufen ist")
        hint.setObjectName("hint")
        hint.setAlignment(Qt.AlignCenter)
        root.addWidget(hint)

        root.addSpacing(20)

        # -- Separator --
        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.HLine)
        root.addWidget(sep2)
        root.addSpacing(16)

        # -- Buttons --
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        if can_defer:
            defer_btn = QPushButton("Verschieben")
            defer_btn.setObjectName("defer_btn")
            defer_btn.setCursor(Qt.PointingHandCursor)
            defer_btn.setMinimumHeight(40)
            defer_btn.clicked.connect(self._on_defer)
            btn_row.addWidget(defer_btn)

        now_btn = QPushButton("Jetzt neustarten")
        now_btn.setObjectName("now_btn")
        now_btn.setCursor(Qt.PointingHandCursor)
        now_btn.setMinimumHeight(40)
        now_btn.clicked.connect(self._on_now)
        btn_row.addWidget(now_btn)

        root.addLayout(btn_row)

        # -- Timer --
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._update_display()

        # Window icon
        if icon_data:
            try:
                pm = QPixmap()
                pm.loadFromData(icon_data)
                self.setWindowIcon(QIcon(pm))
            except Exception:
                pass

    def _update_display(self):
        m, s = divmod(self._remaining, 60)
        self._countdown_label.setText(f"{m:02d}:{s:02d}")
        self._progress.setValue(self._remaining)

    def _tick(self):
        self._remaining -= 1
        self._update_display()
        if self._remaining <= 0:
            self._result = "auto"
            self.accept()

    def _on_now(self):
        self._result = "now"
        self.accept()

    def _on_defer(self):
        self._result = "defer"
        self.reject()

    @property
    def result(self) -> str | None:
        return self._result

    def closeEvent(self, event):
        if self._result is None:
            event.ignore()
        else:
            super().closeEvent(event)
