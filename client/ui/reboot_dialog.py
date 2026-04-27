"""Reboot-Dialog mit Countdown.

Wird vom Tray angezeigt wenn der Proxy einen pending Reboot meldet.
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout,
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont


class RebootDialog(QDialog):
    """Modaler Dialog: 'Neustart erforderlich' mit Countdown."""

    def __init__(self, message: str, countdown: int, can_defer: bool,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Neustart erforderlich")
        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowStaysOnTopHint
            | Qt.CustomizeWindowHint
            | Qt.WindowTitleHint
        )
        self.setMinimumWidth(420)
        self.setMaximumWidth(500)
        self._remaining = max(countdown, 10)
        self._result = None  # "now" | "defer" | "auto"

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Titel
        title = QLabel("Neustart erforderlich")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(title)

        # Meldung
        msg_label = QLabel(
            message or "Es wurden Updates installiert die einen Neustart erfordern."
        )
        msg_label.setWordWrap(True)
        msg_label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(msg_label)

        # Countdown-Anzeige
        self._countdown_label = QLabel()
        self._countdown_label.setAlignment(Qt.AlignCenter)
        self._countdown_label.setFont(QFont("Segoe UI", 28, QFont.Bold))
        self._countdown_label.setStyleSheet("color: #e74c3c; margin: 12px 0;")
        layout.addWidget(self._countdown_label)

        # Hinweis-Text
        hint = QLabel(
            "Der Rechner wird automatisch neu gestartet\n"
            "wenn der Countdown ablauft."
        )
        hint.setAlignment(Qt.AlignCenter)
        hint.setFont(QFont("Segoe UI", 9))
        hint.setStyleSheet("color: #888;")
        layout.addWidget(hint)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        if can_defer:
            defer_btn = QPushButton("Spater")
            defer_btn.setFont(QFont("Segoe UI", 10))
            defer_btn.setMinimumHeight(36)
            defer_btn.clicked.connect(self._on_defer)
            btn_layout.addWidget(defer_btn)

        now_btn = QPushButton("Jetzt neustarten")
        now_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        now_btn.setMinimumHeight(36)
        now_btn.setStyleSheet(
            "QPushButton { background: #e74c3c; color: white; border: none; "
            "border-radius: 6px; padding: 0 20px; }"
            "QPushButton:hover { background: #c0392b; }"
        )
        now_btn.clicked.connect(self._on_now)
        btn_layout.addWidget(now_btn)

        layout.addLayout(btn_layout)

        # Timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._update_display()

    def _update_display(self):
        m, s = divmod(self._remaining, 60)
        self._countdown_label.setText(f"{m:02d}:{s:02d}")

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
        # X-Button sperren — Nutzer muss eine Wahl treffen
        if self._result is None:
            event.ignore()
        else:
            super().closeEvent(event)
