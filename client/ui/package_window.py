"""
Software Center – PyQt5, refined light theme (Linear-inspired).
"""
from collections import defaultdict

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QLineEdit, QSizePolicy,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QRect, QRectF
from PyQt5.QtGui import (
    QColor, QFont, QPainter, QBrush, QPen,
    QPixmap, QIcon, QPainterPath,
)

from api_client import KioskApiClient, Package
from _version import __version__


# ─────────────────────────────────────────────────────────── Design tokens ───

# Surfaces (zinc scale)
C_BG       = "#ffffff"
C_BG_SOFT  = "#fafafa"
C_BG_HOVER = "#f4f4f5"
C_BORDER   = "#e4e4e7"
C_BORDER_S = "#d4d4d8"

# Text
C_FG       = "#09090b"
C_FG_2     = "#27272a"
C_FG_3     = "#52525b"
C_FG_4     = "#71717a"
C_FG_5     = "#a1a1aa"

# Status
C_GREEN    = "#16a34a"
C_GREEN_BG = "#f0fdf4"
C_GREEN_BD = "#bbf7d0"
C_RED      = "#dc2626"
C_RED_BG   = "#fef2f2"
C_RED_BD   = "#fecaca"
C_AMBER    = "#ca8a04"
C_AMBER_BG = "#fefce8"
C_AMBER_BD = "#fde68a"

# Font (Segoe UI is on every Windows install — no bundling needed)
FONT = "Segoe UI"


def _make_window_icon() -> QIcon:
    """Fenster-Icon: schlichtes schwarzes Quadrat mit weißem Innenrahmen."""
    px = QPixmap(32, 32)
    px.fill(Qt.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor(C_FG)))
    p.drawRoundedRect(QRectF(3, 3, 26, 26), 5, 5)
    pen = QPen(QColor(255, 255, 255), 1.6)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawRect(QRectF(10, 10, 12, 12))
    p.end()
    return QIcon(px)


# ───────────────────────────────────────────────────────── Custom widgets ────

class _Avatar(QWidget):
    """Flaches Tile mit Initial — kein Farbtopf-Look, einheitlich neutral."""

    def __init__(self, name: str, size: int = 34, parent=None):
        super().__init__(parent)
        self._letter = (name or "?")[0].upper()
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_OpaquePaintEvent, False)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        p.setPen(QPen(QColor(C_BORDER), 1))
        p.setBrush(QBrush(QColor(C_BG_HOVER)))
        p.drawRoundedRect(r, 6, 6)
        p.setPen(QPen(QColor(C_FG_3)))
        p.setFont(QFont(FONT, 13, QFont.DemiBold))
        p.drawText(self.rect(), Qt.AlignCenter, self._letter)
        p.end()


class _Spinner(QWidget):
    """Animierter Ladekreis – dünn, neutral."""

    def __init__(self, size: int = 28, parent=None):
        super().__init__(parent)
        self._angle = 0
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_OpaquePaintEvent, False)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.destroyed.connect(self._timer.stop)

    def start(self):
        self._timer.start(16)
        self.show()

    def stop(self):
        self._timer.stop()
        self.hide()

    def _tick(self):
        self._angle = (self._angle + 6) % 360
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(3, 3, -3, -3)
        p.setPen(QPen(QColor(C_BORDER_S), 2, Qt.SolidLine, Qt.RoundCap))
        p.drawEllipse(r)
        p.setPen(QPen(QColor(C_FG), 2, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(r, (90 - self._angle) * 16, -260 * 16)
        p.end()


class _Toast(QFrame):
    """Schwarze Pille unten-mitte, auto-dismiss."""

    def __init__(self, msg: str, ok: bool, parent: QWidget):
        super().__init__(parent)
        bg  = "#09090b" if ok else "#dc2626"
        self.setStyleSheet(f"""
            QFrame {{
                background: {bg};
                border-radius: 7px;
            }}
            QLabel {{
                background: transparent;
                color: white;
                border: none;
            }}
        """)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 9, 16, 10)
        lay.setSpacing(8)

        lbl = QLabel(msg)
        lbl.setFont(QFont(FONT, 10))
        lbl.setWordWrap(True)
        lbl.setMaximumWidth(320)
        lay.addWidget(lbl)

        self.adjustSize()
        QTimer.singleShot(3200, self.deleteLater)

    def showEvent(self, event):
        super().showEvent(event)
        if self.parent():
            pw = self.parent()
            self.adjustSize()
            x = (pw.width() - self.width()) // 2
            y = pw.height() - self.height() - 32
            self.move(x, y)


class _SidebarItem(QWidget):
    """Subtile Sidebar-Pille mit Hover/Active Background."""

    selected = pyqtSignal(str)

    def __init__(self, label: str, count: int, parent=None):
        super().__init__(parent)
        self._label  = label
        self._count  = count
        self._active = False
        self._hover  = False
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(32)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(0)

        self._lbl = QLabel(label)
        self._lbl.setFont(QFont(FONT, 10))
        self._lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        lay.addWidget(self._lbl)

        self._badge = QLabel(str(count))
        self._badge.setFont(QFont(FONT, 9))
        self._badge.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        lay.addWidget(self._badge)

        self._update_text()

    def set_active(self, active: bool):
        if self._active == active:
            return
        self._active = active
        self._update_text()
        self.update()

    def _update_text(self):
        if self._active:
            self._lbl.setStyleSheet(f"color: {C_FG}; font-weight: 600; background: transparent;")
            self._badge.setStyleSheet(f"color: {C_FG_4}; background: transparent;")
        else:
            self._lbl.setStyleSheet(f"color: {C_FG_3}; background: transparent;")
            self._badge.setStyleSheet(f"color: {C_FG_5}; background: transparent;")

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(10.5, 2.5, self.width() - 21, self.height() - 5)
        if self._active:
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(QColor(C_BG_HOVER)))
            p.drawRoundedRect(r, 6, 6)
        elif self._hover:
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(QColor(C_BG_SOFT)))
            p.drawRoundedRect(r, 6, 6)
        p.end()

    def enterEvent(self, event):
        self._hover = True
        if not self._active:
            self._lbl.setStyleSheet(f"color: {C_FG}; background: transparent;")
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover = False
        if not self._active:
            self._update_text()
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected.emit(self._label)
        super().mousePressEvent(event)


class _ActionButton(QPushButton):
    """Schwarz / Ghost / Rot-Hover Action Button."""

    _CSS_INSTALL = f"""
        QPushButton {{
            background: {C_FG};
            color: white;
            border: 1px solid {C_FG};
            border-radius: 6px;
            font-family: '{FONT}';
            font-size: 11px;
            font-weight: 600;
            padding: 0 14px;
        }}
        QPushButton:hover {{
            background: {C_FG_2};
            border-color: {C_FG_2};
        }}
        QPushButton:pressed {{
            background: #000000;
        }}
        QPushButton:disabled {{
            background: {C_BG_SOFT};
            color: {C_FG_5};
            border-color: {C_BORDER};
        }}
    """

    _CSS_INSTALLED = f"""
        QPushButton {{
            background: {C_BG};
            color: {C_FG_3};
            border: 1px solid {C_BORDER};
            border-radius: 6px;
            font-family: '{FONT}';
            font-size: 11px;
            font-weight: 500;
            padding: 0 14px;
        }}
        QPushButton:hover {{
            background: {C_BG_SOFT};
            border-color: {C_BORDER_S};
        }}
    """

    _CSS_UNINSTALL = f"""
        QPushButton {{
            background: {C_RED_BG};
            color: {C_RED};
            border: 1px solid {C_RED_BD};
            border-radius: 6px;
            font-family: '{FONT}';
            font-size: 11px;
            font-weight: 600;
            padding: 0 14px;
        }}
        QPushButton:hover {{
            background: #fee2e2;
            border-color: #fca5a5;
        }}
    """

    _CSS_UPDATE = f"""
        QPushButton {{
            background: {C_AMBER_BG};
            color: {C_AMBER};
            border: 1px solid {C_AMBER_BD};
            border-radius: 6px;
            font-family: '{FONT}';
            font-size: 11px;
            font-weight: 600;
            padding: 0 14px;
        }}
        QPushButton:hover {{
            background: {C_AMBER};
            color: white;
            border-color: {C_AMBER};
        }}
    """

    _CSS_BUSY = f"""
        QPushButton {{
            background: {C_BG_SOFT};
            color: {C_FG_5};
            border: 1px solid {C_BORDER};
            border-radius: 6px;
            font-family: '{FONT}';
            font-size: 11px;
            font-weight: 500;
            padding: 0 14px;
        }}
    """

    def __init__(self, pkg: Package, on_install, on_uninstall):
        super().__init__()
        self._pkg          = pkg
        self._on_install   = on_install
        self._on_uninstall = on_uninstall
        self._busy         = False
        self.setFixedSize(QSize(118, 30))
        self.setCursor(Qt.PointingHandCursor)
        self._refresh()
        self.clicked.connect(self._handle)
        if self._pkg.update_available:
            tip = "Updaten klickt installiert die neue Version (Reinstall)."
            if self._pkg.installed_version_label and self._pkg.current_version_label:
                tip = (
                    f"Update verfügbar: {self._pkg.installed_version_label} "
                    f"→ {self._pkg.current_version_label}"
                )
            self.setToolTip(tip)

    def _refresh(self):
        if self._pkg.update_available:
            self.setText("Updaten")
            self.setStyleSheet(self._CSS_UPDATE)
        elif self._pkg.installed:
            self.setText("Installiert")
            self.setStyleSheet(self._CSS_INSTALLED)
        else:
            self.setText("Installieren")
            self.setStyleSheet(self._CSS_INSTALL)

    def set_busy(self, busy: bool):
        self._busy = busy
        self.setEnabled(not busy)
        if busy:
            self.setText("…")
            self.setStyleSheet(self._CSS_BUSY)
        else:
            self._refresh()

    def enterEvent(self, event):
        # Bei update_available kein Hover-Swap → der Click-Pfad ist eindeutig "Updaten"
        if not self._busy and self._pkg.installed and not self._pkg.update_available:
            self.setText("Deinstallieren")
            self.setStyleSheet(self._CSS_UNINSTALL)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if not self._busy and self._pkg.installed and not self._pkg.update_available:
            self._refresh()
        super().leaveEvent(event)

    def _handle(self):
        # update_available → install (Reinstall der current Version)
        if self._pkg.update_available:
            self._on_install(self._pkg, self)
        elif self._pkg.installed:
            self._on_uninstall(self._pkg, self)
        else:
            self._on_install(self._pkg, self)


class _PackageCard(QWidget):
    """Saubere Karte: weiß, dünner Border, Hover-Tint. Keine Schatten."""

    def __init__(self, pkg: Package, on_install, on_uninstall):
        super().__init__()
        from html import escape as _h
        self._hover = False
        self.setMinimumHeight(72)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(14)

        lay.addWidget(_Avatar(pkg.name))

        info = QVBoxLayout()
        info.setSpacing(2)

        # Plain-Text erzwingen, damit display_name aus der DB nicht als HTML
        # interpretiert wird (admin-controlled, aber defense-in-depth).
        name_lbl = QLabel(pkg.display_name or "")
        name_lbl.setTextFormat(Qt.PlainText)
        name_lbl.setFont(QFont(FONT, 11, QFont.DemiBold))
        name_lbl.setStyleSheet(f"color: {C_FG}; background: transparent;")
        info.addWidget(name_lbl)

        # Quelle + Status in der zweiten Zeile.
        #   - choco  → "Chocolatey ↗" (Link zu community.chocolatey.org)
        #   - custom → "Eigenes Paket"
        #   - winget → "winget" (kein Link)
        if pkg.type == "custom":
            source_html = '<span style="color:#71717a">Eigenes Paket</span>'
        elif pkg.type == "winget":
            source_html = '<span style="color:#71717a">winget</span>'
        else:
            url = f"https://community.chocolatey.org/packages/{_h(pkg.name)}"
            source_html = (
                f'<a href="{url}" style="color:#71717a; text-decoration:none">'
                f'Chocolatey&nbsp;↗</a>'
            )

        # ALLE interpolierten Werte unten kommen letztlich aus Tactical bzw.
        # der Server-DB. Tactical's Software-Scan liest Display-Namen, Versionen
        # und Publisher aus der Windows-Registry — diese Werte sind nicht
        # vertrauenswürdig (siehe security review). HTML-escape!
        if pkg.installed and pkg.version:
            sub_html = (
                f'{source_html} <span style="color:#a1a1aa">·</span> '
                f'<span style="color:#71717a">Version {_h(pkg.version)}</span>'
            )
        elif pkg.installed:
            sub_html = (
                f'{source_html} <span style="color:#a1a1aa">·</span> '
                f'<span style="color:#71717a">Installiert</span>'
            )
        else:
            sub_html = source_html

        # Update-Hinweis bei custom-Paketen mit verfügbarem Update
        if pkg.update_available and pkg.installed_version_label and pkg.current_version_label:
            sub_html += (
                f' <span style="color:#a1a1aa">·</span> '
                f'<span style="color:#ca8a04; font-weight:600">'
                f'Update {_h(pkg.installed_version_label)} → {_h(pkg.current_version_label)}'
                f'</span>'
            )
        elif pkg.update_available:
            sub_html += (
                f' <span style="color:#a1a1aa">·</span> '
                f'<span style="color:#ca8a04; font-weight:600">Update verfügbar</span>'
            )

        sub_lbl = QLabel(sub_html)
        sub_lbl.setTextFormat(Qt.RichText)
        # Nur die Chocolatey-URL ist eine vertrauenswürdige externe URL.
        # Bei custom- und winget-Paketen gibt es keinen Link → Open-External
        # abdrehen, damit auch versehentliche file:// Links aus Tactical- bzw.
        # Catalog-Daten nicht geöffnet werden.
        sub_lbl.setOpenExternalLinks(pkg.type == "choco")
        sub_lbl.setFont(QFont(FONT, 9))
        sub_lbl.setStyleSheet(f"color: {C_FG_4}; background: transparent;")
        sub_lbl.setCursor(
            Qt.IBeamCursor if pkg.type in ("custom", "winget") else Qt.ArrowCursor
        )
        info.addWidget(sub_lbl)

        # Publisher als Tooltip wenn vorhanden — Tooltips sind Plain-Text by default
        if pkg.publisher:
            sub_lbl.setToolTip(f"Publisher: {pkg.publisher}")
            name_lbl.setToolTip(f"Publisher: {pkg.publisher}")

        lay.addLayout(info, stretch=1)
        lay.addWidget(_ActionButton(pkg, on_install, on_uninstall), alignment=Qt.AlignVCenter)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        bg = QColor(C_BG_SOFT) if self._hover else QColor(C_BG)
        bd = QColor(C_BORDER_S) if self._hover else QColor(C_BORDER)
        p.setPen(QPen(bd, 1))
        p.setBrush(QBrush(bg))
        p.drawRoundedRect(r, 8, 8)
        p.end()

    def enterEvent(self, e):
        self._hover = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hover = False
        self.update()
        super().leaveEvent(e)


class _CatHeader(QWidget):
    """Kategorie-Überschrift: kleines Label, kein Linien-Schmuck."""

    def __init__(self, text: str, count: int, first: bool = False):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(2, 0 if first else 22, 2, 8)
        lay.setSpacing(8)

        lbl = QLabel(text)
        lbl.setFont(QFont(FONT, 10, QFont.DemiBold))
        lbl.setStyleSheet(f"color: {C_FG_2}; background: transparent;")
        lay.addWidget(lbl)

        cnt = QLabel(str(count))
        cnt.setFont(QFont(FONT, 10))
        cnt.setStyleSheet(f"color: {C_FG_5}; background: transparent;")
        lay.addWidget(cnt)
        lay.addStretch()


# ──────────────────────────────────────────────────────── Worker threads ─────

class _Loader(QThread):
    done   = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, api: KioskApiClient):
        super().__init__()
        self._api = api

    def run(self):
        try:
            self.done.emit(self._api.get_packages())
        except Exception as e:
            msg = str(e)
            try:
                import httpx
                if isinstance(e, httpx.HTTPStatusError):
                    detail = e.response.json().get("detail", msg)
                    msg = f"HTTP {e.response.status_code}: {detail}"
            except Exception:
                pass
            self.failed.emit(msg)


class _ActionWorker(QThread):
    done   = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, api: KioskApiClient, action: str, name: str):
        super().__init__()
        self._api, self._action, self._name = api, action, name

    def run(self):
        try:
            if self._action == "install":
                self.done.emit(self._api.install_package(self._name))
            else:
                self.done.emit(self._api.uninstall_package(self._name))
        except Exception as e:
            msg = str(e)
            try:
                import httpx
                if isinstance(e, httpx.HTTPStatusError):
                    detail = e.response.json().get("detail", msg)
                    msg = f"HTTP {e.response.status_code}: {detail}"
            except Exception:
                pass
            self.failed.emit(msg)


# ──────────────────────────────────────────────────────────── Main window ────

class PackageWindow(QWidget):
    def __init__(self, api: KioskApiClient, app_name: str = "Softshelf"):
        super().__init__()
        self._api       = api
        self._app_name  = app_name
        self._packages: list[Package] = []
        self._loader:   _Loader | None       = None
        self._worker:   _ActionWorker | None = None
        self._active_cat = "Alle"
        self._sidebar_items: dict[str, _SidebarItem] = {}
        self._spinner: _Spinner | None = None

        self.setWindowTitle(app_name)
        self.setWindowIcon(_make_window_icon())
        self.resize(900, 660)
        self.setMinimumSize(640, 480)
        self.setStyleSheet(f"QWidget {{ background: {C_BG}; font-family: '{FONT}'; }}")
        self._build_ui()
        self._load()

    # ── UI build ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        root.addWidget(self._divider())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._divider(vertical=True))
        body.addWidget(self._build_scroll(), stretch=1)

        body_w = QWidget()
        body_w.setStyleSheet(f"background: {C_BG};")
        body_w.setLayout(body)
        root.addWidget(body_w, stretch=1)

        root.addWidget(self._divider())
        root.addWidget(self._build_statusbar())

    def _divider(self, vertical: bool = False) -> QFrame:
        f = QFrame()
        if vertical:
            f.setFixedWidth(1)
        else:
            f.setFixedHeight(1)
        f.setStyleSheet(f"background: {C_BORDER}; border: none;")
        return f

    def _build_header(self) -> QFrame:
        f = QFrame()
        f.setStyleSheet(f"QFrame {{ background: {C_BG}; border: none; }}")
        f.setFixedHeight(64)

        lay = QHBoxLayout(f)
        lay.setContentsMargins(24, 14, 24, 14)
        lay.setSpacing(14)

        ttl = QLabel(self._app_name)
        ttl.setFont(QFont(FONT, 14, QFont.DemiBold))
        ttl.setStyleSheet(f"color: {C_FG}; background: transparent;")
        lay.addWidget(ttl, stretch=1, alignment=Qt.AlignVCenter)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Suchen…")
        self._search.setFixedSize(240, 32)
        self._search.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid {C_BORDER_S};
                border-radius: 6px;
                padding: 0 12px;
                font-size: 11px;
                background: {C_BG};
                color: {C_FG};
                selection-background-color: {C_FG_5};
            }}
            QLineEdit:focus {{
                border-color: {C_FG};
            }}
            QLineEdit::placeholder {{
                color: {C_FG_5};
            }}
        """)
        self._search.textChanged.connect(self._apply_filter)
        lay.addWidget(self._search, alignment=Qt.AlignVCenter)
        return f

    def _build_sidebar(self) -> QWidget:
        w = QWidget()
        w.setFixedWidth(208)
        w.setStyleSheet(f"background: {C_BG};")

        self._sidebar_layout = QVBoxLayout(w)
        self._sidebar_layout.setContentsMargins(0, 18, 0, 18)
        self._sidebar_layout.setSpacing(1)

        heading = QLabel("Kategorien")
        heading.setFont(QFont(FONT, 9))
        heading.setStyleSheet(
            f"color: {C_FG_5}; background: transparent;"
            f" padding: 0 0 6px 22px; font-weight: 500; letter-spacing: 0.02em;"
        )
        self._sidebar_layout.addWidget(heading)
        self._sidebar_layout.addStretch()
        return w

    def _build_scroll(self) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {C_BG}; }}
            QScrollBar:vertical {{
                background: {C_BG};
                width: 10px;
                margin: 0;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {C_BORDER};
                border-radius: 5px;
                min-height: 32px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical:hover {{ background: {C_BORDER_S}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
        """)
        self._list_w = QWidget()
        self._list_w.setStyleSheet(f"background: {C_BG};")
        self._list_l = QVBoxLayout(self._list_w)
        self._list_l.setContentsMargins(28, 22, 28, 22)
        self._list_l.setSpacing(8)
        self._list_l.addStretch()
        scroll.setWidget(self._list_w)
        return scroll

    def _build_statusbar(self) -> QFrame:
        f = QFrame()
        f.setFixedHeight(46)
        f.setStyleSheet(f"QFrame {{ background: {C_BG}; border: none; }}")
        lay = QHBoxLayout(f)
        lay.setContentsMargins(20, 8, 20, 8)
        lay.setSpacing(12)

        refresh = QPushButton("Aktualisieren")
        refresh.setFixedHeight(28)
        refresh.setCursor(Qt.PointingHandCursor)
        refresh.setStyleSheet(f"""
            QPushButton {{
                background: {C_BG};
                color: {C_FG_2};
                border: 1px solid {C_BORDER_S};
                border-radius: 6px;
                font-family: '{FONT}';
                font-size: 11px;
                font-weight: 500;
                padding: 0 12px;
            }}
            QPushButton:hover {{
                background: {C_BG_SOFT};
                border-color: {C_FG_5};
            }}
            QPushButton:pressed {{
                background: {C_BG_HOVER};
            }}
        """)
        refresh.clicked.connect(self._load)
        lay.addWidget(refresh)

        self._status_lbl = QLabel()
        self._status_lbl.setFont(QFont(FONT, 10))
        self._status_lbl.setStyleSheet(f"color: {C_FG_4}; background: transparent;")
        lay.addWidget(self._status_lbl, stretch=1)

        ver_lbl = QLabel(f"v{__version__}")
        ver_lbl.setFont(QFont(FONT, 9))
        ver_lbl.setStyleSheet(f"color: {C_FG_5}; background: transparent;")
        lay.addWidget(ver_lbl, alignment=Qt.AlignRight | Qt.AlignVCenter)
        return f

    # ── Data loading ─────────────────────────────────────────────────────────

    def _load(self, keep_cat: bool = False):
        # Suchfeld bewusst NICHT clearen
        if not keep_cat:
            self._active_cat = "Alle"
        self._set_status("Pakete werden geladen…")
        self._show_loading()

        if self._loader and self._loader.isRunning():
            return
        self._loader = _Loader(self._api)
        self._loader.done.connect(self._on_loaded)
        self._loader.failed.connect(self._on_error)
        self._loader.start()

    def _on_loaded(self, packages: list[Package]):
        self._packages = packages
        installed = sum(1 for p in packages if p.installed)
        n = len(packages)
        self._set_status(f"{n} {'Paket' if n == 1 else 'Pakete'} · {installed} installiert")
        self._rebuild_sidebar(packages)
        self._apply_filter()

    def _on_error(self, msg: str):
        self._set_status(f"Fehler: {msg}", error=True)
        self._clear_list()

        w = QWidget()
        w.setStyleSheet("background: transparent;")
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 80, 0, 0)
        v.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        v.setSpacing(12)

        # Icon-Container
        icon_box = QFrame()
        icon_box.setFixedSize(44, 44)
        icon_box.setStyleSheet(f"""
            QFrame {{
                background: {C_BG_SOFT};
                border: 1px solid {C_BORDER};
                border-radius: 8px;
            }}
            QLabel {{ background: transparent; border: none; }}
        """)
        ibl = QHBoxLayout(icon_box)
        ibl.setContentsMargins(0, 0, 0, 0)
        ico = QLabel("!")
        ico.setFont(QFont(FONT, 18, QFont.DemiBold))
        ico.setStyleSheet(f"color: {C_FG_4}; background: transparent;")
        ico.setAlignment(Qt.AlignCenter)
        ibl.addWidget(ico)
        v.addWidget(icon_box, alignment=Qt.AlignHCenter)

        lbl = QLabel("Verbindungsfehler")
        lbl.setFont(QFont(FONT, 12, QFont.DemiBold))
        lbl.setStyleSheet(f"color: {C_FG}; background: transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        v.addWidget(lbl)

        det = QLabel(msg)
        det.setFont(QFont(FONT, 10))
        det.setStyleSheet(f"color: {C_FG_4}; background: transparent;")
        det.setAlignment(Qt.AlignCenter)
        det.setWordWrap(True)
        det.setMaximumWidth(420)
        v.addWidget(det, alignment=Qt.AlignHCenter)

        self._list_l.insertWidget(0, w)

    # ── Sidebar ──────────────────────────────────────────────────────────────

    def _rebuild_sidebar(self, packages: list[Package]):
        while self._sidebar_layout.count() > 2:
            item = self._sidebar_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        self._sidebar_items.clear()

        counts: dict[str, int] = defaultdict(int)
        for p in packages:
            counts[p.category] += 1

        all_item = _SidebarItem("Alle", len(packages))
        all_item.set_active(self._active_cat == "Alle")
        all_item.selected.connect(self._on_cat_selected)
        self._sidebar_layout.insertWidget(1, all_item)
        self._sidebar_items["Alle"] = all_item

        for idx, (cat, cnt) in enumerate(sorted(counts.items())):
            item = _SidebarItem(cat, cnt)
            item.set_active(self._active_cat == cat)
            item.selected.connect(self._on_cat_selected)
            self._sidebar_layout.insertWidget(2 + idx, item)
            self._sidebar_items[cat] = item

    def _on_cat_selected(self, category: str):
        self._active_cat = category
        for name, item in self._sidebar_items.items():
            item.set_active(name == category)
        self._apply_filter()

    # ── Filter & render ──────────────────────────────────────────────────────

    def _apply_filter(self):
        q    = self._search.text().lower()
        pkgs = self._packages

        if self._active_cat != "Alle":
            pkgs = [p for p in pkgs if p.category == self._active_cat]
        if q:
            pkgs = [p for p in pkgs if q in p.display_name.lower() or q in p.name.lower()]

        self._render(pkgs)

    @staticmethod
    def _sort_key(p: Package) -> tuple:
        """Sort-Key für die Paket-Liste.

        Reihenfolge:
          1. Pakete mit verfügbarem Update (update_available=True) zuerst
          2. Innerhalb jeder Gruppe alphabetisch nach display_name
        """
        return (
            0 if p.update_available else 1,
            (p.display_name or p.name or "").lower(),
        )

    def _render(self, packages: list[Package]):
        self._clear_list()

        if not packages:
            empty = QLabel(
                "Keine Pakete gefunden."
                if self._search.text() else
                "Keine Pakete verfügbar."
            )
            empty.setAlignment(Qt.AlignCenter)
            empty.setFont(QFont(FONT, 11))
            empty.setStyleSheet(f"color: {C_FG_5}; background: transparent;")
            empty.setContentsMargins(0, 60, 0, 0)
            self._list_l.insertWidget(0, empty)
            return

        if self._active_cat == "Alle":
            groups: dict[str, list[Package]] = defaultdict(list)
            for p in packages:
                groups[p.category].append(p)
            pos   = 0
            first = True
            for cat, pkgs in sorted(groups.items()):
                self._list_l.insertWidget(pos, _CatHeader(cat, len(pkgs), first=first))
                pos  += 1
                first = False
                for pkg in sorted(pkgs, key=self._sort_key):
                    self._list_l.insertWidget(pos, _PackageCard(pkg, self._install, self._uninstall))
                    pos += 1
        else:
            for i, pkg in enumerate(sorted(packages, key=self._sort_key)):
                self._list_l.insertWidget(i, _PackageCard(pkg, self._install, self._uninstall))

    def _show_loading(self):
        self._clear_list()
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 100, 0, 0)
        v.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        v.setSpacing(14)

        self._spinner = _Spinner(28)
        self._spinner.start()
        v.addWidget(self._spinner, alignment=Qt.AlignCenter)

        lbl = QLabel("Pakete werden geladen…")
        lbl.setFont(QFont(FONT, 10))
        lbl.setStyleSheet(f"color: {C_FG_5}; background: transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        v.addWidget(lbl)

        self._list_l.insertWidget(0, w)

    def _clear_list(self):
        if self._spinner:
            self._spinner.stop()
            self._spinner = None
        while self._list_l.count() > 1:
            item = self._list_l.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _set_status(self, text: str, error: bool = False):
        self._status_lbl.setText(text)
        color = C_RED if error else C_FG_4
        self._status_lbl.setStyleSheet(f"color: {color}; background: transparent;")

    # ── Actions ──────────────────────────────────────────────────────────────

    def _busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def _install(self, pkg: Package, btn: _ActionButton):
        if self._busy():
            self._show_toast("Bitte warten – andere Aktion läuft noch.", ok=False)
            return
        self._set_status(f"Installiere {pkg.display_name}…")
        btn.set_busy(True)
        self._run_action("install", pkg, btn)

    def _uninstall(self, pkg: Package, btn: _ActionButton):
        if self._busy():
            self._show_toast("Bitte warten – andere Aktion läuft noch.", ok=False)
            return
        self._set_status(f"Deinstalliere {pkg.display_name}…")
        btn.set_busy(True)
        self._run_action("uninstall", pkg, btn)

    def _run_action(self, action: str, pkg: Package, btn: _ActionButton):
        worker = _ActionWorker(self._api, action, pkg.name)

        def on_done(msg: str):
            self._set_status(msg)
            self._show_toast(msg, ok=True)
            pkg.installed = (action == "install")
            btn.set_busy(False)
            self._apply_filter()

        def on_fail(msg: str):
            self._set_status(f"Fehler: {msg}", error=True)
            self._show_toast(msg, ok=False)
            btn.set_busy(False)

        worker.done.connect(on_done)
        worker.failed.connect(on_fail)
        worker.start()
        self._worker = worker

    def _show_toast(self, msg: str, ok: bool):
        toast = _Toast(msg, ok, self)
        toast.show()
        toast.raise_()
