#!/usr/bin/env python3
"""Secure Backup — choose Encrypt or Decrypt, add folders or files, give a
passphrase, and get copies next to the originals. One action per run, one
step at a time. The crypto lives in secure_backup.py; this file is only the
window.

The look borrows from security envelopes: the drop zone and the step bar are
printed with the interlaced waves that keep an envelope's contents unreadable,
with a clear "address window" for the text."""

import math
import subprocess
import sys
import time
from pathlib import Path
from string import Template

from PySide6.QtCore import QByteArray, QPointF, QRectF, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import (
    QColor, QDesktopServices, QFont, QFontDatabase, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen,
    QPixmap,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSizePolicy, QStackedWidget, QToolButton,
    QVBoxLayout, QWidget,
)

from secure_backup import (
    ENCRYPTED_SUFFIX, decrypt_file, default_target, detect_mode, encrypt_file, needs_work, numbered, plan,
    same_passphrase, suggest_passphrase,
)

# --- look ----------------------------------------------------------------

LIGHT = dict(
    paper="#EEF1F5", surface="#FFFFFF", field="#FFFFFF", line="#D9DFE7", track="#DDE3EC",
    ink="#18212F", ink2="#566174", ink3="#646E80",
    accent="#2C49B8", accent_hover="#233D9E", accent_text="#2C49B8", accent_soft="#E4E9FA", on_accent="#FFFFFF",
    open="#16794F", open_soft="#DFF1E8", danger="#C23434", danger_soft="#FAE6E6",
    pattern="0.22",
)
DARK = dict(
    paper="#12161D", surface="#1A1F28", field="#1F2530", line="#2C3340", track="#2A3140",
    ink="#E7EBF1", ink2="#A3ADBC", ink3="#7D8899",
    accent="#4A66E0", accent_hover="#5A75EA", accent_text="#8FA5FF", accent_soft="#222C4D", on_accent="#FFFFFF",
    open="#52C793", open_soft="#1A3328", danger="#F07373", danger_soft="#3B2023",
    pattern="0.17",
)

FONT = "IBM Plex Sans"  # bundled in assets/fonts (SIL Open Font License), so every OS looks the same


def use_bundled_font(app):
    """Load assets/fonts and make FONT the app's font. Without the files Qt quietly
    falls back to the system font."""
    fonts = Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "assets" / "fonts"  # PyInstaller unpacks here
    for path in fonts.glob("*.ttf"):
        QFontDatabase.addApplicationFont(str(path))
    app.setFont(QFont(FONT))

QSS = Template("""
* { font-size: 13px; }
QWidget#root, QMessageBox { background: $paper; }
QLabel { color: $ink; }
QLabel:disabled { color: $ink3; }
QLabel#title { font-size: 22px; font-weight: 600; }
QLabel#subtitle { color: $ink2; }
QLabel#pageTitle { font-size: 24px; font-weight: 700; }
QLabel#section { color: $ink2; font-weight: 600; }
QLabel#dropTitle { font-size: 16px; font-weight: 600; }
QLabel#dropHint, QLabel#meta { color: $ink2; font-size: 12px; }
QLabel#badge { background: $accent_soft; border-radius: 24px; }
QLabel#hint { color: $ink2; font-size: 12px; }
QLabel#hint[tone="ok"] { color: $open; }
QLabel#hint[tone="error"] { color: $danger; }
QLabel#rowName { font-size: 14px; font-weight: 600; }
QLabel#tile { border-radius: 9px; }
QLabel#tile[mode="encrypt"] { background: $accent_soft; }
QLabel#tile[mode="decrypt"] { background: $open_soft; }
QLabel#resultTile { border-radius: 22px; }
QLabel#resultTile[tone="ok"] { background: $open_soft; }
QLabel#resultTile[tone="warn"] { background: $danger_soft; }
QLabel#headline { font-size: 17px; font-weight: 600; }
QLabel#percent { font-size: 17px; font-weight: 600; color: $accent_text; }
QLabel#body { color: $ink2; }
QLabel#choiceTitle { font-size: 17px; font-weight: 600; }
QLabel#suggested { font-size: 20px; font-weight: 600; }
QLabel#stepName { color: $ink2; font-weight: 600; }
QLabel#stepName[state="current"] { color: $ink; }
QFrame#stepLine { background: $line; }
QFrame#suggestBox { background: $surface; border: 1px solid $line; border-radius: 12px; }

QPushButton {
    background: $surface; color: $ink; border: 1px solid $line; border-radius: 8px;
    padding: 0 16px; min-height: 34px; font-weight: 600;
}
QPushButton:hover { background: $paper; }
QPushButton:pressed { background: $track; }
QPushButton:focus { border-color: $accent; }
QPushButton:disabled { color: $ink3; }
QPushButton#primary, QMessageBox QPushButton:default {
    background: $accent; color: $on_accent; border: 2px solid $accent; border-radius: 10px;
}
QPushButton#primary { min-height: 40px; font-size: 14px; }
QPushButton#primary:hover, QMessageBox QPushButton:default:hover { background: $accent_hover; border-color: $accent_hover; }
QPushButton#primary:focus { border-color: $ink; }
QPushButton#primary:disabled { background: $track; border-color: $track; color: $ink3; }
QPushButton[large="true"] { min-height: 40px; }
QPushButton#link { background: transparent; border: none; color: $accent_text; padding: 0; min-height: 0; }
QPushButton#link:hover, QPushButton#link:focus { text-decoration: underline; }
QPushButton#link:disabled { color: $ink3; }
QPushButton#choice { background: $surface; border: 1px solid $line; border-radius: 12px; padding: 0; min-height: 88px; }
QPushButton#choice:hover { border-color: $accent; }
QPushButton#choice:focus { border: 2px solid $accent; }
QToolButton#remove { background: transparent; border: none; border-radius: 14px; }
QToolButton#remove:hover { background: $track; }

QLineEdit {
    background: $field; color: $ink; border: 1px solid $line; border-radius: 8px;
    padding: 0 10px; min-height: 38px; selection-background-color: $accent; selection-color: $on_accent;
}
QLineEdit:focus { border-color: $accent; }
QCheckBox { color: $ink2; spacing: 8px; }

QListWidget#queue { background: transparent; border: none; outline: none; }
QListWidget#queue::item { border-bottom: 1px solid $line; }
QListWidget#queue::item:hover, QListWidget#queue::item:selected { background: transparent; }

QProgressBar { background: $track; border: none; border-radius: 4px; min-height: 8px; max-height: 8px; }
QProgressBar::chunk { background: $accent; border-radius: 4px; }

QPlainTextEdit {
    background: $field; color: $ink2; border: 1px solid $line; border-radius: 8px; padding: 6px; font-size: 12px;
}
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: $line; border-radius: 3px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: $surface; color: $ink; border: 1px solid $line; padding: 4px 8px; }
QMessageBox QLabel#qt_msgbox_label { font-size: 15px; font-weight: 600; }
QMessageBox QLabel#qt_msgbox_informativelabel { color: $ink2; }
""")

ICONS = {  # 24×24 strokes, colored at render time
    "folder": '<path d="M3.5 7a2 2 0 0 1 2-2h3.6l2 2.4h7.4a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
    "file": '<path d="M13.5 3.5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9z"/><path d="M13.5 3.5V9H19"/>',
    "drop": '<path d="M12 3.5v11M7.5 10 12 14.5 16.5 10"/><path d="M4.5 14.5v3a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-3"/>',
    "x": '<path d="M7 7l10 10M17 7 7 17"/>',
    "check": '<path d="M6 12.5l4 4L18 8"/>',
    "alert": '<path d="M12 6.5v7M12 17v.5"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "unlock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.6-1.8"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    "refresh": '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 5v6h-6"/>',
}


def icon_pixmap(name, color, size):
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{}" '
           'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{}</svg>').format(color, ICONS[name])
    dpr = 3
    pm = QPixmap(size * dpr, size * dpr)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    pm.setDevicePixelRatio(dpr)
    return pm


def step_badge(n, state, t):
    """The circle in front of a step's name: a check once it's done, else its number."""
    size, dpr = 22, 3
    pm = QPixmap(size * dpr, size * dpr)
    pm.fill(Qt.GlobalColor.transparent)
    pm.setDevicePixelRatio(dpr)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    circle = QRectF(0.5, 0.5, size - 1, size - 1)
    if state == "done":
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(t["open_soft"]))
        p.drawEllipse(circle)
        p.drawPixmap(QPointF(4, 4), icon_pixmap("check", t["open"], 14))
    else:
        current = state == "current"
        p.setPen(Qt.PenStyle.NoPen if current else QPen(QColor(t["ink3"]), 1))
        p.setBrush(QColor(t["accent"]) if current else Qt.BrushStyle.NoBrush)
        p.drawEllipse(circle)
        font = QApplication.font()
        font.setPixelSize(12)
        font.setBold(current)
        p.setFont(font)
        p.setPen(QColor(t["on_accent" if current else "ink2"]))
        p.drawText(circle, Qt.AlignmentFlag.AlignCenter, str(n))
    p.end()
    return pm


def draw_guilloche(painter, rect, color, spacing, amplitude, wavelength, width=1.0):
    """Interlaced sine waves, the pattern printed inside security envelopes."""
    painter.setPen(QPen(color, width))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    k, step = 2 * math.pi / wavelength, max(1.0, wavelength / 18)
    y, row = rect.top() - spacing, 0
    while y < rect.bottom() + spacing:
        for phase in (row * 0.8, row * 0.8 + math.pi):
            x = rect.left()
            path = QPainterPath(QPointF(x, y + amplitude * math.sin(phase)))
            while x < rect.right():
                x += step
                path.lineTo(x, y + amplitude * math.sin(k * (x - rect.left()) + phase))
            painter.drawPath(path)
        y, row = y + spacing, row + 1


def app_icon(size, inset=100):
    """The app icon, drawn on a 1024 grid: an ink-blue tile with envelope waves and a lock."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 1024, size / 1024)
    tile = QRectF(inset, inset, 1024 - 2 * inset, 1024 - 2 * inset)
    shape = QPainterPath()
    shape.addRoundedRect(tile, tile.width() * 0.225, tile.width() * 0.225)
    gradient = QLinearGradient(tile.topLeft(), tile.bottomLeft())
    gradient.setColorAt(0, QColor("#3E5DD9"))
    gradient.setColorAt(1, QColor("#1E3190"))
    p.fillPath(shape, gradient)
    p.save()
    p.setClipPath(shape)
    draw_guilloche(p, tile, QColor(255, 255, 255, 34), spacing=70, amplitude=20, wavelength=170, width=6)
    p.restore()
    shackle = QPainterPath(QPointF(392, 480))
    shackle.lineTo(392, 400)
    shackle.arcTo(QRectF(392, 280, 240, 240), 180, -180)
    shackle.lineTo(632, 480)
    p.setPen(QPen(QColor("white"), 56, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawPath(shackle)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("white"))
    p.drawRoundedRect(QRectF(322, 460, 380, 290), 64, 64)
    p.setBrush(QColor("#22379A"))
    p.drawEllipse(QPointF(512, 580), 38, 38)
    p.drawRoundedRect(QRectF(495, 590, 34, 90), 17, 17)
    p.end()
    return pm


def palette_for(t):
    pal = QPalette()
    R = QPalette.ColorRole
    for role, key in [(R.Window, "paper"), (R.WindowText, "ink"), (R.Base, "field"), (R.AlternateBase, "paper"),
                      (R.Text, "ink"), (R.Button, "surface"), (R.ButtonText, "ink"), (R.Highlight, "accent"),
                      (R.HighlightedText, "on_accent"), (R.PlaceholderText, "ink3"), (R.ToolTipBase, "surface"),
                      (R.ToolTipText, "ink"), (R.Link, "accent_text")]:
        pal.setColor(role, QColor(t[key]))
    for role in (R.WindowText, R.Text, R.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(t["ink3"]))
    return pal


def set_prop(widget, name, value):
    """Set a property that the stylesheet selects on, and re-apply the style."""
    widget.setProperty(name, value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def plural(n, word):
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def human_size(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def time_left(seconds):
    if seconds < 60:
        return "less than a minute left"
    if seconds < 3600:
        return f"about {plural(round(seconds / 60), 'minute')} left"
    return f"about {plural(round(seconds / 3600), 'hour')} left"


REVEAL_LABEL = {"darwin": "Show in Finder", "win32": "Show in Explorer"}.get(sys.platform, "Open folder")


def reveal(path):
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
    elif sys.platform == "win32":
        subprocess.Popen(f'explorer /select,"{path}"')
    else:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))


# --- widgets -------------------------------------------------------------

VERB = {"encrypt": "Encrypt", "decrypt": "Decrypt"}


class ElidedLabel(QLabel):
    """A label that shortens long names with … instead of widening the window."""

    def __init__(self, text="", name=None, mode=Qt.TextElideMode.ElideMiddle):
        super().__init__(text)
        self.mode = mode
        if name:
            self.setObjectName(name)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setPen(self.palette().color(self.palette().currentColorGroup(), QPalette.ColorRole.WindowText))
        text = self.fontMetrics().elidedText(self.text(), self.mode, self.width())
        p.drawText(self.rect(), int(self.alignment()), text)


def link(text, slot):
    button = QPushButton(text, objectName="link", clicked=slot)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def stack(*widgets):
    """Widgets one under the other, close together: a title and its text."""
    layout = QVBoxLayout()
    layout.setSpacing(4)
    for widget in widgets:
        layout.addWidget(widget)
    return layout


def footer(back, primary):
    """Back on the left, the step's main button on the right."""
    back_btn = QPushButton("Back", clicked=back)
    back_btn.setProperty("large", True)
    row = QHBoxLayout()
    row.addWidget(back_btn)
    row.addStretch()
    row.addWidget(primary)
    return row


class ChoiceButton(QPushButton):
    """A big button on the start page: an icon, the action, and what it does."""

    def __init__(self, mode, text, on_choose):
        super().__init__(objectName="choice", clicked=lambda _=False: on_choose(mode))
        self.mode = mode
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName(VERB[mode])
        self.setAccessibleDescription(text)
        self.tile = QLabel(objectName="tile", alignment=Qt.AlignmentFlag.AlignCenter)
        self.tile.setFixedSize(44, 44)
        self.tile.setProperty("mode", mode)
        words = QVBoxLayout()
        words.setSpacing(2)
        words.addStretch()
        words.addWidget(QLabel(VERB[mode], objectName="choiceTitle"))
        words.addWidget(QLabel(text, objectName="body"))
        words.addStretch()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 18, 0)
        layout.setSpacing(16)
        layout.addWidget(self.tile)
        layout.addLayout(words, 1)
        for label in self.findChildren(QLabel):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)  # clicks go to the button

    def set_theme(self, t):
        encrypt = self.mode == "encrypt"
        self.tile.setPixmap(icon_pixmap("lock" if encrypt else "unlock", t["accent_text" if encrypt else "open"], 22))


class Band(QWidget):
    """A strip printed with envelope waves, with `box` sitting in a clear window."""

    def __init__(self, height):
        super().__init__()
        self.theme = LIGHT
        self.setFixedHeight(height)
        self.box = QWidget(self)
        self.box.setFixedHeight(48)
        outer = QHBoxLayout(self)
        outer.addStretch()
        outer.addWidget(self.box)
        outer.addStretch()

    def set_theme(self, theme):
        self.theme = theme
        self.update()

    def paintEvent(self, _):
        t = self.theme
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        band = QRectF(self.rect())
        p.fillRect(band, QColor(t["accent_soft"]))
        ink = QColor(t["accent_text"])
        ink.setAlphaF(float(t["pattern"]))
        draw_guilloche(p, band, ink, spacing=13, amplitude=4, wavelength=34)
        window = QPainterPath()
        window.addRoundedRect(QRectF(self.box.geometry()), 10, 10)
        p.fillPath(window, QColor(t["surface"]))


class StepBar(Band):
    """The band across the top of every step, with the steps in its window."""

    def __init__(self):
        super().__init__(88)
        row = QHBoxLayout(self.box)
        row.setContentsMargins(18, 0, 18, 0)
        row.setSpacing(10)
        self.badges, self.names = [], []
        for i in range(3):
            if i:
                line = QFrame(objectName="stepLine")
                line.setFixedSize(24, 1)
                row.addWidget(line)
            badge, name = QLabel(), QLabel(objectName="stepName")
            badge.setFixedSize(22, 22)
            row.addWidget(badge)
            row.addWidget(name)
            self.badges.append(badge)
            self.names.append(name)

    def set_step(self, current, action, theme):
        """Steps before `current` are done; `current` 3 means all of them are."""
        for i, (badge, name) in enumerate(zip(self.badges, self.names)):
            state = "done" if i < current else "current" if i == current else "todo"
            name.setText(("Add files", "Passphrase", action)[i])
            set_prop(name, "state", state)
            badge.setPixmap(step_badge(i + 1, state, theme))
        self.set_theme(theme)


class DropZone(QFrame):
    def __init__(self, on_folder, on_files):
        super().__init__()
        self.theme, self.active, self.compact = LIGHT, False, False
        self.badge = QLabel(objectName="badge", alignment=Qt.AlignmentFlag.AlignCenter)
        self.badge.setFixedSize(48, 48)
        self.title = QLabel(objectName="dropTitle", alignment=Qt.AlignmentFlag.AlignCenter)
        self.hint = QLabel(objectName="dropHint", alignment=Qt.AlignmentFlag.AlignCenter)
        links = QHBoxLayout()
        links.setSpacing(6)
        links.addStretch()
        links.addWidget(link("Choose a folder", on_folder))
        links.addWidget(QLabel("or", objectName="dropHint"))
        links.addWidget(link("choose files", on_files))
        links.addStretch()

        self.content = QWidget(self)  # sits in the clear "address window"
        self.content.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)
        inner = QVBoxLayout(self.content)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.setSpacing(6)
        inner.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignHCenter)
        inner.addSpacing(4)
        inner.addWidget(self.title)
        inner.addWidget(self.hint)
        inner.addSpacing(4)
        inner.addLayout(links)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(40, 30, 40, 30)
        outer.addStretch()
        outer.addWidget(self.content, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch()
        self.set_compact(False)

    def set_theme(self, theme):
        self.theme = theme
        self.badge.setPixmap(icon_pixmap("drop", theme["accent_text"], 24))
        self.update()

    def set_hint(self, text):
        self.hint.setText(text)

    def set_compact(self, compact):
        self.compact = compact
        self.badge.setVisible(not compact)
        self.hint.setVisible(not compact)
        self.setMinimumHeight(132 if compact else 280)
        self.setMaximumHeight(132 if compact else 16777215)
        self.set_active(self.active)

    def set_active(self, active):
        self.active = active
        self.title.setText("Release to add" if active else
                           "Drop more folders or files" if self.compact else "Drop folders or files here")
        self.update()

    def changeEvent(self, event):
        super().changeEvent(event)
        self.update()  # pattern fades while disabled

    def paintEvent(self, _):
        t = self.theme
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        frame = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        envelope = QPainterPath()
        envelope.addRoundedRect(frame, 14, 14)
        p.fillPath(envelope, QColor(t["surface"]))

        ink = QColor(t["accent_text"])
        ink.setAlphaF(0.34 if self.active else float(t["pattern"]) if self.isEnabled() else 0.07)
        p.save()
        p.setClipPath(envelope)
        draw_guilloche(p, frame, ink, spacing=13, amplitude=4, wavelength=34)
        p.restore()

        window = QPainterPath()
        window.addRoundedRect(QRectF(self.content.geometry()).adjusted(-28, -18, 28, 18), 10, 10)
        p.fillPath(window, QColor(t["surface"]))
        p.setPen(QPen(QColor(t["line"]), 1))
        p.drawPath(window)
        p.setPen(QPen(QColor(t["accent"] if self.active else t["line"]), 2 if self.active else 1))
        p.drawPath(envelope)


# --- work ----------------------------------------------------------------

class Cancelled(Exception):
    pass


class Worker(QThread):
    progress = Signal(float, int, str, str)  # fraction done, job number, file name, mode
    done = Signal(object)  # {"encrypt": n, "decrypt": n, "failed": [...], "message": (text, tone) | None}

    def __init__(self, jobs, passphrase):
        super().__init__()
        self.jobs, self.passphrase, self.cancelled = jobs, passphrase, False

    def run(self):
        total = sum(size for *_, size in self.jobs) or 1
        before = 0
        result = {"encrypt": 0, "decrypt": 0, "failed": [], "message": None}
        for n, (mode, src, out, size) in enumerate(self.jobs, 1):
            seen = 0

            def tick(nbytes):
                nonlocal seen
                if self.cancelled:
                    raise Cancelled  # secure_backup removes the half-written file
                seen += nbytes
                self.progress.emit((before + seen) / total, n, src.name, mode)

            try:
                tick(0)
                (encrypt_file if mode == "encrypt" else decrypt_file)(src, out, self.passphrase, tick)
                result[mode] += 1
            except Cancelled:
                finished = result["encrypt"] + result["decrypt"]
                after = f" after {plural(finished, 'file')}" if finished else ""
                result["message"] = (f"Cancelled{after}. The file in progress was removed.", "")
                break
            except ValueError as e:
                # Jobs run smallest first, so if the very first decrypt fails it's
                # the passphrase — stop before chewing through big videos.
                if mode == "decrypt" and not result["decrypt"]:
                    result["message"] = (f"Wrong passphrase, or “{src.name}” is damaged. Nothing was changed.", "error")
                    break
                result["failed"].append(f"{src}  ({e})")
            except OSError as e:
                result["failed"].append(f"{src}  ({e.strerror or e})")
            before += size
        self.done.emit(result)


# --- window --------------------------------------------------------------

ROW_HEIGHT = 64
STEP = {"add": 0, "passphrase": 1, "running": 2, "result": 3}  # position in the step bar


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle("Secure Backup")
        self.setAcceptDrops(True)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)  # start with nothing focused; Tab still works
        self.resize(600, 720)
        self.setMinimumSize(520, 620)
        self.page = "start"  # start | add | passphrase | running | result
        self.mode = None  # "encrypt" or "decrypt": chosen first, and the only thing this run does
        self.items = []  # (path, target, summary, file count)
        self.worker = None
        self.message = None  # (text, tone) shown on the current step
        self.suggestion = ""  # six words joined by single spaces: exactly what gets typed later
        self.own = False  # encrypting with a typed passphrase instead of the suggested one
        self.updating = None  # name of an existing _encrypted target: its old passphrase is needed
        self.result_icon = ("check", "open")

        # Start: pick the one thing to do
        self.logo = QLabel()
        title = QLabel("Secure Backup", objectName="title")
        subtitle = QLabel("Encrypt photos and videos before you upload them anywhere.", objectName="subtitle")
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header = QHBoxLayout()
        header.setSpacing(14)
        header.addWidget(self.logo)
        header.addLayout(titles, 1)
        self.choices = [
            ChoiceButton("encrypt", "Make copies that only your passphrase can open.", self.choose),
            ChoiceButton("decrypt", "Turn encrypted copies back into normal files.", self.choose),
        ]
        self.start_band = Band(112)
        promise = QHBoxLayout(self.start_band.box)
        promise.setContentsMargins(20, 0, 20, 0)
        promise.addWidget(QLabel("Your originals are never changed or deleted.", objectName="body"))
        start_page = QWidget()
        start_layout = QVBoxLayout(start_page)
        start_layout.setContentsMargins(0, 0, 0, 0)
        start = QVBoxLayout()
        start.setContentsMargins(28, 24, 28, 24)
        start.setSpacing(12)
        start.addLayout(header)
        start.addSpacing(28)
        for choice in self.choices:
            start.addWidget(choice)
        start_layout.addLayout(start)
        start_layout.addStretch()
        start_layout.addWidget(self.start_band)

        # Step 1: folders or files, only the kind this action takes
        self.add_title = QLabel(objectName="pageTitle")
        self.add_body = QLabel(objectName="body", wordWrap=True)
        self.drop = DropZone(self.pick_folder, self.pick_files)
        self.count = QLabel(objectName="section")
        queue_head = QHBoxLayout()
        queue_head.addWidget(self.count)
        queue_head.addStretch()
        queue_head.addWidget(link("Clear all", self.clear))
        self.queue = QListWidget(objectName="queue")
        self.queue.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.queue.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.queue.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.queue_box = QWidget()
        queue_layout = QVBoxLayout(self.queue_box)
        queue_layout.setContentsMargins(0, 0, 0, 0)
        queue_layout.setSpacing(4)
        queue_layout.addLayout(queue_head)
        queue_layout.addWidget(self.queue)
        queue_layout.addStretch()
        self.add_hint = QLabel(objectName="hint", wordWrap=True)
        self.next_btn = QPushButton("Continue", objectName="primary", clicked=self.to_passphrase)
        add_page = QWidget()
        self.add_layout = add = QVBoxLayout(add_page)
        add.setContentsMargins(28, 24, 28, 24)
        add.setSpacing(16)
        add.addLayout(stack(self.add_title, self.add_body))
        add.addWidget(self.drop, 1)
        add.addWidget(self.add_hint)  # why something wasn't added, right under where it was dropped
        add.addWidget(self.queue_box, 1)
        add.addLayout(footer(self.reset, self.next_btn))

        # Step 2: the passphrase. Encrypting suggests six random words, or you type your own.
        self.pass_context = QLabel(objectName="body")
        self.pass_title = QLabel(objectName="pageTitle")
        self.pass_body = QLabel(objectName="body", wordWrap=True)

        # Three words a line, so it never needs wrapping. Not selectable: a copied line break
        # wouldn't match what gets typed later, so Copy is the way to copy it.
        self.suggested = QLabel(objectName="suggested")
        self.copy_btn = QPushButton("Copy", clicked=self.copy_suggestion)
        self.another_btn = QPushButton("Another one", clicked=self.new_suggestion)
        tools = QHBoxLayout()
        tools.setSpacing(8)
        tools.addWidget(self.copy_btn)
        tools.addWidget(self.another_btn)
        tools.addStretch()
        tools.addWidget(link("Type my own instead", lambda _=False: self.set_own(True)))
        box = QFrame(objectName="suggestBox")
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(18, 14, 18, 16)
        box_layout.setSpacing(12)
        box_layout.addWidget(self.suggested)
        box_layout.addLayout(tools)
        self.suggest_box = QWidget()
        suggest = QVBoxLayout(self.suggest_box)
        suggest.setContentsMargins(0, 0, 0, 0)
        suggest.setSpacing(8)
        suggest.addWidget(QLabel("Suggested passphrase", objectName="section"))
        suggest.addWidget(box)
        suggest.addWidget(QLabel("Six random words is strong enough for this.", objectName="hint"))

        self.passphrase = QLineEdit(placeholderText="Passphrase", echoMode=QLineEdit.EchoMode.Password)
        self.confirm = QLineEdit(placeholderText="Type it again", echoMode=QLineEdit.EchoMode.Password)
        self.show_pass = QCheckBox("Show passphrase", toggled=self.set_revealed)
        self.use_suggestion = link("Use a suggested one", lambda _=False: self.set_own(False))
        for field in (self.passphrase, self.confirm):
            field.returnPressed.connect(self.start)
            field.textChanged.connect(self.on_typing)
        options = QHBoxLayout()
        options.addWidget(self.show_pass)
        options.addStretch()
        options.addWidget(self.use_suggestion)
        self.own_box = QWidget()
        own = QVBoxLayout(self.own_box)
        own.setContentsMargins(0, 0, 0, 0)
        own.setSpacing(8)
        own.addWidget(QLabel("Passphrase", objectName="section"))
        own.addWidget(self.passphrase)
        own.addWidget(self.confirm)
        own.addLayout(options)

        self.saved = QCheckBox("I've saved this passphrase somewhere safe", toggled=self.update_buttons)
        self.hint = QLabel(objectName="hint", wordWrap=True)
        self.start_btn = QPushButton(objectName="primary", clicked=self.start, default=True)
        pass_page = QWidget()
        passphrase = QVBoxLayout(pass_page)
        passphrase.setContentsMargins(28, 24, 28, 24)
        passphrase.setSpacing(16)
        passphrase.addLayout(stack(self.pass_context, self.pass_title, self.pass_body))
        passphrase.addWidget(self.suggest_box)
        passphrase.addWidget(self.own_box)
        passphrase.addWidget(self.saved)
        passphrase.addWidget(self.hint)
        passphrase.addStretch()
        passphrase.addLayout(footer(lambda _=False: self.go("add"), self.start_btn))

        # Step 3, running: one bar, what's happening, and a way out
        self.run_title = QLabel(objectName="headline")
        self.percent = QLabel(objectName="percent")
        self.bar = QProgressBar(maximum=1000, textVisible=False)
        self.run_file = ElidedLabel(name="body")
        self.run_count = QLabel(objectName="body")
        self.run_meta = QLabel(objectName="meta")
        self.cancel_btn = QPushButton("Cancel", clicked=self.cancel)
        self.run_page = QWidget()
        running = QVBoxLayout(self.run_page)
        running.setContentsMargins(0, 0, 0, 0)
        running.setSpacing(10)
        for left, right in ((self.run_title, self.percent), (self.run_file, self.run_count)):
            row = QHBoxLayout()
            row.addWidget(left, 1)
            row.addWidget(right)
            running.addLayout(row)
            if left is self.run_title:
                running.addWidget(self.bar)
        bottom = QHBoxLayout()
        bottom.addWidget(self.run_meta, 1)
        bottom.addWidget(self.cancel_btn)
        running.addLayout(bottom)

        # Step 3, done: the result
        self.result_tile = QLabel(objectName="resultTile", alignment=Qt.AlignmentFlag.AlignCenter)
        self.result_tile.setFixedSize(44, 44)
        self.headline = QLabel(objectName="headline", wordWrap=True)
        self.body = QLabel(objectName="body", wordWrap=True)
        self.details = QPlainTextEdit(readOnly=True)
        self.details.setMaximumHeight(110)
        self.reveal_btn = QPushButton(REVEAL_LABEL, objectName="primary", clicked=self.reveal_output)
        done_btn = QPushButton("Done", clicked=self.reset)
        done_btn.setProperty("large", True)
        self.result_page = QWidget()
        result = QVBoxLayout(self.result_page)
        result.setContentsMargins(0, 0, 0, 0)
        result.setSpacing(12)
        top = QHBoxLayout()
        top.setSpacing(14)
        top.addWidget(self.result_tile, 0, Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(4)
        text.addWidget(self.headline)
        text.addWidget(self.body)
        top.addLayout(text, 1)
        result.addLayout(top)
        result.addWidget(self.details)
        buttons = QHBoxLayout()
        buttons.addWidget(self.reveal_btn)
        buttons.addWidget(done_btn)
        buttons.addStretch()
        result.addLayout(buttons)
        run_step = QWidget()
        last = QVBoxLayout(run_step)
        last.setContentsMargins(28, 32, 28, 24)
        last.addWidget(self.run_page)
        last.addWidget(self.result_page)
        last.addStretch()

        self.step_bar = StepBar()
        self.steps = QStackedWidget()
        for page in (add_page, pass_page, run_step):
            self.steps.addWidget(page)
        flow = QWidget()
        flow_layout = QVBoxLayout(flow)
        flow_layout.setContentsMargins(0, 0, 0, 0)
        flow_layout.setSpacing(0)
        flow_layout.addWidget(self.step_bar)
        flow_layout.addWidget(self.steps, 1)
        self.pages = QStackedWidget()
        self.pages.addWidget(start_page)
        self.pages.addWidget(flow)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.pages)

        QApplication.styleHints().colorSchemeChanged.connect(self.apply_theme)
        self.apply_theme()

    # --- theme ----------------------------------------------------------

    def apply_theme(self, *_):
        dark = QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
        self.t = t = DARK if dark else LIGHT
        app = QApplication.instance()
        app.setPalette(palette_for(t))
        app.setStyleSheet(QSS.substitute(t))
        logo = app_icon(48 * 3, inset=0)
        logo.setDevicePixelRatio(3)
        self.logo.setPixmap(logo)
        self.drop.set_theme(t)
        self.start_band.set_theme(t)
        for choice in self.choices:
            choice.set_theme(t)
        self.copy_btn.setIcon(QIcon(icon_pixmap("copy", t["ink"], 16)))
        self.another_btn.setIcon(QIcon(icon_pixmap("refresh", t["ink"], 16)))
        name, color = self.result_icon
        self.result_tile.setPixmap(icon_pixmap(name, t[color], 22))
        self.refresh()

    # --- state ----------------------------------------------------------

    def refresh(self):
        self.pages.setCurrentIndex(0 if self.page == "start" else 1)
        if self.page == "start":
            self.setFocus()  # don't leave focus (and its outline) parked on a choice
            return
        encrypt = self.mode == "encrypt"
        self.step_bar.set_step(STEP[self.page], VERB[self.mode], self.t)
        self.steps.setCurrentIndex(min(STEP[self.page], 2))

        # Step 1
        has_items = bool(self.items)
        self.add_title.setText(f"Add what you want to {self.mode}")
        self.add_body.setText("Copies are saved next to the originals, subfolders included." if encrypt else
                              "Add _encrypted folders or .enc files. Decrypted copies are saved next to them.")
        self.drop.set_hint("Photos, videos, documents: any folder or file." if encrypt else
                           "The _encrypted folders or .enc files this app made.")
        self.drop.set_compact(has_items)
        self.add_layout.setStretchFactor(self.drop, 0 if has_items else 1)
        self.queue_box.setVisible(has_items)
        self.count.setText(plural(len(self.items), "item"))
        self.queue.clear()
        for path, _, summary, _ in self.items:
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, ROW_HEIGHT))
            self.queue.addItem(item)
            self.queue.setItemWidget(item, self.make_row(path, summary))
        self.queue.setMaximumHeight(len(self.items) * ROW_HEIGHT + 2)
        self.next_btn.setEnabled(has_items)
        text, tone = self.message if self.message and self.page == "add" else ("", "")
        self.add_hint.setText(text)
        self.add_hint.setVisible(bool(text))
        set_prop(self.add_hint, "tone", tone)

        # Step 2
        new = encrypt and not self.updating  # a brand-new passphrase, so one can be suggested
        suggesting = self.suggesting()
        self.pass_context.setText(self.context_text())
        self.pass_title.setText("Choose a passphrase" if new else "Enter the passphrase")
        if new:
            body = "You'll type it every time you open these files. Nobody can reset it, so save it somewhere you won't lose."
        elif encrypt:
            body = (f"“{self.updating}” already has encrypted files. Use the same passphrase as last time, "
                    "or some files won't open with it.")
        else:
            body = "Use the passphrase these files were encrypted with."
        self.pass_body.setText(body)
        self.suggest_box.setVisible(suggesting)
        self.own_box.setVisible(not suggesting)
        self.confirm.setVisible(encrypt)
        self.use_suggestion.setVisible(new)
        self.saved.setVisible(new)
        self.start_btn.setText(self.action_text())
        self.update_buttons()
        self.update_hint()

        # Step 3
        self.run_page.setVisible(self.page == "running")
        self.result_page.setVisible(self.page == "result")

    def make_row(self, path, summary):
        color = self.t["accent_text" if self.mode == "encrypt" else "open"]
        tile = QLabel(objectName="tile", alignment=Qt.AlignmentFlag.AlignCenter)
        tile.setFixedSize(36, 36)
        tile.setProperty("mode", self.mode)
        tile.setPixmap(icon_pixmap("folder" if path.is_dir() else "file", color, 18))
        tile.setToolTip(str(path))
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(ElidedLabel(path.name, "rowName"))
        text.addWidget(ElidedLabel(summary, "meta", Qt.TextElideMode.ElideRight))
        remove = QToolButton(objectName="remove", clicked=lambda _=False, p=path: self.remove(p))
        remove.setIcon(QIcon(icon_pixmap("x", self.t["ink2"], 16)))
        remove.setFixedSize(28, 28)
        remove.setToolTip("Remove from list")
        remove.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(2, 0, 2, 0)
        layout.setSpacing(12)
        layout.addWidget(tile)
        layout.addLayout(text, 1)
        layout.addWidget(remove, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def suggesting(self):
        return self.mode == "encrypt" and not self.updating and not self.own

    def context_text(self):
        files = sum(n for *_, n in self.items)
        what = self.items[0][0].name if len(self.items) == 1 else plural(len(self.items), "item")
        return f"{what}, {plural(files, 'file')}"

    def action_text(self):
        kinds = {path.is_dir() for path, *_ in self.items}
        noun = "folder" if kinds == {True} else "file" if kinds == {False} else "item"
        return f"{VERB[self.mode]} {plural(len(self.items), noun)}"

    def update_buttons(self, *_):
        new = self.mode == "encrypt" and not self.updating
        self.start_btn.setEnabled(not new or self.saved.isChecked())

    def update_hint(self):
        p, c = self.passphrase.text(), self.confirm.text()
        mismatch = c and c != p and (len(c) >= len(p) or not p.startswith(c))
        typing = self.mode == "encrypt" and not self.suggesting()
        text, tone = "", ""
        if self.message and self.page == "passphrase":
            text, tone = self.message
        elif typing and mismatch:
            text, tone = "Passphrases don't match.", "error"
        elif typing and c == p and c:
            text, tone = "Passphrases match.", "ok"
        self.hint.setText(text)
        self.hint.setVisible(bool(text))
        set_prop(self.hint, "tone", tone)

    def on_typing(self):
        self.message = None
        self.update_hint()

    def set_revealed(self, revealed):
        for field in (self.passphrase, self.confirm):
            field.setEchoMode(QLineEdit.EchoMode.Normal if revealed else QLineEdit.EchoMode.Password)

    def forget_passphrase(self):
        self.passphrase.clear()
        self.confirm.clear()
        self.show_pass.setChecked(False)

    # --- moving between steps ---------------------------------------------

    def go(self, page):
        self.page, self.message = page, None
        self.refresh()

    def choose(self, mode):
        self.mode = mode
        self.go("add")

    def to_passphrase(self):
        if not self.items:
            return
        encrypt = self.mode == "encrypt"
        # Adding to an _encrypted folder that's already there needs the passphrase it was made with.
        self.updating = next((target.name for _, target, *_ in self.items if target.exists()), None) if encrypt else None
        if encrypt and not self.suggestion:
            self.new_suggestion()
        self.go("passphrase")
        (self.saved if self.suggesting() else self.passphrase).setFocus()

    def set_own(self, own):
        self.own, self.message = own, None
        self.forget_passphrase()
        self.saved.setChecked(False)  # whichever passphrase is shown now hasn't been saved yet
        self.refresh()
        (self.passphrase if own else self.saved).setFocus()

    def new_suggestion(self):
        self.suggestion = suggest_passphrase()
        words = self.suggestion.split(" ")
        self.suggested.setText(" ".join(words[:3]) + "\n" + " ".join(words[3:]))
        self.saved.setChecked(False)

    def copy_suggestion(self):
        # Never cleared on a timer: the clipboard may be the only copy until it's pasted somewhere safe.
        QApplication.clipboard().setText(self.suggestion)
        self.copy_btn.setText("Copied")
        QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy"))

    def reset(self):
        """Back to the start page, keeping nothing: the list, typed passphrases, the suggestion."""
        self.items.clear()
        self.mode, self.own, self.updating = None, False, None
        self.forget_passphrase()
        self.suggestion = ""
        self.suggested.clear()
        self.saved.setChecked(False)
        self.go("start")

    # --- adding and removing -----------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and self.page == "add":
            event.acceptProposedAction()
            self.drop.set_active(True)

    def dragLeaveEvent(self, event):
        self.drop.set_active(False)

    def dropEvent(self, event):
        self.drop.set_active(False)
        self.add_paths(Path(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile())

    def pick_folder(self):
        if folder := QFileDialog.getExistingDirectory(self, "Choose a folder"):
            self.add_paths([Path(folder)])

    def pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files")
        self.add_paths(Path(f) for f in files)

    def add_paths(self, paths):
        refused = []
        for path in paths:
            if not path.name or not path.exists() or any(path == item[0] for item in self.items):
                continue  # drive roots have no "next to it"; skip missing and duplicates
            target = default_target(path, self.mode)
            pairs = plan(self.mode, path, target)
            if self.mode == "encrypt" and detect_mode(path) == "decrypt":
                refused.append(f"“{path.name}” is already encrypted. To open it, go back and choose Decrypt.")
            elif self.mode == "decrypt" and path.is_file() and not path.name.endswith(ENCRYPTED_SUFFIX):
                refused.append(f"“{path.name}” isn't encrypted: its name doesn't end in .enc. "
                               "If you renamed it, add .enc back to the end of the name.")
            elif self.mode == "decrypt" and not pairs:
                refused.append(f"“{path.name}” has no encrypted files (names ending in .enc). "
                               "To encrypt it, go back and choose Encrypt.")
            elif not pairs:
                refused.append(f"“{path.name}” is empty.")
            else:
                size = sum(i.stat().st_size for i, _ in pairs)
                verb = "Adds to" if target.exists() else "Saves to"
                summary = f"{plural(len(pairs), 'file')}, {human_size(size)}. {verb} {target.name}"
                self.items.append((path, target, summary, len(pairs)))
        self.message = (" ".join(refused), "error") if refused else None
        self.refresh()

    def remove(self, path):
        self.items = [item for item in self.items if item[0] != path]
        self.message = None
        self.refresh()

    def clear(self):
        self.items.clear()
        self.message = None
        self.refresh()

    # --- running --------------------------------------------------------

    def fail(self, text, field):
        self.message = (text, "error")
        self.update_hint()
        field.setFocus()

    def start(self):
        if not self.items or self.worker or self.page != "passphrase" or not self.start_btn.isEnabled():
            return
        if self.suggesting():
            passphrase = self.suggestion
        else:
            passphrase = self.passphrase.text()
            if not passphrase:
                return self.fail("Enter a passphrase.", self.passphrase)
            if self.mode == "encrypt" and passphrase != self.confirm.text():
                return self.fail("Passphrases don't match.", self.confirm)

        jobs, skipped, targets = [], 0, []
        for path, target, *_ in self.items:
            if target.exists():
                target = self.ask_existing(path, self.mode, target)
                if not target:
                    return
            targets.append(target)
            pairs = plan(self.mode, path, target)
            if self.mode == "encrypt" and not same_passphrase(pairs, passphrase):
                field = self.saved if self.suggesting() else self.passphrase
                return self.fail(f"This passphrase doesn't open the files already in “{target.name}”. "
                                 "Use the one they were encrypted with, or save a separate copy.", field)
            todo = [(self.mode, i, o, i.stat().st_size) for i, o in pairs if needs_work(self.mode, i, o)]
            skipped += len(pairs) - len(todo)
            jobs += todo
        if not jobs:
            already = "That file is" if skipped == 1 else f"All {skipped:,} files are"
            self.message = (f"Nothing to do. {already} already done.", "ok")
            return self.update_hint()
        # Smallest first: a wrong passphrase shows up in a second, not after a 4 GB video.
        jobs.sort(key=lambda job: job[3])

        self.jobs, self.targets, self.skipped = jobs, targets, skipped
        self.total, self.started = sum(job[3] for job in jobs) or 1, time.monotonic()
        self.worker = Worker(jobs, passphrase)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.page = "running"
        self.cancel_btn.setEnabled(True)
        self.refresh()
        self.on_progress(0.0, 1, jobs[0][1].name, jobs[0][0])
        self.worker.start()

    def ask_existing(self, path, mode, target):
        """Returns the folder/file to write into, or None to cancel."""
        new = numbered(target)
        encrypt = mode == "encrypt"
        box = QMessageBox(self)
        box.setWindowTitle("Secure Backup")
        box.setText(f"“{target.name}” already exists")
        box.setInformativeText(
            "Add only the files that are new or changed since last time, or save a separate copy?" if encrypt
            else "Skip the files that are already there, or save a separate copy?")
        skip = box.addButton("Only new or changed" if encrypt else "Skip existing", QMessageBox.ButtonRole.AcceptRole)
        copy = box.addButton(f"Save as “{new.name}”", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(skip)
        box.exec()
        clicked = box.clickedButton()
        return target if clicked is skip else new if clicked is copy else None

    def on_progress(self, fraction, n, name, mode):
        self.run_title.setText("Encrypting" if mode == "encrypt" else "Decrypting")
        self.percent.setText(f"{int(fraction * 100)}%")
        self.bar.setValue(int(fraction * 1000))
        self.run_file.setText(name)
        self.run_count.setText(f"{n:,} of {len(self.jobs):,}")
        elapsed = time.monotonic() - self.started
        eta = f", {time_left(elapsed * (1 - fraction) / fraction)}" if elapsed > 3 and fraction > 0.01 else ""
        self.run_meta.setText(f"{human_size(fraction * self.total)} of {human_size(self.total)}{eta}")

    def on_done(self, result):
        self.worker.wait()
        self.worker = None
        self.forget_passphrase()  # typed ones; a suggestion stays until you start over
        if result["message"]:  # cancelled or wrong passphrase: back to the passphrase step
            self.page, self.message = "passphrase", result["message"]
            self.refresh()
            (self.saved if self.suggesting() else self.passphrase).setFocus()
            return
        self.show_result(result)

    def show_result(self, result):
        enc, dec, failed = result["encrypt"], result["decrypt"], result["failed"]
        parts = [f"Encrypted {plural(enc, 'file')}"] if enc else []
        if dec:
            parts.append(f"{'decrypted' if parts else 'Decrypted'} {plural(dec, 'file')}")
        headline = " and ".join(parts) or "Nothing was saved"
        if failed:
            headline += f". {len(failed)} failed"
        if failed:
            body = "The files below couldn't be read or written. Everything else was saved next to the originals."
        elif len(self.targets) == 1:
            target = self.targets[0]
            body = f"Saved as “{target.name}”, next to the original."
            if enc and target.is_dir():
                body += " That's the folder to upload."
        else:
            body = "Saved next to the originals."
        if self.skipped:
            was = "was" if self.skipped == 1 else "were"
            body += f" {plural(self.skipped, 'file')} {was} already up to date and skipped."
        self.result_icon = ("alert", "danger") if failed else ("check", "open")
        name, color = self.result_icon
        self.result_tile.setPixmap(icon_pixmap(name, self.t[color], 22))
        set_prop(self.result_tile, "tone", "warn" if failed else "ok")
        self.headline.setText(headline)
        self.body.setText(body)
        self.details.setPlainText("\n".join(failed))
        self.details.setVisible(bool(failed))
        self.page = "result"
        self.refresh()

    def reveal_output(self):
        reveal(self.targets[0])

    def cancel(self):
        if self.worker:
            self.worker.cancelled = True
            self.cancel_btn.setEnabled(False)
            self.run_meta.setText("Cancelling…")

    def closeEvent(self, event):
        if self.worker:  # finish cleanly so no half-written file is left behind
            self.worker.cancelled = True
            self.worker.wait()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # same base on every OS; the stylesheet does the rest
    use_bundled_font(app)
    app.setWindowIcon(QIcon(app_icon(512)))
    window = Window()
    window.show()
    window.setFocus()
    if "--smoke-test" in sys.argv:  # CI: prove the bundled app starts, then quit
        QTimer.singleShot(0, app.quit)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
