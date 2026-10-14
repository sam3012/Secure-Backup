#!/usr/bin/env python3
"""Secure Backup — drop folders or files in, type a passphrase, and get
encrypted (or decrypted) copies next to the originals. The crypto lives in
secure_backup.py; this file is only the window.

The look borrows from security envelopes: the drop zone is printed with the
interlaced waves that keep an envelope's contents unreadable, with a clear
"address window" for the text."""

import math
import subprocess
import sys
import time
from pathlib import Path
from string import Template

from PySide6.QtCore import QByteArray, QPointF, QRectF, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSizePolicy, QToolButton,
    QVBoxLayout, QWidget,
)

from secure_backup import decrypt_file, default_target, detect_mode, encrypt_file, needs_work, numbered, plan

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

QSS = Template("""
* { font-size: 13px; }
QWidget#root, QMessageBox { background: $paper; }
QLabel { color: $ink; }
QLabel:disabled { color: $ink3; }
QLabel#title { font-size: 22px; font-weight: 600; }
QLabel#subtitle { color: $ink2; }
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
QLabel#pill { border-radius: 8px; padding: 2px 10px; font-size: 12px; font-weight: 600; }
QLabel#pill[mode="encrypt"] { background: $accent_soft; color: $accent_text; }
QLabel#pill[mode="decrypt"] { background: $open_soft; color: $open; }
QLabel#resultTile { border-radius: 22px; }
QLabel#resultTile[tone="ok"] { background: $open_soft; }
QLabel#resultTile[tone="warn"] { background: $danger_soft; }
QLabel#headline { font-size: 17px; font-weight: 600; }
QLabel#percent { font-size: 17px; font-weight: 600; color: $accent_text; }
QLabel#body { color: $ink2; }

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


class DropZone(QFrame):
    def __init__(self, on_folder, on_files):
        super().__init__()
        self.theme, self.active, self.compact = LIGHT, False, False
        self.badge = QLabel(objectName="badge", alignment=Qt.AlignmentFlag.AlignCenter)
        self.badge.setFixedSize(48, 48)
        self.title = QLabel(objectName="dropTitle", alignment=Qt.AlignmentFlag.AlignCenter)
        self.hint = QLabel("Folders you've already encrypted are decrypted instead.",
                           objectName="dropHint", alignment=Qt.AlignmentFlag.AlignCenter)
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
                # Decrypt jobs run first, smallest first, so if the very first one
                # fails it's the passphrase — stop before chewing through big videos.
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


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle("Secure Backup")
        self.setAcceptDrops(True)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)  # start with nothing focused; Tab still works
        self.resize(600, 720)
        self.setMinimumSize(520, 620)
        self.items = []  # (path, mode, target, summary)
        self.worker = None
        self.page = "ready"  # ready | running | result
        self.message = None  # (text, tone) shown under the passphrase
        self.result_icon = ("check", "open")

        # Header
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

        self.drop = DropZone(self.pick_folder, self.pick_files)

        # Queue
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

        # Ready: passphrase and the main button
        self.passphrase = QLineEdit(placeholderText="Passphrase", echoMode=QLineEdit.EchoMode.Password)
        self.confirm = QLineEdit(placeholderText="Type it again", echoMode=QLineEdit.EchoMode.Password)
        self.show_pass = QCheckBox("Show passphrase", toggled=self.set_revealed)
        self.hint = QLabel(objectName="hint", wordWrap=True)
        self.start_btn = QPushButton(objectName="primary", clicked=self.start, default=True)
        for field in (self.passphrase, self.confirm):
            field.returnPressed.connect(self.start)
            field.textChanged.connect(self.on_typing)
        self.ready_page = QWidget()
        ready = QVBoxLayout(self.ready_page)
        ready.setContentsMargins(0, 0, 0, 0)
        ready.setSpacing(8)
        ready.addWidget(QLabel("Passphrase", objectName="section"))
        ready.addWidget(self.passphrase)
        ready.addWidget(self.confirm)
        ready.addWidget(self.show_pass)
        ready.addWidget(self.hint)
        ready.addSpacing(6)
        ready.addWidget(self.start_btn)

        # Running: one bar, what's happening, and a way out
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

        # Result
        self.result_tile = QLabel(objectName="resultTile", alignment=Qt.AlignmentFlag.AlignCenter)
        self.result_tile.setFixedSize(44, 44)
        self.headline = QLabel(objectName="headline", wordWrap=True)
        self.body = QLabel(objectName="body", wordWrap=True)
        self.details = QPlainTextEdit(readOnly=True)
        self.details.setMaximumHeight(110)
        self.reveal_btn = QPushButton(REVEAL_LABEL, objectName="primary", clicked=self.reveal_output)
        done_btn = QPushButton("Done", clicked=self.dismiss_result)
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

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)
        layout.addLayout(header)
        layout.addWidget(self.drop, 1)
        layout.addWidget(self.queue_box, 1)
        layout.addWidget(self.ready_page)
        layout.addWidget(self.run_page)
        layout.addWidget(self.result_page)
        layout.addStretch(0)

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
        name, color = self.result_icon
        self.result_tile.setPixmap(icon_pixmap(name, t[color], 22))
        self.refresh()

    # --- state ----------------------------------------------------------

    def refresh(self):
        has_items = bool(self.items)
        compact = has_items or self.page == "result"
        self.drop.set_compact(compact)
        layout = self.layout()
        layout.setStretchFactor(self.drop, 0 if compact else 1)
        layout.setStretch(layout.count() - 1, 1 if compact and not has_items else 0)  # result: space goes below

        self.queue_box.setVisible(has_items)
        self.count.setText(plural(len(self.items), "item"))
        self.queue.clear()
        for path, mode, _, summary in self.items:
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, ROW_HEIGHT))
            self.queue.addItem(item)
            self.queue.setItemWidget(item, self.make_row(path, mode, summary))
        self.queue.setMaximumHeight(len(self.items) * ROW_HEIGHT + 2)

        self.ready_page.setVisible(has_items and self.page == "ready")
        self.run_page.setVisible(self.page == "running")
        self.result_page.setVisible(self.page == "result")
        self.confirm.setVisible(self.encrypting())
        self.start_btn.setText(self.action_text())
        self.update_hint()
        if not has_items and self.page == "ready":
            self.setFocus()  # don't leave focus (and its underline) parked on a link

    def make_row(self, path, mode, summary):
        color = self.t["accent_text" if mode == "encrypt" else "open"]
        tile = QLabel(objectName="tile", alignment=Qt.AlignmentFlag.AlignCenter)
        tile.setFixedSize(36, 36)
        tile.setProperty("mode", mode)
        tile.setPixmap(icon_pixmap("folder" if path.is_dir() else "file", color, 18))
        tile.setToolTip(str(path))
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(ElidedLabel(path.name, "rowName"))
        text.addWidget(ElidedLabel(summary, "meta", Qt.TextElideMode.ElideRight))
        pill = QLabel(mode.capitalize(), objectName="pill")
        pill.setProperty("mode", mode)
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
        layout.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(remove, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    def encrypting(self):
        return any(mode == "encrypt" for _, mode, *_ in self.items)

    def action_text(self):
        enc = sum(mode == "encrypt" for _, mode, *_ in self.items)
        dec = len(self.items) - enc
        if enc and dec:
            return f"Encrypt {enc} and decrypt {dec}"
        kinds = {path.is_dir() for path, *_ in self.items}
        noun = "folder" if kinds == {True} else "file" if kinds == {False} else "item"
        return f"{'Encrypt' if enc else 'Decrypt'} {plural(enc or dec, noun)}"

    def update_hint(self):
        p, c = self.passphrase.text(), self.confirm.text()
        mismatch = c and c != p and (len(c) >= len(p) or not p.startswith(c))
        if self.message:
            text, tone = self.message
        elif self.encrypting() and mismatch:
            text, tone = "Passphrases don't match.", "error"
        elif self.encrypting() and c == p and c:
            text, tone = "Passphrases match.", "ok"
        elif self.encrypting():
            text, tone = "There's no way to recover a forgotten passphrase, so keep it somewhere safe.", ""
        else:
            text, tone = "Use the passphrase these files were encrypted with.", ""
        self.hint.setText(text)
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

    # --- adding and removing -----------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and not self.worker:
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
        added = False
        for path in paths:
            if not path.name or not path.exists() or any(path == item[0] for item in self.items):
                continue  # drive roots have no "next to it"; skip missing and duplicates
            mode = detect_mode(path)
            target = default_target(path, mode)
            pairs = plan(mode, path, target)
            size = sum(i.stat().st_size for i, _ in pairs)
            verb = "Adds to" if target.exists() else "Saves to"
            summary = f"{plural(len(pairs), 'file')}, {human_size(size)}. {verb} {target.name}"
            self.items.append((path, mode, target, summary))
            added = True
        if added:
            self.message, self.page = None, "ready"
        self.refresh()
        if added:
            self.passphrase.setFocus()

    def remove(self, path):
        self.items = [item for item in self.items if item[0] != path]
        if not self.items:
            self.forget_passphrase()  # an empty list starts over, passphrase included
        self.message = None
        self.refresh()

    def clear(self):
        self.items.clear()
        self.forget_passphrase()
        self.message = None
        self.refresh()

    # --- running --------------------------------------------------------

    def fail(self, text, field):
        self.message = (text, "error")
        self.update_hint()
        field.setFocus()

    def start(self):
        if not self.items or self.worker or self.page != "ready":
            return
        passphrase = self.passphrase.text()
        if not passphrase:
            return self.fail("Enter a passphrase.", self.passphrase)
        if self.encrypting() and passphrase != self.confirm.text():
            return self.fail("Passphrases don't match.", self.confirm)

        jobs, skipped, targets = [], 0, []
        for path, mode, target, _ in self.items:
            if target.exists():
                target = self.ask_existing(path, mode, target)
                if not target:
                    return
            targets.append(target)
            pairs = plan(mode, path, target)
            todo = [(mode, i, o, i.stat().st_size) for i, o in pairs if needs_work(mode, i, o)]
            skipped += len(pairs) - len(todo)
            jobs += todo
        if not jobs:
            already = "That file is" if skipped == 1 else f"All {skipped:,} files are"
            self.message = (f"Nothing to do. {already} already done.", "ok")
            return self.update_hint()
        # Decrypt first, smallest first: a wrong passphrase shows up in a second,
        # not after a 4 GB video.
        jobs.sort(key=lambda job: (job[0] != "decrypt", job[3]))

        self.jobs, self.targets, self.skipped = jobs, targets, skipped
        self.total, self.started = sum(job[3] for job in jobs) or 1, time.monotonic()
        self.worker = Worker(jobs, passphrase)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.page = "running"
        self.cancel_btn.setEnabled(True)
        self.set_busy(True)
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
        self.set_busy(False)
        self.forget_passphrase()
        if result["message"]:
            self.message, self.page = result["message"], "ready"
            self.refresh()
            self.passphrase.setFocus()
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
        self.items.clear()
        self.page = "result"
        self.refresh()

    def reveal_output(self):
        reveal(self.targets[0])

    def dismiss_result(self):
        self.page = "ready"
        self.refresh()

    def set_busy(self, busy):
        self.drop.setEnabled(not busy)
        self.queue_box.setEnabled(not busy)

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
    app.setWindowIcon(QIcon(app_icon(512)))
    window = Window()
    window.show()
    window.setFocus()
    if "--smoke-test" in sys.argv:  # CI: prove the bundled app starts, then quit
        QTimer.singleShot(0, app.quit)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
