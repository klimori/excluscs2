import sys
import os
import subprocess
import webbrowser
import psutil
import time
import ctypes
from ctypes import wintypes
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QStackedWidget
)
from PyQt6.QtCore import Qt, QTimer, QRectF, QPoint
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QPixmap, QRegion, QPainterPath, QCursor, QIcon

# Отключаем вывод в консоль
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

# WinAPI для инжекта DLL
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
GetProcAddress.restype = wintypes.LPVOID

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = [wintypes.LPCSTR]
GetModuleHandleA.restype = wintypes.HMODULE

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04

# Кольцо загрузки
class LoaderRing(QWidget):
    def __init__(self, parent=None, text="Loading..."):
        super().__init__(parent)
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_angle)
        self.timer.start(30)
        self.text = text
        self.setFixedSize(260, 260)

    def update_angle(self):
        self.angle = (self.angle + 4) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(10, 10, 240, 240)

        pen_bg = QPen(QColor("#333333"), 12)
        painter.setPen(pen_bg)
        painter.drawArc(rect, 0, 360 * 16)

        pen_fg = QPen(QColor("#4da6ff"), 12)
        painter.setPen(pen_fg)
        painter.drawArc(rect, self.angle * 16, 60 * 16)

        painter.setPen(QColor("white"))
        font = QFont("Segoe UI", 18)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.text)

# Главное окно
class LoaderWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(400, 460)
        self.setWindowIcon(QIcon(os.path.join("assets", "trace.svg")))
        self.old_pos = QPoint()
        self.initUI()
        QTimer.singleShot(5000, self.show_main_menu)
        self.cs2_process = None

    def get_logo_widget(self):
        path = "C:/Users/brtig/OneDrive/Desktop/Exclus Cs2/assets/Logo.png"
        if os.path.exists(path):
            label = QLabel()
            pixmap = QPixmap(path)
            if not pixmap.isNull():
                label.setPixmap(pixmap.scaled(28, 28, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            return label
        return QLabel("EXCLUS CS2")

    def initUI(self):
        self.stack = QStackedWidget(self)
        self.stack.setGeometry(0, 0, 400, 460)
        self.loading_screen = self.build_loading_screen("Loading...")
        self.menu_screen = self.build_menu_screen()
        self.inject_screen = self.build_loading_screen("Loading...")

        self.stack.addWidget(self.loading_screen)
        self.stack.addWidget(self.menu_screen)
        self.stack.addWidget(self.inject_screen)

    def build_loading_screen(self, text):
        page = QWidget()
        page.setStyleSheet("background-color: #1e1e1e;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        top_bar = QWidget()
        top_bar.setFixedHeight(40)
        top_bar.setStyleSheet("background-color: #2a2a2a; border-top-left-radius: 20px; border-top-right-radius: 20px;")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 0, 10, 0)
        logo = self.get_logo_widget()
        top_layout.addStretch()
        top_layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        top_layout.addStretch()
        layout.addWidget(top_bar)

        layout.addStretch()
        self.ring = LoaderRing(text=text)
        layout.addWidget(self.ring, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

        bottom = QWidget()
        bottom.setFixedHeight(40)
        bottom.setStyleSheet("background-color: #2a2a2a; border-bottom-left-radius: 20px; border-bottom-right-radius: 20px;")
        bottom_layout = QHBoxLayout(bottom)

        buttons = {
            "Discord": "https://example.com",
            "Support": "https://example.com",
            "Website": "https://exclus.site"
        }

        for label, url in buttons.items():
            btn = QPushButton(label)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.setStyleSheet("color: white; background: none; border: none; font-size: 12px;")
            btn.clicked.connect(lambda _, link=url: webbrowser.open(link))
            bottom_layout.addWidget(btn)

        layout.addWidget(bottom)

        return page

    def build_menu_screen(self):
        page = QWidget()
        page.setStyleSheet("background-color: #1e1e1e;")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        top_bar = QWidget()
        top_bar.setFixedHeight(40)
        top_bar.setStyleSheet("background-color: #2a2a2a; border-top-left-radius: 20px; border-top-right-radius: 20px;")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 0, 10, 0)
        logo = self.get_logo_widget()
        top_layout.addStretch()
        top_layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        top_layout.addStretch()
        layout.addWidget(top_bar)

        layout.addSpacing(20)

        title = QLabel("Available Clients")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: white; margin-left: 20px;")
        layout.addWidget(title)

        client_list_widget = QWidget()
        client_list_layout = QVBoxLayout(client_list_widget)
        client_list_layout.setContentsMargins(20, 0, 20, 0)
        client_list_layout.setSpacing(14)

        client_list_layout.addLayout(self.client_entry("Counter-Strike 2", "Undetected", "LOAD", self.load_inject_screen))
        client_list_layout.addLayout(self.client_entry("CS:GO", "Repairing", "LOAD", None, disabled=True))

        layout.addWidget(client_list_widget)
        layout.addStretch()

        bottom = QWidget()
        bottom.setFixedHeight(40)
        bottom.setStyleSheet("background-color: #2a2a2a; border-bottom-left-radius: 20px; border-bottom-right-radius: 20px;")
        bottom_layout = QHBoxLayout(bottom)

        buttons = {
            "Discord": "https://example.com",
            "Support": "https://example.com",
            "Website": "https://exclus.site"
        }

        for label, url in buttons.items():
            btn = QPushButton(label)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.setStyleSheet("color: white; background: none; border: none; font-size: 12px;")
            btn.clicked.connect(lambda _, link=url: webbrowser.open(link))
            bottom_layout.addWidget(btn)

        layout.addWidget(bottom)

        return page

    def client_entry(self, name, status, button_text, callback, disabled=False):
        layout = QHBoxLayout()
        label_box = QVBoxLayout()
        label_box.setSpacing(0)

        label_name = QLabel(name)
        label_name.setFont(QFont("Segoe UI", 14))
        label_status = QLabel(status)
        label_status.setStyleSheet("color: #4da6ff; font-size: 13px; margin-top: -4px;")

        label_box.addWidget(label_name)
        label_box.addWidget(label_status)
        layout.addLayout(label_box)

        layout.addStretch()

        btn = QPushButton(button_text)
        if disabled:
            btn.setStyleSheet("background-color: #333; color: gray; border-radius: 5px; padding: 6px 15px;")
            btn.setEnabled(False)
        else:
            btn.setStyleSheet("background-color: #4da6ff; color: white; border-radius: 5px; padding: 6px 15px;")
        if callback:
            btn.clicked.connect(callback)

        layout.addWidget(btn)
        return layout

    def show_main_menu(self):
        self.stack.setCurrentIndex(1)

    def load_inject_screen(self):
        self.stack.setCurrentIndex(2)
        self.ring.text = "Downloading..."

        # Жестко убиваем Steam
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and 'steam' in proc.info['name'].lower():
                try:
                    proc.kill()
                except Exception:
                    pass

        # Запускаем Steam с выбором аккаунта
        try:
            subprocess.Popen(["start", "steam://open/steam"], shell=True)
        except Exception:
            self.ring.text = "Steam launch failed"
            QTimer.singleShot(5000, self.show_main_menu)
            return

        # Запускаем CS2 через Steam URL
        try:
            subprocess.Popen(["start", "steam://rungameid/730"], shell=True)
        except Exception:
            self.ring.text = "CS2 launch failed"
            QTimer.singleShot(5000, self.show_main_menu)
            return

        # Начинаем ждать появления steam.exe
        self.check_steam_running_timer = QTimer()
        self.check_steam_running_timer.timeout.connect(self.check_steam_running)
        self.check_steam_running_timer.start(2000)

    def check_steam_running(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() == 'steam.exe':
                self.check_steam_running_timer.stop()
                self.ring.text = "Waiting for CS2..."
                QTimer.singleShot(5000, self.wait_cs2_and_inject)
                return

    def wait_cs2_and_inject(self):
        # Ждём запуска cs2.exe до 90 секунд, проверяем каждые 3 секунды
        self.cs2_check_counter = 0
        self.cs2_check_timer = QTimer()
        self.cs2_check_timer.timeout.connect(self.try_inject_cs2)
        self.cs2_check_timer.start(3000)

    def try_inject_cs2(self):
        self.cs2_check_counter += 3
        cs2_proc = None
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            if proc.info['name'] and proc.info['name'].lower() == 'cs2.exe' and proc.info['status'] == psutil.STATUS_RUNNING:
                try:
                    cs2_proc = proc
                    break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        if cs2_proc:
            self.cs2_check_timer.stop()
            self.cs2_process = cs2_proc
            self.ring.text = "Injecting..."
            QTimer.singleShot(15000, lambda: self.perform_injection(cs2_proc.pid))
        else:
            if self.cs2_check_counter >= 90:
                self.cs2_check_timer.stop()
                self.ring.text = "CS2 not found"
                QTimer.singleShot(5000, self.show_main_menu)
            else:
                pass

    def perform_injection(self, pid):
        success = self.inject_dll(pid, r"C:\Users\brtig\OneDrive\Desktop\Exclus Cs2\exclus.dll")
        if success:
            self.ring.text = "Successful injection!"
            QTimer.singleShot(5000, self.close_loader)
        else:
            self.ring.text = "Injection failed"
            QTimer.singleShot(5000, self.show_main_menu)

    def inject_dll(self, pid, dll_path):
        # ПРЕДУПРЕЖДЕНИЕ: Без прав администратора OpenProcess может вернуть ERROR_ACCESS_DENIED (код 5)
        # для cs2.exe, так как CS2 работает с повышенными привилегиями.
        PROCESS_ALL_ACCESS = 0x1F0FFF
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            return False

        dll_path_bytes = dll_path.encode('utf-8')
        size = len(dll_path_bytes) + 1

        addr = VirtualAllocEx(process_handle, None, size, MEM_COMMIT, PAGE_READWRITE)
        if not addr:
            CloseHandle(process_handle)
            return False

        written = ctypes.c_size_t(0)
        if not WriteProcessMemory(process_handle, addr, dll_path_bytes, size, ctypes.byref(written)):
            CloseHandle(process_handle)
            return False

        h_kernel32 = GetModuleHandleA(b"kernel32.dll")
        h_loadlib = GetProcAddress(h_kernel32, b"LoadLibraryA")
        if not h_loadlib:
            CloseHandle(process_handle)
            return False

        thread_id = wintypes.DWORD()
        remote_thread = CreateRemoteThread(process_handle, None, 0, h_loadlib, addr, 0, ctypes.byref(thread_id))
        if not remote_thread:
            CloseHandle(process_handle)
            return False

        kernel32.WaitForSingleObject(remote_thread, 0xFFFFFFFF)  # WAIT_INFINITE
        CloseHandle(remote_thread)
        CloseHandle(process_handle)
        return True

    def close_loader(self):
        self.close()

    def paintEvent(self, event):
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 20, 20)
        region = QRegion(path.toFillPolygon().toPolygon())
        self.setMask(region)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPosition().toPoint()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    loader = LoaderWindow()
    loader.show()
    sys.exit(app.exec())