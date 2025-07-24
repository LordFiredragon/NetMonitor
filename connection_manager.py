import sys
import psutil
import requests
import subprocess
import platform
from functools import partial
import traceback
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QLineEdit, QHBoxLayout, QPushButton, QMessageBox

)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtCore import QRunnable, QThreadPool, pyqtSlot, QObject, pyqtSignal


class GeoWorker(QRunnable):
    def __init__(self, ip, callback):
        super().__init__()
        self.ip = ip
        self.callback = callback

    @pyqtSlot()
    def run(self):
        try:
            response = requests.get(f"http://ip-api.com/json/{self.ip}", timeout=5)
            data = response.json()
        except:
            data = {"country": "Unknown"}
        self.callback(self.ip, data)


class NetMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Connection Monitor")
        self.resize(800, 600)
        self.thread_pool = QThreadPool()
        self.geo_cache = {}
        self.alerted_ips = set()

        self.risky_countries = ["China", "Iran", "Bangladesh", "Pakistan", "Sri Lanka"]

        layout = QVBoxLayout()

        self.label = QLabel("Active Network Connections")
        layout.addWidget(self.label)

        # Filter section
        filter_layout = QHBoxLayout()
        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText("Filter by IP")
        filter_layout.addWidget(self.filter_ip)

        self.filter_port = QLineEdit()
        self.filter_port.setPlaceholderText("Filter by Port")
        filter_layout.addWidget(self.filter_port)

        self.filter_proc = QLineEdit()
        self.filter_proc.setPlaceholderText("Filter by Process")
        filter_layout.addWidget(self.filter_proc)

        layout.addLayout(filter_layout)

        # Connection table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["IP", "Port", "Status", "PID", "Process", "Country", "Block/Allow"])
        layout.addWidget(self.table)

        self.setLayout(layout)

        self.refresh_data()
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(10000)

    def get_country_data(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            self.geo_cache[ip] = data
            return data
        except Exception as e:
            print(f"[ERROR] API failure for {ip}: {e}")
            return {"country": "Unknown"}

    def handle_geo(self, ip, data):
        country = data.get("country", "Unknown")
        self.geo_cache[ip] = country
        # Optionally update your table if you store row_pos references
        # Or refresh the table after all geo lookups

    def block_ip(self, ip):
        if platform.system() == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        else:
            cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
        subprocess.call(cmd, shell=True)
        print(f"[BLOCKED] {ip}")

    def allow_ip(self, ip):
        if platform.system() == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
        else:
            cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
        subprocess.call(cmd, shell=True)
        print(f"[ALLOWED] {ip}")

    def show_alert(self, ip, reason):
        alert = QMessageBox()
        alert.setIcon(QMessageBox.Warning)
        alert.setText(f"⚠️ Suspicious Connection Detected")
        alert.setInformativeText(f"IP: {ip}\nReason: {reason}")
        alert.setWindowTitle("Threat Alert")
        alert.exec_()

    def refresh_data(self):
        self.table.setRowCount(0)
        ip_filter = self.filter_ip.text().strip()
        port_filter = self.filter_port.text().strip()
        proc_filter = self.filter_proc.text().strip().lower()

        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                ip = conn.raddr.ip
                port = str(conn.raddr.port)
                status = conn.status
                pid = str(conn.pid) if conn.pid else "N/A"
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "N/A"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "N/A"

                # Apply filters
                if ip_filter and ip_filter not in ip:
                    continue
                if port_filter and port_filter != port:
                    continue
                if proc_filter and proc_filter not in proc_name.lower():
                    continue

                btn_layout = QHBoxLayout()
                block_btn = QPushButton("Block")
                allow_btn = QPushButton("Allow")

                block_btn.setStyleSheet("background-color: red; color: white;")
                allow_btn.setStyleSheet("background-color: green; color: white;")

                block_btn.clicked.connect(partial(self.block_ip, ip))
                allow_btn.clicked.connect(partial(self.allow_ip, ip))

                btn_layout.addWidget(block_btn)
                btn_layout.addWidget(allow_btn)

                btn_widget = QWidget()
                btn_widget.setLayout(btn_layout)

                if ip not in self.geo_cache:
                    worker = GeoWorker(ip, self.handle_geo)
                    self.thread_pool.start(worker)

                country = self.geo_cache.get(ip, "Fetching...")

                # Add row
                row_pos = self.table.rowCount()
                self.table.insertRow(row_pos)
                self.table.setItem(row_pos, 0, QTableWidgetItem(ip))
                self.table.setItem(row_pos, 1, QTableWidgetItem(port))
                self.table.setItem(row_pos, 2, QTableWidgetItem(status))
                self.table.setItem(row_pos, 3, QTableWidgetItem(pid))
                self.table.setItem(row_pos, 4, QTableWidgetItem(proc_name))
                self.table.setItem(row_pos, 5, QTableWidgetItem(country))
                self.table.setCellWidget(row_pos, 6, btn_widget)

                if country in self.risky_countries:
                    self.table.item(row_pos, 5).setBackground(Qt.red)
                    self.show_alert(ip, reason="Connection from flagged country")
                    self.alerted_ips.add(ip)

                else:
                    pass


if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        window = NetMonitor()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"[CRASH] {e}")
        traceback.print_exc()
        sys.exit(-1)
