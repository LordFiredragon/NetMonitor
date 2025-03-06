import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import QTimer, Qt
import psutil
import requests
import time


def bytes_to_kbps(bytes_amount, time_interval):
    bits = bytes_amount * 8  # Convert bytes to bits
    kbps = bits / 1000 / time_interval  # Convert bits to Kbps
    return kbps


class NetSpeedMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_speed)
        self.timer.start(1000)  # Update every second


    def initUI(self):

        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.setWindowTitle('Net Speed Monitor')
        self.setGeometry(1720, 920, 200, 100)
        self.layout = QVBoxLayout()

        self.upload_label = QLabel('Upload Speed: ')
        self.download_label = QLabel('Download Speed: ')
        self.ip_label = QLabel('IP Address: ')
        self.refresh = QPushButton("Refresh IP")
        self.refresh.clicked.connect(self.update_ip)

        self.layout.addWidget(self.upload_label)
        self.layout.addWidget(self.download_label)
        self.layout.addWidget(self.ip_label)
        self.layout.addWidget(self.refresh)

        self.setLayout(self.layout)

        # Fetch and display the IP address
        self.update_ip()

    def update_speed(self):
        initial_net_io = psutil.net_io_counters()
        time.sleep(1)
        new_net_io = psutil.net_io_counters()
        upload_speed = new_net_io.bytes_sent - initial_net_io.bytes_sent  # Convert to KB
        download_speed = new_net_io.bytes_recv - initial_net_io.bytes_recv  # Convert to KB
        kbps_sent = bytes_to_kbps(upload_speed, 1)
        kbps_recv = bytes_to_kbps(download_speed, 1)

        self.upload_label.setText(f"Upload speed: {kbps_sent:.2f} Kbps")
        self.download_label.setText(f'Download Speed: {kbps_recv:.2f} Kbps')

    def update_ip(self):
        try:
            ip = requests.get('https://api.ipify.org').text
            self.ip_label.setText(f'IP Address: {ip}')
        except requests.RequestException:
            self.ip_label.setText('IP Address: Not available')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    monitor = NetSpeedMonitor()
    monitor.show()
    sys.exit(app.exec())
