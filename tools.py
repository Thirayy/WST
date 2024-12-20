import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, 
                             QVBoxLayout, QHBoxLayout, QListWidget, QMessageBox, 
                             QFileDialog, QInputDialog)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt
from scapy.all import sniff, Dot11, Dot11Beacon, ARP, Ether, srp
import threading
import subprocess

# Global variable to store known SSIDs and MAC addresses
known_ssids = ["MyHomeWiFi", "OfficeWiFi"]  # Add known SSIDs here
scanned_networks = {}  # Dictionary to store SSID and MAC addresses
signal_strengths = {}  # To store signal strengths

class WirelessSecurityTool(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Wireless Security Framework")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("https://techrrival.com/wp-content/uploads/2018/02/Wifi-Hacking.png"))
        self.setStyleSheet("background-color: #1e1e1e; color: white;")  # Dark background

        # Main layout
        self.main_layout = QVBoxLayout()
        self.main_layout.setAlignment(Qt.AlignTop)

        # Title Label
        self.title_label = QLabel("Wireless Security Framework")
        self.title_label.setFont(QFont("Impact", 40, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.title_label)

        # Create a horizontal layout for SSID and MAC list boxes
        list_layout = QHBoxLayout()

        # SSID Listbox Layout
        ssid_layout = QVBoxLayout()
        ssid_label = QLabel("SSID List")
        ssid_label.setAlignment(Qt.AlignCenter)
        ssid_layout.addWidget(ssid_label)

        self.ssid_listbox = QListWidget()
        ssid_layout.addWidget(self.ssid_listbox)
        list_layout.addLayout(ssid_layout)

        # MAC Listbox Layout
        mac_layout = QVBoxLayout()
        mac_label = QLabel("MAC List")
        mac_label.setAlignment(Qt.AlignCenter)
        mac_layout.addWidget(mac_label)

        self.mac_listbox = QListWidget()
        mac_layout.addWidget(self.mac_listbox)
        list_layout.addLayout(mac_layout)

        # Add the horizontal layout to the main layout
        self.main_layout.addLayout(list_layout)

        # Input Fields
        self.custom_ssid_entry = self.create_input_field("Custom SSID")  # Input field for custom SSID

        # Status Label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #00FF00; font-size: 12px;")  # Bright neon green for status
        self.main_layout.addWidget(self.status_label)

        # Buttons Layout
        button_layout = QHBoxLayout()
        button_layout.setAlignment(Qt.AlignCenter)

        # Action Buttons
        self.add_button(button_layout, "Start Monitoring", self.start_monitoring)
        self.add_button(button_layout, "Detect Rogue APs", self.start_rogue_detection)
        self.add_button(button_layout, "Check Encryption", self.start_encryption_check)
        self.add_button(button_layout, "Fake Network", self.start_evil_twin)
        self.add_button(button_layout, "Show Signal Strengths", self.show_signal_strengths)
        self.add_button(button_layout, "Save Scan Results", self.save_scan_results)
        self.add_button(button_layout, "Monitor Traffic", self.start_monitoring_traffic)

        self.main_layout.addLayout(button_layout)
        self.setLayout(self.main_layout)

    def create_input_field(self, placeholder):
        entry = QLineEdit(self)
        entry.setPlaceholderText(placeholder)
        entry.setStyleSheet("font-size: 12px; padding: 10px; border: 1px solid #4CAF50; border-radius: 5px;")
        self.main_layout.addWidget(entry)
        return entry

    def create_button(self, text, callback):
        button = QPushButton(text)
        button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; border-radius:  5px; font-size: 12px;")
        button.clicked.connect(callback)
        button.setCursor(Qt.PointingHandCursor)
        return button

    def add_button(self, layout, text, callback):
        button = self.create_button(text, callback)
        layout.addWidget(button)

    def start_monitoring(self):
        self.mac_listbox.clear()
        threading.Thread(target=self.monitor_network).start()

    def is_interface_available(self, interface):
        try:
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            return interface in result.stdout
        except Exception as e:
            print(f"Error checking interface: {e}")
            return False

    def monitor_network(self):
        print("Starting network monitoring...")

        def packet_handler(packet):
            if packet.haslayer(Dot11):
                ssid = packet.info.decode() if packet.info else "Hidden"
                mac = packet.addr2
                signal_strength = packet.dBm_AntSignal

                # Store the network information
                if ssid not in scanned_networks:
                    scanned_networks[ssid] = mac
                    signal_strengths[ssid] = signal_strength
                    self.ssid_listbox.addItem(f"{ssid} - {signal_strength} dBm")
                    self.mac_listbox.addItem(mac)

        if not self.is_interface_available("wlan0mon"):
            self.status_label.setText("Interface wlan0mon not available. Monitoring will not work properly.")
            return

        try:
            print("Monitoring network... Press Ctrl+C to stop.")
            sniff(prn=packet_handler, iface="wlan0mon", store=0)
        except Exception as e:
            print(f"Error during monitoring: {e}")
            self.status_label.setText(f"Error: {e}")

    def start_rogue_detection(self):
        threading.Thread(target=self.detect_rogue_ap).start()

    def detect_rogue_ap(self):
        rogue_aps = []
        def packet_handler(packet):
            if packet.haslayer(Dot11):
                ssid = packet.info.decode() if packet.info else "Hidden"
                mac = packet.addr2
                if ssid not in known_ssids:
                    rogue_aps.append((ssid, mac))
                    print(f"Rogue AP Detected: SSID: {ssid}, MAC: {mac}")

        if not self.is_interface_available("wlan0mon"):
            self.status_label.setText("Interface wlan0mon not in monitor mode. Detection may not work properly.")
            return

        try:
            print("Scanning for rogue APs...")
            sniff(prn=packet_handler, iface="wlan0mon", timeout=30)
            print("Rogue Access Points Detected:", rogue_aps)
        except Exception as e:
            print(f"Error during rogue AP detection: {e}")
            self.status_label.setText(f"Error: {e}")

    def start_encryption_check(self):
        threading.Thread(target=self.check_encryption).start()

    def check_encryption(self):
        def packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                ssid = packet.info.decode() if packet.info else "Hidden"
                capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                if "privacy" not in capabilities:
                    print(f"Insecure Network Found: {ssid}")
                else:
                    print(f"Secure Network Found: {ssid}")

        if not self.is_interface_available("wlan0mon"):
            self.status_label.setText("Interface wlan0mon not in monitor mode. Encryption check may not work properly.")
            return

        try:
            print("Checking network encryption...")
            sniff(prn=packet_handler, iface="wlan0mon", timeout=30)
        except Exception as e:
            print(f"Error during encryption check: {e}")
            self.status_label.setText(f"Error: {e}")

    def start_evil_twin(self):
        ssid = self.custom_ssid_entry.text()
        channel, ok = QInputDialog.getText(self, "Input Channel", "Enter Channel:")
        if ok and ssid:
            threading.Thread(target=self.evil_twin_attack, args=(ssid, channel)).start()
        else:
            QMessageBox.warning(self, "Warning", "Please enter a valid SSID and channel.")

    def evil_twin_attack(self, ssid, channel):
        if not self.is_interface_available("wlan0mon"):
            self.status_label.setText("Interface wlan0mon not in monitor mode. Evil Twin attack will not work.")
            return

        print(f"Starting Evil Twin attack with SSID: {ssid} on channel {channel}...")
        self.status_label.setText(f"Starting Evil Twin attack with SSID: {ssid}...")

        command = ["sudo", "airbase-ng", "-e", ssid, "-c", str(channel), "wlan0mon"]
        try:
            subprocess.run(command, check=True)
            self.status_label.setText("Evil Twin attack running. Check console for output.")
        except subprocess.CalledProcessError as e:
            print(f"Error during Evil Twin attack: {e}")
            self.status_label.setText(f"Error: {e}")

    def start_monitoring_traffic(self):
        interface, ok = QInputDialog.getText(self, "Enter Network Interface", "Enter the network interface (e.g., wlan0):")
        if ok and interface:
            threading.Thread(target=self.monitor_traffic, args=(interface,)).start()

    def monitor_traffic(self, interface):
        self.status_label.setText("Monitoring network traffic...")
        command = ["sudo", "tcpdump", "-i", interface, "-c", "10"]  # Capture 10 packets
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.status_label.setText("Traffic monitoring completed. Results:\n" + result.stdout)
        except subprocess.CalledProcessError as e:
            self.status_label.setText(f"Error during traffic monitoring: {e}")

    def save_scan_results(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scan Results", "", "Text files (*.txt);;All files (*)")
        if file_path:
            with open(file_path, 'w') as f:
                for ssid, mac in scanned_networks.items():
                    f.write(f"{ssid}, {mac}\n")
            self.status_label.setText("Scan results saved successfully.")

    def show_signal_strengths(self):
        signal_strengths_message = "Signal Strengths:\n"
        for ssid, strength in signal_strengths.items():
            signal_strengths_message += f"{ssid}: {strength} dBm\n"
        
        QMessageBox.information(self, "Signal Strengths", signal_strengths_message)

    def show_error_message(self, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Error")
        msg_box.setText(message)
        msg_box.setStyleSheet("QMessageBox { color: white; background-color: #1e1e1e; }")  # Set text color to white and background to dark
        msg_box.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    tool = WirelessSecurityTool()
    tool.show()
    sys.exit(app.exec_())
