import tkinter as tk
from tkinter import ttk
from include.packet_sniffer import PacketSniffer
from include.network_info import NetworkInfo
from include.socket_info import SocketInfo
from include.device_connection import DeviceConnection
from include.port_scanner import PortScanner
from include.va_scanner import VAScanner
from include.web_validator import WebValidator  # Import WebValidator

class NetworkSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Toolkit")
        
        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Initialize tabs with separate classes
        self.packet_sniffer = PacketSniffer(notebook)
        self.network_info = NetworkInfo(notebook)
        self.socket_info = SocketInfo(notebook)
        self.device_connection = DeviceConnection(notebook)
        self.port_scanner = PortScanner(notebook)
        self.va_scanner = VAScanner(notebook)
        self.web_validator = WebValidator(notebook)  # Initialize WebValidator correctly

        # Add tabs to the notebook
        notebook.add(self.packet_sniffer.frame, text="Packet Sniffer")
        notebook.add(self.network_info.frame, text="Network Info")
        notebook.add(self.socket_info.frame, text="Socket Info")
        notebook.add(self.device_connection.frame, text="Device Connection")
        notebook.add(self.port_scanner.frame, text="Port Scanner")
        notebook.add(self.va_scanner.frame, text="VA Scanner")
        notebook.add(self.web_validator.frame, text="Web Validator")  # Add Web Validator tab

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSecurityGUI(root)
    root.mainloop()
