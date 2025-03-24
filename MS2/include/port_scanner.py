import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading

class PortScanner:
    def __init__(self, notebook):
        self.frame = ttk.Frame(notebook)
        
        ttk.Label(self.frame, text="Target Host/IP:").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(self.frame)
        self.target_entry.grid(row=0, column=1, sticky=tk.EW)
        
        ttk.Label(self.frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W)
        self.start_port_entry = ttk.Entry(self.frame, width=5)
        self.start_port_entry.grid(row=1, column=1, sticky=tk.W)
        self.end_port_entry = ttk.Entry(self.frame, width=5)
        self.end_port_entry.grid(row=1, column=2, sticky=tk.W)
        
        self.scan_button = ttk.Button(self.frame, text="Scan Ports", command=self.scan_ports)
        self.scan_button.grid(row=2, column=0, columnspan=3, pady=(5, 0))
        
        self.result_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, height=15)
        self.result_text.grid(row=3, column=0, columnspan=3, sticky=tk.NSEW)
        
        self.scan_in_progress = False
    
    def scan_ports(self):
        if self.scan_in_progress:
            return
        
        target = self.target_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                raise ValueError("Invalid port range. Use 1-65535.")
            
            self.result_text.delete("1.0", tk.END)
            self.scan_in_progress = True
            threading.Thread(target=self.scan_ports_thread, args=(target, start_port, end_port)).start()
        except ValueError as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")
    
    def scan_ports_thread(self, target, start_port, end_port):
        try:
            target_ip = socket.gethostbyname(target)
            self.result_text.insert(tk.END, f"Scanning {target} ({target_ip})...\n")
            
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    self.result_text.insert(tk.END, f"Port {port}: Open\n")
                sock.close()
            
        except socket.gaierror:
            self.result_text.insert(tk.END, "Invalid Hostname\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")
        finally:
            self.scan_in_progress = False