import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import subprocess

class NetworkInfo:
    def __init__(self, notebook):
        self.frame = ttk.Frame(notebook)
        
        self.info_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, height=15)
        self.info_text.grid(row=0, column=0, columnspan=2, sticky=tk.NSEW)
        
        self.refresh_button = ttk.Button(self.frame, text="Refresh Network Info", command=self.get_network_info)
        self.refresh_button.grid(row=1, column=0, columnspan=2, pady=(5, 0))
    
    def get_network_info(self):
        self.info_text.delete("1.0", tk.END)
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.info_text.insert(tk.END, f"Hostname: {hostname}\n")
            self.info_text.insert(tk.END, f"Local IP Address: {local_ip}\n\n")
            
            if subprocess.run(["which", "ip"], capture_output=True).returncode == 0:
                result = subprocess.run(["ip", "a"], capture_output=True, text=True)
            else:
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, shell=True)
                
            self.info_text.insert(tk.END, result.stdout)
        except Exception as e:
            self.info_text.insert(tk.END, f"Error retrieving network info: {e}\n")
