import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff
import threading

class PacketSniffer:
    def __init__(self, notebook):
        self.frame = ttk.Frame(notebook)
        self.frame.pack(fill=tk.BOTH, expand=True)  # Ensure frame is visible

        self.start_button = ttk.Button(self.frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = ttk.Button(self.frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.text_area = scrolledtext.ScrolledText(self.frame, width=80, height=20)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)  # Expand text area

        self.sniffing = False
        self.sniff_thread = None

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.display_packet, stop_filter=lambda x: not self.sniffing)

    def display_packet(self, packet):
        self.text_area.insert(tk.END, f"{packet.summary()}\n")
        self.text_area.yview(tk.END)
