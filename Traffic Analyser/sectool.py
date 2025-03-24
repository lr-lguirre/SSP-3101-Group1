import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import netmiko
import paramiko
import psutil
import socket
import threading

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        protocol = "Other"
        src_port = "N/A"
        dst_port = "N/A"

        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"

        display_text = f"Protocol: {protocol}\n" \
                       f"Source IP: {src_ip}:{src_port}\n" \
                       f"Destination IP: {dst_ip}:{dst_port}\n" \
                       "-----------------------\n"

        packet_text.insert(tk.END, display_text)
        packet_text.see(tk.END)

def start_sniffing():
    interface = interface_entry.get()
    filter_expression = filter_entry.get()

    packet_text.delete("1.0", tk.END)
    try:
        if interface:
            scapy.sniff(prn=packet_callback, filter=filter_expression, iface=interface, store=0, count=0)
        else:
            scapy.sniff(prn=packet_callback, filter=filter_expression, store=0, count=0)
    except Exception as e:
        packet_text.insert(tk.END, f"Error: {e}\n")

def get_network_info():
    network_text.delete("1.0", tk.END)
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    network_text.insert(tk.END, f"Hostname: {hostname}\nIP Address: {ip_address}\n")

def get_socket_info():
    socket_text.delete("1.0", tk.END)
    try:
        host = socket.gethostname()
        ip = socket.gethostbyname(host)
        socket_text.insert(tk.END, f"Host: {host}\nIP Address: {ip}\n")
    except Exception as e:
        socket_text.insert(tk.END, f"Error: {e}\n")

def scan_devices():
    devices_text.delete("1.0", tk.END)
    devices_text.insert(tk.END, "Scanning for connected devices...\n")
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                devices_text.insert(tk.END, f"Interface: {interface}, IP: {addr.address}\n")

def port_scan():
    port_text.delete("1.0", tk.END)
    target = port_target_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP address or hostname.")
        return
    port_text.insert(tk.END, f"Scanning {target} for open ports...\n")
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            port_text.insert(tk.END, f"Port {port} is open\n")
        sock.close()

def va_scan():
    va_text.delete("1.0", tk.END)
    target_ip = va_target_entry.get()
    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return
    va_text.insert(tk.END, f"Running vulnerability assessment on {target_ip}...\n")
    va_text.insert(tk.END, "(Simulation) No critical vulnerabilities detected.\n")

root = tk.Tk()
root.title("Network Security Toolkit")
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Packet Sniffer Tab
sniffing_tab = ttk.Frame(notebook)
notebook.add(sniffing_tab, text="Packet Sniffer")
interface_label = tk.Label(sniffing_tab, text="Interface:")
interface_label.pack()
interface_entry = tk.Entry(sniffing_tab)
interface_entry.pack()
filter_label = tk.Label(sniffing_tab, text="BPF Filter:")
filter_label.pack()
filter_entry = tk.Entry(sniffing_tab)
filter_entry.pack()
start_button = tk.Button(sniffing_tab, text="Start Sniffing", command=start_sniffing)
start_button.pack()
packet_text = scrolledtext.ScrolledText(sniffing_tab, wrap=tk.WORD, height=10)
packet_text.pack(fill=tk.BOTH, expand=True)

# Network Info Tab
network_tab = ttk.Frame(notebook)
notebook.add(network_tab, text="Network Info")
network_button = tk.Button(network_tab, text="Get Network Info", command=get_network_info)
network_button.pack()
network_text = scrolledtext.ScrolledText(network_tab, wrap=tk.WORD, height=10)
network_text.pack(fill=tk.BOTH, expand=True)

# Socket Info Tab
socket_tab = ttk.Frame(notebook)
notebook.add(socket_tab, text="Socket Info")
socket_button = tk.Button(socket_tab, text="Get Socket Info", command=get_socket_info)
socket_button.pack()
socket_text = scrolledtext.ScrolledText(socket_tab, wrap=tk.WORD, height=10)
socket_text.pack(fill=tk.BOTH, expand=True)

# Device Connection Tab
devices_tab = ttk.Frame(notebook)
notebook.add(devices_tab, text="Device Connection")
devices_button = tk.Button(devices_tab, text="Scan Devices", command=scan_devices)
devices_button.pack()
devices_text = scrolledtext.ScrolledText(devices_tab, wrap=tk.WORD, height=10)
devices_text.pack(fill=tk.BOTH, expand=True)

# Port Scanner Tab
port_tab = ttk.Frame(notebook)
notebook.add(port_tab, text="Port Scanner")
port_target_label = tk.Label(port_tab, text="Target IP/Host:")
port_target_label.pack()
port_target_entry = tk.Entry(port_tab)
port_target_entry.pack()
port_scan_button = tk.Button(port_tab, text="Run Port Scan", command=port_scan)
port_scan_button.pack()
port_text = scrolledtext.ScrolledText(port_tab, wrap=tk.WORD, height=10)
port_text.pack(fill=tk.BOTH, expand=True)

# VA Scanner Tab
va_tab = ttk.Frame(notebook)
notebook.add(va_tab, text="VA Scanner")
va_target_label = tk.Label(va_tab, text="Target IP:")
va_target_label.pack()
va_target_entry = tk.Entry(va_tab)
va_target_entry.pack()
va_scan_button = tk.Button(va_tab, text="Run VA Scan", command=va_scan)
va_scan_button.pack()
va_text = scrolledtext.ScrolledText(va_tab, wrap=tk.WORD, height=10)
va_text.pack(fill=tk.BOTH, expand=True)

root.mainloop()
