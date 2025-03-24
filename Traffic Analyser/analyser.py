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
    net_info_text.delete("1.0", tk.END)
    interfaces = psutil.net_interfaces()
    for interface, addresses in interfaces.items():
        net_info_text.insert(tk.END, f"Interface: {interface}\n")
        for address in addresses:
            net_info_text.insert(tk.END, f"  - {address.family}: {address.address}\n")
        net_info_text.insert(tk.END, "-----------------------\n")

def connect_to_device():
    device_type = device_type_entry.get()
    ip = ip_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    try:
        if device_type == "ssh":
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            device_info_text.delete("1.0", tk.END)
            device_info_text.insert(tk.END, f"SSH Connection Successful to {ip}\n")
            ssh.close()

        else:
            device = {
                "device_type": device_type,
                "host": ip,
                "username": username,
                "password": password,
            }
            net_connect = netmiko.ConnectHandler(**device)
            device_info_text.delete("1.0", tk.END)
            device_info_text.insert(tk.END, f"Netmiko Connection Successful to {ip} (Type: {device_type})\n")
            device_info_text.insert(tk.END, net_connect.send_command("show ip int brief"))
            net_connect.disconnect()
    except Exception as e:
        device_info_text.delete("1.0", tk.END)
        device_info_text.insert(tk.END, f"Connection Error: {e}\n")

def get_socket_info():
    socket_info_text.delete("1.0", tk.END)
    try:
        for conn in psutil.net_connections(kind='tcp'):
            laddr = conn.laddr
            raddr = conn.raddr
            status = conn.status
            if raddr:
                socket_info_text.insert(tk.END, f"Local: {laddr.ip}:{laddr.port}  <->  Remote: {raddr.ip}:{raddr.port}  Status: {status}\n")
            else:
                socket_info_text.insert(tk.END, f"Local: {laddr.ip}:{laddr.port}  Status: {status} (Listening)\n")

        socket_info_text.insert(tk.END, "-----------------------\n")

    except Exception as e:
        socket_info_text.delete("1.0", tk.END)
        socket_info_text.insert(tk.END, f"Error getting socket info: {e}\n")


def scan_ports_thread(target_host, port_range_start, port_range_end):
    try:
        target_ip = socket.gethostbyname(target_host)
        port_scan_text.insert(tk.END, f"Scanning {target_host} ({target_ip})...\n")

        for port in range(port_range_start, port_range_end + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    port_scan_text.insert(tk.END, f"Port {port}: Open\n")
                #else: # Uncomment to show closed ports
                #    port_scan_text.insert(tk.END, f"Port {port}: Closed\n")

                sock.close()
            except socket.gaierror:
                port_scan_text.insert(tk.END, "Invalid Hostname\n")
                return
            except socket.timeout:
                port_scan_text.insert(tk.END, f"Port {port}: Timeout (Likely Filtered)\n")
            except Exception as e:
                port_scan_text.insert(tk.END, f"Error scanning port {port}: {e}\n")

    except socket.gaierror:
        port_scan_text.insert(tk.END, "Invalid Hostname\n")
    except Exception as e:
        port_scan_text.insert(tk.END, f"General Port Scan Error: {e}\n")
    finally:
        global scan_in_progress
        scan_in_progress = False

def scan_ports():
    global scan_in_progress
    if scan_in_progress:
        messagebox.showinfo("Port Scan", "A port scan is already in progress.")
        return

    target_host = target_host_entry.get()
    try:
        port_range_start = int(port_range_start_entry.get())
        port_range_end = int(port_range_end_entry.get())

        if not target_host:
            raise ValueError("Target host cannot be empty.")
        if not (1 <= port_range_start <= 65535 and 1 <= port_range_end <= 65535 and port_range_start <= port_range_end):
             raise ValueError("Invalid port range. Please use a range between 1 and 65535")
        port_scan_text.delete("1.0", tk.END)

        scan_in_progress = True
        thread = threading.Thread(target=scan_ports_thread, args=(target_host, port_range_start, port_range_end))
        thread.start()

    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


root = tk.Tk()
root.title("Network Traffic Analyzer")

# Create a Notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# --- Tab 1: Packet Sniffing ---
sniffing_tab = ttk.Frame(notebook)
notebook.add(sniffing_tab, text="Packet Sniffing")

interface_label = tk.Label(sniffing_tab, text="Interface:")
interface_label.grid(row=0, column=0, sticky=tk.W)
interface_entry = tk.Entry(sniffing_tab)
interface_entry.grid(row=0, column=1, sticky=tk.EW)

filter_label = tk.Label(sniffing_tab, text="BPF Filter:")
filter_label.grid(row=1, column=0, sticky=tk.W)
filter_entry = tk.Entry(sniffing_tab)
filter_entry.grid(row=1, column=1, sticky=tk.EW)

start_button = tk.Button(sniffing_tab, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=2, column=0, columnspan=2, pady=(5, 0))

packet_text = scrolledtext.ScrolledText(sniffing_tab, wrap=tk.WORD, height=10)
packet_text.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW)

# --- Tab 2: Network Information ---
net_info_tab = ttk.Frame(notebook)
notebook.add(net_info_tab, text="Network Info")

net_info_button = tk.Button(net_info_tab, text="Get Network Info", command=get_network_info)
net_info_button.pack()

net_info_text = scrolledtext.ScrolledText(net_info_tab, wrap=tk.WORD, height=10)
net_info_text.pack(fill=tk.BOTH, expand=True)

# --- Tab 3: Socket Information ---
socket_info_tab = ttk.Frame(notebook)
notebook.add(socket_info_tab, text="Socket Info")

socket_info_button = tk.Button(socket_info_tab, text="Get Socket Info", command=get_socket_info)
socket_info_button.pack()

socket_info_text = scrolledtext.ScrolledText(socket_info_tab, wrap=tk.WORD, height=10)
socket_info_text.pack(fill=tk.BOTH, expand=True)

# --- Tab 4: Device Connection ---
device_tab = ttk.Frame(notebook)
notebook.add(device_tab, text="Device Connection")

device_type_label = tk.Label(device_tab, text="Device Type:")
device_type_label.grid(row=0, column=0, sticky=tk.W)
device_type_entry = tk.Entry(device_tab)
device_type_entry.grid(row=0, column=1, sticky=tk.EW)

ip_label = tk.Label(device_tab, text="IP Address:")
ip_label.grid(row=1, column=0, sticky=tk.W)
ip_entry = tk.Entry(device_tab)
ip_entry.grid(row=1, column=1, sticky=tk.EW)

username_label = tk.Label(device_tab, text="Username:")
username_label.grid(row=2, column=0, sticky=tk.W)
username_entry = tk.Entry(device_tab)
username_entry.grid(row=2, column=1, sticky=tk.EW)

password_label = tk.Label(device_tab, text="Password:")
password_label.grid(row=3, column=0, sticky=tk.W)
password_entry = tk.Entry(device_tab, show="*")
password_entry.grid(row=3, column=1, sticky=tk.EW)

connect_button = tk.Button(device_tab, text="Connect", command=connect_to_device)
connect_button.grid(row=4, column=0, columnspan=2, pady=(5, 0))

device_info_text = scrolledtext.ScrolledText(device_tab, wrap=tk.WORD, height=10)
device_info_text.grid(row=5, column=0, columnspan=2, sticky=tk.NSEW)

# --- Tab 5: Port Scanner ---
port_scan_tab = ttk.Frame(notebook)
notebook.add(port_scan_tab, text="Port Scanner")

target_host_label = tk.Label(port_scan_tab, text="Target Host/IP:")
target_host_label.grid(row=0, column=0, sticky=tk.W)
target_host_entry = tk.Entry(port_scan_tab)
target_host_entry.grid(row=0, column=1, sticky=tk.EW)

port_range_label = tk.Label(port_scan_tab, text="Port Range:")
port_range_label.grid(row=1, column=0, sticky=tk.W)

port_range_frame_inner = tk.Frame(port_scan_tab)
port_range_frame_inner.grid(row=1, column=1, sticky=tk.EW)

port_range_start_label = tk.Label(port_range_frame_inner, text="Start:")
port_range_start_label.pack(side=tk.LEFT)
port_range_start_entry = tk.Entry(port_range_frame_inner, width=5)
port_range_start_entry.pack(side=tk.LEFT)

port_range_end_label = tk.Label(port_range_frame_inner, text="End:")
port_range_end_label.pack(side=tk.LEFT)
port_range_end_entry = tk.Entry(port_range_frame_inner, width=5)
port_range_end_entry.pack(side=tk.LEFT)

scan_button = tk.Button(port_scan_tab, text="Scan Ports", command=scan_ports)
scan_button.grid(row=2, column=0, columnspan=2, pady=(5, 0))

port_scan_text = scrolledtext.ScrolledText(port_scan_tab, wrap=tk.WORD, height=10)
port_scan_text.grid(row=3, column=0, columnspan=2, sticky=tk.NSEW)


scan_in_progress = False

root.mainloop()