import tkinter as tk
from tkinter import scrolledtext
import socket
import threading

def scan_port(ip, port):
    """Scans a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return f"Port {port}: Open"
        else:
            return f"Port {port}: Closed"
    except Exception as e:
        return f"Port {port}: Error - {e}"

def start_scan():
    """Starts the port scanning process in a separate thread."""
    ip_or_hostname = ip_entry.get()
    port_range = port_range_entry.get()

    try:
        ip = socket.gethostbyname(ip_or_hostname) #Resolve hostname to IP
    except socket.gaierror:
        results_text.insert(tk.END, f"Invalid IP address or hostname: {ip_or_hostname}\n")
        return

    try:
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
           raise ValueError # Raise error for invalid port range
    except ValueError:
        results_text.insert(tk.END, "Invalid port range. Please enter a range like 20-1024.\n")
        return

    results_text.delete(1.0, tk.END)  # Clear previous results

    def scan_thread():
        for port in range(start_port, end_port + 1):
            result = scan_port(ip, port)
            results_text.insert(tk.END, result + "\n")
            results_text.see(tk.END) # Auto-scroll to the bottom

    threading.Thread(target=scan_thread).start()



def clear_results():
    """Clears the results text area."""
    results_text.delete(1.0, tk.END)

# Create the main window
window = tk.Tk()
window.title("Network Port Scanner")

# IP/Hostname Label and Entry
ip_label = tk.Label(window, text="IP Address/Hostname:")
ip_label.grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(window)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

# Port Range Label and Entry
port_range_label = tk.Label(window, text="Port Range (e.g., 20-1024):")
port_range_label.grid(row=1, column=0, padx=5, pady=5)
port_range_entry = tk.Entry(window)
port_range_entry.grid(row=1, column=1, padx=5, pady=5)


# Buttons
start_button = tk.Button(window, text="Start Scan", command=start_scan)
start_button.grid(row=2, column=0, columnspan=2, pady=(10,5))

clear_button = tk.Button(window, text="Clear Results", command=clear_results)
clear_button.grid(row=3, column=0, columnspan=2, pady=(5,10))

# Results Text Area
results_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=50, height=15)
results_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

window.mainloop()