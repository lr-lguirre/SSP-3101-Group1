import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import paramiko
import netmiko

class DeviceConnection:
    def __init__(self, notebook):
        self.frame = ttk.Frame(notebook)
        self.frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.frame, text="Device Type:").grid(row=0, column=0, sticky=tk.W)

        # Dropdown for device type selection
        self.device_types = [
            "cisco_ios", "cisco_nxos", "juniper", "hp_procurve",
            "mikrotik_routeros", "paloalto_panos", "linux", "generic_ssh", "generic_telnet"
        ]
        self.device_type_var = tk.StringVar()
        self.device_type_dropdown = ttk.Combobox(self.frame, textvariable=self.device_type_var, values=self.device_types, state="readonly")
        self.device_type_dropdown.grid(row=0, column=1, columnspan=4, sticky=tk.EW)
        self.device_type_dropdown.current(0)

        ttk.Label(self.frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W)

        # Frame to hold the 4 IP octets together
        ip_frame = ttk.Frame(self.frame)
        ip_frame.grid(row=1, column=1, columnspan=4, sticky=tk.W)

        # Four separate Entry widgets for the IP octets
        self.ip_octets = []
        for i in range(4):
            octet_var = tk.StringVar()
            octet_entry = ttk.Entry(ip_frame, textvariable=octet_var, width=5, justify=tk.CENTER)
            octet_entry.grid(row=0, column=i, padx=2)
            octet_entry.bind("<FocusOut>", lambda event, i=i: self.validate_octet(i))  # Validate on focus-out
            octet_var.trace_add("write", lambda *args, i=i: self.auto_move(i))  # Auto-move to next octet
            self.ip_octets.append(octet_entry)

        ttk.Label(self.frame, text="Username:").grid(row=2, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(self.frame)
        self.username_entry.grid(row=2, column=1, columnspan=4, sticky=tk.EW)

        ttk.Label(self.frame, text="Password:").grid(row=3, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(self.frame, show="*")
        self.password_entry.grid(row=3, column=1, columnspan=4, sticky=tk.EW)

        self.connect_button = ttk.Button(self.frame, text="Connect", command=self.connect_to_device)
        self.connect_button.grid(row=4, column=0, columnspan=5, pady=(5, 0))

        self.device_info_text = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, height=10)
        self.device_info_text.grid(row=5, column=0, columnspan=5, sticky=tk.NSEW)

        self.frame.columnconfigure(4, weight=1)
        self.frame.rowconfigure(5, weight=1)

    def auto_move(self, index):
        """Automatically moves to the next octet if the current one is valid."""
        octet_text = self.ip_octets[index].get()
        if octet_text.isdigit() and 0 <= int(octet_text) <= 255 and len(octet_text) == 3 and index < 3:
            self.ip_octets[index + 1].focus()

    def validate_octet(self, index):
        """Validates an octet when the user moves away (focus out)."""
        octet_text = self.ip_octets[index].get()
        if octet_text.isdigit():
            octet_value = int(octet_text)
            if not (0 <= octet_value <= 255):
                self.show_error(index, f"Octet {index + 1} must be between 0-255")
        elif octet_text:  # If not empty and not a valid number
            self.show_error(index, f"Octet {index + 1} must be a number between 0-255")

    def show_error(self, index, message):
        """Shows an error message and returns focus to the invalid octet."""
        messagebox.showerror("Invalid Octet", message)
        self.ip_octets[index].focus_set()
        self.ip_octets[index].selection_range(0, tk.END)  # Selects all text in the field

    def get_full_ip(self):
        """Combines the octets into a full IP address."""
        return ".".join(entry.get() for entry in self.ip_octets)

    def connect_to_device(self):
        """Handles device connection logic."""
        ip = self.get_full_ip().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        device_type = self.device_type_var.get()

        # Ensure all octets are filled
        if any(not entry.get().isdigit() for entry in self.ip_octets):
            messagebox.showerror("Invalid IP", "All IP octets must be filled with numbers.")
            return

        try:
            if device_type == "generic_ssh" or device_type == "linux":
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password)
                self.device_info_text.delete("1.0", tk.END)
                self.device_info_text.insert(tk.END, f"SSH Connection Successful to {ip}\n")
                ssh.close()
            else:
                device = {
                    "device_type": device_type,
                    "host": ip,
                    "username": username,
                    "password": password,
                }
                net_connect = netmiko.ConnectHandler(**device)
                self.device_info_text.delete("1.0", tk.END)
                self.device_info_text.insert(tk.END, f"Netmiko Connection Successful to {ip} (Type: {device_type})\n")
                self.device_info_text.insert(tk.END, net_connect.send_command("show ip int brief"))
                net_connect.disconnect()
        except Exception as e:
            self.device_info_text.delete("1.0", tk.END)
            self.device_info_text.insert(tk.END, f"Connection Error: {e}\n")
