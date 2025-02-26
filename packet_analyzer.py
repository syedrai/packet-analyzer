import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import csv
from collections import defaultdict

# Global variables
sniffing = False
packets = []
ip_counts = defaultdict(int)  # Tracks IP packet frequency

# Function to start sniffing
def start_sniffing():
    global sniffing, packets, ip_counts
    sniffing = True
    packets = []
    ip_counts.clear()
    
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    # Get interface name
    interface = interface_entry.get().strip()
    if not interface:
        messagebox.showerror("Error", "Please enter a network interface.")
        start_button.config(state=tk.NORMAL)
        return
    
    # Start sniffing in a separate thread
    thread = threading.Thread(target=sniff_packets, args=(interface,))
    thread.start()

# Function to sniff packets
def sniff_packets(interface):
    sniff(prn=process_packet, iface=interface, store=False, stop_filter=lambda x: not sniffing)

# Function to process each packet
def process_packet(packet):
    if sniffing:
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        packet_len = len(packet)
        
        # Track IP frequency
        ip_counts[src_ip] += 1

        # Vulnerability detection
        vulnerabilities = detect_vulnerabilities(packet, src_ip)
        
        # Store packet info
        packet_info = {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Packet Length": packet_len,
            "Vulnerability": vulnerabilities
        }
        packets.append(packet_info)

        # Update GUI
        packet_table.insert("", "end", values=(src_ip, dst_ip, protocol, packet_len, vulnerabilities))

# Function to detect vulnerabilities
def detect_vulnerabilities(packet, src_ip):
    alerts = []

    # 1. Port Scan Detection (If one IP targets many different ports in short time)
    if ip_counts[src_ip] > 10:
        alerts.append("Possible Port Scan")

    # 2. Unencrypted Traffic (HTTP instead of HTTPS)
    if packet.haslayer(TCP) and packet.dport == 80:
        alerts.append("Unsecured HTTP Traffic")

    # 3. High Traffic from One Source (DDoS-like behavior)
    if ip_counts[src_ip] > 50:
        alerts.append("Possible DDoS Attack")

    return ", ".join(alerts) if alerts else "None"

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to save packets to CSV
def save_to_csv():
    if not packets:
        messagebox.showwarning("Warning", "No packets to save!")
        return
    
    filename = "captured_packets.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["Source IP", "Destination IP", "Protocol", "Packet Length", "Vulnerability"])
        writer.writeheader()
        writer.writerows(packets)
    
    messagebox.showinfo("Success", f"Packets saved to {filename}")

# GUI Setup
root = tk.Tk()
root.title("Advanced Network Packet Sniffer")
root.geometry("700x400")

# Interface Selection
tk.Label(root, text="Enter Network Interface:").pack(pady=5)
interface_entry = tk.Entry(root)
interface_entry.pack(pady=5)

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)
start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_button.grid(row=0, column=0, padx=5)
stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
stop_button.grid(row=0, column=1, padx=5)
save_button = tk.Button(button_frame, text="Save to CSV", command=save_to_csv, bg="blue", fg="white")
save_button.grid(row=0, column=2, padx=5)

# Packet Table
columns = ("Source IP", "Destination IP", "Protocol", "Packet Length", "Vulnerability")
packet_table = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=130)
packet_table.pack(pady=10, fill="both", expand=True)

# Run GUI
root.mainloop()
