import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import threading
import csv
import psutil
from collections import defaultdict

sniffing = False
packets = []
ip_counts = defaultdict(int)

def get_valid_interfaces():
    interfaces = []
    for iface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_LINK" or addr.family.name == "AF_INET":
                interfaces.append(iface_name)
                break
    return list(set(interfaces))

def start_sniffing():
    global sniffing, packets, ip_counts
    sniffing = True
    packets.clear()
    ip_counts.clear()

    selected_interface = interface_var.get()
    if not selected_interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return

    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    sniff_thread = threading.Thread(target=sniff_packets, args=(selected_interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

def sniff_packets(interface):
    try:
        sniff(prn=process_packet, iface=interface, store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        messagebox.showerror("Sniffing Error", f"Error while sniffing:\n{e}")
        stop_sniffing()

def process_packet(packet):
    if sniffing:
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        packet_len = len(packet)

        ip_counts[src_ip] += 1
        vulnerabilities, severity = detect_vulnerabilities(packet, src_ip)

        info = {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Packet Length": packet_len,
            "Vulnerability": f"{vulnerabilities} ({severity})"
        }
        packets.append(info)

        # Insert with tag
        tag = protocol.lower()
        packet_table.insert("", "end", values=(src_ip, dst_ip, protocol, packet_len, f"{vulnerabilities} ({severity})"), tags=(tag,))

def detect_vulnerabilities(packet, src_ip):
    alerts = []
    severity = "None"

    if ip_counts[src_ip] > 10:
        alerts.append("Possible Port Scan")
        severity = "Potential (Low)"
    if packet.haslayer(TCP) and packet.dport == 80:
        alerts.append("Unsecured HTTP Traffic")
        if severity != "Potential (Low)":
            severity = "Likely (Medium)"
    if ip_counts[src_ip] > 50:
        alerts.append("Possible DDoS Attack")
        severity = "Confirmed (High)"

    if not alerts:
        return "None", "None"
    return ", ".join(alerts), severity

def stop_sniffing():
    global sniffing
    sniffing = False
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def save_to_csv():
    if not packets:
        messagebox.showwarning("Warning", "No packets to save!")
        return

    filename = "captured_packets.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Source IP", "Destination IP", "Protocol", "Packet Length", "Vulnerability"])
        writer.writeheader()
        writer.writerows(packets)

    messagebox.showinfo("Saved", f"Packets saved to {filename}")

# GUI Setup
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("950x550")

tk.Label(root, text="Select Network Interface:").pack(pady=5)
interface_var = tk.StringVar()
interface_dropdown = ttk.Combobox(root, textvariable=interface_var, state="readonly")
interface_dropdown["values"] = get_valid_interfaces()
if interface_dropdown["values"]:
    interface_dropdown.current(0)
interface_dropdown.pack(pady=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
stop_button.grid(row=0, column=1, padx=5)

save_button = tk.Button(button_frame, text="Save to CSV", command=save_to_csv, bg="blue", fg="white")
save_button.grid(row=0, column=2, padx=5)

columns = ("Source IP", "Destination IP", "Protocol", "Packet Length", "Vulnerability")
packet_table = ttk.Treeview(root, columns=columns, show="headings", height=15)
for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=150)
packet_table.pack(pady=10, fill="both", expand=True)

# Apply tag styles
style = ttk.Style()
style.theme_use("default")
packet_table.tag_configure("tcp", background="#D0E8FF")   # Light blue
packet_table.tag_configure("udp", background="#DFFFD0")   # Light green
packet_table.tag_configure("other", background="#EEEEEE") # Light gray

root.mainloop()
