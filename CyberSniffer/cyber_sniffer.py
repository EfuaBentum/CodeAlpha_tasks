import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
import threading

captured_packets = []
sniffing = False
sniffer_thread = None

def packet_callback(packet):
    global captured_packets
    captured_packets.append(packet)

    if IP in packet:
        ip_info = f"{packet[IP].src} -> {packet[IP].dst}"
        if TCP in packet:
            proto = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            proto = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other IP Packet"
    else:
        ip_info = "Non-IP Packet"
        proto = "Unknown"

    output = f"{ip_info} | {proto}\n"
    output_box.insert(tk.END, output)
    output_box.yview(tk.END)

def start_sniffing():
    global sniffing, sniffer_thread, captured_packets
    captured_packets.clear()
    sniffing = True

    def run_sniffer():
        proto = proto_var.get()
        bpf_filter = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ALL": ""}.get(proto, "")
        sniff(prn=packet_callback, filter=bpf_filter, store=False, stop_filter=lambda x: not sniffing)

    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    status_label.config(text="Sniffing started...", foreground="green")

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing stopped.", foreground="red")

def save_packets():
    if not captured_packets:
        messagebox.showwarning("No Data", "No packets to save.")
        return

    filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if filepath:
        wrpcap(filepath, captured_packets)
        messagebox.showinfo("Saved", f"Packets saved to:\n{filepath}")

# GUI Setup
root = tk.Tk()
root.title("Cyber Sniffer")
root.geometry("700x500")
root.resizable(False, False)

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Select Protocol:").grid(row=0, column=0, sticky="w")
proto_var = tk.StringVar(value="ALL")
proto_menu = ttk.Combobox(frame, textvariable=proto_var, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly", width=10)
proto_menu.grid(row=0, column=1, padx=5, pady=5)

start_button = ttk.Button(frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=0, column=2, padx=5)

stop_button = ttk.Button(frame, text="Stop", command=stop_sniffing)
stop_button.grid(row=0, column=3, padx=5)

save_button = ttk.Button(frame, text="Save to .pcap", command=save_packets)
save_button.grid(row=0, column=4, padx=5)

status_label = ttk.Label(frame, text="Not sniffing.", foreground="gray")
status_label.grid(row=0, column=5, sticky="w", padx=5)

output_box = scrolledtext.ScrolledText(frame, height=25, width=85, wrap=tk.WORD)
output_box.grid(row=1, column=0, columnspan=6, pady=10)

root.mainloop()


