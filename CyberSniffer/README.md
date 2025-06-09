
## 📡 Cyber Sniffer – GUI-Based Network Packet Analyzer for Windows

Cyber Sniffer is a **Windows-compatible network sniffer** built with Python and Scapy. It allows users to:

* Select specific network protocols (TCP, UDP, ICMP, or All)
* View captured packets in real time through a GUI
* Save captured packets as a downloadable `.pcap` file (viewable in Wireshark)

---

## 🚀 Features

* ✅ **User-friendly GUI** with `tkinter`
* ✅ Choose protocol to sniff: **TCP**, **UDP**, **ICMP**, or **ALL**
* ✅ Real-time display of source/destination IPs and ports
* ✅ Save captured packets to a **`.pcap` file**
* ✅ 100% **Windows compatible** (requires Npcap)

---

## 🛠 Requirements

* Python 3.7+
* [Npcap](https://nmap.org/npcap/) installed with:

  * ✅ WinPcap API-compatible mode
  * ✅ Admin permissions (or allow normal users to sniff)

### 📦 Python Libraries

Install via pip:

```bash
pip install scapy
```

---

## 🔧 How to Run

1. **Download & Install Npcap**

   * From [https://nmap.org/npcap/](https://nmap.org/npcap/)
   * Enable "WinPcap compatibility mode"

2. **Run the script as administrator:**

   ```bash
   python cyber_sniffer.py
   ```

3. **In the app:**

   * Choose a protocol (TCP, UDP, ICMP, or ALL)
   * Click **"Start Sniffing"** to begin
   * View live packets in the scrollable window
   * Click **"Stop"** to end sniffing
   * Click **"Save to .pcap"** to download the captured traffic

---

## 📂 Output Example

The `.pcap` file can be opened in [Wireshark](https://www.wireshark.org/) for deep inspection.

---

## 🛡 Notes & Warnings

* Must be run with **Administrator privileges** on Windows.
* Only works with interfaces supported by **Npcap**.
* If nothing shows up, ensure:

  * Npcap is installed correctly
  * You're sniffing on an active network

---

## 📌 Future Enhancements 

* Real-time IP/port filtering
* Per-protocol traffic counters
* Export to CSV
* Visual dashboards (packet graphs, charts)
* Device selection (choose which NIC to sniff from)

---

## 🤖 Built With

* [Scapy](https://scapy.net/)
* [Tkinter](https://docs.python.org/3/library/tkinter.html)
* Python Standard Library

---

## 🧑‍💻 Author

Efua Bentum – Cybersecurity Intern at CodeAlpha
Passionate about network defense, ethical hacking, and making cybersecurity tools more accessible.

