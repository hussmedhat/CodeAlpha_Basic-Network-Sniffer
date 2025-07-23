# 📡 Basic Network Sniffer

This project is a Python-based **network packet sniffer and analyzer** that captures HTTP and HTTPS traffic on a selected network interface.  
It uses [Scapy](https://scapy.net/) to listen to packets, parse their structure, and display useful details about the data flow between hosts.

---

## ✨ Features

✅ Captures packets in real time from a specified interface.  
✅ Filters for HTTP (port 80) and HTTPS (port 443) traffic.  
✅ Displays:
- Source and destination IP addresses
- Source and destination ports
- Protocol (HTTP/HTTPS)
- TCP flags
- Raw payload (if available and not encrypted)

✅ Provides a summary of captured sessions and protocols.

---

## 📋 Example Output

```text
[14:07:00] 193.227.16.224 -> 192.168.1.11 | TCP 80->52217 [Flags: PA] | HTTP
  Payload: param0=general.General&param1=GetFromRegion&param2=Curr...
