from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict
import time
import platform
import argparse
import sys

conf.use_pcap = True  # force libpcap on Windows for stability

packet_counts = defaultdict(int)
protocol_counts = defaultdict(int)
ip_traffic = defaultdict(int)
tcp_flags = defaultdict(int)
start_time = time.time()

def packet_callback(packet):
    global packet_counts, protocol_counts, ip_traffic, tcp_flags

    try:
        packet_counts['total'] += 1

        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto

            protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
            protocol_counts[protocol] += 1
            ip_traffic[(src_ip, dst_ip)] += 1

            info = f"[{time.strftime('%H:%M:%S')}] {src_ip} -> {dst_ip} | {protocol}"

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = tcp.flags
                info += f" {sport}->{dport} [Flags: {flags}]"

                if flags & 0x01: tcp_flags['FIN'] += 1
                if flags & 0x02: tcp_flags['SYN'] += 1
                if flags & 0x04: tcp_flags['RST'] += 1
                if flags & 0x08: tcp_flags['PSH'] += 1
                if flags & 0x10: tcp_flags['ACK'] += 1
                if flags & 0x20: tcp_flags['URG'] += 1

                # HTTP/HTTPS detection
                if dport == 80 or sport == 80:
                    info += " | HTTP"
                elif dport == 443 or sport == 443:
                    info += " | HTTPS"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info += f" {udp.sport}->{udp.dport}"

            # Check payload
            if Raw in packet:
                raw_payload = packet[Raw].load
                try:
                    decoded = raw_payload.decode(errors="ignore")
                except:
                    decoded = str(raw_payload)
                info += f"\n  Payload: {decoded[:100]}..."  # print max 100 chars

            print(info)

    except Exception as e:
        print(f"Error processing packet: {e}")

def get_windows_interface():
    ifaces = get_if_list()
    for name in ["Wi-Fi", "Ethernet", "Local Area Connection"]:
        for iface in ifaces:
            if name in iface:
                return iface
    return ifaces[0] if ifaces else None

def display_statistics():
    duration = time.time() - start_time
    total = packet_counts['total']
    print("\n--- Capture Statistics ---")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Total packets: {total}")
    print("\nProtocol distribution:")
    for proto, cnt in protocol_counts.items():
        print(f"  {proto}: {cnt} ({cnt/total:.0%})")
    print("\nTCP Flags:")
    for flag, cnt in tcp_flags.items():
        print(f"  {flag}: {cnt}")
    print("\nTop IP Conversations:")
    for (src, dst), cnt in sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {src} <-> {dst}: {cnt}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp port 80')")
    args = parser.parse_args()

    if not args.interface:
        if platform.system() == "Windows":
            args.interface = get_windows_interface()
        else:
            args.interface = get_if_list()[0]

    if not args.interface:
        print("No valid interface found.")
        sys.exit(1)

    print(f"Using interface: {args.interface}")
    print("\nStarting packet capture on Wi-Fi... Press Ctrl+C to stop.\n")

    try:
        sniff(iface=args.interface,
              prn=packet_callback,
              store=False,
              filter=args.filter)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        display_statistics()

if __name__ == "__main__":
    main()
