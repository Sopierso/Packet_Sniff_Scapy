import sys
import os
import argparse
from datetime import datetime
from scapy.all import sniff, TCP, IP, ARP

def handle_tcp(packet, log_tcp):
    #Log TCP
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_tcp.write(f"[{timestamp}] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

def handle_arp(packet, log_arp):
    #Log ARP packet
    if packet.haslayer(ARP):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        op = "Request" if packet[ARP].op == 1 else "Reply"
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        dst_ip = packet[ARP].pdst
        dst_mac = packet[ARP].hwdst
        log_arp.write(f"[{timestamp}] ARP {op}: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})\n")

def main(interface, folder, verbose=False):
    #sniff packets and write logs.
    # Ensure folder exists
    os.makedirs(folder, exist_ok=True)
    tcp_log_path = os.path.join(folder, "tcp_log.txt")
    arp_log_path = os.path.join(folder, "arp_log.txt")

    try:
        with open(tcp_log_path, 'w') as log_tcp, open(arp_log_path, 'w') as log_arp:
            print(f"Sniffing on interface: {interface}")
            print(f"Logs will be saved to: {folder}")

            def handle_packet(packet):
                handle_tcp(packet, log_tcp)
                handle_arp(packet, log_arp)

            sniff(
                iface=interface,
                prn=handle_packet,
                store=False,
                verbose=verbose
            )

    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer for TCP and ARP packets.")
    parser.add_argument("interface", help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--folder", required=True, help="Folder name to save log files")

    args = parser.parse_args()
    main(args.interface, args.folder, args.verbose)
