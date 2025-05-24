TCP and ARP Network Packet Sniffer

Use this with Scapy to log ARP and TCP packets.

Arguments:

-v: Verbose outbput
-f file_name: Used to name the folder in which the files will appear in
interface: Indicates which interface will be "sniffed"

Example Usage
sudo python sniffer.py wlan0 -f log_file --v
