from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS

# Dictionary of common ports and associated services
common_ports = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    53: "DNS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    1433: "SQL Server",
    27017: "MongoDB"
}

# Function to handle packets and identify service by port or protocol
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n[IP] Source: {ip_layer.src} --> Destination: {ip_layer.dst}")

    # Check if packet has TCP or UDP layer
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        if packet.haslayer(TCP):
            print('[PROTOTYPE] TCP')
        elif packet.haslayer(UDP):
            print('[PROTOTYPE] UDP')
        else:
            print('[PROTOTYPE] Unknown or Other Protocol')
        src_port = transport_layer.sport
        dst_port = transport_layer.dport
        print(f"[PORTS] Source Port: {src_port}, Destination Port: {dst_port}")

        # Determine service by port
        service = common_ports.get(dst_port) or common_ports.get(src_port)
        if service:
            print(f"[Service] Detected {service} on Port {dst_port if dst_port in common_ports else src_port}")

        # Additional handling for specific services
        if packet.haslayer(HTTPRequest):
            print(f"[HTTP] HTTP Request: {packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}")
        elif packet.haslayer(DNS):
            print("[DNS] DNS Query Detected")
        elif dst_port == 443 or src_port == 443:
            print("[HTTPS] Encrypted HTTPS Traffic Detected")
        elif dst_port == 22 or src_port == 22:
            print("[SSH] SSH Traffic Detected")

    print("=" * 80)

# Capture packets with IP, TCP, or UDP layers
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(prn=packet_handler, filter="ip", store=0)
