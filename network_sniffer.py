from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        source_port = "-"
        destination_port = "-"

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            protocol = "Other"

        print(
            f"[{protocol}] "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port}"
        )


print("Network Sniffer başladı...")
print("Paketlər gözlənilir...\n")

sniff(prn=packet_callback, store=False)