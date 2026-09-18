from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


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

        print("=" * 60)
        print(f"Protocol       : {protocol}")
        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Source Port    : {source_port}")
        print(f"Destination Port: {destination_port}")

        if Raw in packet:
            payload = bytes(packet[Raw].load)

            try:
                payload_text = payload.decode("utf-8", errors="replace")
            except Exception:
                payload_text = str(payload)

            print(f"Payload        : {payload_text[:100]}")
        else:
            print("Payload        : No payload")


print("Network Sniffer başladı...")
print("Paketlər gözlənilir...\n")

sniff(prn=packet_callback, store=False)