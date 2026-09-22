from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):

    if IP not in packet:
        return

    print("\n========== PACKET ==========")

    # IP information
    print("Source IP      :", packet[IP].src)
    print("Destination IP :", packet[IP].dst)

    # Protocol and port information
    if TCP in packet:
        print("Protocol       : TCP")
        print("Source Port    :", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)

    elif UDP in packet:
        print("Protocol       : UDP")
        print("Source Port    :", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    else:
        print("Protocol       : Other")

    # Packet size
    print("Packet Size    :", len(packet), "bytes")

    # Payload
    if Raw in packet:
        payload = bytes(packet[Raw].load)

        # Display only first 50 bytes
        print("Payload        :", payload[:50])
    else:
        print("Payload        : No readable payload")

    print("=" * 30)


print("=== NETWORK PACKET ANALYZER ===")
print("Capturing 20 packets...\n")

sniff(prn=analyze_packet, count=20)

print("\nCapture completed.")