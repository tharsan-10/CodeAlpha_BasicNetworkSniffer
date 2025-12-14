from scapy.all import sniff, IP, TCP, UDP

def packet_analyzer(packet):
    if packet.haslayer(IP):
        print("\n==========================")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol: Other")

print("Starting Network Sniffer...")
sniff(prn=packet_analyzer, count=10)
