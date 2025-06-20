from scapy.all import sniff, IP, TCP, UDP
import datetime

log_file_path = "captured_packets_log.txt"

def log_packet(packet_info):
    with open(log_file_path, "a") as file:
        file.write(packet_info + "\n")

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        packet_info = (
            f"{timestamp} [{protocol}] {ip_layer.src} -> {ip_layer.dst}\n"
            f"Payload: {bytes(packet.payload)[:100]}\n"
            + "-"*60
        )

        print(packet_info)
        log_packet(packet_info)

print("🔍 Sniffing started... Press CTRL+C to stop.\n")
print(f"📝 Logs will be saved in: {log_file_path}\n")
sniff(filter="ip", prn=process_packet, store=0)
