from scapy.all import *
from collections import defaultdict

def analyze_pcap(file_name):
    packets = rdpcap(file_name)

    dns_ids = defaultdict(lambda: {"request": None, "response": None})

    for packet in packets:
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]

            if dns_layer.qr == 0:  # DNS запрос
                dns_ids[dns_layer.id]["request"] = packet.time
            elif dns_layer.qr == 1:  # DNS ответ
                dns_ids[dns_layer.id]["response"] = packet.time

    max_latency = 0
    max_latency_id = None

    for dns_id, times in dns_ids.items():
        if times["request"] is not None and times["response"] is not None:
            latency = times["response"] - times["request"]
            if latency > max_latency:
                max_latency = latency
                max_latency_id = dns_id

    print(f"Max latency is {max_latency} for DNS ID {max_latency_id}")

if __name__ == "__main__":
    analyze_pcap("dns66_1.pcap")
