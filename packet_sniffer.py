import struct
import time
import socket
from scapy.all import sniff

def capture_packets(packet_count):
    try:
        with open("captured_packets.pcap", "wb") as pcap_file:
            # Write pcap file header
            pcap_file.write(struct.pack("@ IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

            # Sniff packets
            packets = sniff(count=packet_count, iface="Wi-Fi")  # Use "Wi-Fi" as the network interface

            # Write each packet to the pcap file
            for packet in packets:
                timestamp = int(time.time())
                data = bytes(packet)
                packet_length = len(data)
                pcap_file.write(struct.pack("@ IIII", timestamp, 0, packet_length, packet_length))
                pcap_file.write(data)

            print(f"{packet_count} packets captured and saved to captured_packets.pcap")
    except Exception as e:
        print(f"An error occurred: {e}")

capture_packets(5)
