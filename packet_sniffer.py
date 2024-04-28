import struct
import time
from scapy.all import sniff


def capture_packets(packet_count, filter_criteria=None, search_keyword=None):
    try:
        with open("captured_packets.pcap", "wb") as pcap_file:
            # Write pcap file header
            pcap_file.write(struct.pack("@ IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

            # Sniff packets with optional filtering
            if filter_criteria:
                packets = sniff(count=packet_count, filter=filter_criteria)
            else:
                packets = sniff(count=packet_count)

            # Filter packets based on search keyword
            if search_keyword:
                packets = [packet for packet in packets if search_keyword in str(packet)]

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

# Example usage:
# Capture 25 packets without filtering or searching
capture_packets(25)


