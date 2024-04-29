import os
import threading
from flask import Flask, render_template, redirect, url_for, request
from scapy.layers.inet import IP
from scapy.all import sniff, wrpcap, rdpcap

# Initialize Flask app
app = Flask(__name__)

# Protocol names dictionary
protocol_names = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP',
}


# Function to capture packets
def capture_packets(packet_count):
    try:
        packets = sniff(count=packet_count)
        wrpcap("captured_packets.pcap", packets)
        print(f"{packet_count} packets captured and saved to captured_packets.pcap")
    except Exception as e:
        print(f"An error occurred: {e}")


# Route to start capturing packets
@app.route('/capture', methods=['GET', 'POST'])
def start_capture():
    if request.method == 'POST':
        capture_thread = threading.Thread(target=capture_packets, args=(25,))
        capture_thread.start()
        return redirect(url_for('show_packets'))
    else:
        return "Method Not Allowed", 405


# Route to show captured packets
@app.route('/packets')
def show_packets():
    try:
        packets = rdpcap("captured_packets.pcap")
        packet_info = [(pkt[IP].src, pkt[IP].dst, protocol_names.get(pkt[IP].proto, 'Unknown'))
                       for pkt in packets if IP in pkt]
        return render_template('packets.html', packet_info=packet_info)
    except Exception as e:
        return f"An error occurred: {e}"


# Route to filter packets
@app.route("/filter", methods=["POST"])
def filter_packets():
    try:
        filter_ip = request.form.get("filter_ip")
        filter_protocol = request.form.get("filter_protocol")

        packets = rdpcap("captured_packets.pcap")
        filtered_packets = []

        for pkt in packets:
            if IP in pkt:
                if filter_ip:
                    if filter_ip == pkt[IP].src or filter_ip == pkt[IP].dst:
                        protocol_name = protocol_names.get(pkt[IP].proto, "Unknown")
                        if filter_protocol:
                            if filter_protocol.lower() == protocol_name.lower():
                                filtered_packets.append(
                                    (pkt[IP].src, pkt[IP].dst, protocol_name)
                                )
                        else:
                            filtered_packets.append(
                                (pkt[IP].src, pkt[IP].dst, protocol_name)
                            )
                else:
                    filtered_packets.append(
                        (
                            pkt[IP].src,
                            pkt[IP].dst,
                            protocol_names.get(pkt[IP].proto, "Unknown"),
                        )
                    )

        return render_template(
            "packets.html",
            packet_info=filtered_packets,
            filter_ip=filter_ip,
            filter_protocol=filter_protocol,
        )
    except Exception as e:
        return f"An error occurred: {e}"


# Root route
@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    # Use the PORT provided by Heroku if available
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
