import threading
from flask import Flask, render_template, redirect, url_for, request
from scapy.layers.inet import IP
from scapy.all import rdpcap

app = Flask(__name__)

# Function to capture packets
def capture_packets(packet_count):
    try:
        from scapy.all import sniff, wrpcap
        # Sniff packets and write to a pcap file
        packets = sniff(count=packet_count)
        wrpcap("captured_packets.pcap", packets)
        print(f"{packet_count} packets captured and saved to captured_packets.pcap")
    except Exception as e:
        print(f"An error occurred: {e}")

# Route to trigger packet capture
@app.route('/capture', methods=['GET', 'POST'])
def start_capture():
    if request.method == 'POST':
        # Start packet capture in a new thread
        capture_thread = threading.Thread(target=capture_packets, args=(5,))  # Change packet_count as needed
        capture_thread.start()
        
        return redirect(url_for('show_packets'))
    else:
        return "Method Not Allowed", 405

# Route to display captured packets
@app.route('/packets')
def show_packets():
    try:
        from scapy.all import rdpcap
        # Read the captured pcap file
        packets = rdpcap("captured_packets.pcap")
        # Extract relevant information from packets (e.g., source and destination IP addresses)
        packet_info = [(pkt[IP].src, pkt[IP].dst) for pkt in packets if IP in pkt]
        return render_template('packets.html', packet_info=packet_info)
    except Exception as e:
        return f"An error occurred: {e}"

# Index route
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
