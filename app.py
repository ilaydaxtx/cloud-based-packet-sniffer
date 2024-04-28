import threading
import os
from flask import Flask, render_template, redirect, url_for, request
from flask import Flask, render_template, request, make_response
from scapy.layers.inet import IP
from scapy.all import rdpcap
import packet_sniffer
from flask import Flask
from flask_mysqldb import MySQL





app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'ilaydanhn'
app.config['MYSQL_PASSWORD'] = 'howtorunlnx2002'
app.config['MYSQL_DB'] = 'packet_data'
mysql = MySQL(app)

protocol_names = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP',

}


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
        capture_thread = threading.Thread(target=capture_packets, args=(25,))  # Change packet_count as needed
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
        packet_info = [(pkt[IP].src, pkt[IP].dst, protocol_names.get(pkt[IP].proto, 'Unknown')) for pkt in packets if IP in pkt]
        return render_template('packets.html', packet_info=packet_info)
    except Exception as e:
        return f"An error occurred: {e}"

# Index route
@app.route('/')
def index():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM your_table')
    data = cur.fetchall()
    cur.close()
    return str(data)


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
                    # Check if the packet matches the IP filter
                    if filter_ip == pkt[IP].src or filter_ip == pkt[IP].dst:
                        protocol_name = protocol_names.get(pkt[IP].proto, "Unknown")
                        if filter_protocol:
                            # Check if the packet matches the protocol filter
                            if filter_protocol.lower() == protocol_name.lower():
                                filtered_packets.append(
                                    (pkt[IP].src, pkt[IP].dst, protocol_name)
                                )
                        else:
                            # If no protocol filter is applied, add the packet
                            filtered_packets.append(
                                (pkt[IP].src, pkt[IP].dst, protocol_name)
                            )
                else:
                    # If no IP filter is applied, add all packets
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

if __name__ == '__main__':
    app.run(debug=True)
