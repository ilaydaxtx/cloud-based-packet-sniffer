import threading
import os
from flask import Flask, render_template, redirect, url_for, request, jsonify
from scapy.layers.inet import IP
from scapy.all import rdpcap
import packet_sniffer
from flask_mysqldb import MySQL





app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'ilaydanhn'
app.config['MYSQL_PASSWORD'] = 'howtorunlnx2002'
app.config['MYSQL_DB'] = 'packet_data'
mysql = MySQL(app)

connection = pymysql.connect(host='localhost',
                             user='ilaydanhn',
                             password='',
                             db='app_test',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

protocol_names = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP',

}



def capture_packets(packet_count):
    try:
        from scapy.all import sniff, wrpcap
        packets = sniff(count=packet_count)
        wrpcap("captured_packets.pcap", packets)
        print(f"{packet_count} packets captured and saved to captured_packets.pcap")
    except Exception as e:
        print(f"An error occurred: {e}")


@app.route('/capture', methods=['GET', 'POST'])
def start_capture():
    if request.method == 'POST':
        capture_thread = threading.Thread(target=capture_packets, args=(25,))  # Change packet_count as needed
        capture_thread.start()
        
        return redirect(url_for('show_packets'))
    else:
        return "Method Not Allowed", 405
    
@app.route('/test_db_connection')
def test_db_connection():
    try:
        # Attempt to establish a connection to the database
        conn = mysql.connection
        # If connection is successful, return a success message
        return jsonify({'message': 'Database connection successful!'})
    except Exception as e:
        # If connection fails, return an error message
        return jsonify({'error': str(e)}), 500

@app.route('/create_table')
def create_table():
    try:
        cur = mysql.connection.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS packet_data (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        data VARCHAR(255)
                        )''')  # Define the structure of your table here
        mysql.connection.commit()
        cur.close()
        return "Table created successfully"  # Adjust the response message as needed
    except Exception as e:
        return f"An error occurred: {e}"



@app.route('/packets')
def show_packets():
    try:
        from scapy.all import rdpcap
        packets = rdpcap("captured_packets.pcap")
        packet_info = [(pkt[IP].src, pkt[IP].dst, protocol_names.get(pkt[IP].proto, 'Unknown')) 
                       for pkt in packets if IP in pkt]
        return render_template('packets.html', packet_info=packet_info)
    except Exception as e:
        return f"An error occurred: {e}"

# Index route
@app.route('/')
def index():
    try:
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM your_table')  # Replace 'your_table' with the actual table name
        data = cur.fetchall()
        cur.close()
        return str(data)  
    except Exception as e:
        return f"An error occurred: {e}"



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

if __name__ == '__main__':
    app.run(debug=True)
