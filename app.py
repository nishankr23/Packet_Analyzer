from flask import Flask, render_template, request, Response, send_from_directory, jsonify, redirect, url_for
from scapy.all import (
    sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, getmacbyip,
    IPv6, GRE
)

# Try to import additional layers / protocols.
try:
    from scapy.layers.mpls import MPLS
except ImportError:
    MPLS = None

try:
    from scapy.layers.l2tp import L2TP
except ImportError:
    L2TP = None

try:
    from scapy.layers.l2 import Dot1Q  # VLAN tagging
except ImportError:
    Dot1Q = None

try:
    from scapy.layers.ppp import PPP  # PPP protocol
except ImportError:
    PPP = None

try:
    from scapy.layers.ipsec import ESP, AH  # IPsec protocols
except ImportError:
    ESP = None
    AH = None

try:
    from scapy.contrib.ospf import OSPF_Hdr  # OSPF protocol
except ImportError:
    OSPF_Hdr = None

try:
    from scapy.contrib.bgp import BGPHeader  # BGP protocol
except ImportError:
    BGPHeader = None

try:
    from scapy.layers.sctp import SCTP  # SCTP protocol
except ImportError:
    SCTP = None

try:
    from scapy.layers.dccp import DCCP  # DCCP protocol
except ImportError:
    DCCP = None

try:
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded
except ImportError:
    ICMPv6EchoRequest = None
    ICMPv6DestUnreach = None
    ICMPv6PacketTooBig = None
    ICMPv6TimeExceeded = None

import threading
import time
import json
import os
import random  # For ARP filtering
from fpdf import FPDF

app = Flask(__name__)

UPLOAD_FOLDER = './captures'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Global Variables
captured_packets = []         # For table view
raw_packets = []              # For detailed packet objects
seen_packet_hashes = set()    # To filter duplicates
packet_counter = 1            # Sequential numbering
capture_flag = False          # Capture active flag
stop_flag = False             # Flag for stopping capture
packet_lock = threading.Lock()
MAX_PACKETS = 10000           # Rolling buffer limit

# -------------------------
# Packet Processing Functions
# -------------------------
def process_packet(packet):
    global packet_counter, seen_packet_hashes
    try:
        # For ARP packets, process only 10% of them.
        if ARP in packet:
            if random.random() > 0.1:  # 90% chance to skip.
                return

        # Create a unique hash from the packet's time and summary.
        packet_hash = hash((packet.time, packet.summary()))
        with packet_lock:
            if packet_hash in seen_packet_hashes:
                return  # Skip duplicate
            seen_packet_hashes.add(packet_hash)
            raw_packets.append(packet)
            details = extract_packet_details(packet)
            if details:
                captured_packets.append(details)
                packet_counter += 1
            if len(captured_packets) > MAX_PACKETS:
                captured_packets.pop(0)
            if len(raw_packets) > MAX_PACKETS:
                raw_packets.pop(0)
    except Exception as e:
        print(f"Error processing packet: {e}")

def extract_packet_details(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
    packet_length = len(packet)
    
    # Default values
    src_ip, dst_ip = "N/A", "N/A"
    src_mac, dst_mac = "N/A", "N/A"
    protocol, info = "Unknown", ""
    layers = []
    src_port, dst_port = "-", "-"

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        layers.append("Layer 2")
        
        if ARP in packet:
            protocol = "ARP"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            info = f"ARP: Src IP {src_ip}, Dst IP {dst_ip}"
            layers.append("Layer 2")
        elif Dot1Q is not None and Dot1Q in packet:
            protocol = "VLAN"
            info = f"VLAN Tag: {packet[Dot1Q].vlan}"
            layers.append("Layer 2 (VLAN)")
        elif PPP is not None and PPP in packet:
            protocol = "PPP"
            info = "PPP packet"
            layers.append("Layer 2 (PPP)")
        elif IP in packet:
            ip = packet[IP]
            src_ip, dst_ip = ip.src, ip.dst
            layers.append("Layer 3 (IPv4)")
            if TCP in packet:
                protocol, info = detect_tcp_protocol(packet)
                layers.append("Layer 4 (TCP)")
            elif UDP in packet:
                protocol, info = detect_udp_protocol(packet)
                layers.append("Layer 4 (UDP)")
            elif ICMP in packet:
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
                layers.append("Layer 4 (ICMP)")
            else:
                protocol = "IPv4"
                info = f"Protocol Number: {ip.proto}"
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            src_ip, dst_ip = ipv6.src, ipv6.dst
            layers.append("Layer 3 (IPv6)")
            if TCP in packet:
                protocol, info = detect_tcp_protocol(packet)
                layers.append("Layer 4 (TCP)")
            elif UDP in packet:
                protocol, info = detect_udp_protocol(packet)
                layers.append("Layer 4 (UDP)")
            elif any(proto in packet for proto in [ICMPv6EchoRequest, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded]):
                protocol = "ICMPv6"
                try:
                    icmpv6 = packet[ICMPv6EchoRequest]
                    info = f"Type: {icmpv6.type}, Code: {icmpv6.code}"
                except Exception:
                    info = "ICMPv6 packet"
                layers.append("Layer 4 (ICMPv6)")
            else:
                protocol = "IPv6"
                info = f"Next Header: {ipv6.nh}"
        elif GRE in packet:
            protocol = "GRE"
            info = "GRE packet"
            layers.append("Layer 3/4 (GRE)")
        elif MPLS is not None and MPLS in packet:
            protocol = "MPLS"
            info = "MPLS packet"
            layers.append("Layer 2 (MPLS)")
        elif L2TP is not None and L2TP in packet:
            protocol = "L2TP"
            info = "L2TP packet"
            layers.append("Layer 2/3 (L2TP)")
        elif ESP is not None and ESP in packet:
            protocol = "IPsec (ESP)"
            info = "IPsec ESP packet"
            layers.append("Security")
        elif AH is not None and AH in packet:
            protocol = "IPsec (AH)"
            info = "IPsec AH packet"
            layers.append("Security")
        elif OSPF_Hdr is not None and OSPF_Hdr in packet:
            protocol = "OSPF"
            info = "OSPF packet"
            layers.append("Routing")
        elif BGPHeader is not None and BGPHeader in packet:
            protocol = "BGP"
            info = "BGP packet"
            layers.append("Routing")
        elif SCTP is not None and SCTP in packet:
            protocol = "SCTP"
            sctp = packet[SCTP]
            info = f"SCTP packet, Src Port: {sctp.sport}, Dst Port: {sctp.dport}"
            layers.append("Layer 4 (SCTP)")
        elif DCCP is not None and DCCP in packet:
            protocol = "DCCP"
            dccp = packet[DCCP]
            info = f"DCCP packet, Src Port: {dccp.sport}, Dst Port: {dccp.dport}"
            layers.append("Layer 4 (DCCP)")
        elif Raw in packet:
            protocol = "Raw"
            raw_data = bytes(packet[Raw])
            info = f"Data: {raw_data[:16]}"
            layers.append("Layer 4 (Raw)")
        else:
            src_ip = resolve_ip_from_mac(src_mac)
            dst_ip = resolve_ip_from_mac(dst_mac)
            protocol = "Layer 2 Protocol"
            info = f"Src MAC={src_mac}, Dst MAC={dst_mac}"
            layers.append("Layer 2")
    else:
        protocol = "Unknown"
        info = "No Ethernet Frame"
        layers.append("Layer 1")
    
    if protocol == "Unknown" and src_mac != "N/A":
        protocol = "Unknown Layer 2 Protocol"
        info = f"Src MAC={src_mac}, Dst MAC={dst_mac}"
        layers.append("Layer 2")
    
    if protocol == "Unknown":
        protocol = "Unresolved Protocol"
        info = f"Src IP: {src_ip}, Dst IP: {dst_ip}"
    
    if TCP in packet:
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
    elif UDP in packet:
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport

    return [packet_counter, timestamp, packet_length, src_ip, src_mac, src_port,
            dst_ip, dst_mac, dst_port, protocol, info, ", ".join(layers)]

def resolve_ip_from_mac(mac):
    ip = getmacbyip(mac)
    return ip if ip else "Unknown"

def detect_tcp_protocol(packet):
    tcp = packet[TCP]
    info = f"Src Port: {tcp.sport}, Dst Port: {tcp.dport}"
    # Existing protocols
    if tcp.dport == 443 or tcp.sport == 443:
        if Raw in packet:
            raw_data = packet[Raw].load
            if raw_data.startswith(b'\x16') and raw_data[1:3] == b'\x03\x03':
                return "TLS v1.2", f"TLS handshake, {info}"
        return "HTTPS", f"Encrypted HTTPS traffic, {info}"
    elif tcp.dport == 80 or tcp.sport == 80:
        return "HTTP", f"HTTP traffic, {info}"
    elif tcp.dport == 22 or tcp.sport == 22:
        return "SSH", f"SSH traffic, {info}"
    elif tcp.dport == 21 or tcp.sport == 21:
        return "FTP", f"FTP traffic, {info}"
    elif tcp.dport == 25 or tcp.sport == 25:
        return "SMTP", f"SMTP traffic, {info}"
    elif tcp.dport == 23 or tcp.sport == 23:
        return "Telnet", f"Telnet traffic, {info}"
    elif tcp.dport == 110 or tcp.sport == 110:
        return "POP3", f"POP3 traffic, {info}"
    elif tcp.dport == 995 or tcp.sport == 995:
        return "POP3S", f"POP3S traffic, {info}"
    elif tcp.dport == 143 or tcp.sport == 143:
        return "IMAP", f"IMAP traffic, {info}"
    elif tcp.dport == 993 or tcp.sport == 993:
        return "IMAPS", f"IMAPS traffic, {info}"
    elif tcp.dport == 389 or tcp.sport == 389:
        return "LDAP", f"LDAP traffic, {info}"
    elif tcp.dport == 636 or tcp.sport == 636:
        return "LDAPS", f"LDAPS traffic, {info}"
    elif tcp.dport == 1723 or tcp.sport == 1723:
        return "PPTP", f"PPTP traffic, {info}"
    elif tcp.dport == 3389 or tcp.sport == 3389:
        return "RDP", f"RDP traffic, {info}"
    elif tcp.dport == 5900 or tcp.sport == 5900:
        return "VNC", f"VNC traffic, {info}"
    elif tcp.dport == 1935 or tcp.sport == 1935:
        return "RTMP", f"RTMP traffic, {info}"
    elif tcp.dport == 5222 or tcp.sport == 5222:
        return "XMPP", f"XMPP traffic, {info}"
    elif tcp.dport == 194 or tcp.sport == 194:
        return "IRC", f"IRC traffic, {info}"
    elif tcp.dport == 119 or tcp.sport == 119:
        return "NNTP", f"NNTP traffic, {info}"
    # Additional protocols
    elif tcp.dport == 1883 or tcp.sport == 1883:
        return "MQTT", f"MQTT traffic, {info}"
    elif tcp.dport == 445 or tcp.sport == 445:
        return "SMB", f"SMB traffic, {info}"
    elif tcp.dport == 139 or tcp.sport == 139:
        return "NetBIOS", f"NetBIOS traffic, {info}"
    elif tcp.dport == 1433 or tcp.sport == 1433:
        return "SQL Server", f"SQL Server traffic, {info}"
    elif tcp.dport == 3306 or tcp.sport == 3306:
        return "MySQL", f"MySQL traffic, {info}"
    elif tcp.dport == 5432 or tcp.sport == 5432:
        return "PostgreSQL", f"PostgreSQL traffic, {info}"
    elif tcp.dport == 1521 or tcp.sport == 1521:
        return "Oracle DB", f"Oracle DB traffic, {info}"
    elif tcp.dport == 6379 or tcp.sport == 6379:
        return "Redis", f"Redis traffic, {info}"
    elif tcp.dport == 27017 or tcp.sport == 27017:
        return "MongoDB", f"MongoDB traffic, {info}"
    elif tcp.dport == 9200 or tcp.sport == 9200:
        return "Elasticsearch", f"Elasticsearch traffic, {info}"
    elif tcp.dport == 11211 or tcp.sport == 11211:
        return "Memcached", f"Memcached traffic, {info}"
    elif tcp.dport == 2049 or tcp.sport == 2049:
        return "NFS", f"NFS traffic, {info}"
    elif tcp.dport == 88 or tcp.sport == 88:
        return "Kerberos", f"Kerberos traffic, {info}"
    elif tcp.dport == 5061 or tcp.sport == 5061:
        return "SIPS", f"SIPS traffic, {info}"
    else:
        return "TCP", info

def detect_udp_protocol(packet):
    udp = packet[UDP]
    info = f"Src Port: {udp.sport}, Dst Port: {udp.dport}"
    # Existing protocols
    if udp.dport == 53 or udp.sport == 53:
        return "DNS", f"DNS traffic, {info}"
    elif udp.dport in (67, 68) or udp.sport in (67, 68):
        return "DHCP", f"DHCP traffic, {info}"
    elif udp.dport == 5353 or udp.sport == 5353:
        return "mDNS", f"mDNS traffic, {info}"
    elif udp.dport == 5355 or udp.sport == 5355:
        return "LLMNR", f"LLMNR traffic, {info}"
    elif udp.dport == 137 or udp.sport == 137:
        return "NBNS", f"NBNS traffic, {info}"
    elif udp.dport == 161 or udp.sport == 161:
        return "SNMP", f"SNMP traffic, {info}"
    elif udp.dport == 123 or udp.sport == 123:
        return "NTP", f"NTP traffic, {info}"
    elif udp.dport == 5060 or udp.sport == 5060:
        return "SIP", f"SIP traffic, {info}"
    elif udp.dport == 5004 or udp.sport == 5004:
        return "RTP", f"RTP traffic, {info}"
    elif udp.dport == 5005 or udp.sport == 5005:
        return "RTCP", f"RTCP traffic, {info}"
    elif udp.dport == 5683 or udp.sport == 5683:
        return "CoAP", f"CoAP traffic, {info}"
    elif udp.dport == 6343 or udp.sport == 6343:
        return "sFlow", f"sFlow traffic, {info}"
    elif udp.dport == 2055 or udp.sport == 2055:
        return "NetFlow", f"NetFlow traffic, {info}"
    elif (3386 <= udp.dport <= 3389) or (3386 <= udp.sport <= 3389):
        return "GTP", f"GTP traffic, {info}"
    elif udp.dport == 1812 or udp.sport == 1812:
        return "RADIUS", f"RADIUS traffic, {info}"
    # Additional protocols
    elif udp.dport == 69 or udp.sport == 69:
        return "TFTP", f"TFTP traffic, {info}"
    elif udp.dport == 514 or udp.sport == 514:
        return "Syslog", f"Syslog traffic, {info}"
    elif udp.dport == 443 or udp.sport == 443:
        if Raw in packet:
            raw_data = packet[Raw].load
            if raw_data.startswith(b'\x00\x00'):
                return "QUIC", f"QUIC traffic, {info}"
        return "QUIC", f"QUIC traffic, {info}"
    elif udp.dport == 2049 or udp.sport == 2049:
        return "NFS", f"NFS traffic, {info}"
    elif udp.dport == 88 or udp.sport == 88:
        return "Kerberos", f"Kerberos traffic, {info}"
    else:
        return "UDP", info

# -------------------------
# Packet Capture Functions
# -------------------------
def capture_packets(packet_count=None):
    global capture_flag, stop_flag
    capture_flag = True
    stop_flag = False

    def stop_sniffing(packet):
        if packet_count is not None and len(captured_packets) >= packet_count:
            stop_capture()
        return stop_flag

    sniff(prn=process_packet, stop_filter=stop_sniffing, store=False, promisc=True)
    capture_flag = False

def stop_capture():
    global stop_flag
    stop_flag = True

# -------------------------
# Save Captures
# -------------------------
def save_capture(file_format):
    filename = f'captured_packets_{int(time.time())}'
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    if file_format == "json":
        filepath += ".json"
        with open(filepath, 'w') as f:
            json.dump(captured_packets, f, indent=4)
    elif file_format == "pcap":
        filepath += ".pcap"
        wrpcap(filepath, raw_packets)
    elif file_format == "pdf":
        filepath += ".pdf"
        save_as_pdf(filepath)
    
    return os.path.basename(filepath)

def save_as_pdf(filepath):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Captured Packets:", ln=True, align='C')
    pdf.ln(10)
    for packet in captured_packets:
        packet_info = (f"Packet #{packet[0]}: Timestamp={packet[1]}, Length={packet[2]} bytes, "
                       f"Src IP={packet[3]}, Src MAC={packet[4]}, Src Port={packet[5]}, "
                       f"Dst IP={packet[6]}, Dst MAC={packet[7]}, Dst Port={packet[8]}, "
                       f"Protocol={packet[9]}, Info={packet[10]}, Layers={packet[11]}")
        pdf.multi_cell(0, 10, packet_info)
        pdf.ln(2)
    pdf.output(filepath)

# -------------------------
# Flask Routes
# -------------------------
@app.route('/packet_detail/<int:packet_id>')
def packet_detail(packet_id):
    index = packet_id - 1
    if 0 <= index < len(raw_packets):
        pkt = raw_packets[index]
        detailed_info = pkt.show(dump=True)
        return jsonify({"detailed_info": detailed_info})
    else:
        return jsonify({"error": "Invalid packet id"}), 404

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route("/stream")
def stream():
    def generate():
        last_sent_index = 0
        while capture_flag:
            with packet_lock:
                if len(captured_packets) > last_sent_index:
                    for packet in captured_packets[last_sent_index:]:
                        yield f"data: {json.dumps(packet)}\n\n"
                    last_sent_index = len(captured_packets)
            time.sleep(0.1)
    return Response(generate(), content_type="text/event-stream")

@app.route('/refresh', methods=['POST'])
def refresh():
    global captured_packets, seen_packet_hashes, packet_counter, raw_packets
    with packet_lock:
        captured_packets.clear()
        raw_packets.clear()
        seen_packet_hashes.clear()
        packet_counter = 1
    return jsonify({"status": "ok"})

@app.route("/start_capture", methods=["POST"])
def start_capture_route():
    packet_count = request.args.get("count")
    if packet_count and packet_count.isdigit():
        packet_count = int(packet_count)
    else:
        packet_count = None
    threading.Thread(target=capture_packets, args=(packet_count,), daemon=True).start()
    return jsonify({"status": "capture started"})

@app.route("/stop_capture", methods=["POST"])
def stop_capture_route():
    stop_capture()
    return jsonify({"status": "capture stopped"})

@app.route("/save_capture_pdf", methods=["POST"])
def save_capture_pdf():
    filename = save_capture("pdf")
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route("/save_capture/<file_format>", methods=["POST"])
def save_capture_file(file_format):
    if file_format not in ["json", "pcap"]:
        return jsonify({"error": "Invalid file format"}), 400
    filename = save_capture(file_format)
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

# -------------------------
# Statistics Route
# -------------------------
@app.route("/stats", methods=["GET"])
def stats():
    protocol_counts = {}
    total_packets = len(captured_packets)
    total_length = 0

    for packet in captured_packets:
        protocol = packet[9]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        total_length += packet[2]

    average_length = total_length / total_packets if total_packets > 0 else 0

    return jsonify({
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "average_length": average_length
    })

@app.route("/", methods=["GET", "POST"])
def index():
    # Optionally, you can pass filename to the template if capture was saved
    filename = request.args.get("filename", None)
    return render_template("index.html", packets=captured_packets, capturing=capture_flag, filename=filename)

if __name__ == "__main__":
    app.run(debug=True)
