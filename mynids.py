from scapy.all import *
from collections import defaultdict, deque
import time
import threading

# Configuration
INTERFACE = "wlo1"  # Network interface to monitor
THRESHOLD = 100  # Threshold for packets from one IP (for port scans)
DNS_THRESHOLD = 50  # Threshold for repeated DNS queries from an IP
LOG_FILE = "nids_alerts.log"  # Log file for alerts
CONTENT_FILE = "content.txt"  # File to store HTTP content
THREATS_FILE = "detected_threats.txt"  # File to store detected threats

# DoS and DDoS detection settings
DOS_THRESHOLD = 200  # Threshold for DoS per IP within the time window
DDOS_THRESHOLD = 1000  # Threshold for total packets across multiple IPs
TIME_WINDOW = 10  # Time window in seconds for DoS/DDoS detection

# Data structures to keep track of packet counts
packet_count = defaultdict(int)
syn_count = defaultdict(int)
dns_count = defaultdict(int)
packet_counts = defaultdict(int)
timestamps = defaultdict(deque)  # Tracks packet arrival times per IP

# Protocol mapping
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def get_protocol_name(proto):
    """Return the protocol name for a given protocol number."""
    return PROTOCOL_NAMES.get(proto, f"Unknown Protocol ({proto})")

def detect_dns_query(pkt):
    """Monitor DNS requests and flag repeated or suspicious requests."""
    if UDP in pkt and pkt[UDP].dport == 53:
        src_ip = pkt[IP].src
        dns_count[src_ip] += 1
        dns_query = pkt[DNSQR].qname.decode('utf-8', errors='ignore') if DNSQR in pkt else "<unknown>"

        # Log DNS query details
        alert_message = f"[INFO] DNS Query from {src_ip} for {dns_query}"
        print(alert_message, flush=True)
        log_alert(alert_message)

        if dns_count[src_ip] > DNS_THRESHOLD:
            alert_message = f"[ALERT] High Volume of DNS Queries Detected from IP: {src_ip} (Total: {dns_count[src_ip]})"
            print(alert_message, flush=True)
            log_alert(alert_message)
            log_threat(alert_message)

def detect_http_packet(pkt):
    """Check if the packet contains HTTP data and write it to a file."""
    if TCP in pkt and (pkt[TCP].dport == 8080 or pkt[TCP].sport == 8080):
        try:
            http_payload = bytes(pkt[TCP].payload)
            if http_payload:
                with open(CONTENT_FILE, "a") as f:
                    f.write(http_payload.decode('utf-8', errors='ignore') + "\n")
                print(f"[INFO] HTTP Content Captured: {http_payload.decode('utf-8', errors='ignore')}", flush=True)
        except Exception as e:
            print(f"[ERROR] Failed to capture HTTP content: {e}", flush=True)

port_scan_tracker = defaultdict(set)

def detect_port_scan(pkt):
    """Detect port scans by tracking packets from a single IP and unique destination ports."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > THRESHOLD:
            alert_message = f"[ALERT] Possible Port Scan Detected from IP: {src_ip} (Ports: {len(port_scan_tracker[src_ip])})"
            print(alert_message, flush=True)
            log_alert(alert_message)  # Log to `nids_alerts.log`
            log_threat(alert_message)  # Log to `detected_threats.txt`
            
        detect_http_packet(pkt)

def detect_syn_flood(pkt):
    """Detect SYN flood attacks by monitoring TCP SYN packets."""
    if TCP in pkt and pkt[TCP].flags == "S":
        src_ip = pkt[IP].src
        syn_count[src_ip] += 1
        if syn_count[src_ip] > THRESHOLD:
            alert_message = f"[ALERT] Possible SYN Flood Detected from IP: {src_ip}"
            print(alert_message, flush=True)
            log_alert(alert_message)
            log_threat(alert_message)

def log_alert(message):
    """Log alerts to a file with a timestamp."""
    try:
        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            f.write(f"{timestamp} - {message}\n")
            print(f"[INFO] Alert logged: {message}")
    except Exception as e:
        print(f"[ERROR] Failed to log alert: {e}")

def log_threat(message):
    """Log detected threats to a specific file."""
    try:
        with open(THREATS_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            f.write(f"{timestamp} - {message}\n")
            print(f"[INFO] Threat logged: {message}")
    except Exception as e:
        print(f"[ERROR] Failed to log threat: {e}")

def detect_dos_ddos():
    """Periodically check for DoS and DDoS based on packet counts."""
    global packet_counts

    while True:
        time.sleep(TIME_WINDOW)
        
        total_packets = sum(packet_counts.values())
        
        if total_packets > DDOS_THRESHOLD:
            alert_message = "[ALERT] Potential DDoS attack detected from multiple IPs."
            print(alert_message, flush=True)
            log_alert(alert_message)
            log_threat(alert_message)
        
        for ip, count in packet_counts.items():
            if count > DOS_THRESHOLD:
                alert_message = f"[ALERT] Potential DoS attack detected from IP: {ip}"
                print(alert_message, flush=True)
                log_alert(alert_message)
                log_threat(alert_message)

        packet_counts.clear()

def packet_callback(pkt):
    """Callback function for packet sniffing with DoS/DDoS detection."""
    if IP in pkt:
        src_ip = pkt[IP].src
        packet_counts[src_ip] += 1
        timestamps[src_ip].append(time.time())

        detect_port_scan(pkt)
        detect_syn_flood(pkt)
        detect_dns_query(pkt)

def start_sniffing():
    """Start sniffing packets on the given interface."""
    print(f"[+] Starting packet capture on {INTERFACE}...", flush=True)
    sniff(iface=INTERFACE, prn=packet_callback, store=False)

if __name__ == "__main__":
    try:
        custom_alert_message = "[ALERT] Custom Test Alert: NIDS has started monitoring."
        log_alert(custom_alert_message)
        log_threat(custom_alert_message)

        threading.Thread(target=detect_dos_ddos, daemon=True).start()
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[+] Stopping NIDS. Exiting...", flush=True)
