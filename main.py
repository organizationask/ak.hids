from scapy.all import sniff, IP, TCP, UDP
from flask import Flask, render_template, jsonify, request
import threading
import os
import logging
from core.file_monitor import monitor_files
from core.user_monitor import monitor_users
from core.rule_engine import apply_rules
from core.malware_detection import scan_for_malware
import socket

app = Flask(__name__)

# Global variables
network_traffic = ["Packet 1", "Packet 2", "Packet 3"]  # Store captured network traffic
detected_attacks = ["Attack 1", "Attack 2"]  # Store detected attacks
detected_intrusions = []  # Store detected intrusions

# Define a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(name)s:%(message)s')
file_handler = logging.FileHandler('logs/app_logs.txt')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

@app.route("/")
def index():
    """Render the dashboard."""
    return render_template("index.html")

@app.route("/logs")
def get_logs():
    """Return the latest logs."""
    log_file = "logs/intrusion_logs.txt"
    try:
        with open(log_file, "r") as log:
            logs = log.readlines()
        return jsonify({"logs": logs})
    except FileNotFoundError:
        return jsonify({"logs": []})

@app.route("/alerts")
def get_alerts():
    """Return the latest alerts."""
    alert_file = "logs/alerts.txt"
    try:
        with open(alert_file, "r") as alerts:
            alert_logs = alerts.readlines()
            # Filter out any port-related alerts (if any exist)
            filtered_alerts = [alert for alert in alert_logs if "port" not in alert.lower()]
        return jsonify({"alerts": filtered_alerts})
    except FileNotFoundError:
        logger.error("Alert file not found")
        return jsonify({"alerts": []})

@app.route("/network_traffic")
def get_network_traffic():
    """Return the captured network traffic."""
    return jsonify({"traffic": network_traffic})

@app.route("/detected_attacks")
def get_detected_attacks():
    """Return the detected network attacks."""
    return jsonify({"attacks": detected_attacks})

@app.route("/set_target_ip", methods=["POST"])
def set_target_ip():
    """Set the target IP address for monitoring."""
    global target_ip
    target_ip = request.json.get("target_ip")
    if target_ip:
        logger.info(f"Target IP set to {target_ip}")
        return jsonify({"message": f"Target IP set to {target_ip}"}), 200
    logger.error("Invalid IP address")
    return jsonify({"error": "Invalid IP address"}), 400

@app.route("/host_logs")
def get_host_logs():
    """Return all host logs."""
    log_file = "logs/intrusion_logs.txt"
    try:
        with open(log_file, "r") as log:
            logs = log.readlines()
        return jsonify({"logs": logs})
    except FileNotFoundError:
        logger.error("Log file not found")
        return jsonify({"logs": []})

@app.route("/host_alerts")
def get_host_alerts():
    """Return all host alerts."""
    alert_file = "logs/alerts.txt"
    try:
        with open(alert_file, "r") as alerts:
            alert_logs = alerts.readlines()
        return jsonify({"alerts": alert_logs})
    except FileNotFoundError:
        logger.error("Alert file not found")
        return jsonify({"alerts": []})

@app.route("/intrusions")
def get_intrusions():
    """Return the detected intrusions."""
    return jsonify({"intrusions": detected_intrusions})

@app.route("/host_ip")
def get_host_ip():
    """Return the host IP address."""
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        return jsonify({"host_ip": host_ip})
    except Exception as e:
        logger.error(f"Error retrieving host IP: {e}")
        return jsonify({"host_ip": "Unavailable"})

def detect_attack(packet):
    """Detect potential network attacks."""
    global detected_attacks
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        # Example: Detect SYN flood attack (many SYN packets to the target IP)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            attack_info = f"SYN flood detected from {packet[IP].src} to {packet[IP].dst}"
            detected_attacks.append(attack_info)
            logger.warning(attack_info)
            print(attack_info)  # Display in terminal
        # Example: Detect suspicious UDP traffic
        elif packet.haslayer(UDP):
            attack_info = f"Suspicious UDP traffic from {packet[IP].src} to {packet[IP].dst}"
            detected_attacks.append(attack_info)
            logger.warning(attack_info)
            print(attack_info)  # Display in terminal

        # Limit the stored attacks to 100 entries
        if len(detected_attacks) > 100:
            detected_attacks.pop(0)

def capture_traffic(packet):
    """Callback function to process captured packets."""
    global network_traffic
    if packet.haslayer(IP):
        packet_info = f"{packet.summary()}"
        network_traffic.append(packet_info)
        print(packet_info)  # Display in terminal
        detect_attack(packet)  # Check for attacks
        # Limit the stored traffic to 100 entries
        if len(network_traffic) > 100:
            network_traffic.pop(0)

def start_network_monitoring():
    """Start capturing network traffic."""
    sniff(prn=capture_traffic, store=False)

def start_user_monitoring():
    """Start user activity monitoring."""
    monitor_users("logs/intrusion_logs.txt", detected_intrusions)

def start_file_monitoring():
    """Start file activity monitoring."""
    directory = "C:\\Users\\Asus\\Documents\\GitHub\\ak.hids\\monitored_directory"
    if not os.path.exists(directory):
        os.makedirs(directory)  # Create the directory if it doesn't exist
    monitor_files(directory, "logs/intrusion_logs.txt", detected_intrusions)

def start_rule_engine():
    """Start the rule engine to analyze logs and generate alerts."""
    apply_rules("logs/intrusion_logs.txt", "logs/alerts.txt")

def start_malware_detection():
    """Start malware detection."""
    malware_signatures = {
        "e99a18c428cb38d5f260853678922e03",  # Example hash for malware
        "5d41402abc4b2a76b9719d911017c592"   # Add more malware hashes here
    }
    monitored_directory = "C:\\Users\\Asus\\Documents\\GitHub\\ak.hids\\monitored_directory"
    while True:
        scan_for_malware(monitored_directory, malware_signatures, detected_intrusions)

if __name__ == "__main__":
    # Display "AKASH" in a stylish format
    print("""
     █████╗ ██╗  ██╗ █████╗ ███████╗██╗  ██╗
    ██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██║  ██╔╝
    ███████║█████╔╝ ███████║███████╗███████╝ 
    ██╔══██║██╔═██╗ ██╔══██║╚════██║██╔═ ██╗ 
    ██║  ██║██║  ██╗██║  ██║███████║██║  ██╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)

    # Display "Created by Akash Patil" in the terminal
    print("===================================")
    print("       Created by Akash Patil      ")
    print("===================================")

    # Ensure the logs directory and files exist
    os.makedirs("logs", exist_ok=True)
    open("logs/intrusion_logs.txt", "a").close()
    open("logs/alerts.txt", "a").close()

    # Start monitoring in separate threads
    threading.Thread(target=start_user_monitoring, daemon=True).start()
    threading.Thread(target=start_file_monitoring, daemon=True).start()
    threading.Thread(target=start_rule_engine, daemon=True).start()
    threading.Thread(target=start_network_monitoring, daemon=True).start()
    threading.Thread(target=start_network_monitoring, daemon=True).start()
    threading.Thread(target=start_malware_detection, daemon=True).start()

    # Start the Flask app
    app.run(debug=True)