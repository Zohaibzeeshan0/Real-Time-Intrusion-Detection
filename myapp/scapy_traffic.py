import warnings
import os

# Suppress warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Suppress scapy libpcap warning
os.environ['SCAPY_USE_PCAP'] = '0'

from scapy.all import IP, TCP, UDP, sniff, get_if_list
import numpy as np
import joblib
import tensorflow as tf
import scapy.all as scapy

# Load trained model & scalers
model = tf.keras.models.load_model("myapp/models/GRU_IDS_model.keras")
scaler = joblib.load("myapp/models/scaler.pkl")
label_encoder = joblib.load("myapp/models/label_encoder.pkl")

# Print available network interfaces
interfaces = get_if_list()
print("Available Network Interfaces:", interfaces)

# Define network interface (Replace with actual interface name)
WIFI_INTERFACE = r"\Device\NPF_{54EC6C67-06C7-4574-A83C-CBB8E167ED15}"

# Features required by the model
FEATURES = ['flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate', 
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 
            'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 
            'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 
            'Variance', 'Weight']

# Extract features from packet
def extract_features(packet):
    features = {key: 0 for key in FEATURES}  # Initialize feature dictionary

    # Extract protocol type
    if IP in packet:
        features['Protocol Type'] = int(packet[IP].proto)
    if TCP in packet:
        features['TCP'] = 1
    if UDP in packet:
        features['UDP'] = 1
    if packet.haslayer("HTTP"):
        features["HTTP"] = 1
    if packet.haslayer("HTTPS"):
        features["HTTPS"] = 1
    if packet.haslayer("DNS"):
        features["DNS"] = 1
    if packet.haslayer("ICMP"):
        features["ICMP"] = 1
    if packet.haslayer("ARP"):
        features["ARP"] = 1

    # Extract header length
    if IP in packet:
        features['Header_Length'] = int(packet[IP].ihl) * 4

    # Extract flag counts safely
    if TCP in packet:
        flags = int(packet[TCP].flags)  # Ensure flags are numeric
        features['fin_flag_number'] = flags & 0x01
        features['syn_flag_number'] = (flags & 0x02) >> 1
        features['rst_flag_number'] = (flags & 0x04) >> 2
        features['psh_flag_number'] = (flags & 0x08) >> 3
        features['ack_flag_number'] = (flags & 0x10) >> 4

    # Convert to NumPy array
    try:
        feature_values = np.array([[features[key] for key in FEATURES]], dtype=np.float32)  # Convert all to float
    except KeyError as e:
        print(f"Feature mismatch error: {e}")
        return None
    return feature_values

# Predict traffic type
def classify_packet(packet):
    try:
        features = extract_features(packet)
        if features is None:
            return "Feature Extraction Error"
        
        scaled_features = scaler.transform(features)  # Scale features
        reshaped_features = scaled_features.reshape(1, 1, -1)  # Reshape for GRU
        prediction = model.predict(reshaped_features)
        predicted_class = np.argmax(prediction)  # Get class index
        class_label = label_encoder.inverse_transform([predicted_class])[0]  # Decode label
        return class_label
    except Exception as e:
        print(f"Error in classification: {e}")
        return "Unknown"

# Process and classify packets in real-time
def process_packet(packet):
    classification = classify_packet(packet)
    print(f"[PACKET] Captured Packet: {packet.summary()}")
    print(f"[PREDICTION] Model Prediction: {classification}\n")

# Sniff live packets and classify them
def capture_live_traffic(packet_count=10):
    print(f"[CAPTURE] Capturing {packet_count} packets from {WIFI_INTERFACE}...")

    # Capture packets
    packets = sniff(iface=WIFI_INTERFACE, count=packet_count)

    # Extract features, classify and print results
    for pkt in packets:
        classification = classify_packet(pkt)
        print(f"[PACKET] Captured Packet: {pkt.summary()}")
        print(f"[PREDICTION] Model Prediction: {classification}\n")

# Start sniffing packets (Fixed: Only capture 10 packets at a time)
print(f"[LISTENING] Listening on {WIFI_INTERFACE}...")
sniff(iface=WIFI_INTERFACE, count=10, filter="ip", prn=process_packet, store=False)
