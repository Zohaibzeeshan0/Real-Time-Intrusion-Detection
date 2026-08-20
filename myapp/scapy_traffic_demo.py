"""
Simplified demo version of the IDS traffic analyzer
Shows how the project analyzes network traffic in real-time
"""
from scapy.all import IP, TCP, UDP, sniff, get_if_list, ICMP
import numpy as np
import joblib
import os
import sys

print("""
╔════════════════════════════════════════════════════════════════╗
║         IDS Network Traffic Analyzer - Demo Mode              ║
║   Analyzes live network traffic for potential threats         ║
╚════════════════════════════════════════════════════════════════╝
""")

# Get available interfaces
interfaces = get_if_list()
print(f"\n✅ Available Network Interfaces: {interfaces}")

# Define features (same as the ML model expects)
FEATURES = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
    'Variance', 'Weight'
]

print(f"\n📊 Model expects {len(FEATURES)} features for classification")
print("🔍 Features include: Protocol, Flags, Packet Size, Duration, Rate, etc.\n")

# Load scalers/encoders if available
scaler = None
label_encoder = None

try:
    scaler = joblib.load("myapp/models/scaler.pkl")
    print("✅ Loaded feature scaler")
except Exception as e:
    print(f"⚠️  Could not load scaler: {e}")

try:
    label_encoder = joblib.load("myapp/models/label_encoder.pkl")
    print("✅ Loaded label encoder")
except Exception as e:
    print(f"⚠️  Could not load label encoder: {e}")

# Feature extraction function
def extract_features(packet):
    """Extract features from a captured packet"""
    features = {key: 0 for key in FEATURES}
    
    # Extract protocol type and basic info
    try:
        if IP in packet:
            ip_layer = packet[IP]
            features['Protocol Type'] = int(ip_layer.proto)
            features['Header_Length'] = int(ip_layer.ihl) * 4
            features['Tot size'] = ip_layer.len
        
        if TCP in packet:
            features['TCP'] = 1
            tcp_layer = packet[TCP]
            flags = int(tcp_layer.flags)
            features['fin_flag_number'] = flags & 0x01
            features['syn_flag_number'] = (flags & 0x02) >> 1
            features['rst_flag_number'] = (flags & 0x04) >> 2
            features['psh_flag_number'] = (flags & 0x08) >> 3
            features['ack_flag_number'] = (flags & 0x10) >> 4
            if features['ack_flag_number']:
                features['ack_count'] = 1
            if features['syn_flag_number']:
                features['syn_count'] = 1
            if features['fin_flag_number']:
                features['fin_count'] = 1
        
        if UDP in packet:
            features['UDP'] = 1
        
        if ICMP in packet:
            features['ICMP'] = 1
        
        # Return feature vector
        feature_vector = np.array([features[key] for key in FEATURES], dtype=np.float32)
        return feature_vector, features
    except Exception as e:
        print(f"❌ Error extracting features: {e}")
        return None, None


def analyze_packet(packet):
    """Analyze a captured packet and display results"""
    try:
        # Extract features
        feature_vector, features_dict = extract_features(packet)
        
        if feature_vector is None:
            return
        
        # Display packet summary
        print("\n" + "="*70)
        print(f"📡 Captured Packet #{packet.info if hasattr(packet, 'info') else 'Unknown'}")
        print("="*70)
        print(f"Summary: {packet.summary()}")
        
        # Extract key information
        if IP in packet:
            ip_layer = packet[IP]
            print(f"🔹 Source IP: {ip_layer.src}")
            print(f"🔹 Destination IP: {ip_layer.dst}")
            print(f"🔹 Protocol: {ip_layer.proto} (6=TCP, 17=UDP, 1=ICMP)")
            print(f"🔹 Packet Size: {ip_layer.len} bytes")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            flags_names = []
            if features_dict['syn_flag_number']: flags_names.append("SYN")
            if features_dict['ack_flag_number']: flags_names.append("ACK")
            if features_dict['fin_flag_number']: flags_names.append("FIN")
            if features_dict['rst_flag_number']: flags_names.append("RST")
            print(f"🔹 TCP Flags: {', '.join(flags_names) if flags_names else 'None'}")
            print(f"🔹 Source Port: {tcp_layer.sport}")
            print(f"🔹 Destination Port: {tcp_layer.dport}")
        
        if UDP in packet:
            udp_layer = packet[UDP]
            print(f"🔹 UDP Source Port: {udp_layer.sport}")
            print(f"🔹 UDP Destination Port: {udp_layer.dport}")
        
        # Show extracted features (sample)
        print("\n📊 Extracted Features (sample):")
        print(f"  • TCP: {features_dict.get('TCP', 0)}")
        print(f"  • UDP: {features_dict.get('UDP', 0)}")
        print(f"  • ICMP: {features_dict.get('ICMP', 0)}")
        print(f"  • Total: {len([k for k, v in features_dict.items() if v > 0])} active features")
        
        print("\n🤖 Model Analysis:")
        print("  ✓ Features extracted and ready for ML model")
        print("  ✓ Would be scaled using pre-trained scaler")
        print("  ✓ Ready for GRU neural network classification")
        print("  ⓘ Classification disabled (TensorFlow not available in demo mode)")
        
    except Exception as e:
        print(f"❌ Error analyzing packet: {e}")


def main():
    """Main function to start traffic capture"""
    print("\n" + "🔴 "*24)
    print("\n📍 How the Project Works:")
    print("  1. Captures live network packets from your network interface")
    print("  2. Extracts 43+ statistical features from each packet")
    print("  3. Scales features using pre-trained MinMaxScaler")
    print("  4. Runs through GRU (Gated Recurrent Unit) neural network")
    print("  5. Classifies traffic as NORMAL, ATTACK, or other threat types")
    print("  6. Stores results in database and displays on dashboard")
    print("\n🔴 "*24 + "\n")
    
    # Select interface
    print("📌 Network Interfaces Available:")
    for i, interface in enumerate(interfaces):
        print(f"  {i}: {interface}")
    
    print("\n⏳ Starting packet capture (first 5 packets for demo)...")
    print("💡 Press Ctrl+C to stop\n")
    
    try:
        # Capture packets (using filter for IP traffic only)
        sniff(filter="ip", prn=analyze_packet, count=5, store=False)
        print("\n✅ Capture complete! In production, this would:")
        print("  • Continue monitoring 24/7")
        print("  • Store all packets in database")
        print("  • Send alerts on suspicious activity")
        print("  • Update the dashboard in real-time")
    except KeyboardInterrupt:
        print("\n\n⚠️  Capture stopped by user")
    except PermissionError:
        print("\n❌ ERROR: This script requires administrator privileges!")
        print("   Please run as Administrator: python -m pip install --user pyinstaller")
    except Exception as e:
        print(f"\n❌ Error during capture: {e}")


if __name__ == "__main__":
    print("\n⚠️  REQUIREMENTS:")
    print("  • This demo requires Administrator privileges to capture packets")
    print("  • Run: python myapp/scapy_traffic_demo.py")
    print("  • Or access the web dashboard at: http://localhost:8000\n")
    
    # Uncomment to run: main()
    print("✨ To run the live traffic analysis, you need:")
    print("  1. Administrator privileges")
    print("  2. The command: python myapp/scapy_traffic_demo.py")
    print("\n📊 Alternatively, you can:")
    print("  • Use the Django web dashboard: python manage.py runserver")
    print("  • Check the database: python manage.py shell")
    print("  • Review the ML model: See myapp/models/GRU_IDS_model.keras")
