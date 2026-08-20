"""
Traffic Generator for IDS Dashboard
This script generates and sends synthetic network traffic to the Django database
so you can see real-time predictions on the dashboard.
"""

import os
import sys
import warnings
import django
import random
import time
from datetime import datetime, timedelta

# Suppress warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Suppress scapy libpcap warning
os.environ['SCAPY_USE_PCAP'] = '0'

# Add the parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import IP, TCP, UDP, ICMP, send
except ImportError:
    print("Warning: Scapy not fully available on this system")
    IP = TCP = UDP = ICMP = send = None

import socket

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myIDS.settings')
django.setup()

from myapp.models import CapturedTraffic

# Common protocols
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']

# Traffic types and classifications
TRAFFIC_TYPES = {
    'Normal': ['HTTP', 'HTTPS', 'DNS', 'SSH'],
    'Anomaly': ['Port Scan', 'DoS Attack', 'Malware Activity', 'Suspicious Pattern'],
    'Attack': ['DDoS', 'SQL Injection', 'Buffer Overflow', 'Brute Force']
}

def generate_ip():
    """Generate a random IP address"""
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def classify_traffic():
    """Randomly classify traffic as Normal or Anomaly"""
    classification_pool = [
        'Normal', 'Normal', 'Normal', 'Normal', 'Normal',  # 50% Normal
        'Anomaly', 'Anomaly', 'Anomaly',  # 30% Anomaly
        'Attack', 'Attack'  # 20% Attack
    ]
    return random.choice(classification_pool)

def send_synthetic_traffic(packet_count=10, interval=2):
    """
    Send synthetic traffic packets and log them to the database
    
    Args:
        packet_count: Number of packets to generate
        interval: Delay between packets in seconds
    """
    print(f"🚀 Starting Traffic Generator - Sending {packet_count} packets...")
    print("=" * 70)
    
    for i in range(packet_count):
        try:
            src_ip = generate_ip()
            dest_ip = generate_ip()
            protocol = random.choice(PROTOCOLS)
            classification = classify_traffic()
            
            # Create traffic record in database
            traffic = CapturedTraffic.objects.create(
                src_ip=src_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                prediction=classification
            )
            
            # Display the packet info
            timestamp = traffic.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            status_icon = "✅" if classification == "Normal" else "🚨"
            
            print(f"{status_icon} Packet #{i+1}")
            print(f"   Time: {timestamp}")
            print(f"   Source: {src_ip} → Destination: {dest_ip}")
            print(f"   Protocol: {protocol}")
            print(f"   Prediction: {classification}")
            print("-" * 70)
            
            # Wait before sending next packet
            if i < packet_count - 1:
                time.sleep(interval)
                
        except Exception as e:
            print(f"❌ Error creating traffic record: {e}")
            continue
    
    print(f"\n✅ Traffic generation complete! {packet_count} packets sent.")
    print("📊 Check the dashboard at http://localhost:8000/dashboard/ to see the predictions")

def send_real_scapy_packets(packet_count=5):
    """
    Send real network packets using Scapy and log them
    Note: Requires admin/root privileges
    """
    print(f"🚀 Sending {packet_count} real network packets with Scapy...")
    print("=" * 70)
    
    try:
        for i in range(packet_count):
            src_ip = "192.168.1." + str(random.randint(1, 255))
            dest_ip = "8.8.8." + str(random.randint(1, 255))
            
            # Create a packet
            if random.choice([True, False]):
                packet = IP(dst=dest_ip, src=src_ip)/TCP(dport=random.choice([80, 443, 22, 21]))
                protocol = "TCP"
            else:
                packet = IP(dst=dest_ip, src=src_ip)/UDP(dport=53)
                protocol = "UDP"
            
            # Send the packet
            print(f"\n📡 Packet #{i+1}")
            print(f"   From: {src_ip} → To: {dest_ip}")
            print(f"   Protocol: {protocol}")
            print(f"   Packet: {packet.summary()}")
            
            # Log to database
            classification = classify_traffic()
            traffic = CapturedTraffic.objects.create(
                src_ip=src_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                prediction=classification
            )
            print(f"   Prediction: {classification}")
            
            # Send packet (commented out - uncomment if running as admin)
            # send(packet, verbose=False)
            
            time.sleep(1)
            
    except PermissionError:
        print("❌ Error: Root/Admin privileges required to send real packets")
        print("💡 Use the synthetic traffic mode instead: python traffic_generator.py")
    except Exception as e:
        print(f"❌ Error sending packets: {e}")

def continuous_monitoring(duration_minutes=5, interval=2):
    """
    Continuously generate traffic for a specified duration
    
    Args:
        duration_minutes: How long to run the generator (in minutes)
        interval: Delay between packets (in seconds)
    """
    print(f"🚀 Starting continuous traffic monitoring for {duration_minutes} minutes...")
    print("=" * 70)
    start_time = time.time()
    end_time = start_time + (duration_minutes * 60)
    packet_count = 0
    
    try:
        while time.time() < end_time:
            src_ip = generate_ip()
            dest_ip = generate_ip()
            protocol = random.choice(PROTOCOLS)
            classification = classify_traffic()
            
            traffic = CapturedTraffic.objects.create(
                src_ip=src_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                prediction=classification
            )
            
            packet_count += 1
            timestamp = traffic.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            status_icon = "✅" if classification == "Normal" else "🚨"
            remaining = (end_time - time.time()) / 60
            
            print(f"{status_icon} [{packet_count:04d}] {timestamp} | {src_ip:>15} → {dest_ip:>15} | {protocol:>6} | {classification:>15} | {remaining:.1f}m remaining")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Monitoring stopped. Generated {packet_count} traffic records.")
    except Exception as e:
        print(f"❌ Error during monitoring: {e}")
    
    print("📊 View results at http://localhost:8000/dashboard/")

if __name__ == "__main__":
    import sys
    
    print("\n" + "=" * 70)
    print("          IDS TRAFFIC GENERATOR - Dashboard Traffic Simulator")
    print("=" * 70 + "\n")
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        
        if mode == "real":
            # Send real Scapy packets
            packets = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            send_real_scapy_packets(packets)
        
        elif mode == "continuous":
            # Continuous monitoring
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            interval = int(sys.argv[3]) if len(sys.argv) > 3 else 2
            continuous_monitoring(duration, interval)
        
        else:
            # Default: send synthetic traffic
            packets = int(mode) if mode.isdigit() else 10
            send_synthetic_traffic(packets)
    else:
        # Default: send 10 synthetic packets
        send_synthetic_traffic(10)
    
    print("\n" + "=" * 70)
    print("✅ Traffic generation complete!")
    print("📊 Dashboard: http://localhost:8000/dashboard/")
    print("=" * 70 + "\n")
