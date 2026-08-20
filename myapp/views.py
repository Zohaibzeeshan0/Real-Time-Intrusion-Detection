import threading
import time
import random
import warnings
import os

# Suppress sklearn version warnings and scapy libpcap warnings
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Suppress scapy libpcap warning
os.environ['SCAPY_USE_PCAP'] = '0'

import numpy as np
import pandas as pd
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from .models import CapturedTraffic
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import login, authenticate, logout
import re
from . import models
from django.core.mail import send_mail
from django.contrib.sessions.models import Session
from django.conf import settings

# Global variable to store active user emails for notifications
active_user_emails = set()

# Load trained model & scalers
import os
from django.conf import settings

# Get the base directory for the Django project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(BASE_DIR, "myapp", "models", "GRU_IDS_model.keras")
scaler_path = os.path.join(BASE_DIR, "myapp", "models", "scaler.pkl")
label_encoder_path = os.path.join(BASE_DIR, "myapp", "models", "label_encoder.pkl")

# Try to load TensorFlow model - if not available, set to None (optional for traffic generator)
try:
    import tensorflow as tf
    model = tf.keras.models.load_model(model_path)
except ImportError:
    # TensorFlow optional - not needed for basic traffic monitoring
    model = None
except Exception as e:
    model = None

try:
    scaler = joblib.load(scaler_path)
except Exception as e:
    scaler = None

try:
    label_encoder = joblib.load(label_encoder_path)
except Exception as e:
    label_encoder = None

# Identify correct network interface
interfaces = get_if_list()
print("Available Network Interfaces:", interfaces)
WIFI_INTERFACE = r"\Device\NPF_{54EC6C67-06C7-4574-A83C-CBB8E167ED15}"  # Change if needed

# Features expected by the model
FEATURES = ['flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate', 
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 
            'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 
            'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 
            'Variance', 'Weight']

def preprocess_features(features):
    if scaler is None:
        return None
    df = pd.DataFrame([features], columns=FEATURES)  # Convert to DataFrame with correct column names
    df_scaled = scaler.transform(df)  # Apply MinMaxScaler
    return df_scaled

# Extract features from captured packet
def extract_features(packet):
    features = {key: 0 for key in FEATURES}  # Initialize all to 0

    if IP in packet:
        features['Protocol Type'] = int(packet[IP].proto)
        features['src_ip'] = packet[IP].src
        features['dest_ip'] = packet[IP].dst
    if TCP in packet:
        features['TCP'] = 1
    if UDP in packet:
        features['UDP'] = 1
    if ICMP in packet:
        features['ICMP'] = 1

    if IP in packet:
        features['Header_Length'] = int(packet[IP].ihl) * 4
    
    if TCP in packet:
        flags = int(packet[TCP].flags)
        features['fin_flag_number'] = flags & 0x01
        features['syn_flag_number'] = (flags & 0x02) >> 1
        features['rst_flag_number'] = (flags & 0x04) >> 2
        features['psh_flag_number'] = (flags & 0x08) >> 3
        features['ack_flag_number'] = (flags & 0x10) >> 4

    return features

# Predict traffic type
def classify_packet(packet):
    try:
        if model is None or scaler is None or label_encoder is None:
            return None, None, None, None
        
        features = extract_features(packet)
        if features is None:
            return "Feature Extraction Error", None, None, None
        
        feature_values = np.array([[features[key] for key in FEATURES if key in features]], dtype=np.float32)
        scaled_features = scaler.transform(feature_values)
        reshaped_features = scaled_features.reshape(1, 1, -1)  # Reshape for GRU
        prediction = model.predict(reshaped_features)
        predicted_class = np.argmax(prediction)
        class_label = label_encoder.inverse_transform([predicted_class])[0]
        return class_label, features.get('src_ip'), features.get('dest_ip'), features.get('Protocol Type')
    except Exception as e:
        print(f"Error in classification: {e}")
        return "Unknown", None, None, None

# Function to send anomaly email notifications
def send_anomaly_notification(src_ip, dest_ip, protocol, classification, timestamp):
    """
    Send email notification to all active users when an anomaly is detected
    """
    if not active_user_emails:
        print("No active users to notify")
        return
    
    subject = "🚨 Security Alert: Network Anomaly Detected"
    message = f"""
    SECURITY ALERT: An anomaly has been detected in your network traffic.

    Incident Details:
    ================
    Timestamp: {timestamp}
    Source IP: {src_ip}
    Destination IP: {dest_ip}
    Protocol: {protocol}
    Classification: {classification}
    Threat Level: HIGH

    Recommended Actions:
    ===================
    1. Investigate the source IP address immediately
    2. Check if this is legitimate traffic from your network
    3. Consider blocking suspicious IPs if necessary
    4. Monitor your network for additional anomalies

    This is an automated alert from your Intrusion Detection System.
    If you believe this is a false positive, please review your network configuration.

    Stay secure!
    Your IDS Team
    """
    
    try:
        # Send email to all active users
        for email in active_user_emails:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            print(f"✅ Anomaly notification sent to: {email}")
    except Exception as e:
        print(f"❌ Error sending email notification: {e}")

# Process packets and store in database
def process_packet(packet):
    classification, src_ip, dest_ip, protocol = classify_packet(packet)

    if src_ip and dest_ip:
        # Create timestamp for the current packet
        from datetime import datetime
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Store in database
        traffic_record = CapturedTraffic.objects.create(
            src_ip=src_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            prediction=classification
        )

        # Check if the classification indicates an anomaly
        # Common anomaly classifications (adjust based on your model's output)
        anomaly_keywords = ['anomaly', 'attack', 'malicious', 'intrusion', 'suspicious', 'dos', 'ddos', 'malware']
        
        if any(keyword in classification.lower() for keyword in anomaly_keywords):
            print(f"🚨 ANOMALY DETECTED: {classification}")
            # Send email notification to all active users
            send_anomaly_notification(src_ip, dest_ip, protocol, classification, current_time)

    print(f"📡 Captured Packet: {packet.summary()}")
    print(f"🔍 Model Prediction: {classification}\n")

# Sniff live packets
def capture_live_traffic():
    print(f"🔍 Capturing traffic on {WIFI_INTERFACE}...")
    sniff(iface=WIFI_INTERFACE, prn=process_packet, store=False)

# Start sniffing
#capture_live_traffic()

# Fetch latest traffic data for dashboard
def get_latest_traffic(request):
    traffic_data = CapturedTraffic.objects.order_by('-timestamp')[:10]
    data = [
        {
            "timestamp": traffic.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": traffic.src_ip,
            "dest_ip": traffic.dest_ip,
            "protocol": traffic.protocol,
            "prediction": traffic.prediction
        } for traffic in traffic_data
    ]
    return JsonResponse(data, safe=False)

def get_anomaly_stats(request):
    """
    API endpoint to get anomaly statistics
    """
    anomaly_keywords = ['anomaly', 'attack', 'malicious', 'intrusion', 'suspicious', 'dos', 'ddos', 'malware']
    
    # Get total traffic count
    total_traffic = CapturedTraffic.objects.count()
    
    # Get anomaly count
    anomalies = CapturedTraffic.objects.filter(
        prediction__iregex=r'(' + '|'.join(anomaly_keywords) + ')'
    )
    anomaly_count = anomalies.count()
    
    # Get recent anomalies (last 24 hours)
    from datetime import datetime, timedelta
    last_24h = datetime.now() - timedelta(hours=24)
    recent_anomalies = anomalies.filter(timestamp__gte=last_24h).count()
    
    # Get active users count
    active_users = len(active_user_emails)
    
    stats = {
        'total_traffic': total_traffic,
        'total_anomalies': anomaly_count,
        'recent_anomalies_24h': recent_anomalies,
        'active_users': active_users,
        'anomaly_percentage': round((anomaly_count / total_traffic * 100), 2) if total_traffic > 0 else 0,
        'latest_anomalies': [
            {
                'timestamp': anomaly.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'src_ip': anomaly.src_ip,
                'dest_ip': anomaly.dest_ip,
                'protocol': anomaly.protocol,
                'prediction': anomaly.prediction
            } for anomaly in anomalies.order_by('-timestamp')[:5]
        ]
    }
    
    return JsonResponse(stats)

# Dashboard view
def dashboard(request):
    traffic_data = CapturedTraffic.objects.order_by('-timestamp')[:10]
    return render(request, 'dashboard.html', {'traffic_data': traffic_data})

# Basic views
def home(request):
    return render(request, 'home.html')


def SignUp(request):
    if request.method == 'POST':
        # Get form data
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Validation checks
        if not all([first_name, last_name, username, email, password]):
            messages.error(request, 'All fields are required!')
            return render(request, 'signup.html')

        if len(username) < 3 or len(username) > 30:
            messages.error(request, 'Username must be between 3 and 30 characters!')
            return render(request, 'signup.html')

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Invalid email address!')
            return render(request, 'signup.html')

        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters!')
            return render(request, 'signup.html')

        # Check for unique username and email
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken!')
            return render(request, 'signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered!')
            return render(request, 'signup.html')

        try:
            # Create new user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            user.save()
            messages.success(request, 'Signup successful! Please log in.')
            return redirect('login')
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            return render(request, 'signup.html')

    return render(request, 'signup.html')


def Login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Validation checks
        if not all([username, password]):
            messages.error(request, 'Username and password are required!')
            return render(request, 'login.html')

        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Log the user in
            login(request, user)
            # Store user's email in the session
            request.session['user_email'] = user.email
            # Add user email to active users for notifications
            active_user_emails.add(user.email)
            messages.success(request, 'Login successful!')
            print(f"[LOGIN SUCCESS] User {user.email} logged in and added to notification list")
            return redirect('user_dashboard')  # Replace with your actual dashboard URL name
        else:
            messages.error(request, 'Invalid username or password!')
            return render(request, 'login.html')

    return render(request, 'login.html')

def user_dashboard(request):
    # Get recent traffic data
    recent_traffic = CapturedTraffic.objects.order_by('-timestamp')[:20]
    
    # Get anomaly statistics
    total_traffic = CapturedTraffic.objects.count()
    anomaly_keywords = ['anomaly', 'attack', 'malicious', 'intrusion', 'suspicious', 'dos', 'ddos', 'malware']
    
    anomalies = CapturedTraffic.objects.filter(
        prediction__iregex=r'(' + '|'.join(anomaly_keywords) + ')'
    ).order_by('-timestamp')[:10]
    
    anomaly_count = anomalies.count()
    
    context = {
        'recent_traffic': recent_traffic,
        'recent_anomalies': anomalies,
        'total_traffic': total_traffic,
        'anomaly_count': anomaly_count,
        'user_email': request.user.email if request.user.is_authenticated else None,
        'active_users_count': len(active_user_emails)
    }
    
    return render(request, 'user_dashboard.html', context)

def logout_view(request):
    """
    Custom logout function to remove user from active notifications
    """
    if request.user.is_authenticated:
        user_email = request.user.email
        # Remove user from active notifications
        active_user_emails.discard(user_email)
        print(f"[LOGOUT SUCCESS] User {user_email} logged out and removed from notification list")
    
    logout(request)
    messages.success(request, 'You have been logged out successfully!')
    return redirect('home')

def start_traffic_monitoring(request):
    """
    Start the traffic monitoring in a separate thread
    """
    if request.method == 'POST':
        try:
            # Start traffic monitoring in background thread
            monitoring_thread = threading.Thread(target=capture_live_traffic, daemon=True)
            monitoring_thread.start()
            return JsonResponse({'status': 'success', 'message': 'Traffic monitoring started'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Failed to start monitoring: {str(e)}'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def stop_traffic_monitoring(request):
    """
    Stop traffic monitoring (this is a placeholder - actual implementation would need more complex thread management)
    """
    if request.method == 'POST':
        # In a real implementation, you'd need a way to properly stop the sniffing thread
        return JsonResponse({'status': 'success', 'message': 'Traffic monitoring stop requested'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@csrf_exempt
def test_email_notification(request):
    """
    Test function to manually trigger an email notification
    """
    if request.method == 'POST':
        try:
            # Sample test data
            test_data = {
                'src_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'protocol': 'TCP',
                'classification': 'Malicious Attack',
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            send_anomaly_notification(
                test_data['src_ip'],
                test_data['dest_ip'], 
                test_data['protocol'],
                test_data['classification'],
                test_data['timestamp']
            )
            
            return JsonResponse({
                'status': 'success', 
                'message': f'Test email sent to {len(active_user_emails)} active users'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error', 
                'message': f'Failed to send test email: {str(e)}'
            })
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def AboutUs(request):
    return render(request, 'AboutUs.html')

def ContactUs(request):
    return render(request, 'ContactUs.html')

def PrivacyPolicy(request):
    return render(request, 'PrivacyPolicy.html')

def TermsOfService(request):
    return render(request, 'TermsOfService.html')
