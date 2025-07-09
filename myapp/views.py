import threading
import time
import random
import numpy as np
import pandas as pd
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from tensorflow.keras.models import load_model
import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from .models import CapturedTraffic
import tensorflow as tf
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import login, authenticate, logout
import re
from . import models

# Load trained model & scalers
model = tf.keras.models.load_model("myapp/models/GRU_IDS_model.keras")
scaler = joblib.load("myapp/models/scaler.pkl")
label_encoder = joblib.load("myapp/models/label_encoder.pkl")

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
        features = extract_features(packet)
        if features is None:
            return "Feature Extraction Error"
        
        feature_values = np.array([[features[key] for key in FEATURES if key in features]], dtype=np.float32)
        scaled_features = scaler.transform(feature_values)
        reshaped_features = scaled_features.reshape(1, 1, -1)  # Reshape for GRU
        prediction = model.predict(reshaped_features)
        predicted_class = np.argmax(prediction)
        class_label = label_encoder.inverse_transform([predicted_class])[0]
        return class_label, features['src_ip'], features['dest_ip'], features['Protocol Type']
    except Exception as e:
        print(f"Error in classification: {e}")
        return "Unknown", None, None, None

# Process packets and store in database
def process_packet(packet):
    classification, src_ip, dest_ip, protocol = classify_packet(packet)
    
    if src_ip and dest_ip:
        CapturedTraffic.objects.create(
            src_ip=src_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            prediction=classification
        )

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
            messages.success(request, 'Login successful!')
            return redirect('user_dashboard')  # Replace with your actual dashboard URL name
        else:
            messages.error(request, 'Invalid username or password!')
            return render(request, 'login.html')

    return render(request, 'login.html')

def user_dashboard(request):
    return render(request, 'user_dashboard.html')


def AboutUs(request):
    return render(request, 'AboutUs.html')

def ContactUs(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')

        if not all([name, email, subject, message]):
            messages.error(request, 'All fields are required!')
            return render(request, 'ContactUs.html')

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Invalid email address!')
            return render(request, 'ContactUs.html')

        if len(name) > 100 or len(subject) > 200:
            messages.error(request, 'Name or subject too long!')
            return render(request, 'ContactUs.html')

        try:
            contact = models.Contact.objects.create(
                name=name,
                email=email,
                subject=subject,
                message=message
            )
            contact.save()
            messages.success(request, 'Thank you for your message! We will get back to you soon.')
            return redirect('contact-us')
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            return render(request, 'ContactUs.html')

    return render(request, 'ContactUs.html')

def PrivacyPolicy(request):
    return render(request, 'PrivacyPolicy.html')

def TermsOfService(request):
    return render(request, 'TermsOfService.html')
