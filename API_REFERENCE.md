# DeepThreat IDS - API Reference & Developer Guide

## 📚 Table of Contents
1. [Web URLs/Routes](#web-urlsroutes)
2. [REST API Endpoints](#rest-api-endpoints)
3. [Request/Response Examples](#requestresponse-examples)
4. [Authentication](#authentication)
5. [Database Models Reference](#database-models-reference)
6. [Code Examples](#code-examples)
7. [Common Tasks](#common-tasks)

---

## 🌐 Web URLs/Routes

### Public Routes (No Authentication Required)

| HTTP | Path | Function | Template | Purpose |
|------|------|----------|----------|---------|
| GET | `/` | `home` | home.html | Landing page |
| GET | `/login/` | `Login` (GET) | login.html | Login page form |
| POST | `/login/` | `Login` (POST) | - | Process login |
| GET | `/logout/` | `logout_view` | - | Logout user |
| GET | `/signup/` | `SignUp` (GET) | signup.html | Registration page |
| POST | `/signup/` | `SignUp` (POST) | - | Create account |
| GET | `/about-us/` | `AboutUs` | AboutUs.html | About page |
| GET | `/contact-us/` | `ContactUs` (GET) | ContactUs.html | Contact form |
| POST | `/contact-us/` | `ContactUs` (POST) | - | Submit contact |
| GET | `/privacy-policy/` | `PrivacyPolicy` | PrivacyPolicy.html | Privacy policy |
| GET | `/terms-of-service/` | `TermsOfService` | TermsOfService.html | Terms page |

### Protected Routes (Authentication Required)

| HTTP | Path | Function | Template | Purpose |
|------|------|----------|----------|---------|
| GET | `/user-dashboard/` | `user_dashboard` | user_dashboard.html | User dashboard |
| GET | `/dashboard/` | `dashboard` | dashboard.html | Traffic dashboard |

### API Endpoints (JSON Responses)

| HTTP | Path | Function | Response | Purpose |
|------|------|----------|----------|---------|
| POST | `/start_monitoring/` | `start_traffic_monitoring` | JSON | Start capture |
| POST | `/stop_monitoring/` | `stop_traffic_monitoring` | JSON | Stop capture |
| GET | `/latest_traffic/` | `get_latest_traffic` | JSON Array | Last 10 packets |
| GET | `/anomaly_stats/` | `get_anomaly_stats` | JSON Object | Statistics |
| POST | `/test_email/` | `test_email_notification` | JSON | Test alerts |

---

## 📡 REST API Endpoints

### 1. Latest Traffic Endpoint

**URL:** `/latest_traffic/`  
**Method:** GET  
**Authentication:** Optional (returns all if public, would be user-filtered if added)  
**Rate Limit:** None  

**Request:**
```bash
curl http://127.0.0.1:8000/latest_traffic/
```

**Response (200 OK):**
```json
[
  {
    "timestamp": "2026-03-11 22:05:30",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "protocol": "TCP",
    "prediction": "Normal"
  },
  {
    "timestamp": "2026-03-11 22:05:29",
    "src_ip": "203.0.113.45",
    "dest_ip": "192.168.1.1",
    "protocol": "UDP",
    "prediction": "DDoS Attack"
  }
]
```

---

### 2. Anomaly Statistics Endpoint

**URL:** `/anomaly_stats/`  
**Method:** GET  
**Authentication:** Optional  
**Rate Limit:** None  

**Request:**
```bash
curl http://127.0.0.1:8000/anomaly_stats/
```

**Response (200 OK):**
```json
{
  "total_traffic": 1250,
  "total_anomalies": 45,
  "recent_anomalies_24h": 12,
  "active_users": 3,
  "anomaly_percentage": 3.6,
  "latest_anomalies": [
    {
      "timestamp": "2026-03-11 21:45:00",
      "src_ip": "203.0.113.45",
      "dest_ip": "192.168.1.1",
      "protocol": "UDP",
      "prediction": "DDoS Attack"
    },
    {
      "timestamp": "2026-03-11 21:30:15",
      "src_ip": "198.51.100.25",
      "dest_ip": "192.168.1.50",
      "protocol": "TCP",
      "prediction": "Port Scan"
    }
  ]
}
```

---

### 3. Start Monitoring Endpoint

**URL:** `/start_monitoring/`  
**Method:** POST  
**Authentication:** Optional  
**Rate Limit:** None  

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/start_monitoring/ \
  -H "Content-Type: application/json"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Traffic monitoring started"
}
```

**Response (400 Bad Request):**
```json
{
  "status": "error",
  "message": "Invalid request method"
}
```

---

### 4. Stop Monitoring Endpoint

**URL:** `/stop_monitoring/`  
**Method:** POST  
**Authentication:** Optional  
**Rate Limit:** None  

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/stop_monitoring/ \
  -H "Content-Type: application/json"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Traffic monitoring stop requested"
}
```

---

### 5. Test Email Notification Endpoint

**URL:** `/test_email/`  
**Method:** POST  
**Authentication:** Optional  
**Requires:** `@csrf_exempt` decorator (CSRF not required)  

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/test_email/ \
  -H "X-CSRFToken: your_csrf_token"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "message": "Test email sent to 3 active users"
}
```

**Response (400 Error):**
```json
{
  "status": "error",
  "message": "Failed to send test email: SMTP error"
}
```

---

## 🔐 Authentication

### Session-Based Authentication

All form submissions use Django's built-in session authentication:

```python
# After successful login
login(request, user)
request.session['user_email'] = user.email
```

### CSRF Protection

All POST requests to forms require CSRF token:

```html
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

### API Key (Future Implementation)

Proposed structure for API key authentication:

```python
# Header
Authorization: Bearer YOUR_API_KEY

# Example usage:
curl -H "Authorization: Bearer abc123def456" \
     http://127.0.0.1:8000/api/latest_traffic/
```

---

## 📊 Database Models Reference

### CapturedTraffic Model

**Purpose:** Store all captured network packets and their classifications

**Fields:**
```python
class CapturedTraffic(models.Model):
    # IP Information
    src_ip = models.CharField(max_length=255)
    dest_ip = models.CharField(max_length=255)
    
    # Protocol Information
    protocol = models.CharField(max_length=50)
    prediction = models.CharField(max_length=255)
    
    # Flow Statistics
    flow_duration = models.FloatField(default=0)
    Header_Length = models.IntegerField(default=0)
    Duration = models.FloatField(default=0)
    Rate = models.FloatField(default=0)
    Srate = models.FloatField(default=0)
    Drate = models.FloatField(default=0)
    
    # TCP Flags
    fin_flag_number = models.IntegerField(default=0)
    syn_flag_number = models.IntegerField(default=0)
    rst_flag_number = models.IntegerField(default=0)
    psh_flag_number = models.IntegerField(default=0)
    ack_flag_number = models.IntegerField(default=0)
    ece_flag_number = models.IntegerField(default=0)
    cwr_flag_number = models.IntegerField(default=0)
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
```

**Usage Examples:**

```python
# Get all traffic
traffic = CapturedTraffic.objects.all()

# Get recent traffic
recent = CapturedTraffic.objects.order_by('-timestamp')[:10]

# Filter by source IP
from_ip = CapturedTraffic.objects.filter(src_ip='192.168.1.100')

# Filter by prediction
anomalies = CapturedTraffic.objects.filter(prediction__icontains='attack')

# Get count
total = CapturedTraffic.objects.count()

# Get statistics
from django.db.models import Count
stats = CapturedTraffic.objects.values('prediction').annotate(count=Count('id'))
# Output: [{'prediction': 'Normal', 'count': 1200}, {'prediction': 'DDoS Attack', 'count': 50}]

# Date range
from datetime import datetime, timedelta
last_24h = datetime.now() - timedelta(hours=24)
recent_traffic = CapturedTraffic.objects.filter(timestamp__gte=last_24h)

# Delete old records (cleanup)
old_traffic = CapturedTraffic.objects.filter(timestamp__lt=last_30_days)
old_traffic.delete()
```

---

### User Model (Django Built-in)

**Fields:**
```python
# Django's User model fields:
username         # Unique username
email            # Email address
first_name       # First name
last_name        # Last name
password         # Hashed password
is_active        # Account active status
is_staff         # Admin access
is_superuser     # Full admin access
date_joined      # Account creation date
```

**Usage Examples:**

```python
# Create user
from django.contrib.auth.models import User
user = User.objects.create_user(
    username='johndoe',
    email='john@example.com',
    password='SecurePass123',
    first_name='John',
    last_name='Doe'
)

# Authenticate
from django.contrib.auth import authenticate
user = authenticate(username='johndoe', password='SecurePass123')

# Check if authenticated in views
if request.user.is_authenticated:
    user_email = request.user.email

# Get all users
all_users = User.objects.all()

# Update user
user.email = 'newemail@example.com'
user.save()

# Delete user
user.delete()
```

---

### Contact Model

**Purpose:** Store contact form submissions

**Fields:**
```python
class Contact(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    # created_at auto-generated
```

**Usage Examples:**

```python
# Create contact entry
contact = Contact.objects.create(
    name='John Doe',
    email='john@example.com',
    subject='Question about IDS',
    message='How does the threat detection work?'
)

# Get all contacts
all_contacts = Contact.objects.all()

# Get recent contacts
recent = Contact.objects.order_by('-created_at')[:10]

# Search contacts
contacts = Contact.objects.filter(subject__icontains='billing')
```

---

## 💻 Code Examples

### Example 1: Check Traffic Statistics in Django Shell

```bash
python manage.py shell
```

```python
from myapp.models import CapturedTraffic
from django.db.models import Count
from datetime import datetime, timedelta

# Total packets
total = CapturedTraffic.objects.count()
print(f"Total Packets: {total}")

# Last 24 hours
last_24h = datetime.now() - timedelta(hours=24)
traffic_24h = CapturedTraffic.objects.filter(timestamp__gte=last_24h).count()
print(f"Traffic in Last 24h: {traffic_24h}")

# Count by protocol
by_protocol = CapturedTraffic.objects.values('protocol').annotate(count=Count('id'))
print("Traffic by Protocol:")
for item in by_protocol:
    print(f"  {item['protocol']}: {item['count']}")

# Count anomalies
anomalies = CapturedTraffic.objects.filter(
    prediction__iregex=r'attack|anomaly|malicious|intrusion'
)
print(f"Total Anomalies: {anomalies.count()}")

# Top source IPs
top_sources = CapturedTraffic.objects.values('src_ip').annotate(
    count=Count('id')
).order_by('-count')[:5]
print("Top 5 Source IPs:")
for item in top_sources:
    print(f"  {item['src_ip']}: {item['count']} packets")
```

---

### Example 2: Query Specific Anomalies

```python
from myapp.models import CapturedTraffic
from datetime import datetime, timedelta

# Get all DDoS attacks
ddos = CapturedTraffic.objects.filter(prediction__icontains='ddos')
print(f"DDoS Attacks: {ddos.count()}")

# Get anomalies from specific IP
anomalies_from_ip = CapturedTraffic.objects.filter(
    src_ip='203.0.113.45',
    prediction__icontains='attack'
)

# Get anomalies to specific destination
anomalies_to_dest = CapturedTraffic.objects.filter(
    dest_ip='192.168.1.50',
    prediction__icontains='attack'
)

# Export to CSV
import csv
with open('anomalies.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Prediction'])
    for traffic in anomalies:
        writer.writerow([
            traffic.timestamp,
            traffic.src_ip,
            traffic.dest_ip,
            traffic.protocol,
            traffic.prediction
        ])
print("Exported to anomalies.csv")
```

---

### Example 3: Manual Feature Extraction & Prediction

```python
import numpy as np
from myapp.views import extract_features, preprocess_features, classify_packet
from scapy.all import IP, TCP, sniff

# Function to process a single packet
def process_single_packet(packet):
    # Extract features
    features = extract_features(packet)
    
    # Preprocess
    preprocessed = preprocess_features(features)
    
    # Classify
    classification, src_ip, dest_ip, protocol = classify_packet(packet)
    
    return {
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        'protocol': protocol,
        'classification': classification
    }

# Capture and process one packet
def capture_one_packet():
    captured_packets = []
    
    def packet_callback(packet):
        if len(captured_packets) == 0:  # Get first packet only
            result = process_single_packet(packet)
            captured_packets.append(result)
    
    sniff(iface="eth0", prn=packet_callback, count=1)
    return captured_packets[0]

result = capture_one_packet()
print(f"Classification: {result['classification']}")
print(f"From {result['src_ip']} to {result['dest_ip']}")
```

---

### Example 4: Send Custom Notification

```python
from django.core.mail import send_mail
from django.conf import settings

# Get all active users
from myapp.views import active_user_emails

# Send custom alert
subject = "🚨 SECURITY ALERT: Suspicious Activity Detected"
message = """
INTRUSION DETECTION SYSTEM ALERT
================================
Alert Time: 2026-03-11 22:30:00
Source IP: 203.0.113.45
Destination IP: 192.168.1.1
Protocol: TCP
Classification: Port Scan

Action Required: Check dashboard for details.
"""

for email in active_user_emails:
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

print(f"Alert sent to {len(active_user_emails)} users")
```

---

## 🛠️ Common Tasks

### Task 1: Export Traffic Data to CSV

```python
import csv
from myapp.models import CapturedTraffic

traffic_data = CapturedTraffic.objects.all()

with open('traffic_export.csv', 'w', newline='') as csvfile:
    fieldnames = ['timestamp', 'src_ip', 'dest_ip', 'protocol', 'prediction']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for traffic in traffic_data:
        writer.writerow({
            'timestamp': traffic.timestamp.isoformat(),
            'src_ip': traffic.src_ip,
            'dest_ip': traffic.dest_ip,
            'protocol': traffic.protocol,
            'prediction': traffic.prediction,
        })

print(f"Exported {traffic_data.count()} records")
```

---

### Task 2: Generate Daily Report

```python
from django.db.models import Count
from datetime import datetime, timedelta
from myapp.models import CapturedTraffic

# Get data for yesterday
yesterday = datetime.now() - timedelta(days=1)
today = datetime.now()

daily_data = CapturedTraffic.objects.filter(
    timestamp__gte=yesterday,
    timestamp__lt=today
)

# Generate report
report = {
    'date': yesterday.strftime('%Y-%m-%d'),
    'total_packets': daily_data.count(),
    'anomalies': daily_data.filter(prediction__icontains='attack').count(),
    'protocols': dict(daily_data.values('protocol').annotate(count=Count('id')).values_list('protocol', 'count')),
    'top_sources': list(daily_data.values('src_ip').annotate(count=Count('id')).order_by('-count')[:5]),
}

import json
print(json.dumps(report, indent=2))
```

---

### Task 3: Bulk Delete Old Records

```python
from datetime import datetime, timedelta
from myapp.models import CapturedTraffic

# Delete records older than 30 days
thirty_days_ago = datetime.now() - timedelta(days=30)
old_records = CapturedTraffic.objects.filter(timestamp__lt=thirty_days_ago)

count = old_records.count()
old_records.delete()

print(f"Deleted {count} old records")
```

---

### Task 4: Create Backup of Database

```bash
# SQLite backup
cp db.sqlite3 db.sqlite3.backup.$(date +%Y%m%d_%H%M%S)

# Export to JSON
python manage.py dumpdata > backup.json

# Export specific model
python manage.py dumpdata myapp.CapturedTraffic > traffic_backup.json

# Restore from JSON
python manage.py loaddata backup.json
```

---

### Task 5: Reset Database (Careful!)

```bash
# WARNING: This deletes all data!

# Delete database
rm db.sqlite3

# Recreate from migrations
python manage.py migrate

# Create new superuser
python manage.py createsuperuser
```

---

## 📝 HTTP Status Codes Reference

| Code | Status | Meaning |
|------|--------|---------|
| 200 | OK | Request successful |
| 301 | Moved Permanently | Permanent redirect |
| 302 | Found | Temporary redirect |
| 400 | Bad Request | Invalid request |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 500 | Server Error | Internal server error |
| 503 | Service Unavailable | Server temporarily down |

---

## 🔑 Django Shell Shortcuts

```python
# Import common modules
from django.shortcuts import render, redirect
from django.http import JsonResponse
from myapp.models import CapturedTraffic, Contact
from django.contrib.auth.models import User

# Clear screen
import os; os.system('clear')  # Linux
import os; os.system('cls')    # Windows

# Exit shell
exit()  # or Ctrl+D
```

---

**End of API Reference Document**

For more information, see README.md or INSTALLATION.md
