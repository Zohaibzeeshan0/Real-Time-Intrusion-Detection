# DeepThreat IDS - Intrusion Detection System

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation & Setup](#installation--setup)
5. [Project Structure](#project-structure)
6. [Database Models](#database-models)
7. [API Endpoints](#api-endpoints)
8. [User Workflows](#user-workflows)
9. [Security Features](#security-features)
10. [Troubleshooting](#troubleshooting)
11. [Future Enhancements](#future-enhancements)

---

## 🎯 Project Overview

**DeepThreat IDS** is an advanced Intrusion Detection System built with Django and modern web technologies. It provides real-time network traffic monitoring, anomaly detection, and threat classification using machine learning models.

### Purpose
- Monitor network traffic in real-time
- Detect malicious activities and anomalies
- Provide a user-friendly dashboard for security monitoring
- Send email alerts to authorized users when threats are detected
- Store and analyze historical traffic data

### Technology Stack
- **Backend**: Django 6.0.3 (Python)
- **Frontend**: React + TypeScript (separate folder)
- **Database**: SQLite
- **ML Models**: TensorFlow/Keras (GRU-based IDS model)
- **Network Monitoring**: Scapy
- **Scalers**: scikit-learn

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     DeepThreat IDS                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐         ┌──────────────────────────┐  │
│  │   React Frontend │         │   Django Backend API     │  │
│  │  (Port: 3000/    │◄───────►│   (Port: 8000)           │  │
│  │   5173)          │         │                          │  │
│  └──────────────────┘         └──────────────────────────┘  │
│                                        │                     │
│                                        ▼                     │
│                              ┌──────────────────┐            │
│                              │   SQLite DB      │            │
│                              │  (db.sqlite3)    │            │
│                              └──────────────────┘            │
│                                        │                     │
│                                        ▼                     │
│                              ┌──────────────────┐            │
│                              │  ML Model (GRU)  │            │
│                              │  Threat Detection│            │
│                              └──────────────────┘            │
│                                        │                     │
│                                        ▼                     │
│                              ┌──────────────────┐            │
│                              │  Scapy Traffic   │            │
│                              │    Sniffer       │            │
│                              └──────────────────┘            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow
1. **Network Layer** → Scapy captures live traffic from network interface
2. **Feature Extraction** → Converts packets to feature vectors
3. **Preprocessing** → Scales features using MinMaxScaler
4. **ML Model** → GRU model classifies traffic (Normal/Anomaly/Attack)
5. **Storage** → Saves results to SQLite database
6. **Notification** → Sends email alerts for anomalies
7. **Visualization** → Frontend displays real-time data

---

## ✨ Features

### 1. **User Authentication**
   - User registration with validation
   - Secure login/logout
   - Email validation
   - Password strength requirements

### 2. **Real-time Traffic Monitoring**
   - Captures live network packets
   - Extracts 40+ features per packet
   - Processes packets in real-time
   - Displays on dashboard instantly

### 3. **Threat Detection**
   - TensorFlow GRU model for classification
   - Detects various attack types
   - Identifies anomalous traffic patterns
   - Color-coded threat indicators

### 4. **Dashboard Analytics**
   - Shows traffic statistics
   - Displays anomaly count
   - Real-time updates
   - Historical data tracking

### 5. **Email Notifications**
   - Sends alerts when threats detected
   - Notifies all active users
   - Includes threat details
   - Timestamp and source/destination IPs

### 6. **Static Pages**
   - About Us
   - Contact Us
   - Privacy Policy
   - Terms of Service

### 7. **Mobile Responsive**
   - Works on desktop and mobile
   - Adaptive grid layouts
   - Touch-friendly buttons

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.13+
- Windows/Linux/Mac
- pip package manager

### Step 1: Clone/Extract Project
```bash
cd c:\Users\zohai\Desktop\mainnn\IDS\IDS\myIDS
```

### Step 2: Create Virtual Environment
```bash
python -m venv venv
```

### Step 3: Activate Virtual Environment
**Windows (PowerShell):**
```bash
.\venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

### Step 4: Install Dependencies
```bash
pip install django django-cors-headers scikit-learn numpy pandas scapy joblib
```

### Step 5: Run Migrations
```bash
python manage.py migrate
```

### Step 6: Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### Step 7: Run Development Server
```bash
python manage.py runserver
```

Server will start at: `http://127.0.0.1:8000/`

### Step 8: Access Application
- **Home**: http://127.0.0.1:8000/
- **Admin Panel**: http://127.0.0.1:8000/admin/
- **Dashboard**: http://127.0.0.1:8000/dashboard/
- **User Dashboard**: http://127.0.0.1:8000/user-dashboard/

---

## 📁 Project Structure

```
myIDS/
├── manage.py                    # Django management commands
├── db.sqlite3                   # SQLite database
├── sniff.py                     # Traffic sniffer script
├── output.json                  # Output logs
│
├── myIDS/                       # Project configuration
│   ├── __init__.py
│   ├── settings.py              # Django settings
│   ├── urls.py                  # URL routing
│   ├── asgi.py                  # ASGI configuration
│   └── wsgi.py                  # WSGI configuration
│
├── myapp/                       # Main application
│   ├── __init__.py
│   ├── models.py                # Database models
│   ├── views.py                 # View functions
│   ├── urls.py                  # App URL patterns
│   ├── admin.py                 # Admin configuration
│   ├── apps.py                  # App configuration
│   ├── tests.py                 # Unit tests
│   │
│   ├── migrations/              # Database migrations
│   │   ├── __init__.py
│   │   ├── 0001_initial.py
│   │   ├── 0002_...
│   │   └── ...
│   │
│   ├── models/                  # ML Models & Scalers
│   │   ├── GRU_IDS_model.keras  # Trained GRU model
│   │   ├── scaler.pkl           # Feature scaler
│   │   └── label_encoder.pkl    # Label encoder
│   │
│   ├── static/                  # Static files
│   │   └── images/              # Images & assets
│   │
│   └── templates/               # HTML templates
│       ├── home.html            # Home page
│       ├── login.html           # Login page
│       ├── signup.html          # Registration page
│       ├── user_dashboard.html  # User dashboard
│       ├── dashboard.html       # Traffic dashboard
│       ├── AboutUs.html         # About page
│       ├── ContactUs.html       # Contact page
│       ├── PrivacyPolicy.html   # Privacy policy
│       └── TermsOfService.html  # Terms of service
│
└── project-bolt-sb1-kskkxney/  # Frontend (React)
    └── project/
        ├── src/
        │   ├── App.tsx
        │   ├── main.tsx
        │   ├── components/
        │   ├── pages/
        │   ├── contexts/
        │   └── services/
        └── public/
```

---

## 📊 Database Models

### 1. CapturedTraffic Model
Stores all captured network packets and their classifications.

```python
class CapturedTraffic(models.Model):
    src_ip              : CharField      # Source IP address
    dest_ip             : CharField      # Destination IP address
    protocol            : CharField      # Protocol (TCP/UDP/ICMP)
    prediction          : CharField      # ML model prediction
    flow_duration       : FloatField     # Flow duration in seconds
    Header_Length       : IntegerField   # Header length in bytes
    Duration            : FloatField     # Packet duration
    Rate                : FloatField     # Data rate
    Srate               : FloatField     # Source rate
    Drate               : FloatField     # Destination rate
    fin_flag_number     : IntegerField   # FIN flag count
    syn_flag_number     : IntegerField   # SYN flag count
    rst_flag_number     : IntegerField   # RST flag count
    psh_flag_number     : IntegerField   # PUSH flag count
    ack_flag_number     : IntegerField   # ACK flag count
    ece_flag_number     : IntegerField   # ECE flag count
    cwr_flag_number     : IntegerField   # CWR flag count
    timestamp           : DateTimeField  # When packet was captured
```

### 2. Contact Model
Stores contact form submissions.

```python
class Contact(models.Model):
    name        : CharField      # Sender's name
    email       : EmailField     # Sender's email
    subject     : CharField      # Message subject
    message     : TextField      # Message content
    created_at  : DateTimeField  # When submitted
```

---

## 🔌 API Endpoints

### Authentication Endpoints
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Home page |
| GET | `/login/` | Login page |
| POST | `/login/` | Process login |
| GET | `/logout/` | Logout user |
| GET | `/signup/` | Registration page |
| POST | `/signup/` | Create new user |

### Dashboard Endpoints
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/user-dashboard/` | User dashboard |
| GET | `/dashboard/` | Traffic dashboard |
| POST | `/start_monitoring/` | Start traffic capture |
| POST | `/stop_monitoring/` | Stop traffic capture |
| GET | `/latest_traffic/` | Get latest traffic data (JSON) |
| GET | `/anomaly_stats/` | Get anomaly statistics (JSON) |
| POST | `/test_email/` | Test email notification |

### Static Pages
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/about-us/` | About page |
| GET | `/contact-us/` | Contact page |
| POST | `/contact-us/` | Submit contact form |
| GET | `/privacy-policy/` | Privacy policy |
| GET | `/terms-of-service/` | Terms of service |

### Example API Responses

**GET /latest_traffic/**
```json
[
  {
    "timestamp": "2026-03-11 22:05:30",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "protocol": "TCP",
    "prediction": "Normal"
  }
]
```

**GET /anomaly_stats/**
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
    }
  ]
}
```

---

## 👥 User Workflows

### Workflow 1: New User Registration
1. User clicks "Sign Up" on home page
2. Fills registration form:
   - First Name
   - Last Name
   - Username (3-30 chars)
   - Email (valid format)
   - Password (minimum 8 chars)
3. System validates all fields
4. Creates user account
5. Redirects to login page
6. Success message displayed

### Workflow 2: User Login & Dashboard Access
1. User enters username and password
2. System authenticates credentials
3. Session created, user email stored
4. User email added to active notifications list
5. Redirected to user dashboard
6. Dashboard displays:
   - Welcome message with username
   - Traffic statistics (total, anomalies, active users)
   - Recent traffic table (last 20 packets)
   - Recent anomalies table
   - Action buttons (Start Monitoring, Refresh, Test Alert)

### Workflow 3: Real-time Traffic Monitoring
1. User clicks "Start Monitoring" button
2. System starts Scapy packet sniffer in background thread
3. Captures live packets from network interface
4. For each packet:
   - Extracts 40+ features
   - Scales features using MinMaxScaler
   - Runs through GRU model
   - Gets classification (Normal/Anomaly/Attack)
   - Stores in database
5. If anomaly detected:
   - Sends email to all active users
   - Updates dashboard in real-time
6. User can view data in dashboard tables

### Workflow 4: Threat Detection & Notification
1. System detects anomalous traffic
2. Classification: "DDoS Attack", "Malware", etc.
3. Email sent to all logged-in users with:
   - Alert title
   - Source IP
   - Destination IP
   - Protocol type
   - Timestamp
   - Recommendation to check dashboard
4. Dashboard shows threat in red highlighted row
5. Anomaly count incremented

---

## 🔒 Security Features

### 1. Authentication & Authorization
```python
# Login required decorator ensures only authenticated users access dashboard
@login_required
def user_dashboard(request):
    ...
```

### 2. CSRF Protection
```python
# CSRF token included in all forms
{% csrf_token %}
```

### 3. Email Validation
```python
# Validates email format during registration
validate_email(email)
```

### 4. Password Security
```python
# Django's make_password hashes passwords using PBKDF2
user = User.objects.create_user(
    username=username,
    password=password  # Automatically hashed
)
```

### 5. Session Management
```python
# Session stored after login
request.session['user_email'] = user.email
```

### 6. Input Validation
```python
# All inputs validated before database storage
if len(username) < 3 or len(username) > 30:
    messages.error(request, 'Invalid username length!')
```

### 7. SQL Injection Prevention
```python
# Django ORM prevents SQL injection
CapturedTraffic.objects.filter(src_ip=user_input)  # Safe
```

---

## 🔧 Key Views & Functions

### views.py Functions

#### `home(request)`
Renders home page template

#### `Login(request)`
- Validates credentials
- Authenticates user
- Creates session
- Adds user to active notifications
- Redirects to user_dashboard

#### `SignUp(request)`
- Validates registration form
- Checks username/email uniqueness
- Creates new User object
- Displays success/error messages

#### `user_dashboard(request)`
- Gets recent traffic (last 20 packets)
- Gets recent anomalies (last 10)
- Calculates statistics:
  - Total traffic count
  - Anomaly count
  - Active users count
- Renders dashboard with context data

#### `capture_live_traffic()`
- Starts Scapy packet sniffer
- Processes each packet with `process_packet()`
- Runs in background thread

#### `process_packet(packet)`
- Extracts features from packet
- Classifies using ML model
- Stores in database
- Sends email if anomaly detected

#### `get_latest_traffic(request)`
- Returns last 10 traffic records as JSON
- Used by frontend for real-time updates

#### `get_anomaly_stats(request)`
- Calculates anomaly statistics
- Returns JSON with:
  - Total traffic
  - Anomaly count
  - 24-hour anomalies
  - Active users
  - Recent anomalies list

---

## 📧 Email Notification System

### Configuration in settings.py
```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your_email@gmail.com'
EMAIL_HOST_PASSWORD = 'your_app_password'
```

### Notification Trigger
```python
def send_anomaly_notification(src_ip, dest_ip, protocol, classification, timestamp):
    # Sends email to all active_user_emails
    # Subject: "🚨 SECURITY ALERT: {classification}"
    # Body: Contains threat details
```

---

## 🎓 Feature Extraction

The system extracts 43 features from network packets:

1. **Flow Features**
   - flow_duration
   - Header_Length
   - Protocol Type
   - Duration
   - Rate (total bytes/duration)
   - Srate (source rate)
   - Drate (destination rate)

2. **TCP Flags**
   - fin_flag_number
   - syn_flag_number
   - rst_flag_number
   - psh_flag_number
   - ack_flag_number
   - ece_flag_number
   - cwr_flag_number
   - ack_count, syn_count, fin_count, urg_count, rst_count

3. **Protocol Indicators**
   - HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC
   - TCP, UDP, DHCP, ARP, ICMP, IPv, LLC

4. **Statistical Features**
   - Tot sum (total sum of packets)
   - Min (minimum packet size)
   - Max (maximum packet size)
   - AVG (average)
   - Std (standard deviation)
   - Tot size (total size)
   - IAT (inter-arrival time)
   - Number (number of packets)
   - Magnitude
   - Radius
   - Covariance
   - Variance
   - Weight

---

## 🤖 Machine Learning Model

### Model Type: GRU (Gated Recurrent Unit)
- **Input Shape**: (1, 43) - 43 features
- **Architecture**: GRU layers with dropout
- **Output**: Classification (Normal/Anomaly/Attack types)
- **File**: `myapp/models/GRU_IDS_model.keras`

### Preprocessing Pipeline
1. **Feature Extraction** → 43 features per packet
2. **Scaling** → MinMaxScaler (0-1 range)
3. **Reshaping** → (1, 1, 43) for GRU input
4. **Prediction** → Model output
5. **Decoding** → LabelEncoder converts to class name

### Classification Labels
- Normal
- DoS Attack
- DDoS Attack
- Port Scan
- Botnet
- Malware
- Anomalous Behavior
- (and other attack types)

---

## 🧪 Testing

### Test Email Notification
```bash
POST /test_email/

Response:
{
  "status": "success",
  "message": "Test email sent to 3 active users"
}
```

### Test Traffic Capture
```bash
python manage.py shell
>>> from myapp.views import capture_live_traffic
>>> capture_live_traffic()  # Captures packets
```

### View Database Records
```bash
python manage.py shell
>>> from myapp.models import CapturedTraffic
>>> CapturedTraffic.objects.all().count()  # Total packets
>>> CapturedTraffic.objects.filter(
...     prediction__icontains='attack'
... ).count()  # Anomalies
```

---

## 🐛 Troubleshooting

### Issue 1: ModuleNotFoundError: No module named 'corsheaders'
**Solution**: Remove CORS dependency from settings.py
- Already fixed in current version ✅

### Issue 2: django.db.utils.OperationalError: no such table
**Solution**: Run migrations
```bash
python manage.py migrate
```

### Issue 3: TensorFlow Not Installed
**Solution**: Install with pip
```bash
pip install tensorflow keras
```
**Note**: System still works without TensorFlow (graceful degradation)

### Issue 4: Cannot bind to port 8000
**Solution**: Use different port
```bash
python manage.py runserver 8001
```

### Issue 5: Network interface not found for Scapy
**Solution**: Check available interfaces
```python
from scapy.all import get_if_list
print(get_if_list())
# Update WIFI_INTERFACE in views.py
```

### Issue 6: Email not sending
**Solution**: 
- Check EMAIL settings in settings.py
- Verify Gmail app password
- Ensure SMTP credentials are correct
- Check firewall/antivirus blocking port 587

### Issue 7: Database locked (SQLite)
**Solution**: Close other connections
- Only keep one Django server instance running

---

## 📈 Performance Optimization

### Current Setup
- Single-threaded packet processing (can be improved)
- SQLite database (suitable for small-medium deployments)
- In-memory model loading

### Future Optimizations
- Implement queue-based processing (Celery)
- Use PostgreSQL for production
- Add caching (Redis)
- Implement pagination for large datasets
- Optimize feature extraction

---

## 🔄 Workflow Summary

```
User Visit Home
      ↓
Choose: Login or Signup
      ↓
[Login Path]                [Signup Path]
    ↓                           ↓
Enter Credentials        Fill Registration Form
    ↓                           ↓
Validate & Authenticate   Validate & Create User
    ↓                           ↓
Create Session           Redirect to Login
    ↓
User Dashboard
    ↓
View Statistics & Recent Traffic
    ↓
Start Monitoring (Optional)
    ↓
PacketCapture → Feature Extract → Scale → ML Model
    ↓
Store in DB & Send Alert (if anomaly)
    ↓
Real-time Dashboard Update
    ↓
View Anomalies & Threats
```

---

## 📞 Contact & Support

For issues or questions:
- Contact Us page: `/contact-us/`
- Email: admin@deepthreats.com
- Documentation: Check README.md

---

## 📝 License & Credits

**Project**: DeepThreat IDS v1.0  
**Created**: 2025-2026  
**Status**: Active Development  

---

## 🎯 Quick Reference

### Essential Commands
```bash
# Start server
python manage.py runserver

# Create admin user
python manage.py createsuperuser

# Access admin panel
http://127.0.0.1:8000/admin/

# Run migrations
python manage.py migrate

# Create new migration
python manage.py makemigrations

# Open Django shell
python manage.py shell
```

### Important Files
- **Settings**: `myIDS/settings.py`
- **URLs**: `myIDS/urls.py` and `myapp/urls.py`
- **Models**: `myapp/models.py`
- **Views**: `myapp/views.py`
- **Templates**: `myapp/templates/`

---

**End of Documentation**

Last Updated: March 11, 2026
