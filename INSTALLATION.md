# DeepThreat IDS - Installation & Configuration Guide

## 📦 Complete Setup Instructions

### System Requirements
- **OS**: Windows 10/11, Linux, or macOS
- **Python**: 3.10 or higher (tested with 3.13)
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: 2GB free space
- **Network**: Active internet connection for dependencies

---

## 🔧 Detailed Installation Steps

### Step 1: Prepare Your System

**Windows:**
```bash
# Open PowerShell as Administrator
# Check Python installation
python --version
```

**Linux/Mac:**
```bash
# Update package manager
sudo apt update && sudo apt upgrade  # Ubuntu/Debian
brew update                          # macOS

# Check Python
python3 --version
```

### Step 2: Navigate to Project Directory
```bash
# Windows
cd c:\Users\zohai\Desktop\mainnn\IDS\IDS\myIDS

# Linux/Mac
cd ~/path/to/myIDS
```

### Step 3: Create Virtual Environment

**Windows (PowerShell):**
```bash
python -m venv venv
```

**Linux/Mac:**
```bash
python3 -m venv venv
```

### Step 4: Activate Virtual Environment

**Windows (PowerShell):**
```bash
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```bash
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

**You should see `(venv)` prefix in your terminal**

### Step 5: Install Python Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install all requirements
pip install django==6.0.3
pip install joblib
pip install numpy
pip install pandas
pip install scikit-learn
pip install scapy
```

**Optional (for ML predictions):**
```bash
pip install tensorflow keras
# Note: These are large packages (1-2GB), only needed for full ML functionality
```

### Step 6: Verify Installation
```bash
pip list  # View all installed packages
```

Expected packages:
- Django
- joblib
- numpy
- pandas
- scikit-learn
- scapy
- (tensorflow, keras - if installed)

### Step 7: Database Setup

```bash
# Run migrations to create database tables
python manage.py migrate

# You should see output like:
# Running migrations:
#   Applying contenttypes.0001_initial... OK
#   Applying auth.0001_initial... OK
#   ...
```

### Step 8: Create Admin Account (Optional but Recommended)

```bash
python manage.py createsuperuser

# Follow prompts:
# Username: admin
# Email: admin@example.com
# Password: your_secure_password
```

### Step 9: Collect Static Files (Production)

```bash
python manage.py collectstatic --noinput
```

### Step 10: Start Development Server

```bash
python manage.py runserver
```

**Expected output:**
```
Starting development server at http://127.0.0.1:8000/
Django version 6.0.3, using settings 'myIDS.settings'
System check identified no issues (0 silenced).
```

**Access the application:**
- Home: http://127.0.0.1:8000/
- Admin: http://127.0.0.1:8000/admin/
- User Dashboard: http://127.0.0.1:8000/user-dashboard/

---

## ⚙️ Configuration

### Configure Email Notifications

Edit `myIDS/settings.py`:

```python
# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your_email@gmail.com'
EMAIL_HOST_PASSWORD = 'your_app_password'
DEFAULT_FROM_EMAIL = 'your_email@gmail.com'

# Gmail Setup:
# 1. Enable 2-Factor Authentication in Gmail
# 2. Create App Password: https://myaccount.google.com/apppasswords
# 3. Use App Password instead of regular password
```

**Test Email Configuration:**
```bash
python manage.py shell

# Inside Django shell:
from django.core.mail import send_mail
send_mail(
    'Subject here',
    'Here is the message.',
    'your_email@gmail.com',
    ['recipient@example.com'],
    fail_silently=False,
)
```

### Configure Network Interface (for traffic capture)

Edit `myapp/views.py`, find section:

```python
# Identify correct network interface
interfaces = get_if_list()
print("Available Network Interfaces:", interfaces)
WIFI_INTERFACE = r"\Device\NPF_{YOUR_INTERFACE_ID}"  
```

**Find your interface:**
```bash
python manage.py shell

# Inside Django shell:
from scapy.all import get_if_list
interfaces = get_if_list()
for i in interfaces:
    print(i)

# Copy the interface ID for your active network connection
```

### Configure Database (for Production)

Change from SQLite to PostgreSQL in `myIDS/settings.py`:

```python
# Production: Use PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'deepthreats_db',
        'USER': 'postgres',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# First install psycopg2:
# pip install psycopg2-binary
```

---

## 🔐 Security Configuration

### Development vs Production

**Development (current):**
```python
DEBUG = True
ALLOWED_HOSTS = []
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
SECRET_KEY = 'django-insecure-xxx'  # Change this!
```

**Production Checklist:**
```python
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECRET_KEY = os.environ.get('SECRET_KEY')  # Use environment variable

# Run checks:
python manage.py check --deploy
```

### Change Secret Key

```bash
# Generate new secret key
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Update in settings.py
SECRET_KEY = 'newly_generated_key'
```

---

## 📊 ML Model Setup

### Model Files Location
```
myapp/models/
├── GRU_IDS_model.keras      # Trained neural network
├── scaler.pkl               # Feature scaler
└── label_encoder.pkl        # Label encoder
```

### Load Model Manually (for testing)

```bash
python manage.py shell

# Inside Django shell:
import tensorflow as tf
model = tf.keras.models.load_model('myapp/models/GRU_IDS_model.keras')
print(model.summary())  # Show model architecture
```

### Train Custom Model

```bash
# If you have training data:
python manage.py shell

# Inside Django shell:
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import tensorflow as tf

# Load your training data
X_train = pd.read_csv('training_data.csv')  # 43 features

# Scale features
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X_train)

# Train model
model = tf.keras.Sequential([
    tf.keras.layers.GRU(64, input_shape=(1, 43)),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dense(num_classes, activation='softmax')
])

model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
model.fit(X_scaled, y_encoded, epochs=50, batch_size=32)
```

---

## 🚀 Running the Application

### Start in Development Mode

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate     # Linux/Mac

# Run server
python manage.py runserver
```

### Run on Different Port

```bash
python manage.py runserver 8001
python manage.py runserver 0.0.0.0:8000  # Accessible from network
```

### Run in Production Mode (with Gunicorn)

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn myIDS.wsgi:application --bind 0.0.0.0:8000 --workers 4
```

### Run as Background Process (Windows)

```bash
# Create start_server.bat
python manage.py runserver

# Run:
start start_server.bat
```

---

## 🧪 Testing the System

### Test 1: Access Home Page
```bash
# In browser:
http://127.0.0.1:8000/

# Expected: See DeepThreat home page with login/signup options
```

### Test 2: Create User Account
```bash
# Go to: http://127.0.0.1:8000/signup/
# Fill form:
# - First Name: John
# - Last Name: Doe
# - Username: johndoe
# - Email: john@example.com
# - Password: SecurePass123

# Expected: Success message, redirect to login
```

### Test 3: Login
```bash
# Go to: http://127.0.0.1:8000/login/
# Enter credentials
# Expected: Redirect to user dashboard
```

### Test 4: View Dashboard
```bash
# After login, you should see:
# - Welcome message
# - Statistics cards
# - Traffic table
# - Anomalies table
# - Action buttons
```

### Test 5: Check Admin Panel
```bash
# Go to: http://127.0.0.1:8000/admin/
# Login with superuser credentials
# Expected: See admin panel with Users, Contact, Traffic models
```

### Test 6: View Database Records

```bash
python manage.py shell

# Inside Django shell:
from django.contrib.auth.models import User
print(User.objects.all())  # All users

from myapp.models import CapturedTraffic, Contact
print(CapturedTraffic.objects.count())  # Total traffic packets
print(Contact.objects.all())  # All contact submissions
```

---

## 🔍 Monitoring & Logging

### View Server Logs
```bash
# Logs appear in terminal running Django
# You can redirect to file:
python manage.py runserver > server.log 2>&1
```

### Enable Debug Logging

In `myIDS/settings.py`:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
        },
    },
    'root': {
        'handlers': ['file'],
        'level': 'DEBUG',
    },
}
```

### View Traffic Monitoring Logs

```bash
# During capture, logs show in terminal
# Or check database:
python manage.py shell

from myapp.models import CapturedTraffic
traffic = CapturedTraffic.objects.latest('timestamp')
print(traffic.src_ip, traffic.dest_ip, traffic.prediction)
```

---

## 📋 Checklist for First-Time Setup

- [ ] Python 3.10+ installed
- [ ] Virtual environment created
- [ ] Virtual environment activated
- [ ] Dependencies installed
- [ ] Database migrated
- [ ] Superuser created (optional)
- [ ] Email configured (optional)
- [ ] Network interface identified
- [ ] Development server running
- [ ] Home page accessible
- [ ] User account created
- [ ] Login working
- [ ] Dashboard displaying data

---

## ❌ Common Issues & Solutions

### Issue: "ModuleNotFoundError: No module named 'django'"
```bash
# Solution: Ensure virtual environment is activated
# Windows:
.\venv\Scripts\Activate.ps1

# Linux/Mac:
source venv/bin/activate

# Then install:
pip install django
```

### Issue: "Port 8000 already in use"
```bash
# Solution 1: Use different port
python manage.py runserver 8001

# Solution 2: Kill process using port 8000 (Windows)
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Solution 2: Kill process using port 8000 (Linux)
lsof -i :8000
kill -9 <PID>
```

### Issue: "FileNotFoundError: [Errno 2] No such file or directory: db.sqlite3"
```bash
# Solution: Run migrations
python manage.py migrate
```

### Issue: "DisallowedHost at /: Invalid HTTP_HOST header"
```python
# Solution: Add to ALLOWED_HOSTS in settings.py
ALLOWED_HOSTS = ['*']  # Development only!
```

---

## 🎓 Next Steps After Installation

1. **Create test user account**
2. **Explore admin panel** (`/admin/`)
3. **Setup email notifications**
4. **Configure network interface**
5. **Start monitoring traffic**
6. **Review dashboard features**
7. **Test threat detection**
8. **Set up production deployment**

---

**Installation Complete! 🎉**

For more information, see main README.md file.
