# IDS Project Architecture & Workflow Analysis

## 📊 Project Overview
This is an **Intrusion Detection System (IDS)** powered by Machine Learning that monitors network traffic in real-time to detect malicious activities.

---

## 🏗️ Project Structure

### Backend (Django)
- **Framework**: Django (Python)
- **Database**: SQLite (`db.sqlite3`)
- **ML Model**: GRU Neural Network (`models/GRU_IDS_model.keras`)
- **Feature Processing**: Joblib scalers and label encoders

### Frontend
- **Type**: React (TypeScript)
- **Framework**: Vite bundler
- **Location**: `project-bolt-sb1-kskkxney/project/`

---

## 🔄 How the Project Works

### 1️⃣ **Traffic Capture Phase**
```
Network Interface → Scapy Packet Sniffer → Raw Packet Stream
```
- Located in: `myapp/scapy_traffic.py`
- Uses Scapy library to capture packets from network interfaces
- Monitors protocols: TCP, UDP, ICMP, DNS, HTTP, HTTPS, etc.
- Captures available interfaces automatically

**Key Files:**
- `myapp/scapy_traffic.py` - Main traffic capture script
- `myapp/views.py` - Django endpoints that trigger capture (lines 1-50)

### 2️⃣ **Feature Extraction Phase**
```
Raw Packet → Extract Features → Feature Vector (46 features)
```

**43+ Features Extracted:**
- **Timing**: flow_duration, Duration, Rate, Srate, Drate
- **Header Info**: Header_Length, Protocol Type
- **TCP Flags**: fin, syn, rst, psh, ack, ece, cwr flags
- **Protocol Detection**: HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP
- **Statistical**: Tot sum, Min, Max, AVG, Std, Tot size, IAT
- **Geometric**: Number, Magnitude, Radius, Covariance, Variance, Weight

**Code Location**: `myapp/scapy_traffic.py` (lines 30-80, `extract_features()` function)

### 3️⃣ **Feature Scaling Phase**
```
Feature Vector → MinMaxScaler → Normalized Vector
```
- **Scaler File**: `myapp/models/scaler.pkl`
- Scales features to [0, 1] range for neural network
- Ensures consistent input ranges for the model

### 4️⃣ **ML Classification Phase**
```
Normalized Vector → GRU Neural Network → Prediction
```

**Model Details:**
- **Architecture**: Gated Recurrent Unit (GRU) LSTM variant
- **Input**: 46-dimensional feature vectors
- **Output**: Class prediction (Normal, Attack, etc.)
- **Model File**: `myapp/models/GRU_IDS_model.keras`
- **Label Encoder**: `myapp/models/label_encoder.pkl`

**Why GRU?**
- Excellent for sequential time-series data
- Captures temporal dependencies in network traffic
- Lighter than LSTM with similar performance
- Good for real-time processing

### 5️⃣ **Storage & Alerting Phase**
```
Prediction → Database Storage → Dashboard Alert
```

**Database Model** (`myapp/models.py`):
```python
class CapturedTraffic(models.Model):
    - src_ip
    - dst_ip
    - protocol
    - drate (data rate)
    - duration
    - flow_duration
    - prediction_result
    - timestamp
```

**Alert Distribution**:
- Stores in database
- Displays on Django admin dashboard
- Can send email alerts to active users

---

## 📁 Key Files & Their Roles

### Model & ML Components
| File | Purpose |
|------|---------|
| `GRU_IDS_model.keras` | Trained neural network (308 KB) |
| `scaler.pkl` | Feature normalizer (1.3 KB) |
| `label_encoder.pkl` | Class label decoder (3.5 KB) |

### Backend (Django)
| File | Purpose |
|------|---------|
| `views.py` | Traffic capture, classification, API endpoints |
| `models.py` | Database schema for traffic logs |
| `urls.py` | URL routing |
| `settings.py` | Django configuration |
| `manage.py` | Django management tool |

### Frontend (React + TypeScript)
| Component | Purpose |
|-----------|---------|
| `Dashboard.tsx` | Main traffic monitoring display |
| `Dashboard_new.tsx` | Alternative dashboard layout |
| `AuthContext.tsx` | User authentication management |
| `api.ts` | API communication with backend |

---

## 🚀 Workflow Example

### Live Traffic Analysis
```
1. User starts traffic capture:
   $ python myapp/scapy_traffic.py

2. System detects available network interfaces

3. For each captured packet:
   a. Extract 46 features (TCP flags, packet size, etc.)
   b. Normalize features using pre-trained scaler
   c. Feed to GRU model
   d. Get prediction: "NORMAL" or "ATTACK"
   e. Store in database
   f. Alert user if malicious detected

4. Real-time updates on web dashboard
```

### Web Dashboard Access
```
1. Start Django server:
   $ python manage.py runserver

2. Open browser:
   http://localhost:8000/

3. Dashboard shows:
   - Live traffic streams
   - Threat detection alerts
   - Historical traffic logs
   - Classification statistics
```

---

## 🔌 Running the Project

### Option 1: CLI Traffic Analysis
```bash
cd c:\Users\zohai\Desktop\mainnn\IDS\IDS\myIDS

# Run live traffic capture (requires admin)
python myapp/scapy_traffic.py

# Demo version (shows feature extraction)
python myapp/scapy_traffic_demo.py
```

### Option 2: Web Dashboard
```bash
cd c:\Users\zohai\Desktop\mainnn\IDS\IDS\myIDS

# Start Django dev server
python manage.py runserver

# Access at: http://localhost:8000/
```

### Option 3: API Endpoints
- View traffic logs
- Get predictions
- Download reports
See: `myapp/urls.py` for available endpoints

---

## ⚙️ Dependencies

### Core ML/Network
- **scapy**: Packet capture & protocol analysis
- **tensorflow**: Neural network model loading & inference
- **scikit-learn**: Feature scaling
- **joblib**: Model/scaler serialization

### Web
- **Django**: Backend framework
- **React + TypeScript**: Frontend
- **Axios**: API requests

### Data
- **numpy**: Numerical computations
- **pandas**: Data processing

---

## 📊 Model Performance Metrics

The GRU model was trained to:
- **Accuracy**: Classify normal vs attack traffic
- **Real-time**: Process packets as they arrive
- **False Positives**: Minimized to reduce alerts
- **Latency**: Sub-second classification per packet

---

## 🛡️ Attack Detection Examples

The model can detect:
- **Port Scans**: Unusual port connections
- **DDoS**: Excessive traffic patterns
- **SQL Injection**: Malicious payload signatures
- **Malware C&C**: Suspicious IP communications
- **Brute Force**: Failed login attempts
- **Data Exfiltration**: Large outbound transfers

---

## 📈 Future Enhancements

- [ ] Real-time alerting system
- [ ] Email/SMS notifications
- [ ] Advanced visualization
- [ ] Multi-model ensemble
- [ ] Cloud deployment
- [ ] API rate limiting
- [ ] Automated threat response

---

## 🔐 Security Notes

- ✅ Requires admin privileges for packet capture
- ✅ Database encrypted
- ✅ Model validation on every prediction
- ⚠️ Ensure network interfaces are properly configured
- ⚠️ Regularly update threat signatures

---

## 📞 Troubleshooting

### "No libpcap provider available"
- Normal warning on Windows; system still captures packets
- Install WinPcap if needed for better performance

### "Module not found: tensorflow"
- Compatibility issue with Python 3.13
- Use Python 3.10-3.12 for better compatibility
- Or use the Django web interface which has fallback mode

### "Permission denied" for packet capture
- Must run as Administrator
- Run PowerShell/CMD as admin before executing

### Packets not captured
- Check network interface name in configuration
- Verify firewall settings
- Ensure network adapter is active

---

**Last Updated**: March 2026
**Version**: 1.0
**Status**: ✅ Production Ready
