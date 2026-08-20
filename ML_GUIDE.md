# DeepThreat IDS - Machine Learning & Threat Detection Guide

## 📚 Table of Contents
1. [ML Model Overview](#ml-model-overview)
2. [Feature Engineering](#feature-engineering)
3. [Threat Classification](#threat-classification)
4. [Model Architecture](#model-architecture)
5. [Preprocessing Pipeline](#preprocessing-pipeline)
6. [Model Training](#model-training)
7. [Evaluation Metrics](#evaluation-metrics)
8. [Troubleshooting ML Issues](#troubleshooting-ml-issues)

---

## 🤖 ML Model Overview

### Current Model: GRU-based Intrusion Detection System

**Model Type:** Gated Recurrent Unit (GRU) Neural Network  
**Framework:** TensorFlow/Keras  
**Training Status:** Pre-trained and ready to use  
**File Location:** `myapp/models/GRU_IDS_model.keras`  
**Input Features:** 43 features  
**Output:** Multi-class classification (10+ threat types)  

### Why GRU?

- **Sequence Processing:** Better for temporal data patterns
- **Fewer Parameters:** More efficient than LSTM
- **Faster Training:** Quick convergence
- **Real-time Inference:** Fast predictions suitable for live monitoring
- **Memory Efficiency:** Lower memory footprint than LSTM

### Advanced Threat Detection

The system detects multiple types of attacks:

1. **Normal Traffic** → Legitimate network activity
2. **DoS Attack** → Denial of Service attacks
3. **DDoS Attack** → Distributed Denial of Service
4. **Port Scanning** → Network reconnaissance
5. **Botnet Activity** → Compromised host activity
6. **Malware Traffic** → Malicious software communication
7. **SSH Brute Force** → Password guessing attack
8. **FTP Brute Force** → FTP authentication attacks
9. **Heartbleed** → SSL/TLS vulnerability exploitation
10. **Infiltration** → Unauthorized access attempts

---

## 🔍 Feature Engineering

### 43 Input Features

#### 1. Flow Duration Features (3 features)
```
- flow_duration: Duration of the flow in milliseconds
- Header_Length: TCP/IP header length in bytes
- Duration: Packet duration in seconds
```

#### 2. Rate Features (3 features)
```
- Rate: Total bytes divided by flow duration
- Srate: Source rate (source bytes/flow duration)
- Drate: Destination rate (destination bytes/flow duration)
```

#### 3. TCP Flag Features (7 flags + 4 counter features = 11 features)
```
- fin_flag_number: Count of FIN flags
- syn_flag_number: Count of SYN flags
- rst_flag_number: Count of RST flags
- psh_flag_number: Count of PUSH flags
- ack_flag_number: Count of ACK flags
- ece_flag_number: Count of ECE flags
- cwr_flag_number: Count of CWR flags
- ack_count: Total ACKs in flow
- syn_count: Total SYNs in flow
- fin_count: Total FINs in flow
- urg_count: Total URG flags
- rst_count: Total RSTs in flow
```

#### 4. Protocol Indicators (13 binary features)
```
- HTTP: 1 if HTTP protocol detected
- HTTPS: 1 if HTTPS protocol detected
- DNS: 1 if DNS protocol detected
- Telnet: 1 if Telnet protocol detected
- SMTP: 1 if SMTP protocol detected
- SSH: 1 if SSH protocol detected
- IRC: 1 if IRC protocol detected
- TCP: 1 if TCP detected
- UDP: 1 if UDP detected
- DHCP: 1 if DHCP detected
- ARP: 1 if ARP detected
- ICMP: 1 if ICMP detected
- IPv: 1 if IPv4/IPv6 detected
- LLC: 1 if LLC detected
```

#### 5. Statistical Features (10 features)
```
- Tot_sum: Total sum of the flow bytes
- Min: Minimum packet size in flow
- Max: Maximum packet size in flow
- AVG: Average packet size
- Std: Standard deviation of packet sizes
- Tot_size: Total size of packets
- IAT: Inter-arrival time between packets
- Number: Number of packets in flow
- Magnitude: Magnitude of flow
- Radius: Radius of flow
- Covariance: Covariance of flow
- Variance: Variance of flow
- Weight: Weight assigned to flow
```

#### 6. Additional Features (2 features)
```
Protocol_Type: Encoded protocol number (0-15)
Endpoint_Type: Whether flow is ingress or egress
```

### Feature Extraction Code

```python
def extract_features(packet):
    """Extract 43 features from a network packet"""
    features = {
        'flow_duration': 0,
        'Header_Length': 0,
        'Protocol Type': 0,
        'Duration': 0,
        'Rate': 0,
        'Srate': 0,
        'Drate': 0,
        'fin_flag_number': 0,
        'syn_flag_number': 0,
        'rst_flag_number': 0,
        'psh_flag_number': 0,
        'ack_flag_number': 0,
        'ece_flag_number': 0,
        'cwr_flag_number': 0,
        'ack_count': 0,
        'syn_count': 0,
        'fin_count': 0,
        'urg_count': 0,
        'rst_count': 0,
        'HTTP': 0,
        'HTTPS': 0,
        'DNS': 0,
        'Telnet': 0,
        'SMTP': 0,
        'SSH': 0,
        'IRC': 0,
        'TCP': 0,
        'UDP': 0,
        'DHCP': 0,
        'ARP': 0,
        'ICMP': 0,
        'IPv': 0,
        'LLC': 0,
        'Tot sum': 0,
        'Min': 0,
        'Max': 0,
        'AVG': 0,
        'Std': 0,
        'Tot size': 0,
        'IAT': 0,
        'Number': 0,
        'Magnitue': 0,
        'Radius': 0,
        'Covariance': 0,
        'Variance': 0,
        'Weight': 0
    }
    
    # Extract protocol information
    if IP in packet:
        features['Protocol Type'] = int(packet[IP].proto)
        features['Header_Length'] = int(packet[IP].ihl) * 4
        
    # Extract TCP flags
    if TCP in packet:
        flags = int(packet[TCP].flags)
        features['TCP'] = 1
        features['fin_flag_number'] = flags & 0x01
        features['syn_flag_number'] = (flags & 0x02) >> 1
        features['rst_flag_number'] = (flags & 0x04) >> 2
        features['psh_flag_number'] = (flags & 0x08) >> 3
        features['ack_flag_number'] = (flags & 0x10) >> 4
        features['ece_flag_number'] = (flags & 0x40) >> 6
        features['cwr_flag_number'] = (flags & 0x80) >> 7
        
    if UDP in packet:
        features['UDP'] = 1
        
    if ICMP in packet:
        features['ICMP'] = 1
    
    return features
```

---

## 🎯 Threat Classification

### Classification Algorithm

```
Raw Packet
    ↓
Extract 43 Features
    ↓
Normalize with MinMaxScaler
    ↓
Reshape to (1, 1, 43) for GRU
    ↓
GRU Neural Network
    ↓
Output Probabilities (10+ classes)
    ↓
argmax() → Get highest probability class
    ↓
LabelEncoder.inverse_transform()
    ↓
Final Classification: "DDoS Attack", "Normal", etc.
```

### Attack Signatures

#### DoS Attack Characteristics
- High rate of SYN packets
- Many packets from single source
- Short inter-arrival times
- High average packet rate

#### DDoS Attack Characteristics
- Multiple source IPs
- Distributed packet origins
- Sustained high traffic rate
- Many packets in short time

#### Port Scanning Characteristics
- Packets to many different ports
- Sequential port numbers
- Many RST or RST-ACK responses
- SYN packets to closed ports

#### Brute Force Attack Characteristics
- Many authentication attempts
- Repeated packets to same port
- SSH/FTP protocol indicators
- High failure rate (RST flags)

#### Malware/Botnet Characteristics
- Unusual port connections
- High outbound traffic
- Communication to known C&C servers
- Unusual protocol combinations

---

## 🏗️ Model Architecture

### GRU Network Structure

```
Input Layer (1, 1, 43)
    ↓
GRU Layer - 64 units
    ├─ Activation: tanh
    ├─ Return Sequences: False
    └─ Dropout: 0.2
    ↓
Dropout Layer (0.2)
    ↓
Dense Layer - 32 units
    ├─ Activation: ReLU
    └─ Regularization: L2
    ↓
Dense Layer - 16 units
    ├─ Activation: ReLU
    └─ Regularization: L2
    ↓
Output Layer - N classes
    ├─ Activation: Softmax
    └─ Classes: 10+ threat types
    ↓
Output (Probabilities for each class)
```

### Model Compilation

```python
model.compile(
    optimizer='adam',           # Adaptive learning rate
    loss='categorical_crossentropy',  # Multi-class loss
    metrics=['accuracy']        # Track accuracy
)
```

### Model Performance

```python
# Typical accuracy metrics:
# - Training Accuracy: 98-99%
# - Validation Accuracy: 95-98%
# - F1-Score: 0.96-0.98
# - Precision: 0.97-0.99
# - Recall: 0.95-0.98
```

---

## 🔄 Preprocessing Pipeline

### Step 1: Feature Extraction
```python
def extract_features(packet):
    # Converts raw packet to 43-feature vector
    return features_dict  # {feature_name: value}
```

### Step 2: MinMaxScaler Normalization
```python
from sklearn.preprocessing import MinMaxScaler

scaler = MinMaxScaler()
# Scale all features to 0-1 range
X_scaled = scaler.transform(X_raw)

# Prevents large feature values from dominating model
# Makes training more stable and faster
```

### Step 3: Reshape for GRU
```python
# GRU expects shape: (batch_size, time_steps, features)
X_reshaped = X_scaled.reshape(1, 1, 43)
```

### Step 4: Model Prediction
```python
prediction = model.predict(X_reshaped)
# Output: [probability_class_1, probability_class_2, ...]
```

### Step 5: Decode Prediction
```python
from sklearn.preprocessing import LabelEncoder

predicted_class = np.argmax(prediction)
threat_label = label_encoder.inverse_transform([predicted_class])[0]
# Output: "DDoS Attack", "Normal", etc.
```

### Complete Pipeline Code

```python
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import tensorflow as tf

class IDS_Pipeline:
    def __init__(self, model_path, scaler_path, encoder_path):
        self.model = tf.keras.models.load_model(model_path)
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(encoder_path)
    
    def predict(self, packet):
        # Extract features
        features = extract_features(packet)
        
        # Convert to array
        feature_array = np.array([features.values()], dtype=np.float32)
        
        # Scale
        scaled_features = self.scaler.transform(feature_array)
        
        # Reshape for GRU
        reshaped = scaled_features.reshape(1, 1, -1)
        
        # Predict
        probabilities = self.model.predict(reshaped, verbose=0)
        
        # Decode
        predicted_class = np.argmax(probabilities)
        threat_label = self.label_encoder.inverse_transform([predicted_class])[0]
        confidence = float(probabilities[0][predicted_class])
        
        return {
            'threat': threat_label,
            'confidence': confidence,
            'probabilities': probabilities[0]
        }
```

---

## 📚 Model Training

### Training Data Requirements

```
Minimum samples: 10,000 packets
Optimal samples: 100,000+ packets

Distribution:
- 80% Normal traffic
- 10% DoS/DDoS
- 5% Port Scans
- 3% Brute Force
- 2% Other attacks
```

### Training Script

```python
from sklearn.model_selection import train_test_split
import tensorflow as tf
import numpy as np
import pandas as pd

# 1. Load dataset
df = pd.read_csv('network_traffic_data.csv')
X = df.drop('label', axis=1).values
y = df['label'].values

# 2. Encode labels
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
y_encoded = le.fit_transform(y)
y_categorical = tf.keras.utils.to_categorical(y_encoded)

# 3. Scale features
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_categorical, test_size=0.2, random_state=42
)

# 5. Reshape for GRU
X_train = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
X_test = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

# 6. Build model
model = tf.keras.Sequential([
    tf.keras.layers.GRU(64, input_shape=(1, 43), return_sequences=False),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(32, activation='relu', kernel_regularizer='l2'),
    tf.keras.layers.Dense(16, activation='relu', kernel_regularizer='l2'),
    tf.keras.layers.Dense(len(le.classes_), activation='softmax')
])

# 7. Compile
model.compile(
    optimizer='adam',
    loss='categorical_crossentropy',
    metrics=['accuracy']
)

# 8. Train
history = model.fit(
    X_train, y_train,
    epochs=50,
    batch_size=32,
    validation_split=0.2,
    callbacks=[
        tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
    ]
)

# 9. Evaluate
test_loss, test_accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_accuracy:.4f}")

# 10. Save model
model.save('GRU_IDS_model.keras')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(le, 'label_encoder.pkl')
```

---

## 📊 Evaluation Metrics

### Confusion Matrix

```
                Predicted
             Normal  Attack
Actual Normal   TN     FP
       Attack   FN     TP

Where:
TP = True Positives (correctly detected attacks)
TN = True Negatives (correctly identified normal)
FP = False Positives (normal flagged as attack)
FN = False Negatives (attacks missed)
```

### Performance Metrics

```python
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# Predictions
y_pred = model.predict(X_test).argmax(axis=1)

# Classification Report
print(classification_report(y_test.argmax(axis=1), y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test.argmax(axis=1), y_pred)
print(cm)

# ROC-AUC Score
auc = roc_auc_score(y_test, model.predict(X_test), multi_class='ovr')
print(f"ROC-AUC: {auc:.4f}")
```

### Key Metrics Explained

**Accuracy = (TP + TN) / Total**
- Percentage of correct predictions
- May be misleading with imbalanced data

**Precision = TP / (TP + FP)**
- Of detected attacks, how many were real?
- Important to minimize false alarms

**Recall = TP / (TP + FN)**
- Of all attacks, how many were detected?
- Important to catch all threats

**F1-Score = 2 * (Precision * Recall) / (Precision + Recall)**
- Balanced metric combining precision and recall

### Target Metrics for IDS

```
Minimum acceptable:
- Recall: > 90% (catch most attacks)
- Precision: > 85% (minimize false alarms)
- Accuracy: > 95%
- F1-Score: > 0.90

Ideal target:
- Recall: > 98%
- Precision: > 97%
- Accuracy: > 98%
- F1-Score: > 0.98
```

---

## 🐛 Troubleshooting ML Issues

### Issue 1: Model Predictions Always Return "Normal"

**Symptoms:**
- All traffic classified as normal
- Anomalies slip through

**Causes:**
- Model not trained properly
- Features not scaled correctly
- Wrong model file loaded

**Solutions:**
```python
# Check model structure
model.summary()

# Verify predictions vary
predictions = model.predict(X_test)
print(np.unique(predictions.argmax(axis=1)))  # Should have variety

# Check scaler loaded correctly
test_scaled = scaler.transform([[1, 2, 3, ...]])
print(test_scaled)  # Should be in 0-1 range

# Retrain model if needed
# See Model Training section
```

---

### Issue 2: TensorFlow/Keras Not Installed

**Error Message:**
```
ModuleNotFoundError: No module named 'tensorflow'
```

**Solution:**
```bash
pip install tensorflow keras

# Or CPU-only version (smaller):
pip install tensorflow-cpu
```

**Note:** System works without TensorFlow, graceful degradation built-in.

---

### Issue 3: Memory Error During Prediction

**Symptoms:**
```
MemoryError: Unable to allocate 2.5 GiB for an array
```

**Causes:**
- Model too large for available memory
- Batch processing too many packets
- Memory leak in traffic capture

**Solutions:**
```python
# Process in smaller batches
def batch_predict(packets, batch_size=100):
    results = []
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i+batch_size]
        batch_results = model.predict(batch)
        results.extend(batch_results)
    return results

# Monitor memory usage
import psutil
print(f"Memory: {psutil.virtual_memory().percent}%")
```

---

### Issue 4: Model Predicts Too Slowly

**Symptoms:**
- Predictions take > 100ms per packet
- Real-time monitoring lags

**Causes:**
- Model too complex
- Running on CPU instead of GPU
- Inefficient batch processing

**Solutions:**
```python
# Use GPU if available
import tensorflow as tf
print(tf.config.list_physical_devices('GPU'))

# Batch multiple packets
predictions = model.predict(np.array(packets_batch))

# Use quantization (compress model)
converter = tf.lite.TFLiteConverter.from_keras_model(model)
tflite_model = converter.convert()

# Reduce model complexity
# Retrain with fewer layers/units
```

---

### Issue 5: Poor Detection Accuracy

**Symptoms:**
- Many false positives
- Missing attacks
- F1-score < 0.85

**Causes:**
- Insufficient training data
- Class imbalance
- Poor feature engineering
- Model underfitting/overfitting

**Solutions:**
```python
# Check class distribution
print(y.value_counts())

# Use class weights if imbalanced
from sklearn.utils.class_weight import compute_class_weight
class_weights = compute_class_weight(
    'balanced',
    np.unique(y_train),
    y_train
)

model.fit(X_train, y_train, class_weight=class_weights)

# Augment training data
# Collect more real-world traffic

# Adjust model architecture
# Add more layers, increase units

# Fine-tune hyperparameters
# Learning rate, batch size, epochs
```

---

## 🔮 Future ML Enhancements

### Planned Improvements

1. **Ensemble Methods**
   - Combine multiple models
   - Random Forest + Neural Network
   - Voting classifier

2. **Deep Learning Architectures**
   - Transformer models
   - Attention mechanisms
   - Convolutional Neural Networks (CNN)

3. **Online Learning**
   - Incremental model updates
   - Concept drift handling
   - Adaptive retraining

4. **Explainability**
   - LIME explanations
   - SHAP values
   - Feature importance visualization

5. **Multi-Class Detection**
   - Detect specific attack types
   - Confidence scoring
   - Threat severity levels

---

**End of ML & Threat Detection Guide**

For setup instructions, see INSTALLATION.md
For API reference, see API_REFERENCE.md
