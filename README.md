# ThreatGuard AI
## Behavioral Log-Based Insider Threat Level Detection Using Anomaly Analytics
### College Mini Project | Python Flask + Machine Learning

---

## 📁 Project Structure

```
threatguard/
├── app.py                  ← Flask main application (routes + API)
├── requirements.txt        ← Python dependencies
├── data/
│   └── threatguard.db      ← SQLite database (auto-created)
├── models/
│   ├── __init__.py
│   ├── anomaly_detector.py ← Isolation Forest ML model
│   ├── risk_engine.py      ← Risk scoring + alert generation
│   └── data_generator.py   ← Demo data seeder
└── templates/
    ├── login.html          ← Login page (with demo credentials)
    ├── user_dashboard.html ← Employee portal
    └── admin_dashboard.html← Security Operations Center
```

---

## ⚡ Quick Setup

### Step 1 — Install dependencies
```bash
pip install flask scikit-learn numpy pandas
```

### Step 2 — Run the application
```bash
cd threatguard
python app.py
```

### Step 3 — Open in browser
```
http://localhost:5000
```

---

## 🔑 Demo Login Credentials

| Role         | User ID    | Password   |
|-------------|------------|------------|
| Admin       | admin_01   | admin123   |
| Normal User | EMP_001    | pass123    |
| High Risk   | EMP_006    | pass123    |
| Medium Risk | EMP_005    | pass123    |

---

## 🎯 Key Features

### User Dashboard
- Personal risk score (0–100) with gauge visualization
- Activity log with suspicious event detection
- File access monitoring vs baseline (100 files reference)
- Security alert notifications
- Demo simulator (trigger bulk access / off-hours / failed logins)

### Admin Dashboard
- Real-time alert feed with acknowledge functionality
- User risk leaderboard with investigation modal
- ML detection trigger button (runs Isolation Forest)
- XAI explanation panel (why a user is flagged)
- Charts: org risk trend, distribution, anomaly by hour, threat categories

### ML Pipeline
- **Isolation Forest** — detects statistical outliers in user behavior
- **Feature Extraction** — files accessed, failed logins, off-hours, unknown IPs
- **Risk Engine** — converts anomaly scores → 0–100 risk score → LOW/MEDIUM/HIGH
- **Alert Manager** — generates typed alerts with full context

---

## 🔄 Data Flow

```
User logs activity → activity_logs table
       ↓
Admin clicks "Run ML Detection"
       ↓
Extract features per user (files, logins, hours, IPs)
       ↓
Isolation Forest predicts anomaly score (0–1)
       ↓
Risk Engine: score × 70 + contextual bonuses = risk_score/100
       ↓
If MEDIUM or HIGH → generate alert → alerts table
       ↓
Admin Dashboard shows updated rankings & alerts
```

---

## 📊 Example Alert

```
ALERT: Bulk File Access Detected
User: EMP_006
Files Accessed: 487 (Baseline: 120)
Ratio: 4.06x above baseline
Risk Level: HIGH (87/100)
Triggers: Off-hours activity, unknown IP, bulk writes
```

---

## 🛠 API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | /api/run-detection | Run ML anomaly detection on all users |
| GET  | /api/user-detail/<uid> | Full user logs + alerts for investigation |
| GET  | /api/dashboard-stats | KPI counts for admin dashboard |
| GET  | /api/alerts | All alerts (latest 30) |
| POST | /api/acknowledge-alert/<id> | Mark alert as acknowledged |
| POST | /api/simulate-event/<uid> | Inject demo suspicious event |

---

## 📚 Technology Stack

- **Backend**: Python + Flask
- **ML Model**: scikit-learn Isolation Forest
- **Database**: SQLite (file-based, no setup required)
- **Frontend**: HTML5 + CSS3 + Vanilla JS
- **Charts**: Chart.js (CDN)
- **Fonts**: Google Fonts (Syne, DM Mono, Instrument Sans)
