"""
Anomaly Detection Engine
Uses Isolation Forest to detect behavioral anomalies in user activity logs
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle, os
from datetime import datetime


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,   # expect ~10% anomalous users
            random_state=42,
            max_features=1.0
        )
        self.scaler = StandardScaler()
        self.model_path = "models/isolation_forest.pkl"
        self.is_fitted = False

        # Try to load pre-trained model
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                saved = pickle.load(f)
                self.model = saved["model"]
                self.scaler = saved["scaler"]
                self.is_fitted = True

    def extract_features(self, logs, baseline_files=100):
        """
        Extract behavioral features from raw activity logs.
        Returns a feature dict and numpy array.
        """
        total_files = sum(r["files_accessed"] for r in logs)
        total_events = len(logs)
        failed_logins = sum(1 for r in logs if r["action"] == "LOGIN_FAILED")
        bulk_accesses = sum(1 for r in logs if r["files_accessed"] > 50)
        suspicious_events = sum(1 for r in logs if r["status"] == "suspicious")
        unknown_ips = sum(1 for r in logs if "unknown" in str(r.get("ip_address", "")))

        # Off-hours activity (before 8am or after 8pm)
        off_hours = 0
        for r in logs:
            try:
                ts = datetime.strptime(str(r["timestamp"])[:19], "%Y-%m-%d %H:%M:%S")
                if ts.hour < 8 or ts.hour >= 20:
                    off_hours += 1
            except Exception:
                pass

        # Ratio of files accessed vs baseline
        access_ratio = total_files / max(baseline_files, 1)

        features = {
            "total_files_accessed": total_files,
            "access_ratio": access_ratio,
            "failed_logins": failed_logins,
            "off_hours_events": off_hours,
            "bulk_access_count": bulk_accesses,
            "suspicious_events": suspicious_events,
            "unknown_ips": unknown_ips,
            "total_events": total_events
        }

        feature_array = np.array([[
            access_ratio,
            failed_logins,
            off_hours,
            bulk_accesses,
            suspicious_events,
            unknown_ips
        ]])

        return features, feature_array

    def train(self, X):
        """Train model on feature matrix X (shape: n_samples x n_features)"""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        os.makedirs("models", exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)

    def predict(self, features_tuple):
        """
        Predict anomaly score for a single user.
        Returns normalized score 0.0 – 1.0 (higher = more anomalous).
        """
        _, X = features_tuple

        if not self.is_fitted:
            # Fallback rule-based score when model not trained yet
            return self._rule_based_score(features_tuple[0])

        X_scaled = self.scaler.transform(X)
        # Isolation Forest score: closer to -1 = anomaly, +1 = normal
        raw_score = self.model.decision_function(X_scaled)[0]
        # Normalize to 0–1 range (invert so 1 = most anomalous)
        normalized = max(0.0, min(1.0, (0.5 - raw_score)))
        return round(normalized, 4)

    def _rule_based_score(self, features):
        """Simple rule-based fallback score"""
        score = 0.0
        if features["access_ratio"] > 2.0:   score += 0.4
        elif features["access_ratio"] > 1.5: score += 0.2
        if features["failed_logins"] > 5:    score += 0.25
        elif features["failed_logins"] > 2:  score += 0.1
        if features["off_hours_events"] > 3: score += 0.15
        if features["bulk_access_count"] > 2: score += 0.2
        if features["suspicious_events"] > 0: score += 0.3
        if features["unknown_ips"] > 0:       score += 0.15
        return round(min(score, 1.0), 4)

    def explain(self, features_dict):
        """Return human-readable explanation of anomaly drivers"""
        reasons = []
        if features_dict["access_ratio"] > 2.0:
            ratio = features_dict["access_ratio"]
            files = features_dict["total_files_accessed"]
            reasons.append({
                "factor": "Excessive File Access",
                "detail": f"Accessed {files} files — {ratio:.1f}x above normal baseline",
                "weight": min(0.42, 0.15 * ratio),
                "severity": "HIGH"
            })
        if features_dict["failed_logins"] > 3:
            reasons.append({
                "factor": "Multiple Failed Logins",
                "detail": f"{features_dict['failed_logins']} failed login attempts detected",
                "weight": 0.25,
                "severity": "HIGH" if features_dict["failed_logins"] > 8 else "MEDIUM"
            })
        if features_dict["off_hours_events"] > 2:
            reasons.append({
                "factor": "Off-Hours Activity",
                "detail": f"Active during {features_dict['off_hours_events']} off-hours periods",
                "weight": 0.18,
                "severity": "MEDIUM"
            })
        if features_dict["bulk_access_count"] > 0:
            reasons.append({
                "factor": "Bulk File Operations",
                "detail": f"Performed {features_dict['bulk_access_count']} bulk file access events",
                "weight": 0.22,
                "severity": "HIGH"
            })
        if features_dict["unknown_ips"] > 0:
            reasons.append({
                "factor": "Unknown IP Address",
                "detail": f"Accessed system from {features_dict['unknown_ips']} unknown IP(s)",
                "weight": 0.15,
                "severity": "MEDIUM"
            })
        if not reasons:
            reasons.append({
                "factor": "Normal Behavior",
                "detail": "All activity within expected baseline parameters",
                "weight": 0.0,
                "severity": "LOW"
            })
        return reasons

