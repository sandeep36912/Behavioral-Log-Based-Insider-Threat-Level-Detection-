"""
Risk Scoring Engine
Converts anomaly scores + contextual factors into a 0–100 risk score
"""


class RiskEngine:
    THRESHOLDS = {"HIGH": 65, "MEDIUM": 35, "LOW": 0}

    def calculate(self, anomaly_score: float, features_tuple) -> tuple:
        """
        Compute final risk score 0–100 from anomaly score + feature context.
        Returns (score: float, level: str)
        """
        features, _ = features_tuple

        # Base from anomaly model (0–1 → 0–70 points)
        base = anomaly_score * 70

        # Bonus points from contextual signals
        bonus = 0
        if features["failed_logins"] > 5:    bonus += 15
        elif features["failed_logins"] > 2:  bonus += 7
        if features["off_hours_events"] > 3: bonus += 10
        if features["bulk_access_count"] > 0: bonus += 8
        if features["unknown_ips"] > 0:       bonus += 12
        if features["suspicious_events"] > 2: bonus += 15
        elif features["suspicious_events"] > 0: bonus += 8

        score = round(min(base + bonus, 100), 1)

        if score >= self.THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level


"""
Alert Manager
Generates structured security alerts when anomalous behavior detected
"""


class AlertManager:
    ALERT_TYPES = {
        "BULK_FILE_ACCESS": "Bulk File Access Detected",
        "OFF_HOURS":        "Off-Hours System Access",
        "FAILED_LOGIN":     "Repeated Login Failures",
        "UNKNOWN_IP":       "Access from Unknown IP",
        "DATA_EXFIL":       "Potential Data Exfiltration",
        "ANOMALY":          "Behavioral Anomaly Detected"
    }

    def generate(self, user_id: str, features_tuple, risk_score: float, level: str) -> dict:
        features, _ = features_tuple

        # Determine primary alert type
        if features["bulk_access_count"] > 1:
            atype = "BULK_FILE_ACCESS"
        elif features["failed_logins"] > 5:
            atype = "FAILED_LOGIN"
        elif features["off_hours_events"] > 3:
            atype = "OFF_HOURS"
        elif features["unknown_ips"] > 0:
            atype = "UNKNOWN_IP"
        else:
            atype = "ANOMALY"

        files = features["total_files_accessed"]
        baseline = 100  # fixed reference

        message = (
            f"ALERT: {self.ALERT_TYPES[atype]} | "
            f"User: {user_id} | "
            f"Files Accessed: {files} (Baseline: {baseline}) | "
            f"Risk Level: {level}"
        )

        return {
            "user_id": user_id,
            "type": atype,
            "severity": level,
            "message": message,
            "details": {
                "files_accessed": files,
                "baseline": baseline,
                "ratio": round(files / max(baseline, 1), 2),
                "failed_logins": features["failed_logins"],
                "off_hours": features["off_hours_events"],
                "unknown_ips": features["unknown_ips"],
                "risk_score": risk_score
            }
        }

