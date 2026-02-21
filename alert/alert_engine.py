"""
Alert Engine for RAM Radar
Monitors scam events from the database and triggers alerts when thresholds are crossed.
"""

from typing import Dict
from datetime import datetime
from database.database import ScamDatabase


class AlertEngine:
    """Manages alerts for scam types by querying the database."""
    
    def __init__(self, threshold: int = 5, db_path: str = "data/scam_records.json"):
        """
        Initialize AlertEngine.
        
        Args:
            threshold: Number of scams of a type needed to trigger alert
            db_path: Path to the scam records database
        """
        self.threshold = threshold
        self.db = ScamDatabase(db_path)
        self.active_alerts = {}  # Track which alerts have been sent
    
    def add_event(self, flags: list) -> None:
        """
        Check database for scam types exceeding threshold and send alerts.
        
        Returns:
            Dictionary of {scam_type: count} for types at or above threshold
        """
        scam_types = self.grouper.detect_scam_type(flags)
        for scam_type in scam_types:
            self.type_counts[scam_type] += 1

            # If count reached threshold and we haven't alerted yet, create alert
            if self.type_counts[scam_type] >= self.threshold and scam_type not in self.alerts:
                self.alerts[scam_type] = self.type_counts[scam_type]
                self.send_alert(scam_type)

        # Build and return a snapshot of all scam group counts and alerts above threshold
        counts_snapshot: Dict[str, int] = dict(self.type_counts)
        alerts_above_threshold: Dict[str, int] = {
            k: v for k, v in counts_snapshot.items() if v >= self.threshold
        }

        return {"counts": counts_snapshot, "alerts": alerts_above_threshold}
    
    def get_all_alerts(self):
        """Get all active alerts."""
        return {k: v for k, v in self.alerts.items() if v >= self.threshold}
    
    def send_alert(self, scam_type: str, count: int):
        """
        Send alert for a scam type exceeding threshold.
        
        Args:
            scam_type: Type of scam (e.g., 'phishing', 'payment_fraud')
            count: Number of reports for this scam type
        """
        timestamp = datetime.now().isoformat()
        alert_message = (
            f"[{timestamp}] ALERT: {scam_type.upper()} scams detected! "
            f"Total reports: {count} (threshold: {self.threshold})"
        )
        print(alert_message)


