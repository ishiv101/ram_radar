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
    
    def check_and_alert(self) -> Dict[str, int]:
        """
        Check database for scam types exceeding threshold and send alerts.
        
        Returns:
            Dictionary of {scam_type: count} for types at or above threshold
        """
        records = self.db.get_all_records()
        scam_type_counts = {}
        
        # Count occurrences of each scam type across all records
        for record in records:
            for scam_type in record.scam_types:
                scam_type_counts[scam_type] = scam_type_counts.get(scam_type, 0) + 1
        
        # Check for new alerts and send them
        alerts = {}
        for scam_type, count in scam_type_counts.items():
            if count >= self.threshold:
                alerts[scam_type] = count
                # Send alert if not already sent for this type
                if scam_type not in self.active_alerts or self.active_alerts[scam_type] < count:
                    self.send_alert(scam_type, count)
                    self.active_alerts[scam_type] = count
        
        return alerts
    
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


