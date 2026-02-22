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
        from src.scam_grouper import ScamGrouper
        self.grouper = ScamGrouper()
        self.type_counts = {}
        self.alerts = {}
    
    def add_event(self, items: list[str]) -> Dict[str, Dict[str, int]]:
        """
        Add an event to the alert engine.

        `items` can be either:
        - scam TYPES (e.g., ["phishing", "job_scam"])
        - FLAGS from analysis (e.g., ["Phishing phrase detected", "Fake UNC email domain"])
        - or a mix (we'll do the right thing)
        """
        if not items:
            return {"counts": dict(self.type_counts), "alerts": {k: v for k, v in self.type_counts.items() if v >= self.threshold}}

        # Normalize
        items_norm = [str(x).strip() for x in items if str(x).strip()]

        known_types: Set[str] = set(self.grouper.SCAM_TYPES.keys())

        # If every item is a known scam type, treat as types directly.
        # Otherwise, treat items as flags and run the grouper.
        if all(x in known_types for x in items_norm):
            scam_types = set(items_norm)
        else:
            scam_types = self.grouper.detect_scam_type(items_norm)

        for scam_type in scam_types:
            self.type_counts[scam_type] = self.type_counts.get(scam_type, 0) + 1

            # Only trigger alert if count is exactly threshold
            if self.type_counts[scam_type] == self.threshold and scam_type not in self.alerts:
                self.alerts[scam_type] = self.type_counts[scam_type]
                self.send_alert(scam_type, self.type_counts[scam_type])
            # Persist alert in session state if already triggered
            if scam_type in self.alerts:
                self.persist_alert_to_inbox(scam_type, self.alerts[scam_type])

    def persist_alert_to_inbox(self, scam_type: str, count: int):
        import streamlit as st
        timestamp = datetime.now().isoformat()
        alert_message = (
            f"[{timestamp}] ALERT: {scam_type.upper()} scams detected! "
            f"Total reports: {count}"
        )
        if 'ae_frontend_alerts' not in st.session_state:
            st.session_state['ae_frontend_alerts'] = []
        # Only add if not already present
        already = any(a.get('scam_type') == scam_type for a in st.session_state['ae_frontend_alerts'])
        if not already:
            st.session_state['ae_frontend_alerts'].append({
                'scam_type': scam_type,
                'count': count,
                'timestamp': timestamp,
                'message': alert_message
            })

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
        Instead of printing, store alert in Streamlit session state for frontend display.
        """
        import streamlit as st
        timestamp = datetime.now().isoformat()
        alert_message = (
            f"[{timestamp}] ALERT: {scam_type.upper()} scams detected! "
            f"Total reports: {count}"
        )
        # Store alert in session state for inbox and popup
        if 'ae_frontend_alerts' not in st.session_state:
            st.session_state['ae_frontend_alerts'] = []
        st.session_state['ae_frontend_alerts'].append({
            'scam_type': scam_type,
            'count': count,
            'timestamp': timestamp,
            'message': alert_message
        })
        st.session_state['ae_popup_alert'] = alert_message


