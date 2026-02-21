"""
Alert Engine for RAM Radar
Monitors scam events and triggers alerts based on scam type thresholds.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict
from src.scam_grouper import ScamGrouper
import argparse
import sys


class AlertEngine:
    """Manages alerts for scam types."""
    
    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self.type_counts = defaultdict(int)  # Counts per scam type
        self.alerts = {}  # Active alerts {scam_type: count}
        self.grouper = ScamGrouper()
    
    def add_event(self, flags: List[str]) -> Dict[str, Any]:
        """
        Add an event with flags and detect scam types.
        
        Args:
            flags: List of flag strings from scam analysis
            
        """
        # Normalize input to a list of strings
        if isinstance(flags, str):
            flags_list = [flags]
        else:
            flags_list = list(flags or [])

        # First try to detect scam types from flags (usual path)
        scam_types = self.grouper.detect_scam_type(flags_list)

        # If detection returned unknown, allow callers to pass scam type names directly
        # e.g., engine.add_event(["phishing"]) from the UI tester. Map those to known types.
        if scam_types == {"unknown"}:
            direct_types = {t for t in self.grouper.SCAM_TYPES.keys() if t in set(flags_list)}
            if direct_types:
                scam_types = direct_types
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
    
    def dismiss(self, scam_type: str):
        """Dismiss an alert for a scam type."""
        if scam_type in self.alerts:
            del self.alerts[scam_type]

    def send_alert(self, scam_type: str):
        """Simulate sending an alert (e.g., email, notification)."""
        print(f"ALERT: {scam_type} scams have reached {self.type_counts[scam_type]} reports!")


