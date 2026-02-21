"""
Alert Engine for RAM Radar
Monitors scam events and triggers alerts based on group thresholds.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict


class AlertEngine:
    """
    Manages alerts for scam event groups.
    Tracks event counts per group and triggers alerts when thresholds are exceeded.
    """
    
    def __init__(self, alert_threshold: int = 5):
        """
        Initialize the Alert Engine.
        
        Args:
            alert_threshold: Number of events in a group before triggering an alert
        """
        self.alert_threshold = alert_threshold
        self.group_counts: Dict[str, int] = defaultdict(int)
        self.group_details: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.alert_history: List[Dict[str, Any]] = []
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
    
    def add_event(self, event: Dict[str, Any], group_id: str) -> Optional[Dict[str, Any]]:
        """
        Add an event to a group and check if alert threshold is exceeded.
        
        Args:
            event: Event data containing scam details
            group_id: The group ID this event belongs to
            
        Returns:
            Alert details if threshold is exceeded, None otherwise
        """
        self.group_counts[group_id] += 1
        self.group_details[group_id].append(event)
        
        if self.group_counts[group_id] >= self.alert_threshold:
            return self._trigger_alert(group_id)
        
        return None
    
    def _trigger_alert(self, group_id: str) -> Dict[str, Any]:
        """
        Trigger an alert for a group that has exceeded the threshold.
        
        Args:
            group_id: The group ID that triggered the alert
            
        Returns:
            Alert details dictionary
        """
        alert = {
            "group_id": group_id,
            "timestamp": datetime.now().isoformat(),
            "event_count": self.group_counts[group_id],
            "events": self.group_details[group_id],
            "severity": self._calculate_severity(group_id)
        }
        
        self.active_alerts[group_id] = alert
        self.alert_history.append(alert)
        
        return alert
    
    def _calculate_severity(self, group_id: str) -> str:
        """
        Calculate severity level based on event count.
        
        Args:
            group_id: The group ID to calculate severity for
            
        Returns:
            Severity level: "low", "medium", or "high"
        """
        count = self.group_counts[group_id]
        if count >= self.alert_threshold * 2:
            return "high"
        elif count >= self.alert_threshold:
            return "medium"
        return "low"
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all currently active alerts.
        
        Returns:
            List of active alert dictionaries
        """
        return list(self.active_alerts.values())
    
    def dismiss_alert(self, group_id: str) -> bool:
        """
        Dismiss an active alert for a group.
        
        Args:
            group_id: The group ID to dismiss the alert for
            
        Returns:
            True if alert was dismissed, False if not found
        """
        if group_id in self.active_alerts:
            del self.active_alerts[group_id]
            return True
        return False
    
    def get_group_summary(self, group_id: str) -> Dict[str, Any]:
        """
        Get summary information for a specific group.
        
        Args:
            group_id: The group ID to get summary for
            
        Returns:
            Summary dictionary with group statistics
        """
        return {
            "group_id": group_id,
            "event_count": self.group_counts[group_id],
            "events": self.group_details[group_id],
            "threshold": self.alert_threshold,
            "alert_active": group_id in self.active_alerts,
            "severity": self._calculate_severity(group_id)
        }
    
    def reset_group(self, group_id: str) -> None:
        """
        Reset count and details for a group.
        
        Args:
            group_id: The group ID to reset
        """
        self.group_counts[group_id] = 0
        self.group_details[group_id] = []
        self.dismiss_alert(group_id)
    
    def get_alert_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get historical alerts.
        
        Args:
            limit: Maximum number of alerts to return (None for all)
            
        Returns:
            List of alert dictionaries
        """
        if limit:
            return self.alert_history[-limit:]
        return self.alert_history
