# Database schema for storing scam detection results per screenshot

from dataclasses import dataclass, field
from typing import List, Dict, Set
import json
import os


@dataclass
class ScamRecord:
    """Simple schema for storing scam analysis results from a screenshot."""
    
    timestamp: str  # ISO format timestamp
    scam_types: List[str] = field(default_factory=list)  # From scam_grouper.py
    scam_score: int = 0  # From scam_analyzer.py (0-100)
    confidence: float = 0.0  # From ocr_extractor.py (avg OCR confidence)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "scam_types": self.scam_types,
            "scam_score": self.scam_score,
            "confidence": self.confidence,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScamRecord":
        """Create ScamRecord from dictionary."""
        return cls(**data)


class ScamDatabase:
    """Simple database for storing and retrieving scam records."""
    
    def __init__(self, db_path: str = "data/scam_records.json"):
        self.db_path = db_path
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """Create database file if it doesn't exist."""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w') as f:
                json.dump([], f)
    
    def add_record(self, record: ScamRecord) -> bool:
        """Add a scam record to the database."""
        try:
            records = self._load_records()
            records.insert(0, record.to_dict())
            self._save_records(records)
            return True
        except Exception as e:
            print(f"Error adding record: {e}")
            return False
    
    def get_all_records(self) -> List[ScamRecord]:
        """Get all records from database."""
        try:
            data = self._load_records()
            return [ScamRecord.from_dict(d) for d in data]
        except Exception:
            return []
    
    def get_records_by_scam_type(self, scam_type: str) -> List[ScamRecord]:
        """Get all records of a specific scam type."""
        all_records = self.get_all_records()
        return [r for r in all_records if scam_type in r.scam_types]
    
    def get_high_risk_records(self, threshold: int = 70) -> List[ScamRecord]:
        """Get all records with scam score >= threshold."""
        all_records = self.get_all_records()
        return [r for r in all_records if r.scam_score >= threshold]
    
    def _load_records(self) -> List[Dict]:
        """Load records from JSON file."""
        with open(self.db_path, 'r') as f:
            return json.load(f)
    
    def _save_records(self, records: List[Dict]):
        """Save records to JSON file."""
        with open(self.db_path, 'w') as f:
            json.dump(records, f, indent=2, ensure_ascii=False) 