from typing import List, Dict, Any, Optional, Set
from fuzzywuzzy import fuzz
from src.config import FUZZY_MATCH_THRESHOLD


class ScamGrouper:
    """Groups and categorizes scams by type based on detected flags."""
    
    # Scam type patterns
    SCAM_TYPES = {
        "phishing": [
            "Phishing phrase detected",
            "Fake UNC email domain",
            "account locked",
            "verify account",
            "confirm identity"
        ],
        "payment_fraud": [
            "Peer-to-peer payment mention",
            "Suspicious link"
        ],
        "campus_sale": [
            "Campus sale keyword",
            "High-risk combo: Sale + P2P payment"
        ],
        "job_scam": [
            "Job scam phrase"
        ],
        "domain_spoofing": [
            "Spoofed domain detected",
            "Fake UNC email domain"
        ]
    }
    
    def __init__(self, fuzzy_threshold: int = FUZZY_MATCH_THRESHOLD):
        """
        Initialize ScamGrouper.
        
        Args:
            fuzzy_threshold: Threshold for fuzzy matching (0-100)
        """
        self.fuzzy_threshold = fuzzy_threshold
    
    def detect_scam_type(self, flags: List[str]) -> Set[str]:
        """
        Detect scam types based on present flags.
        
        Args:
            flags: List of flag strings from scam analysis
            
        Returns:
            Set of detected scam types
        """
        detected_types = set()
        flags_lower = [flag.lower() for flag in flags]
        
        for scam_type, keywords in self.SCAM_TYPES.items():
            for keyword in keywords:
                if any(keyword.lower() in flag for flag in flags_lower):
                    detected_types.add(scam_type)
                    break
        
        return detected_types if detected_types else {"unknown"}
    
    def group_by_type(self, scams: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group scams by their detected type.
        
        Args:
            scams: List of scam dictionaries with 'score' and 'flags' keys
            
        Returns:
            Dictionary mapping scam types to lists of scams
        """
        grouped = {scam_type: [] for scam_type in self.SCAM_TYPES.keys()}
        grouped["unknown"] = []
        
        for scam in scams:
            types = self.detect_scam_type(scam.get("flags", []))
            for scam_type in types:
                grouped[scam_type].append(scam)
        
        # Remove empty groups
        return {k: v for k, v in grouped.items() if v}
    
    def find_similar_scams(self, scam_text: str, scam_list: List[str], 
                          threshold: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Find similar scams using fuzzy matching.
        
        Args:
            scam_text: The scam text to match
            scam_list: List of known scam texts
            threshold: Fuzzy match threshold (uses instance default if None)
            
        Returns:
            List of similar scams with match scores
        """
        threshold = threshold or self.fuzzy_threshold
        similar = []
        
        for known_scam in scam_list:
            score = fuzz.token_set_ratio(scam_text.lower(), known_scam.lower())
            if score >= threshold:
                similar.append({
                    "text": known_scam,
                    "match_score": score
                })
        
        return sorted(similar, key=lambda x: x["match_score"], reverse=True)
    
    def get_summary_by_type(self, grouped_scams: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get summary statistics for grouped scams.
        
        Args:
            grouped_scams: Dictionary from group_by_type()
            
        Returns:
            Dictionary with summary for each scam type
        """
        summary = {}
        
        for scam_type, scams in grouped_scams.items():
            if scams:
                scores = [s.get("score", 0) for s in scams]
                summary[scam_type] = {
                    "count": len(scams),
                    "avg_score": round(sum(scores) / len(scores), 2),
                    "max_score": max(scores),
                    "min_score": min(scores)
                }
        
        return summary
