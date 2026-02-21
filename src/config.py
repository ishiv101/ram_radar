# Scam Detection Configuration

SCAM_KEYWORDS = [
    # Phishing-related
    "verify account", "confirm identity", "update payment", 
    "urgent action required", "suspicious activity",
    "click here immediately", "validate account",
    # Financial
    "wire transfer", "bitcoin", "gift card", "tax refund",
    "prize", "lottery", "claim reward", "inheritance",
    # Bank related
    "banking details", "account locked", "unauthorized access",
    "re-activate account", "restore access",
]

SUSPICIOUS_DOMAINS = [
    "paypa1.com", "amaz0n.com", "g00gle.com", "aplicaion.com",
    "loginbanking.com", "secure-verify.com", "account-confirm.com",
]

RISK_THRESHOLDS = {
    "low": (0, 30),
    "medium": (30, 60),
    "high": (60, 85),
    "critical": (85, 100),
}

FUZZY_MATCH_THRESHOLD = 80  # Percentage similarity for grouping

DATA_DIR = "data"
SCAMS_FILE = "data/scams.json"
