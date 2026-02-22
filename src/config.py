# scam_config.py

# High-risk phishing phrases
PHISHING_KEYWORDS = [
    "verify", "confirm", "update",
    "required", "suspicious",
    "immediately", "validate",
    "locked", "unauthorized",
    "re-activate", "restore ", "permanently",
    "security", "compromised", "expired", "24 hours", "danger", "account", 
    "identity", "payment", "activity", "access", "security", "password", "action", "click here"
]

# Payment-related (very high weight)
PAYMENT_KEYWORDS = [
    "venmo", "zelle", "cashapp", "apple pay",
    "wire transfer", "bitcoin", "gift card",
    "deposit", "send first", "upfront payment"
]

# UNC campus sale scams (tickets/devices)
CAMPUS_SALE_KEYWORDS = [
    "ticket", "duke", "basketball", "football",
    "student section", "macbook", "ipad",
    "airpods", "calculator", "cheap price",
    "discount", "selling", "contact"
]

# Fake job signals
JOB_SCAM_KEYWORDS = [
    "remote job", "easy money", "weekly pay",
    "$500/week", "$300 weekly", "data entry",
    "personal assistant", "work from home",
    "kindly", "flexible", "contact", "professor"
    "research assistant", "admin assistant", "no experience"
]

# Suspicious domains (spoofing)
SUSPICIOUS_DOMAINS = [
    "paypa1.com", "amaz0n.com", "g00gle.com",
    "loginbanking.com", "secure-verify.com",
    "account-confirm.com",
    "unc-careers.com", "uncjobs-career.com",
    "unc-edu.com"
]

CERTIFIED_SAFE_KEYWORDS = [
    "cs.unc.edu", "unc.edu", "uncedu"
]

# Risk weights
WEIGHTS = {
    "phishing": 20,
    "payment": 30,
    "campus_sale": 30,
    "job": 20,
    "suspicious_domain": 30,
    "link": 30,
    "urgency": 40,
    "sale_payment_bonus": 50,
    "safe_certified": -50,
}

# Risk thresholds
RISK_THRESHOLDS = {
    "low": (0, 30),
    "medium": (30, 60),
    "high": (60, 85),
    "critical": (85, 100),
}

FUZZY_MATCH_THRESHOLD = 80

DATA_DIR = "data"
SCAMS_FILE = "data/scams.json"