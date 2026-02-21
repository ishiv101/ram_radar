# scam_config.py

# High-risk phishing phrases
PHISHING_KEYWORDS = [
    "verify account", "confirm identity", "update payment",
    "urgent action required", "suspicious activity",
    "click here immediately", "validate account",
    "account locked", "unauthorized access",
    "re-activate account", "restore access"
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
    "discount"
]

# Fake job signals
JOB_SCAM_KEYWORDS = [
    "remote job", "easy money", "weekly pay",
    "$500/week", "$300 weekly", "data entry",
    "personal assistant", "work from home",
    "kindly", "flexible hours"
]

# Suspicious domains (spoofing)
SUSPICIOUS_DOMAINS = [
    "paypa1.com", "amaz0n.com", "g00gle.com",
    "loginbanking.com", "secure-verify.com",
    "account-confirm.com",
    "unc-careers.com", "uncjobs-career.com",
    "unc-edu.com"
]

# Risk weights
WEIGHTS = {
    "phishing": 15,
    "payment": 20,
    "campus_sale": 10,
    "job": 15,
    "suspicious_domain": 30,
    "link": 15,
    "urgency": 10,
    "sale_payment_bonus": 15
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