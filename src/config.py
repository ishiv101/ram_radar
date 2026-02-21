# scam_config.py

# High-risk phishing phrases
PHISHING_KEYWORDS = [
    "verify", "account", "confirm", "identity", "update", "payment",
    "action required", "suspicious activity",
    "click here immediately", "validate",
    "locked", "unauthorized",
    "re-activate", "restore access", "permanently", "permanently",
    "security", "compromised", "password expired", "24 hours", "danger"
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
    "kindly", "flexible hours", "contact", "professor"
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

# Risk weights
WEIGHTS = {
    "phishing": 20,
    "payment": 20,
    "campus_sale": 20,
    "job": 20,
    "suspicious_domain": 30,
    "link": 30,
    "urgency": 40,
    "sale_payment_bonus": 50
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