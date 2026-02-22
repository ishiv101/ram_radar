import re
from src.config import (
    CERTIFIED_SAFE_KEYWORDS,
    PHISHING_KEYWORDS,
    PAYMENT_KEYWORDS,
    CAMPUS_SALE_KEYWORDS,
    JOB_SCAM_KEYWORDS,
    SUSPICIOUS_DOMAINS,
    WEIGHTS
)

def calculate_scam_score(text: str) -> dict:
    text = text.lower()
    score = 0
    flags = []

    # Phishing keywords
    for word in PHISHING_KEYWORDS:
        if word in text:
            score += WEIGHTS["phishing"]
            flags.append(f"Phishing phrase detected: '{word}'")

    # Payment keywords
    payment_found = False
    for word in PAYMENT_KEYWORDS:
        if word in text:
            score += WEIGHTS["payment"]
            payment_found = True
            flags.append(f"Peer-to-peer payment mention: '{word}'")

    # Campus sale keywords
    sale_found = False
    for word in CAMPUS_SALE_KEYWORDS:
        if word in text:
            score += WEIGHTS["campus_sale"]
            sale_found = True
            flags.append(f"Campus sale keyword: '{word}'")

    # Bonus: sale + payment combo
    if sale_found and payment_found:
        score += WEIGHTS["sale_payment_bonus"]
        flags.append("High-risk combo: Sale + P2P payment")

    # Job scam keywords
    for word in JOB_SCAM_KEYWORDS:
        if word in text:
            score += WEIGHTS["job"]
            flags.append(f"Job scam phrase: '{word}'")

    # Suspicious domains
    for domain in SUSPICIOUS_DOMAINS:
        if domain in text:
            score += WEIGHTS["suspicious_domain"]
            flags.append(f"Spoofed domain detected: '{domain}'")

    # UNC spoof detection
    email_matches = re.findall(r'[\w\.-]+@[\w\.-]+', text)
    for email in email_matches:
        if any(safe in email for safe in CERTIFIED_SAFE_KEYWORDS):
            flags.append(f"Certified safe domain detected: '{email}'")
            score += WEIGHTS["safe_certified"]
        elif "unc" in email and not email.endswith(("@unc.edu", "@cs.unc.edu", "@uncedu")):
            score += WEIGHTS["suspicious_domain"]
            flags.append(f"Fake UNC email domain: '{email}'")

    # Suspicious links
    if "http" in text or "bit.ly" in text or "tinyurl" in text:
        score += WEIGHTS["link"]
        flags.append("Contains external or shortened link")

    # Urgency language
    urgency_words = ["urgent", "immediately", "asap", "act now"]
    for word in urgency_words:
        if word in text:
            score += WEIGHTS["urgency"]
            flags.append(f"Urgency language detected: '{word}'")

    score = min(score, 100)
    if score < 10:
        score = 10  # Minimum score for any detected indicators
    if score > 90:
        score = 90  # Cap score to avoid false positives

    return {
        "score": score,
        "flags": flags
    }