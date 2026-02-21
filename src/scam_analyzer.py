import re
from config import (
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
        if "unc" in email and not email.endswith("@unc.edu"):
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

    return {
        "score": score,
        "flags": flags
    }


def analyze_ocr_output(ocr_result: dict, min_confidence: float = 0.3) -> dict:
    """
    Analyze OCR output and return scam score.
    
    Args:
        ocr_result: Dictionary returned from ImageToText.extract_text()
        min_confidence: Minimum average confidence required (0-1)
        
    Returns:
        Dictionary with scam analysis including score, flags, and OCR metadata
    """
    if not ocr_result.get("success"):
        return {
            "success": False,
            "error": ocr_result.get("error", "OCR extraction failed"),
            "score": 0,
            "flags": []
        }
    
    extracted_text = ocr_result.get("text", "").strip()
    avg_confidence = ocr_result.get("avg_confidence", 0.0)
    
    # Check if text is meaningful
    if not extracted_text or len(extracted_text) < 5:
        return {
            "success": False,
            "error": "Extracted text too short or empty",
            "score": 0,
            "flags": []
        }
    
    # Check confidence threshold
    if avg_confidence < min_confidence:
        return {
            "success": True,
            "warning": f"Low OCR confidence: {avg_confidence:.2f}",
            "score": 0,
            "flags": ["OCR confidence below threshold"]
        }
    
    # Analyze the text
    analysis = calculate_scam_score(extracted_text)
    
    return {
        "success": True,
        "score": analysis["score"],
        "flags": analysis["flags"],
        "ocr_confidence": avg_confidence,
        "text_length": len(extracted_text)
    }