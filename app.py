#frontend - main app & display

import streamlit as st
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Page config + styling
# -----------------------------
st.set_page_config(
    page_title="Campus Scam Signal",
    page_icon="🚨",
    layout="wide",
)

CSS = """
<style>
/* Layout polish */
.block-container { padding-top: 1.5rem; padding-bottom: 2.0rem; }
h1, h2, h3 { letter-spacing: -0.02em; }

/* Card look */
.card {
  border: 1px solid rgba(49, 51, 63, 0.15);
  border-radius: 16px;
  padding: 16px 16px;
  background: rgba(255,255,255,0.7);
  margin-bottom: 12px;
}
.card-title { font-weight: 700; font-size: 16px; margin-bottom: 8px; }
.small-muted { color: rgba(49,51,63,0.65); font-size: 13px; }

/* Badges */
.badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  border: 1px solid rgba(49, 51, 63, 0.15);
  margin: 4px 6px 0 0;
}
.badge-red { background: rgba(255, 227, 227, 0.9); }
.badge-yellow { background: rgba(255, 243, 191, 0.9); }
.badge-green { background: rgba(211, 249, 216, 0.9); }
.badge-gray { background: rgba(241, 243, 245, 0.9); }

/* Risk pill */
.risk-pill {
  display:inline-block; padding:6px 10px; border-radius:999px;
  font-weight:700; font-size:12px; border:1px solid rgba(49,51,63,0.15);
}

/* Top alert banner */
.banner {
  border-radius: 16px;
  padding: 14px 16px;
  border: 1px solid rgba(49, 51, 63, 0.15);
  margin-bottom: 16px;
}
.banner-danger { background: rgba(255, 227, 227, 0.7); }
.banner-info { background: rgba(231, 245, 255, 0.7); }
.banner-ok { background: rgba(211, 249, 216, 0.7); }

/* Button row */
.btnrow { display:flex; gap:8px; flex-wrap: wrap; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# -----------------------------
# Helpers (UI)
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def risk_label(score: int) -> Dict[str, str]:
    if score >= 70:
        return {"label": "HIGH", "cls": "badge-red"}
    if score >= 40:
        return {"label": "MEDIUM", "cls": "badge-yellow"}
    return {"label": "LOW", "cls": "badge-green"}


def pill_html(text: str, cls: str) -> str:
    return f'<span class="badge {cls}">{text}</span>'


def render_flags(flags: List[str]):
    if not flags:
        st.markdown(pill_html("No major red flags detected", "badge-green"), unsafe_allow_html=True)
        return
    # heuristic coloring
    for f in flags:
        lc = f.lower()
        if any(k in lc for k in ["credential", "password", "ssn", "payment", "gift", "wire", "urgent", "non-unc", "spoof"]):
            cls = "badge-red"
        elif any(k in lc for k in ["link", "domain", "capital"]):
            cls = "badge-yellow"
        else:
            cls = "badge-gray"
        st.markdown(pill_html(f, cls), unsafe_allow_html=True)


def banner(kind: str, title: str, body: str):
    cls = {"danger": "banner-danger", "info": "banner-info", "ok": "banner-ok"}.get(kind, "banner-info")
    st.markdown(
        f"""
        <div class="banner {cls}">
          <div style="font-weight:800; font-size:16px; margin-bottom:4px;">{title}</div>
          <div class="small-muted">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def card(title: str, subtitle: Optional[str] = None):
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown(f'<div class="card-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="small-muted" style="margin-bottom:10px;">{subtitle}</div>', unsafe_allow_html=True)


def end_card():
    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# Sidebar navigation
# -----------------------------
st.sidebar.markdown("## 🚨 Campus Scam Signal")
st.sidebar.caption("UNC-style scam detection + campus-wide alerting (hackathon demo).")

viewer_id = st.sidebar.text_input("Viewer ID (for analytics)", value="anon_viewer")

page = st.sidebar.radio(
    "Navigate",
    ["Report a message", "Active alerts", "Dashboard", "How it works"],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.caption("⚠️ This tool provides *risk signals*, not definitive conclusions.")


# -----------------------------
# Main area: two tabs (Report / Active alerts)
# -----------------------------
import os
import json
from pathlib import Path
from PIL import Image

try:
    # prefer importing project config; falls back to src.config if run from project root
    import src.config as cfg
except Exception:
    import config as cfg


def analyze_text_simple(text: str):
    """Lightweight scam scoring using configured keyword lists.

    Returns (score:int, flags:List[str])
    """
    t = text.lower()
    score = 0
    flags = []

    for word in getattr(cfg, "PHISHING_KEYWORDS", []):
        if word in t:
            score += cfg.WEIGHTS.get("phishing", 10)
            flags.append(f"Phishing phrase detected: '{word}'")

    payment_found = False
    for word in getattr(cfg, "PAYMENT_KEYWORDS", []):
        if word in t:
            score += cfg.WEIGHTS.get("payment", 15)
            payment_found = True
            flags.append(f"Peer-to-peer payment mention: '{word}'")

    sale_found = False
    for word in getattr(cfg, "CAMPUS_SALE_KEYWORDS", []):
        if word in t:
            score += cfg.WEIGHTS.get("campus_sale", 5)
            sale_found = True
            flags.append(f"Campus sale keyword: '{word}'")

    if sale_found and payment_found:
        score += cfg.WEIGHTS.get("sale_payment_bonus", 10)
        flags.append("High-risk combo: Sale + P2P payment")

    for word in getattr(cfg, "JOB_SCAM_KEYWORDS", []):
        if word in t:
            score += cfg.WEIGHTS.get("job", 10)
            flags.append(f"Job scam phrase: '{word}'")

    for domain in getattr(cfg, "SUSPICIOUS_DOMAINS", []):
        if domain in t:
            score += cfg.WEIGHTS.get("suspicious_domain", 20)
            flags.append(f"Spoofed domain detected: '{domain}'")

    if "http" in t or "bit.ly" in t or "tinyurl" in t:
        score += cfg.WEIGHTS.get("link", 10)
        flags.append("Contains external or shortened link")

    for w in ["urgent", "immediately", "asap", "act now"]:
        if w in t:
            score += cfg.WEIGHTS.get("urgency", 5)
            flags.append(f"Urgency language detected: '{w}'")

    score = min(100, score)
    return score, flags


def _scams_file_path() -> Path:
    d = Path(getattr(cfg, "DATA_DIR", "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d / getattr(cfg, "SCAMS_FILE", "scams.json").split(os.sep)[-1]


def load_alerts():
    p = _scams_file_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_alert(entry: dict):
    p = _scams_file_path()
    items = load_alerts()
    items.insert(0, entry)
    p.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


# Use sidebar `page` radio to control what the main area shows
if page == "Report a message":
    st.header("Report a message")
    st.markdown("Use this page to paste suspicious message text or upload a screenshot.")

    with st.form("report_form"):
        provided_text = st.text_area("Message text (paste or leave empty to OCR an image)", height=200)
        uploaded = st.file_uploader("Screenshot (optional)", type=["png", "jpg", "jpeg"])
        use_gpu = st.checkbox("Use GPU for OCR (if available)", value=False)
        submitted = st.form_submit_button("Analyze")

    if submitted:
        text_to_analyze = (provided_text or "").strip()
        ocr_used = False
        if uploaded and not text_to_analyze:
            try:
                # try using the project's OCR if available
                from src.ocr_extractor import ImageToText
                img = Image.open(uploaded).convert("RGB")
                ocr = ImageToText(gpu=use_gpu)
                res = ocr.extract_text(img)
                if res.get("success"):
                    text_to_analyze = res.get("text", "").strip()
                    ocr_used = True
                else:
                    st.warning("OCR returned no usable text: " + str(res.get("error", "unknown")))
            except Exception as e:
                st.warning(f"OCR unavailable or failed: {e}")

        if not text_to_analyze:
            st.warning("Please provide message text or upload a readable screenshot.")
        else:
            score, flags = analyze_text_simple(text_to_analyze)
            lbl = risk_label(score)
            kind = "danger" if score >= 70 else "info" if score >= 40 else "ok"
            banner(kind, f"Risk: {lbl['label']} — {score}", f"Analyzed at {now_iso()}")
            st.subheader("Extracted / Provided text")
            st.write(text_to_analyze)
            st.subheader("Detected flags")
            render_flags(flags)

            # persist locally
            entry = {
                "viewer_id": viewer_id,
                "timestamp": now_iso(),
                "text": text_to_analyze,
                "score": score,
                "flags": flags,
                "ocr_used": ocr_used,
            }
            try:
                save_alert(entry)
                st.success("Report saved locally to data directory.")
            except Exception as e:
                st.error(f"Failed to save report: {e}")

elif page == "Active alerts":
    st.header("Active alerts")
    st.markdown("Recent reported messages (local).")
    alerts = load_alerts()
    if not alerts:
        st.info("No reports yet.")
    else:
        for a in alerts[:50]:
            card(f"Score: {a.get('score', 0)} — {a.get('viewer_id', 'anon')}", subtitle=a.get("timestamp"))
            st.write(a.get("text"))
            render_flags(a.get("flags", []))
            end_card()

elif page == "Dashboard":
    st.header("Dashboard")
    st.markdown("Quick summary of recent reports.")
    alerts = load_alerts()
    total = len(alerts)
    avg = round(sum((a.get("score", 0) for a in alerts), 0) / total, 1) if total else 0
    st.metric("Total reports", total)
    st.metric("Average score", f"{avg}")

    if alerts:
        top = sorted(alerts, key=lambda x: x.get("score", 0), reverse=True)[:5]
        st.subheader("Top recent high-risk reports")
        for a in top:
            card(f"Score: {a.get('score', 0)}", subtitle=a.get("timestamp"))
            st.write(a.get("text"))
            render_flags(a.get("flags", []))
            end_card()

elif page == "How it works":
    st.header("How it works")
    st.markdown(
        """
        This demo extracts text from images or pasted messages, runs a lightweight heuristic
        analysis using configured keyword weights, and surfaces risk signals.

        - "Report a message": paste text or upload a screenshot to analyze and save a report.
        - "Active alerts": list recently saved reports.
        - "Dashboard": simple aggregates of recent reports.

        Notes: This is a demo and provides risk signals, not definitive evidence.
        """,
    )

else:
    st.info("Select a page from the sidebar to get started.")
