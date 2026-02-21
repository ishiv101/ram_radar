#frontend - main app & display

import streamlit as st
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Page config + styling
# -----------------------------
st.set_page_config(
    page_title="Ram Radar",
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


# Top header + viewer id input (no sidebar)
import os
import json
from pathlib import Path
from PIL import Image
cols = st.columns([3, 1])
with cols[0]:
    st.markdown("## 🚨 Ram Radar")
with cols[1]:
    viewer_id = st.text_input("Viewer ID", value="anon_viewer")
st.markdown("---")


# -----------------------------
# Main area: two tabs (Report / Active alerts)
# -----------------------------


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
tabs = st.tabs(["Report a message", "Active alerts"])

with tabs[0]:
    st.header("Report a message")
    st.markdown("Use this tab to paste suspicious message text or upload a screenshot.")

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

with tabs[1]:
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


# --- AlertEngine Streamlit integration (appended; does not modify existing UI) ---
st.markdown("---")
st.header("Alert System Tester")

try:
    import importlib
    try:
        import alert.alert_engine as _ae_mod
        importlib.reload(_ae_mod)
        AlertEngine = _ae_mod.AlertEngine
    except Exception:
        from alert.alert_engine import AlertEngine

    # Use ScamGrouper to get scam types
    try:
        from src.scam_grouper import ScamGrouper
        grouper = ScamGrouper()
        scam_types = list(grouper.SCAM_TYPES.keys())
    except Exception:
        scam_types = ["phishing", "payment_fraud", "campus_sale", "job_scam", "domain_spoofing"]

    selected_types = st.multiselect("Select scam group(s)", options=scam_types, default=[scam_types[0]] if scam_types else [])
    count = st.number_input("Instances per group", min_value=1, max_value=100, value=1)
    threshold = st.number_input("Alert threshold", min_value=1, max_value=100, value=5)
    run_demo = st.button("Run AlertEngine Test")

    if run_demo:
        engine = AlertEngine(threshold=int(threshold))
        for scam_type in selected_types:
            for _ in range(int(count)):
                try:
                    engine.add_event([scam_type])
                except Exception as e:
                    st.error(f"add_event failed: {e}")
        alerts = engine.get_all_alerts()
        if alerts:
            st.success("Alerts triggered:")
            for k, v in alerts.items():
                st.write(f"- {k}: {v}")
        else:
            st.info("No alerts triggered.")
except Exception:
    st.warning("AlertEngine or ScamGrouper unavailable.")
try:
    import importlib
    # Attempt to import the AlertEngine module and reload to pick up local edits
    try:
        import alert.alert_engine as _ae_mod
        importlib.reload(_ae_mod)
        AlertEngine = _ae_mod.AlertEngine
    except Exception:
        from alert.alert_engine import AlertEngine
    st.sidebar.header("AlertEngine Tester")
    _threshold = st.sidebar.number_input("Threshold", min_value=1, max_value=100, value=5)
    _send = st.sidebar.checkbox("Call send_alert()", value=False)

    # Provide scam types from ScamGrouper so users can pick from known categories
    try:
        from src.scam_grouper import ScamGrouper
        grouper = ScamGrouper()
        available_types = list(grouper.SCAM_TYPES.keys())
    except Exception:
        available_types = ["unknown"]

    _selected_types = st.sidebar.multiselect("Select scam type(s)", options=available_types, default=[available_types[0]] if available_types else [])
    _count = st.sidebar.number_input("Count per selected type", min_value=1, max_value=100, value=1)

    if st.sidebar.button("Run AlertEngine Demo"):
        engine = AlertEngine(threshold=int(_threshold))

        # Feed events into the engine based on selected types and count
        for scam_type in _selected_types:
            for _ in range(int(_count)):
                try:
                    engine.add_event([scam_type])
                except Exception as e:
                    st.sidebar.error(f"add_event failed: {e}")

        # Retrieve and display alerts (only types meeting threshold)
        alerts = engine.get_all_alerts()
        if alerts:
            st.sidebar.success("Alerts triggered")
            for k, v in alerts.items():
                st.sidebar.write(f"- {k}: {v}")
                if _send:
                    try:
                        engine.send_alert(k)
                    except Exception as e:
                        st.sidebar.error(f"send_alert failed: {e}")
        else:
            st.sidebar.info("No alerts triggered")
except Exception:
    # Keep the main app functional even if AlertEngine import fails
    pass
