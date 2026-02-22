# Add missing import for streamlit
import streamlit as st
#frontend - main app & display
from datetime import datetime, timezone
# Store scam types that have already triggered at threshold to avoid duplicate alerts
from typing import List, Optional
import os
import json
from pathlib import Path
from PIL import Image
from src.utils import analyze_image_for_scams, analyze_text_for_scams

# Database integration
try:
    from database.database import ScamDatabase, ScamRecord
    _db = ScamDatabase()
except Exception:
    _db = None


# Page config + styling
# -----------------------------
logo = Image.open("assets/logo.png")

st.set_page_config(
    page_title="Ram Radar",
    page_icon=logo,
    layout="wide",
)

# -----------------------------
# Helpers (UI)
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

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


def card(title: str, subtitle: Optional[str] = None):
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown(f'<div class="card-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="small-muted" style="margin-bottom:10px;">{subtitle}</div>', unsafe_allow_html=True)


def end_card():
    st.markdown("</div>", unsafe_allow_html=True)


# Top header (no sidebar)
col1, col2 = st.columns([1, 12])  # adjust ratio if needed

with col1:
    st.markdown("")
    st.image(logo, width=150)

with col2:
    st.markdown("# Ram Radar")
    st.markdown("##### Protecting the Carolina community from scams.")


# -----------------------------
# Main area: two tabs (Report / Active alerts)
# -----------------------------


try:
    # prefer importing project config; falls back to src.config if run from project root
    import src.config as cfg
except Exception:
    import config as cfg

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
    """Save an alert locally and to the ScamDatabase if available.

    Keeps the existing local JSON storage for compatibility but will also add
    a record to the `ScamDatabase` when the `database` package is importable.
    """
    # First, try to persist to the ScamDatabase (preferred)
    try:
        if _db is not None:
            # Map entry to ScamRecord fields where available
            rec = ScamRecord(
                timestamp=entry.get("timestamp", now_iso()),
                scam_types=entry.get("scam_types", []),
                scam_score=int(entry.get("score", 0) or 0),
                confidence=float(entry.get("confidence", 0.0) or 0.0),
            )
            added = _db.add_record(rec)
            if added:
                # also keep legacy JSON file for backwards compatibility
                try:
                    p = _scams_file_path()
                    items = load_alerts()
                    items.insert(0, entry)
                    p.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
                except Exception:
                    pass
                return True
    except Exception:
        # fall through to legacy behavior
        pass

    # Legacy JSON fallback
    try:
        p = _scams_file_path()
        items = load_alerts()
        items.insert(0, entry)
        p.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception:
        return False


def _get_all_records_as_dicts():
    """Return all stored records as a list of dicts (DB or legacy JSON)."""
    try:
        if _db is not None:
            return [r.to_dict() if hasattr(r, "to_dict") else r for r in _db.get_all_records()]
        return load_alerts()
    except Exception:
        return []


def check_and_notify_threshold(entry: dict, threshold: int = 1):
    """Check counts for scam types and notify if any exceed threshold.

    Uses session_state to avoid repeating the same alert for a scam type.
    """
    try:
        if "threshold_alerts_shown" not in st.session_state:
            st.session_state["threshold_alerts_shown"] = set()

        records = _get_all_records_as_dicts()
        # Count occurrences per scam type
        counts = {}
        for r in records:
            for t in (r.get("scam_types") or []):
                counts[t] = counts.get(t, 0) + 1

        triggered = []
        for t, cnt in counts.items():
            if cnt >= threshold and t not in st.session_state["threshold_alerts_shown"]:
                triggered.append((t, cnt))
        
        if triggered:
            # Mark them as shown so we don't repeat
            for t, _ in triggered:
                st.session_state["threshold_alerts_shown"].add(t)
            for t, c in triggered:
                st.toast(f"🚨 **{t}** has reached **{c}** reports!", icon="🚨")

            # ensure inbox exists in session state
            if "inbox_alerts" not in st.session_state:
                st.session_state["inbox_alerts"] = []

            # add each triggered alert into the inbox (type, count, timestamp)
            for t, c in triggered:
                st.session_state["inbox_alerts"].append({
                    "type": t,
                    "count": c,
                    "timestamp": now_iso(),
                })

            # Prepare HTML list items for each triggered alert
            msgs = ''.join(f"<li><b>{t}</b>: {c} reports</li>" for t, c in triggered)

            # Render a prominent banner and an expanding detail box
            st.markdown(
                f"<div class='banner banner-danger'><div style='font-weight:800; font-size:16px;'>Threshold reached</div>\n"
                f"<div class='small-muted'>The following scam types exceeded the threshold of {threshold} reports:</div>\n"
                f"<ul style='margin-top:8px'>{msgs}</ul></div>",
                unsafe_allow_html=True,
            )
    except Exception as e:
        # Non-fatal: show a warning in the sidebar for debugging
        try:
            st.sidebar.warning(f"Threshold check failed: {e}")
        except Exception:
            pass


# Use sidebar `page` radio to control what the main area shows
tabs = st.tabs(["Report a message", "Active alerts", "Inbox"])

with tabs[0]:
    st.markdown("## Scam Detection Tool")
    st.write("Upload an image of a potential scam message to analyze it for suspicious content.")

    use_gpu = False  # GPU acceleration disabled by default

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Upload Image")
        uploaded_file = st.file_uploader(
            "Choose an image file",
            type=["jpg", "jpeg", "png", "bmp", "gif"]
        )

    with col2:
        st.subheader("Paste Message Text")
        text_input = st.text_area(
            "Enter suspicious message text to analyze",
            placeholder="Paste the scam message text here...",
            height=150,
            key="text_input_col"
        )
        analyze_text_btn = st.button("Analyze Text", key="analyze_text_btn_col")

    st.markdown("""
<style>
.custom-warning {
    background-color: #a6d1ed;  /* Carolina Blue */
    color: #13294B;
    padding: 12px 16px;
    border-radius: 10px;
    margin-bottom: 10px;
    font-weight: 500;
}
</style>
""", unsafe_allow_html=True)
    
    if uploaded_file is not None:
        try:
            # Save temporarily
            image = Image.open(uploaded_file)
            temp_path = f"/tmp/{uploaded_file.name}"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Analyze with spinner right under input columns
            with st.spinner("Analyzing image..."):
                result = analyze_image_for_scams(temp_path, use_gpu=use_gpu)
            
            if result["success"]:
                # Two-column layout: Results (left) | Image (right)
                result_col, image_col = st.columns([1.5, 1])
                
                with result_col:
                    # Scam Score
                    score = result["scam_score"]
                    if score >= 70:
                        risk_level = "HIGH RISK"
                    elif score >= 40:
                        risk_level = "MEDIUM RISK"
                    else:
                        risk_level = "LOW RISK"
                    
                    st.metric("Scam Score", f"{score}/100", delta=risk_level)
                    
                    # Scam Types
                    st.subheader("Scam Type(s)")
                    scam_types = result["scam_types"]
                    types_text = ", ".join(scam_types) if scam_types else "None detected"
                    st.write(types_text)
                    
                    # Detected Red Flags
                    st.subheader("Detected Red Flags")
                    if result["flags"]:
                        for flag in result["flags"]:
                            st.markdown(
                                f'<div class="custom-warning">⚠️ {flag}</div>',
                                    unsafe_allow_html=True
            )
                    else:
                        st.info("No suspicious indicators detected.")
                
                with image_col:
                    st.subheader("Uploaded Image")
                    st.image(image, use_container_width=True)
                
                # Bottom: OCR Confidence
                st.subheader("OCR Confidence")
                st.progress(result["confidence"], text=f"{result['confidence']:.1%}")
                
                # Extracted Text
                st.subheader("Extracted Text")
                st.text_area("Text from image:", value=result["extracted_text"], height=150, disabled=True)
                
                # Save to alerts
                entry = {
                    "viewer_id": "anon_viewer",
                    "timestamp": now_iso(),
                    "text": result["extracted_text"],
                    "score": result["scam_score"],
                    "flags": result["flags"],
                    "scam_types": list(result["scam_types"]) if result["scam_types"] else [],
                    "ocr_used": True,
                }
                saved = save_alert(entry)
                if not saved:
                    st.error("Failed to save report to storage")
                else:
                    st.success("Report saved")
                    check_and_notify_threshold(entry, threshold=1)
                
            else:
                st.error(f"❌ Analysis Failed: {result['error']}")
        
        except Exception as e:
            st.error(f"Error during analysis: {str(e)}")
            import traceback
            st.text(traceback.format_exc())

    # Handle text input analysis from col2
    if analyze_text_btn and text_input.strip():
        try:
            with st.spinner("Analyzing text..."):
                result = analyze_text_for_scams(text_input)
            
            if result["success"]:
                st.divider()
                st.subheader("Results")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    score = result["scam_score"]
                    if score >= 70:
                        risk_level = "HIGH RISK"
                    elif score >= 40:
                        risk_level = "MEDIUM RISK"
                    else:
                        risk_level = "LOW RISK"
                    
                    st.metric("Scam Score", f"{score}/100", delta=risk_level)
                
                with col2:
                    scam_types = result["scam_types"]
                    types_text = ", ".join(scam_types) if scam_types else "None detected"
                    st.metric("Scam Type(s)", types_text)
                
                # Analyzed Text
                st.subheader("Analyzed Text")
                st.text_area("Input text:", value=text_input, height=150, disabled=True, key="analyzed_text")
                
                # Detected Flags
                if result["flags"]:
                    st.subheader("Detected Red Flags")
                    for flag in result["flags"]:
                        st.warning(f"⚠️ {flag}")
                else:
                    st.info("No suspicious indicators detected.")
                
                # Save to alerts
                entry = {
                    "viewer_id": "anon_viewer",
                    "timestamp": now_iso(),
                    "text": text_input,
                    "score": result["scam_score"],
                    "flags": result["flags"],
                    "scam_types": list(result["scam_types"]) if result["scam_types"] else [],
                    "ocr_used": False,
                }
                saved = save_alert(entry)
                if saved:
                    st.success("Report saved locally to data directory.")
                    check_and_notify_threshold(entry, threshold=1)
                else:
                    st.error("Failed to save report to storage")
            else:
                st.error(f"❌ Analysis Failed: {result['error']}")
        
        except Exception as e:
            st.error(f"Error during analysis: {str(e)}")
            import traceback
            st.text(traceback.format_exc())

    st.divider()
    st.caption("This tool analyzes images and text for common scam indicators including phishing, payment fraud, and job scams.")

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

    if st.button("Clear active alerts"):
        # Clear the alerts file (legacy JSON)
        p = _scams_file_path()
        if p.exists():
            p.write_text("[]", encoding="utf-8")
        st.success("Active alerts cleared")


with tabs[2]:

    st.header("Inbox")
    st.markdown("Alerts that were generated when a scam type exceeded the configured threshold or were triggered by AlertEngine.")
    inbox = st.session_state.get("inbox_alerts", [])
    ae_alerts = st.session_state.get("ae_frontend_alerts", [])
    # Show all alerts that have been triggered (count >= 5), persist until cleared
    persisted_alerts = [a for a in (list(reversed(inbox)) + list(reversed(ae_alerts))) if a.get("count") >= 5]
    if not persisted_alerts:
        st.info("No alerts yet.")
    else:
        for it in persisted_alerts:
            t = it.get("scam_type") or it.get("type")
            c = it.get("count")
            ts = it.get("timestamp")
            msg = it.get("message")
            card(f"{t} — {c} reports", subtitle=ts)
            if msg:
                st.write(msg)
            else:
                st.write(f"Type: **{t}** — Count: **{c}**")
            end_card()
    # Display AlertEngine popup warning if alert is in inbox
    if persisted_alerts:
        for it in persisted_alerts:
            msg = it.get("message")
            if msg:
                st.warning(msg, icon="🚨")

    if st.button("Clear inbox alerts"):
        st.session_state["inbox_alerts"] = []
        st.success("Inbox cleared")
