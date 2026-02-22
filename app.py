# Clear inbox and AlertEngine frontend alerts on Streamlit startup
import streamlit as st
st.session_state["inbox_alerts"] = []
st.session_state["ae_frontend_alerts"] = []
import os
#frontend - main app & display
# Clear active alerts file on Streamlit startup
def _scams_file_path_startup() -> str:
    from pathlib import Path
    import src.config as cfg
    d = Path(getattr(cfg, "DATA_DIR", "data"))
    d.mkdir(parents=True, exist_ok=True)
    return str(d / getattr(cfg, "SCAMS_FILE", "scams.json").split(os.sep)[-1])

alerts_path = _scams_file_path_startup()
if os.path.exists(alerts_path):
    with open(alerts_path, "w", encoding="utf-8") as f:
        f.write("[]")

import streamlit as st
import threading
import time
# --- Background polling for AlertEngine ---
from alert.alert_engine import AlertEngine

# Store scam types that have already triggered at threshold to avoid duplicate alerts
if 'ae_exact_threshold_shown' not in st.session_state:
    st.session_state['ae_exact_threshold_shown'] = set()

def poll_alert_engine_exact_threshold(threshold=5, poll_interval=5):
    engine = AlertEngine(threshold=threshold)
    while True:
        alerts = engine.get_all_alerts()
        # Only trigger if count == threshold (not over)
        for scam_type, count in alerts.items():
            if count == threshold and scam_type not in st.session_state['ae_exact_threshold_shown']:
                st.session_state['ae_exact_threshold_shown'].add(scam_type)
                st.session_state['ae_exact_threshold_alert'] = (scam_type, count)
        time.sleep(poll_interval)

# Start polling thread only once
if 'ae_polling_thread_started' not in st.session_state:
    t = threading.Thread(target=poll_alert_engine_exact_threshold, args=(5, 5), daemon=True)
    t.start()
    st.session_state['ae_polling_thread_started'] = True
# --- Main area: two tabs (Report / Active alerts)
# -----------------------------

# Display alert if scam group hits exactly the threshold
if 'ae_exact_threshold_alert' in st.session_state:
    scam_type, count = st.session_state['ae_exact_threshold_alert']
    st.warning(f"Scam group '{scam_type}' has reached the threshold of {count} reports!", icon="🚨")
from datetime import datetime, timezone
from typing import Dict, List, Optional
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
st.set_page_config(
    page_title="Ram Radar",
    page_icon="🚨",
    layout="wide",
)

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


# Top header (no sidebar)
st.markdown("## 🚨 Ram Radar")
st.markdown("---")


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


def show_db_contents():
    """Display the current database contents in the Streamlit UI.

    If a ScamDatabase is available, read from it; otherwise fall back to the
    legacy JSON storage used by load_alerts().
    """
    try:
        #st.subheader("Stored reports (database)")
        if _db is not None:
            records = _db.get_all_records()
            # ScamRecord -> dict
            recs = []
            for r in records:
                try:
                    recs.append(r.to_dict())
                except Exception:
                    # already a dict
                    recs.append(r)
            #st.json(recs)
        else:
            recs = load_alerts()
            #st.json(recs)
    except Exception as e:
        st.error(f"Failed to load DB records: {e}")


def _get_all_records_as_dicts():
    """Return all stored records as a list of dicts (DB or legacy JSON)."""
    try:
        if _db is not None:
            return [r.to_dict() if hasattr(r, "to_dict") else r for r in _db.get_all_records()]
        return load_alerts()
    except Exception:
        return []


def check_and_notify_threshold(entry: dict, threshold: int = 5):
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
            if cnt > threshold and t not in st.session_state["threshold_alerts_shown"]:
                triggered.append((t, cnt))

        if triggered:
            # Mark them as shown so we don't repeat
            for t, _ in triggered:
                st.session_state["threshold_alerts_shown"].add(t)

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

            # Render a prominent banner and an expanding detail box
            msgs = "".join([f"<li><strong>{t}</strong>: {c} reports</li>" for t, c in triggered])
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
    st.title("🚨 Scam Detection Tool")
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
                            st.warning(f"⚠️ {flag}")
                    else:
                        st.info("No suspicious indicators detected.")
                
                with image_col:
                    st.subheader("Uploaded Image")
                    st.image(image, use_column_width=True)
                
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
                    show_db_contents()
                    check_and_notify_threshold(entry, threshold=5)
                
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
                    show_db_contents()
                    check_and_notify_threshold(entry, threshold=5)
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


# --- AlertEngine Streamlit integration (appended; does not modify existing UI) ---
try:
    import importlib
    import streamlit as st

    # -------------------------
    # Import AlertEngine (reload for local edits)
    # -------------------------
    try:
        import alert.alert_engine as _ae_mod
        importlib.reload(_ae_mod)
        AlertEngine = _ae_mod.AlertEngine
    except Exception:
        from alert.alert_engine import AlertEngine

    st.sidebar.header("AlertEngine Tester")
    _threshold = st.sidebar.number_input("Threshold", min_value=1, max_value=100, value=5)
    _send = st.sidebar.checkbox("Call send_alert()", value=False)

    # -------------------------
    # Scam types (safe fallback)
    # -------------------------
    try:
        from src.scam_grouper import ScamGrouper
        grouper = ScamGrouper()
        scam_types_dict = getattr(grouper, "SCAM_TYPES", {})
        available_types = list(scam_types_dict.keys()) if isinstance(scam_types_dict, dict) else []
    except Exception:
        available_types = []

    if not available_types:
        available_types = ["phishing", "payment_fraud", "campus_sale", "job_scam", "domain_spoofing"]

    _selected_types = st.sidebar.multiselect(
        "Select scam type(s)",
        options=available_types,
        default=[available_types[0]] if available_types else [],
    )

    st.sidebar.subheader("Counts per selected type")

    # -------------------------
    # Per-type unique counts
    # -------------------------
    per_type_counts = {}
    for scam_type in _selected_types:
        per_type_counts[scam_type] = st.sidebar.number_input(
            f"{scam_type} count",
            min_value=0,
            max_value=500,
            value=0,
            step=1,
            key=f"count_{scam_type}",
        )

    # -------------------------
    # Session state for persistence across reruns
    # -------------------------
    if "ae_last_result" not in st.session_state:
        st.session_state.ae_last_result = None
    if "ae_last_alerts" not in st.session_state:
        st.session_state.ae_last_alerts = None
    if "ae_last_error" not in st.session_state:
        st.session_state.ae_last_error = None

    # -------------------------
    # Run engine on click
    # -------------------------
    if st.sidebar.button("Inbox"):
        st.session_state.ae_last_error = None
        try:
            engine = AlertEngine(threshold=int(_threshold))

            # Feed events based on per-type counts
            last_result = None
            for scam_type, n in per_type_counts.items():
                for _ in range(int(n)):
                    last_result = engine.add_event([scam_type])

            st.session_state.ae_last_result = last_result
            st.session_state.ae_last_alerts = engine.get_all_alerts()

            # Send alerts immediately if requested
            if _send and st.session_state.ae_last_alerts:
                for k, v in st.session_state.ae_last_alerts.items():
                    try:
                        engine.send_alert(k, v)
                    except Exception as e:
                        st.sidebar.error(f"send_alert failed for {k}: {type(e).__name__}: {e}")

        except Exception as e:
            st.session_state.ae_last_error = f"{type(e).__name__}: {e}"

    # -------------------------
    # Display results: ALERTS ONLY (counts >= threshold)
    # -------------------------
    if st.session_state.ae_last_error:
        st.sidebar.error(f"Inbox failed: {st.session_state.ae_last_error}")

    result = st.session_state.ae_last_result
    alerts = st.session_state.ae_last_alerts

    st.sidebar.write("**Alerts (count ≥ threshold):**")
    if alerts:
        for k, v in alerts.items():
            st.sidebar.write(f"- {k}: {v}")
        st.sidebar.success("Alerts triggered")
    else:
        # Only show this after at least one run
        if result is not None or st.session_state.ae_last_error is not None:
            st.sidebar.info("No alerts triggered")

except Exception as e:
    st.sidebar.error(f"AlertEngine integration failed: {type(e).__name__}: {e}")
    raise