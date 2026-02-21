#frontend - main app & display

import streamlit as st
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Page config + styling

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