import streamlit as st
import sys
from pathlib import Path

# Add the project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from PIL import Image
    from src.utils import analyze_image_for_scams
    from src.scam_grouper import ScamGrouper
except ImportError as e:
    st.error(f"Import Error: {e}")
    st.stop()

st.set_page_config(page_title="Scam Detector", layout="centered")

st.title("🚨 Scam Detection Tool")
st.write("Upload an image of a potential scam message to analyze it for suspicious content.")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Upload Image")
    uploaded_file = st.file_uploader(
        "Choose an image file",
        type=["jpg", "jpeg", "png", "bmp", "gif"]
    )

with col2:
    st.subheader("Options")
    use_gpu = st.checkbox("Use GPU (if available)", value=False)

if uploaded_file is not None:
    try:
        # Display uploaded image
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Image", use_container_width=True)
        
        # Save temporarily and analyze
        temp_path = f"/tmp/{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Analyze
        with st.spinner("Analyzing image..."):
            result = analyze_image_for_scams(temp_path, use_gpu=use_gpu)
        
        # Display results
        st.divider()
        
        if result["success"]:
            # Scam Score - Large and prominent
            st.subheader("Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Color code the score
                score = result["scam_score"]
                if score >= 70:
                    color = "🔴"  # Red - High risk
                    risk_level = "HIGH RISK"
                elif score >= 40:
                    color = "🟡"  # Yellow - Medium risk
                    risk_level = "MEDIUM RISK"
                else:
                    color = "🟢"  # Green - Low risk
                    risk_level = "LOW RISK"
                
                st.metric("Scam Score", f"{score}/100", delta=risk_level)
            
            with col2:
                scam_types = result["scam_types"]
                types_text = ", ".join(scam_types) if scam_types else "None detected"
                st.metric("Scam Type(s)", types_text)
            
            # Extracted Text
            st.subheader("Extracted Text")
            st.text_area("Text from image:", value=result["extracted_text"], height=150, disabled=True)
            
            # Detected Flags
            if result["flags"]:
                st.subheader("Detected Red Flags")
                for flag in result["flags"]:
                    st.warning(f"⚠️ {flag}")
            else:
                st.info("No suspicious indicators detected.")
            
            # OCR Confidence
            st.subheader("OCR Confidence")
            st.progress(result["confidence"], text=f"{result['confidence']:.1%}")
            
        else:
            st.error(f"❌ Analysis Failed: {result['error']}")
    
    except Exception as e:
        st.error(f"Error during analysis: {str(e)}")
        import traceback
        st.text(traceback.format_exc())

st.divider()
st.caption("This tool analyzes images for common scam indicators including phishing, payment fraud, and job scams.")

# --- AlertEngine Streamlit integration (appended; does not modify existing UI) ---
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
    _entries = st.sidebar.text_area(
        "Enter scam types and counts (one per line: type,count)",
        value="Fake UNC email domain,6\nPayment fraud,3"
    )
    _send = st.sidebar.checkbox("Call send_alert()", value=False)

    if st.sidebar.button("Run AlertEngine Demo"):
        engine = AlertEngine(threshold=int(_threshold))

        # Parse user entries
        lines = [l.strip() for l in _entries.splitlines() if l.strip()]
        parsed = []  # list of (type, count)
        for line in lines:
            if "," in line:
                t, c = line.split(",", 1)
            elif ":" in line:
                t, c = line.split(":", 1)
            else:
                t, c = line, "1"
            try:
                count = int(c.strip())
            except Exception:
                count = 1
            parsed.append((t.strip(), count))

        # Feed events into the engine
        for scam_type, count in parsed:
            for _ in range(max(0, int(count))):
                try:
                    engine.add_event([scam_type])
                except Exception as e:
                    st.sidebar.error(f"add_event failed: {e}")

        # Retrieve and display alerts (only types meeting threshold)
        alerts = engine.get_all_alerts()
        if alerts:
            st.sidebar.success("Active Alerts:")
            for scam_type, count in alerts.items():
                st.sidebar.write(f"- {scam_type}: {count} reports")
        else:
            st.sidebar.info("No scam types have crossed the threshold.")
except Exception as e:
    st.sidebar.error(f"AlertEngine integration failed: {e}")
