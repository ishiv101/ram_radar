# ram_radar

Quick run examples for `AlertEngine` CLI:

- Run the built-in demo sequence:

```bash
python -m alert.alert_engine --demo
```

- Trigger an alert by repeating a flag until the threshold (example threshold=5):

```bash
python -m alert.alert_engine --flag "Fake UNC email domain" --repeat 5 --threshold 5 --send
```

The demo and CLI are implemented in [alert/alert_engine.py](alert/alert_engine.py).

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
