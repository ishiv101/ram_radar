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

