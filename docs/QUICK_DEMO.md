# SugiSOC — Reproducible Quick Demo

Run the actual SugiSOC ingestion, detection and case-correlation
pipeline against synthetic SSH authentication evidence.

## Run

Install SugiSOC in a Python environment, then execute:

```bash
python scripts/demo.py
```

## Expected behavior

- Six synthetic SSH authentication failures are generated.
- An alert and correlated case are created by the real detection pipeline.
- The fixture is processed a second time to verify replay protection.
- No duplicate events, alerts or cases are created.
- The script prints `SUGISOC DEMO PASSED`.

The source address `192.0.2.44` is reserved for documentation.
No SSH attacks or network connections are performed by the demo.

All temporary demo files are automatically removed after execution.
This is laboratory validation, not a production performance benchmark.
