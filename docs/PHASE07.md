# Phase 07 — ATT&CK-aligned detection and offline context

SugiSOC adds a conservative cross-source authentication-failure rule (`AUTH-DISTRIBUTED-004`) and an ATT&CK annotation catalog for existing authentication rules. Mapping a rule to MITRE ATT&CK describes a possible technique; it **never proves compromise**.

The offline indicator reader accepts only locally supplied JSON objects with `ip`, `source`, and `context` keys. It performs **no external threat-intelligence calls** and makes no claims about real-world maliciousness.

Limitations: 500-event bounded query, batch-time windows, no streaming, simplistic IP grouping, and no production-calibrated thresholds. The dashboard is unchanged in this phase; advanced alerts can be populated with the Python `run_advanced_detection` function before browsing. Real feeds and empirical validation remain future work.
