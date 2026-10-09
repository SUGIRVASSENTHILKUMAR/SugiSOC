# Phase 08 — Real Linux authentication lab

This phase adds a real SSH journal exporter and a reproducible importer that
connects the existing collector, SQLite evidence store, advanced rules and cases.
The automated integration test uses **synthetic data**; it is not a live-lab result.

## Real Kali Linux validation (must be performed separately)

1. On your own Kali Linux VM, export existing *genuine* SSH authentication events:

   ```bash
   sudo journalctl -u ssh -o json --no-pager | python3 scripts/export_kali_journal.py > kali-ssh.log
   ```

   Run from a checkout of this SugiSOC repository on Kali, or copy only the
   `scripts/export_kali_journal.py` file to Kali. Never export private credentials.
   If the journal contains no SSH events, zero records is a valid result.

2. Transfer `kali-ssh.log` securely to your Mac into a local private folder.
   Check and redact personal data before recording or sharing demo material.
3. On your Mac from the SugiSOC project folder:

   ```bash
   .venv/bin/python -m sugisoc.services.lab_runner /path/to/kali-ssh.log
   ```

4. Run it **twice**: the second run should show zero accepted lines and no new
   alerts or cases. Existing events remain in `.collection-state/lab.db`.
5. The detection engine requires multiple timestamped SSH records that match
   rule conditions. **Zero detections is not a failed import.** Do not manufacture
   logs and label them as live Kali results.

## Limitations

- Reads an exported snapshot, not continuous endpoint telemetry.
- Requires actual `journalctl` records; access may require sudo on Kali.
- Only currently supported SSH authentication message formats are normalized.
- Detection searches at most 500 most recently stored events per run.
- Results require analyst judgment; warnings do not prove compromise.
- No SSH attack traffic generation; this feature only reads existing records.
- Validate the real journal integration before claiming Phase 08 complete.
