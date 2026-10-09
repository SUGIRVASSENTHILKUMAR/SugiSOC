# SugiSOC Phase 09 — Security and Reliability Review

Scope: local-only dashboard, SQLite evidence retention, and repeatable lab import.

## Controls and evidence
- Same-origin checks for browser-initiated case changes; cross-origin POST requests are rejected.
- No authentication is provided. **Never expose this service to a public interface or port-forward it.**
- Static file allow-list prevents arbitrary repository file serving.
- Body-size checks and event-query limits are tested.
- `scripts/phase9_audit.py` performs a read-only SQLite integrity check and isolated evidence replay.
- Phase 08 genuine Kali evidence may be passed via `--evidence .collection-state/kali-attack-evidence.log`.
- Every alert and case remains a lead for analyst verification, not proof of compromise.

## Explicit limitations
- No authentication, user roles, TLS termination, remote collectors, cross-host trust, or production deployment readiness.
- A local hostile process or a compromised browser remains outside this narrow phase's protection.
- Detection coverage is limited to implemented authentication patterns. One successful lab detection is **not** an accuracy or false-positive rate.
- Benchmarking on representative large log corpora, multi-worker concurrency and resource ceilings require additional measurement.
- Keep `.collection-state/` and exported logs private; do not publish real account activity in GitHub.

## Manual validation before release
1. Open the local dashboard with actual Phase 08 evidence and inspect original records and a case timeline.
2. Run `python scripts/phase9_audit.py --evidence .collection-state/kali-attack-evidence.log` inside the project virtual environment.
3. Verify expected refusals for cross-origin POST requests.
4. Test keyboard navigation, reduced-motion setting and narrow viewport, including Matrix animation.
5. Verify GitHub Actions after repository publication (local checks do not prove cloud CI).
