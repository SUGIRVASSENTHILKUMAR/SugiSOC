# Security and Limitations

## Intended use

SugiSOC is a defensive security education and portfolio project for use in controlled laboratory environments.

## Deployment model

- The application HTTP server binds to the local loopback interface.
- The default application has no built-in user login or role-based authorization.
- An origin check rejects mismatched browser origins for supported POST routes, but origin checking is **not authentication**.
- Requests without an `Origin` header are not an authorization guarantee.
- `--read-only` disables case-note and case-status POST operations in the application handler.
- A separate synthetic database is used for the private read-only demo.
- Tailscale Serve was tested as a private HTTPS reverse proxy; Tailscale Funnel was not enabled.

Do not directly expose a writable SugiSOC instance to untrusted networks.

## Data handling

Real logs can contain personal, device, account, or infrastructure information. Avoid committing or publishing real investigation evidence.

The repository ignores local state, SQLite databases, generated logs, local environments, and environment files. Review new files and Git history before each public release.

## Limitations

This project does not claim:

- Production-grade authentication or authorization
- Comprehensive endpoint or network telemetry coverage
- Complete MITRE ATT&CK technique coverage
- Validated precision/recall across real attack datasets
- Multi-tenant isolation
- High availability, distributed ingestion, or enterprise scalability
- A completed independent security assessment

## Reporting issues

For responsible disclosure, contact the repository maintainer privately through their published GitHub contact methods. Avoid opening public issues containing credentials, sensitive logs, or exploitable details about a live system.
