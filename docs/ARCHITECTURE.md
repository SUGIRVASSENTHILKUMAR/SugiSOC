# SugiSOC Architecture

## Purpose

SugiSOC demonstrates a small end-to-end SOC workflow:

1. Collect authentication-related evidence from log files.
2. Normalize source records into consistent security events.
3. Persist events in SQLite.
4. Run detection logic against stored events.
5. Create alerts backed by event evidence.
6. Correlate alerts into investigation cases.
7. Present findings through a local API and dashboard.

## Backend modules

| Component | Location | Responsibility |
| --- | --- | --- |
| Collection | `backend/sugisoc/collectors/` | Read source log records |
| Models | `backend/sugisoc/models/` | Normalize events |
| Event storage | `backend/sugisoc/services/event_store.py` | Store and query event evidence |
| Ingestion | `backend/sugisoc/services/ingestion.py` | Import evidence with checkpoints |
| Detection | `backend/sugisoc/detection/` | Generate security alerts |
| Correlation | `backend/sugisoc/correlation/` | Maintain investigation cases |
| HTTP API | `backend/sugisoc/api/server.py` | Serve API responses and frontend |
| Dashboard | `frontend/` | Display SOC findings and investigations |

## API routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/overview` | Aggregate counts |
| GET | `/api/events` | Search security events |
| GET | `/api/alerts` | List alerts |
| GET | `/api/cases` | List investigation cases |
| GET | `/api/cases/{case_id}` | View case evidence |
| POST | `/api/cases/{case_id}/status` | Update local case status |
| POST | `/api/cases/{case_id}/notes` | Add a local analyst note |

The POST operations return HTTP 405 when the server is launched with `--read-only`.

## Validation

Automated integration tests check evidence ingestion, repeated-import behavior, detection, case creation, and API behavior.

A controlled Kali Linux SSH-log exercise validated the lab ingestion pathway. A separate synthetic dataset validated 18 events, three alerts, three cases, and replay protection.

These tests establish behavior for the exercised fixtures and environment, not comprehensive real-world detection coverage.

## Deployment boundaries

The Python server binds to `127.0.0.1` by default.

Private HTTPS testing was performed using Tailscale Serve as a reverse proxy to a separate read-only instance backed by synthetic evidence. This is not a public hosting configuration and does not provide a general-purpose user authentication system.
