# AB Teacher Directory V1

Safe additive backend extension for the existing AB room server.

Preserved unchanged in behavior:
- `/healthz`
- `/v1/rooms/{code}/events` GET/POST
- `/v1/rooms/{code}/ws`
- six-digit room validation, event replay/dedupe, room TTL, WebSocket flow

Added:
- teacher email/password registration and login
- hashed passwords using PBKDF2-HMAC-SHA256 with per-account random salt
- bearer sessions with hashed session tokens and expiry
- teacher profile update and public visibility
- teacher directory filters by governorate, city, subject and text query
- public teacher profile endpoint
- private email/contact fields are not exposed in public directory when contact visibility is disabled

Storage:
- SQLite for the current rollout/test path.
- `AB_DIRECTORY_DB_PATH` can point to a durable mounted path.
- If a writable `/data` mount exists it is preferred automatically.

Before large public launch, move the directory/auth tables to managed PostgreSQL or attach a durable Railway volume.
