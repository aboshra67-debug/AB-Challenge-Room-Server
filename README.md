# AB Challenge dedicated room server

This server replaces public ntfy relays for multiplayer rooms.

Production requirements:
- HTTPS/WSS endpoint.
- One server process (`uvicorn --workers 1`) with the current in-memory room store.
- For horizontal scaling or multiple workers, move room/event state to Redis first.
- Keep the server URL in Android Gradle property `AB_ROOM_SERVER_URL` without a trailing slash.

Health endpoint: `/healthz`
Room REST recovery: `/v1/rooms/{6_digit_code}/events`
Live room stream: `/v1/rooms/{6_digit_code}/ws`

The transport keeps a bounded room event history, deduplicates retried publishes by `_eventId`, replays missed events after reconnect, sends heartbeats, and expires inactive rooms after 6 hours.
