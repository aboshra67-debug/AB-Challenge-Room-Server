from __future__ import annotations

import asyncio
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

APP_VERSION = "0.12.28"
ROOM_RE = re.compile(r"^\d{6}$")
ROOM_TTL_SECONDS = int(os.getenv("AB_ROOM_TTL_SECONDS", "21600"))  # 6 hours
MAX_EVENTS_PER_ROOM = int(os.getenv("AB_MAX_EVENTS_PER_ROOM", "1200"))
MAX_EVENT_BYTES = int(os.getenv("AB_MAX_EVENT_BYTES", "262144"))
CLIENT_QUEUE_SIZE = int(os.getenv("AB_CLIENT_QUEUE_SIZE", "256"))


@dataclass
class StoredEvent:
    seq: int
    time_sec: int
    data: Dict[str, Any]

    def wire(self) -> Dict[str, Any]:
        return {"id": str(self.seq), "time": self.time_sec, "data": self.data}


@dataclass
class RoomState:
    code: str
    events: Deque[StoredEvent] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_ROOM))
    next_seq: int = 1
    updated_at: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    clients: Dict[int, asyncio.Queue] = field(default_factory=dict)
    event_ids: Dict[str, int] = field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = time.time()


class RoomHub:
    def __init__(self) -> None:
        self._rooms: Dict[str, RoomState] = {}
        self._rooms_lock = asyncio.Lock()

    async def get(self, code: str, create: bool = False) -> Optional[RoomState]:
        async with self._rooms_lock:
            room = self._rooms.get(code)
            if room is None and create:
                room = RoomState(code=code)
                self._rooms[code] = room
            return room

    async def publish(self, code: str, data: Dict[str, Any]) -> StoredEvent:
        room = await self.get(code, create=True)
        assert room is not None
        event_id = str(data.get("_eventId") or "")
        async with room.lock:
            if event_id and event_id in room.event_ids:
                seq = room.event_ids[event_id]
                for item in room.events:
                    if item.seq == seq:
                        room.touch()
                        return item
            event = StoredEvent(
                seq=room.next_seq,
                time_sec=int(time.time()),
                data=data,
            )
            room.next_seq += 1
            room.events.append(event)
            if event_id:
                room.event_ids[event_id] = event.seq
                # Keep dedupe map bounded to the retained event window.
                if len(room.event_ids) > MAX_EVENTS_PER_ROOM * 2:
                    retained = {e.data.get("_eventId"): e.seq for e in room.events if e.data.get("_eventId")}
                    room.event_ids = {str(k): int(v) for k, v in retained.items()}
            room.touch()
            queues = list(room.clients.values())
        for queue in queues:
            self._offer(queue, event)
        return event

    async def poll(self, code: str, since: int = 0, limit: int = 500) -> list[StoredEvent]:
        room = await self.get(code, create=False)
        if room is None:
            return []
        limit = max(1, min(limit, MAX_EVENTS_PER_ROOM))
        async with room.lock:
            room.touch()
            selected = [e for e in room.events if e.seq > since]
            if len(selected) > limit:
                selected = selected[-limit:]
            return list(selected)

    async def register(self, code: str, client_key: int, since: int) -> tuple[asyncio.Queue, list[StoredEvent]]:
        room = await self.get(code, create=True)
        assert room is not None
        queue: asyncio.Queue = asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE)
        async with room.lock:
            backlog = [e for e in room.events if e.seq > since]
            room.clients[client_key] = queue
            room.touch()
            return queue, backlog

    async def unregister(self, code: str, client_key: int) -> None:
        room = await self.get(code, create=False)
        if room is None:
            return
        async with room.lock:
            room.clients.pop(client_key, None)
            room.touch()

    async def stats(self) -> Dict[str, Any]:
        async with self._rooms_lock:
            rooms = list(self._rooms.values())
        total_clients = 0
        total_events = 0
        for room in rooms:
            async with room.lock:
                total_clients += len(room.clients)
                total_events += len(room.events)
        return {
            "rooms": len(rooms),
            "clients": total_clients,
            "events": total_events,
            "version": APP_VERSION,
        }

    async def prune(self) -> int:
        cutoff = time.time() - ROOM_TTL_SECONDS
        async with self._rooms_lock:
            stale = [code for code, room in self._rooms.items() if room.updated_at < cutoff]
            for code in stale:
                self._rooms.pop(code, None)
        return len(stale)

    @staticmethod
    def _offer(queue: asyncio.Queue, event: StoredEvent) -> None:
        try:
            queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass


hub = RoomHub()
app = FastAPI(title="AB Challenge Room Server", version=APP_VERSION)


def validate_room(code: str) -> str:
    if not ROOM_RE.fullmatch(code or ""):
        raise HTTPException(status_code=400, detail="room code must be 6 digits")
    return code


def parse_since(raw: Optional[str]) -> int:
    if raw is None or raw == "":
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


@app.on_event("startup")
async def startup_pruner() -> None:
    async def loop() -> None:
        while True:
            await asyncio.sleep(60)
            await hub.prune()

    asyncio.create_task(loop())


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {"ok": True, **(await hub.stats())}


@app.get("/v1/rooms/{code}/events")
async def get_events(code: str, since: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
    validate_room(code)
    events = await hub.poll(code, parse_since(since), limit)
    return {"room": code, "events": [e.wire() for e in events]}


@app.post("/v1/rooms/{code}/events")
async def post_event(code: str, request: Request) -> JSONResponse:
    validate_room(code)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_EVENT_BYTES:
                raise HTTPException(status_code=413, detail="event too large")
        except ValueError:
            pass
    raw = await request.body()
    if len(raw) > MAX_EVENT_BYTES:
        raise HTTPException(status_code=413, detail="event too large")
    try:
        data = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="event must be a json object")
    event = await hub.publish(code, data)
    return JSONResponse({"ok": True, "event": event.wire()})


@app.websocket("/v1/rooms/{code}/ws")
async def room_ws(websocket: WebSocket, code: str) -> None:
    if not ROOM_RE.fullmatch(code or ""):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    since = parse_since(websocket.query_params.get("since"))
    key = id(websocket)
    queue, backlog = await hub.register(code, key, since)
    receiver: Optional[asyncio.Task] = None
    try:
        await websocket.send_json({"type": "ready", "room": code, "version": APP_VERSION})
        for event in backlog:
            await websocket.send_json({"type": "event", "event": event.wire()})
        receiver = asyncio.create_task(websocket.receive_text())
        while True:
            queue_task = asyncio.create_task(queue.get())
            done, pending = await asyncio.wait(
                {queue_task, receiver}, timeout=12.0, return_when=asyncio.FIRST_COMPLETED
            )
            if receiver in done:
                # Clients never need to send application messages. Any received frame
                # simply proves the connection is alive; immediately wait for the next.
                try:
                    receiver.result()
                except Exception:
                    queue_task.cancel()
                    break
                receiver = asyncio.create_task(websocket.receive_text())
            if queue_task in done:
                event = queue_task.result()
                await websocket.send_json({"type": "event", "event": event.wire()})
            else:
                queue_task.cancel()
            if not done:
                await websocket.send_json({"type": "heartbeat", "ts": int(time.time() * 1000)})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if receiver is not None and not receiver.done():
            receiver.cancel()
        await hub.unregister(code, key)
