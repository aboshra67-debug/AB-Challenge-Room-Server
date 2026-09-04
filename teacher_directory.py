from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/v1/teachers", tags=["teachers"])
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DB_LOCK = threading.RLock()


def _db_path() -> str:
    configured = os.getenv("AB_DIRECTORY_DB_PATH", "").strip()
    if configured:
        return configured
    data_dir = Path("/data")
    try:
        if data_dir.exists() and os.access(str(data_dir), os.W_OK):
            return str(data_dir / "ab_teacher_directory.db")
    except Exception:
        pass
    return str(Path("ab_teacher_directory.db").resolve())


DB_PATH = _db_path()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_directory_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with DB_LOCK, _db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS teachers (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                subject TEXT NOT NULL DEFAULT '',
                governorate TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                grades TEXT NOT NULL DEFAULT '',
                teaching_place TEXT NOT NULL DEFAULT '',
                schedule TEXT NOT NULL DEFAULT '',
                contact TEXT NOT NULL DEFAULT '',
                contact_type TEXT NOT NULL DEFAULT 'phone',
                show_contact INTEGER NOT NULL DEFAULT 0,
                bio TEXT NOT NULL DEFAULT '',
                classroom_code TEXT NOT NULL DEFAULT '',
                public_enabled INTEGER NOT NULL DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0,
                featured INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_teachers_location ON teachers(governorate, city);
            CREATE INDEX IF NOT EXISTS idx_teachers_subject ON teachers(subject);
            CREATE TABLE IF NOT EXISTS teacher_sessions (
                token_hash TEXT PRIMARY KEY,
                teacher_id TEXT NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_teacher_sessions_teacher ON teacher_sessions(teacher_id);
            """
        )


def install_teacher_directory(app: FastAPI) -> None:
    app.include_router(router)
    app.add_event_handler("startup", init_directory_db)


def _text(value: Any, maximum: int = 180) -> str:
    value = "" if value is None else str(value).strip()
    value = re.sub(r"\s+", " ", value)
    return value[:maximum]


def _email(value: Any) -> str:
    value = _text(value, 160).lower()
    if not EMAIL_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="valid email is required")
    return value


def _password(value: Any) -> str:
    value = "" if value is None else str(value)
    if len(value) < 8 or len(value) > 128:
        raise HTTPException(status_code=400, detail="password must be 8-128 characters")
    return value


def _hash_password(password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240000)
    return digest.hex(), salt.hex()


def _public(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "fullName": row["full_name"],
        "subject": row["subject"],
        "governorate": row["governorate"],
        "city": row["city"],
        "grades": row["grades"],
        "teachingPlace": row["teaching_place"],
        "schedule": row["schedule"],
        "contact": row["contact"] if bool(row["show_contact"]) else "",
        "contactType": row["contact_type"],
        "showContact": bool(row["show_contact"]),
        "bio": row["bio"],
        "classroomCode": row["classroom_code"],
        "verified": bool(row["verified"]),
        "featured": bool(row["featured"]),
        "updatedAt": row["updated_at"],
    }


def _private(row: sqlite3.Row) -> Dict[str, Any]:
    result = _public(row)
    result.update(
        {
            "email": row["email"],
            "contact": row["contact"],
            "publicEnabled": bool(row["public_enabled"]),
            "createdAt": row["created_at"],
        }
    )
    return result


def _bearer(request: Request) -> str:
    raw = request.headers.get("authorization", "")
    if not raw.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="sign in required")
    token = raw[7:].strip()
    if len(token) < 20:
        raise HTTPException(status_code=401, detail="invalid session")
    return token


def _current(request: Request) -> sqlite3.Row:
    token_hash = hashlib.sha256(_bearer(request).encode("utf-8")).hexdigest()
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        conn.execute("DELETE FROM teacher_sessions WHERE expires_at<=?", (now,))
        row = conn.execute(
            """SELECT t.* FROM teacher_sessions s JOIN teachers t ON t.id=s.teacher_id
               WHERE s.token_hash=? AND s.expires_at>?""",
            (token_hash, now),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="session expired")
    return row


def _payload(data: Dict[str, Any], current: Optional[sqlite3.Row] = None) -> Dict[str, Any]:
    mapping = {
        "fullName": "full_name",
        "teachingPlace": "teaching_place",
        "contactType": "contact_type",
        "classroomCode": "classroom_code",
    }

    def get(key: str, default: str = "", maximum: int = 180) -> str:
        if key in data:
            return _text(data.get(key), maximum)
        if current is None:
            return default
        return str(current[mapping.get(key, key)] or "")

    classroom = re.sub(r"[^0-9]", "", get("classroomCode"))[:6]
    if classroom and len(classroom) != 6:
        raise HTTPException(status_code=400, detail="classroom code must be 6 digits")
    return {
        "full_name": get("fullName"),
        "subject": get("subject"),
        "governorate": get("governorate"),
        "city": get("city"),
        "grades": get("grades"),
        "teaching_place": get("teachingPlace"),
        "schedule": get("schedule", maximum=500),
        "contact": get("contact"),
        "contact_type": get("contactType", "phone") or "phone",
        "show_contact": 1
        if bool(data.get("showContact", bool(current["show_contact"]) if current else False))
        else 0,
        "bio": get("bio", maximum=500),
        "classroom_code": classroom,
        "public_enabled": 1
        if bool(data.get("publicEnabled", bool(current["public_enabled"]) if current else False))
        else 0,
    }


@router.post("/register")
async def register(request: Request) -> JSONResponse:
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    email = _email(data.get("email"))
    password = _password(data.get("password"))
    payload = _payload(data)
    if len(payload["full_name"]) < 2:
        raise HTTPException(status_code=400, detail="full name is required")
    teacher_id = secrets.token_hex(12)
    password_hash, salt = _hash_password(password)
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        try:
            conn.execute(
                """INSERT INTO teachers(
                id,email,password_hash,password_salt,full_name,subject,governorate,city,grades,
                teaching_place,schedule,contact,contact_type,show_contact,bio,classroom_code,
                public_enabled,verified,featured,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,?,?)""",
                (
                    teacher_id,
                    email,
                    password_hash,
                    salt,
                    payload["full_name"],
                    payload["subject"],
                    payload["governorate"],
                    payload["city"],
                    payload["grades"],
                    payload["teaching_place"],
                    payload["schedule"],
                    payload["contact"],
                    payload["contact_type"],
                    payload["show_contact"],
                    payload["bio"],
                    payload["classroom_code"],
                    payload["public_enabled"],
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="email already registered")
        row = conn.execute("SELECT * FROM teachers WHERE id=?", (teacher_id,)).fetchone()
    return JSONResponse({"ok": True, "teacher": _private(row)})


@router.post("/login")
async def login(request: Request) -> JSONResponse:
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    email = _email(data.get("email"))
    password = _password(data.get("password"))
    with DB_LOCK, _db() as conn:
        row = conn.execute("SELECT * FROM teachers WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="wrong email or password")
        check, _ = _hash_password(password, row["password_salt"])
        if not hmac.compare_digest(check, row["password_hash"]):
            raise HTTPException(status_code=401, detail="wrong email or password")
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        expires = now + 30 * 86400
        conn.execute(
            "INSERT INTO teacher_sessions(token_hash,teacher_id,expires_at,created_at) VALUES(?,?,?,?)",
            (token_hash, row["id"], expires, now),
        )
    return JSONResponse({"ok": True, "token": token, "expiresAt": expires, "teacher": _private(row)})


@router.post("/logout")
async def logout(request: Request) -> Dict[str, Any]:
    token_hash = hashlib.sha256(_bearer(request).encode("utf-8")).hexdigest()
    with DB_LOCK, _db() as conn:
        conn.execute("DELETE FROM teacher_sessions WHERE token_hash=?", (token_hash,))
    return {"ok": True}


@router.get("/me")
async def me(request: Request) -> Dict[str, Any]:
    return {"ok": True, "teacher": _private(_current(request))}


@router.put("/me")
async def update_me(request: Request) -> Dict[str, Any]:
    current = _current(request)
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    payload = _payload(data, current)
    if len(payload["full_name"]) < 2:
        raise HTTPException(status_code=400, detail="full name is required")
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        conn.execute(
            """UPDATE teachers SET full_name=?,subject=?,governorate=?,city=?,grades=?,teaching_place=?,
            schedule=?,contact=?,contact_type=?,show_contact=?,bio=?,classroom_code=?,public_enabled=?,updated_at=?
            WHERE id=?""",
            (
                payload["full_name"],
                payload["subject"],
                payload["governorate"],
                payload["city"],
                payload["grades"],
                payload["teaching_place"],
                payload["schedule"],
                payload["contact"],
                payload["contact_type"],
                payload["show_contact"],
                payload["bio"],
                payload["classroom_code"],
                payload["public_enabled"],
                now,
                current["id"],
            ),
        )
        row = conn.execute("SELECT * FROM teachers WHERE id=?", (current["id"],)).fetchone()
    return {"ok": True, "teacher": _private(row)}


@router.get("")
async def directory(
    governorate: str = "", city: str = "", subject: str = "", q: str = "", limit: int = 100
) -> Dict[str, Any]:
    governorate = _text(governorate)
    city = _text(city)
    subject = _text(subject)
    q = _text(q)
    limit = max(1, min(limit, 200))
    where = ["public_enabled=1"]
    params = []
    if governorate:
        where.append("governorate=?")
        params.append(governorate)
    if city:
        where.append("city=?")
        params.append(city)
    if subject:
        where.append("subject=?")
        params.append(subject)
    if q:
        where.append("(full_name LIKE ? OR subject LIKE ? OR grades LIKE ? OR teaching_place LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like])
    sql = (
        "SELECT * FROM teachers WHERE "
        + " AND ".join(where)
        + " ORDER BY featured DESC, verified DESC, updated_at DESC LIMIT ?"
    )
    params.append(limit)
    with DB_LOCK, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"ok": True, "teachers": [_public(row) for row in rows], "count": len(rows)}


@router.get("/{teacher_id}")
async def public_profile(teacher_id: str) -> Dict[str, Any]:
    teacher_id = _text(teacher_id, 64)
    with DB_LOCK, _db() as conn:
        row = conn.execute(
            "SELECT * FROM teachers WHERE id=? AND public_enabled=1", (teacher_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="teacher not found")
    return {"ok": True, "teacher": _public(row)}
