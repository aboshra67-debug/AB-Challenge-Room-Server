from __future__ import annotations

import hashlib
import hmac
import json
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

from teacher_directory import _current as current_teacher

router = APIRouter(prefix="/v1/family", tags=["family"])
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9._:-]{8,180}$")
DB_LOCK = threading.RLock()


def _db_path() -> str:
    configured = os.getenv("AB_FAMILY_DB_PATH", "").strip()
    if configured:
        return configured
    data_dir = Path("/data")
    try:
        if data_dir.exists() and os.access(str(data_dir), os.W_OK):
            return str(data_dir / "ab_family_accounts.db")
    except Exception:
        pass
    return str(Path("ab_family_accounts.db").resolve())


DB_PATH = _db_path()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_family_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with DB_LOCK, _db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS parents (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                governorate TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS parent_sessions (
                token_hash TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_parent_sessions_parent ON parent_sessions(parent_id);
            CREATE TABLE IF NOT EXISTS parent_devices (
                device_id TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS students (
                id TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                student_code TEXT NOT NULL UNIQUE,
                pin_hash TEXT NOT NULL,
                pin_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                grade TEXT NOT NULL DEFAULT '',
                school TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_students_parent ON students(parent_id);
            CREATE TABLE IF NOT EXISTS student_sessions (
                token_hash TEXT PRIMARY KEY,
                student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_student_sessions_student ON student_sessions(student_id);
            CREATE TABLE IF NOT EXISTS monthly_reports (
                id TEXT PRIMARY KEY,
                teacher_id TEXT NOT NULL,
                parent_id TEXT,
                student_id TEXT,
                target_device_id TEXT NOT NULL,
                classroom_code TEXT NOT NULL,
                classroom_name TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL DEFAULT '',
                student_name TEXT NOT NULL,
                parent_name TEXT NOT NULL DEFAULT '',
                month TEXT NOT NULL,
                present_count INTEGER NOT NULL DEFAULT 0,
                absent_count INTEGER NOT NULL DEFAULT 0,
                excused_count INTEGER NOT NULL DEFAULT 0,
                late_count INTEGER NOT NULL DEFAULT 0,
                due REAL NOT NULL DEFAULT 0,
                paid REAL NOT NULL DEFAULT 0,
                remaining REAL NOT NULL DEFAULT 0,
                payment_status TEXT NOT NULL DEFAULT '',
                finalized INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(teacher_id,classroom_code,target_device_id,student_name,month)
            );
            CREATE INDEX IF NOT EXISTS idx_reports_parent ON monthly_reports(parent_id,month);
            CREATE INDEX IF NOT EXISTS idx_reports_student ON monthly_reports(student_id,month);
            CREATE INDEX IF NOT EXISTS idx_reports_device ON monthly_reports(target_device_id,month);
            """
        )


def install_family_accounts(app: FastAPI) -> None:
    app.include_router(router)
    app.add_event_handler("startup", init_family_db)


def _text(value: Any, maximum: int = 180) -> str:
    value = "" if value is None else str(value).strip()
    value = re.sub(r"\s+", " ", value)
    return value[:maximum]


def _email(value: Any, required: bool = True) -> str:
    value = _text(value, 160).lower()
    if not value and not required:
        return ""
    if not EMAIL_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="valid email is required")
    return value


def _password(value: Any) -> str:
    value = "" if value is None else str(value)
    if len(value) < 8 or len(value) > 128:
        raise HTTPException(status_code=400, detail="password must be 8-128 characters")
    return value


def _pin(value: Any) -> str:
    value = re.sub(r"\D", "", "" if value is None else str(value))
    if len(value) < 4 or len(value) > 8:
        raise HTTPException(status_code=400, detail="PIN must be 4-8 digits")
    return value


def _hash_secret(secret: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 240000)
    return digest.hex(), salt.hex()


def _issue_session(conn: sqlite3.Connection, table: str, owner_column: str, owner_id: str) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    expires = now + 30 * 86400
    conn.execute(
        f"INSERT INTO {table}(token_hash,{owner_column},expires_at,created_at) VALUES(?,?,?,?)",
        (token_hash, owner_id, expires, now),
    )
    return token, expires


def _bearer(request: Request) -> str:
    raw = request.headers.get("authorization", "")
    if not raw.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="sign in required")
    token = raw[7:].strip()
    if len(token) < 20:
        raise HTTPException(status_code=401, detail="invalid session")
    return token


def _current_parent(request: Request) -> sqlite3.Row:
    token_hash = hashlib.sha256(_bearer(request).encode("utf-8")).hexdigest()
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        conn.execute("DELETE FROM parent_sessions WHERE expires_at<=?", (now,))
        row = conn.execute(
            """SELECT p.* FROM parent_sessions s JOIN parents p ON p.id=s.parent_id
               WHERE s.token_hash=? AND s.expires_at>?""",
            (token_hash, now),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="session expired")
    return row


def _current_student(request: Request) -> sqlite3.Row:
    token_hash = hashlib.sha256(_bearer(request).encode("utf-8")).hexdigest()
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        conn.execute("DELETE FROM student_sessions WHERE expires_at<=?", (now,))
        row = conn.execute(
            """SELECT s.* FROM student_sessions x JOIN students s ON s.id=x.student_id
               WHERE x.token_hash=? AND x.expires_at>? AND s.active=1""",
            (token_hash, now),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="session expired")
    return row


def _parent_public(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "fullName": row["full_name"],
        "phone": row["phone"],
        "governorate": row["governorate"],
        "city": row["city"],
        "createdAt": row["created_at"],
    }


def _student_public(row: sqlite3.Row, include_parent: bool = False) -> Dict[str, Any]:
    result = {
        "id": row["id"],
        "studentCode": row["student_code"],
        "fullName": row["full_name"],
        "grade": row["grade"],
        "school": row["school"],
        "email": row["email"],
        "active": bool(row["active"]),
        "createdAt": row["created_at"],
    }
    if include_parent:
        result["parentId"] = row["parent_id"]
    return result


def _normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


def _claim_reports(conn: sqlite3.Connection, parent_id: str, device_id: str = "") -> None:
    if device_id:
        conn.execute(
            "UPDATE monthly_reports SET parent_id=? WHERE target_device_id=? AND (parent_id IS NULL OR parent_id='')",
            (parent_id, device_id),
        )
    students = conn.execute("SELECT id,full_name FROM students WHERE parent_id=? AND active=1", (parent_id,)).fetchall()
    reports = conn.execute(
        "SELECT id,student_name FROM monthly_reports WHERE parent_id=? AND (student_id IS NULL OR student_id='')",
        (parent_id,),
    ).fetchall()
    name_map: Dict[str, Optional[str]] = {}
    for student in students:
        key = _normalize_name(student["full_name"])
        if key in name_map:
            name_map[key] = None
        else:
            name_map[key] = student["id"]
    for report in reports:
        sid = name_map.get(_normalize_name(report["student_name"]))
        if sid:
            conn.execute("UPDATE monthly_reports SET student_id=? WHERE id=?", (sid, report["id"]))


def _bind_device(conn: sqlite3.Connection, parent_id: str, device_id: str) -> None:
    device_id = _text(device_id, 180)
    if not device_id:
        return
    if not DEVICE_RE.fullmatch(device_id):
        raise HTTPException(status_code=400, detail="invalid device id")
    now = int(time.time())
    conn.execute(
        "INSERT INTO parent_devices(device_id,parent_id,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(device_id) DO UPDATE SET parent_id=excluded.parent_id,updated_at=excluded.updated_at",
        (device_id, parent_id, now),
    )
    _claim_reports(conn, parent_id, device_id)


def _new_student_code(conn: sqlite3.Connection) -> str:
    for _ in range(50):
        code = "AB-" + str(secrets.randbelow(900000) + 100000)
        if conn.execute("SELECT 1 FROM students WHERE student_code=?", (code,)).fetchone() is None:
            return code
    raise HTTPException(status_code=503, detail="could not create student id")


def _report_dict(row: sqlite3.Row, include_money: bool) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "id": row["id"],
        "classroomCode": row["classroom_code"],
        "classroomName": row["classroom_name"],
        "subject": row["subject"],
        "studentName": row["student_name"],
        "parentName": row["parent_name"],
        "month": row["month"],
        "present": row["present_count"],
        "absent": row["absent_count"],
        "excused": row["excused_count"],
        "late": row["late_count"],
        "paymentStatus": row["payment_status"],
        "finalized": bool(row["finalized"]),
        "updatedAt": row["updated_at"],
    }
    if include_money:
        result.update({"due": row["due"], "paid": row["paid"], "remaining": row["remaining"]})
    return result


@router.get("/health")
async def health() -> Dict[str, Any]:
    with DB_LOCK, _db() as conn:
        parents = conn.execute("SELECT COUNT(*) c FROM parents").fetchone()["c"]
        students = conn.execute("SELECT COUNT(*) c FROM students").fetchone()["c"]
    return {"ok": True, "parents": parents, "students": students, "version": 1}


@router.post("/parents/register")
async def parent_register(request: Request) -> JSONResponse:
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    email = _email(data.get("email"))
    password = _password(data.get("password"))
    full_name = _text(data.get("fullName"))
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="full name is required")
    parent_id = secrets.token_hex(12)
    ph, salt = _hash_secret(password)
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        try:
            conn.execute(
                "INSERT INTO parents(id,email,password_hash,password_salt,full_name,phone,governorate,city,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (parent_id, email, ph, salt, full_name, _text(data.get("phone")), _text(data.get("governorate")), _text(data.get("city")), now, now),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="email already registered")
        _bind_device(conn, parent_id, _text(data.get("deviceId"), 180))
        token, expires = _issue_session(conn, "parent_sessions", "parent_id", parent_id)
        row = conn.execute("SELECT * FROM parents WHERE id=?", (parent_id,)).fetchone()
    return JSONResponse({"ok": True, "token": token, "expiresAt": expires, "parent": _parent_public(row)})


@router.post("/parents/login")
async def parent_login(request: Request) -> JSONResponse:
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    email = _email(data.get("email"))
    password = _password(data.get("password"))
    with DB_LOCK, _db() as conn:
        row = conn.execute("SELECT * FROM parents WHERE email=?", (email,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="wrong email or password")
        check, _ = _hash_secret(password, row["password_salt"])
        if not hmac.compare_digest(check, row["password_hash"]):
            raise HTTPException(status_code=401, detail="wrong email or password")
        _bind_device(conn, row["id"], _text(data.get("deviceId"), 180))
        token, expires = _issue_session(conn, "parent_sessions", "parent_id", row["id"])
    return JSONResponse({"ok": True, "token": token, "expiresAt": expires, "parent": _parent_public(row)})


@router.get("/parents/me")
async def parent_me(request: Request) -> Dict[str, Any]:
    parent = _current_parent(request)
    with DB_LOCK, _db() as conn:
        students = conn.execute("SELECT * FROM students WHERE parent_id=? ORDER BY created_at", (parent["id"],)).fetchall()
    return {"ok": True, "parent": _parent_public(parent), "students": [_student_public(s) for s in students]}


@router.put("/parents/me")
async def parent_update(request: Request) -> Dict[str, Any]:
    parent = _current_parent(request)
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    full_name = _text(data.get("fullName", parent["full_name"]))
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="full name is required")
    now = int(time.time())
    with DB_LOCK, _db() as conn:
        conn.execute(
            "UPDATE parents SET full_name=?,phone=?,governorate=?,city=?,updated_at=? WHERE id=?",
            (full_name, _text(data.get("phone", parent["phone"])), _text(data.get("governorate", parent["governorate"])), _text(data.get("city", parent["city"])), now, parent["id"]),
        )
        _bind_device(conn, parent["id"], _text(data.get("deviceId"), 180))
        row = conn.execute("SELECT * FROM parents WHERE id=?", (parent["id"],)).fetchone()
    return {"ok": True, "parent": _parent_public(row)}


@router.post("/parents/logout")
async def parent_logout(request: Request) -> Dict[str, Any]:
    token_hash = hashlib.sha256(_bearer(request).encode("utf-8")).hexdigest()
    with DB_LOCK, _db() as conn:
        conn.execute("DELETE FROM parent_sessions WHERE token_hash=?", (token_hash,))
    return {"ok": True}


@router.get("/parents/students")
async def parent_students(request: Request) -> Dict[str, Any]:
    parent = _current_parent(request)
    with DB_LOCK, _db() as conn:
        rows = conn.execute("SELECT * FROM students WHERE parent_id=? ORDER BY created_at", (parent["id"],)).fetchall()
    return {"ok": True, "students": [_student_public(r) for r in rows]}


@router.post("/parents/students")
async def create_student(request: Request) -> Dict[str, Any]:
    parent = _current_parent(request)
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    full_name = _text(data.get("fullName"))
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="student name is required")
    pin = _pin(data.get("pin"))
    email = _email(data.get("email"), required=False)
    ph, salt = _hash_secret(pin)
    now = int(time.time())
    student_id = secrets.token_hex(12)
    with DB_LOCK, _db() as conn:
        code = _new_student_code(conn)
        conn.execute(
            "INSERT INTO students(id,parent_id,student_code,pin_hash,pin_salt,full_name,grade,school,email,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",
            (student_id, parent["id"], code, ph, salt, full_name, _text(data.get("grade")), _text(data.get("school")), email, now, now),
        )
        _claim_reports(conn, parent["id"])
        row = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    return {"ok": True, "student": _student_public(row)}


@router.post("/students/login")
async def student_login(request: Request) -> JSONResponse:
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    code = _text(data.get("studentCode"), 32).upper()
    pin = _pin(data.get("pin"))
    with DB_LOCK, _db() as conn:
        row = conn.execute("SELECT * FROM students WHERE student_code=? AND active=1", (code,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="wrong student id or PIN")
        check, _ = _hash_secret(pin, row["pin_salt"])
        if not hmac.compare_digest(check, row["pin_hash"]):
            raise HTTPException(status_code=401, detail="wrong student id or PIN")
        token, expires = _issue_session(conn, "student_sessions", "student_id", row["id"])
    return JSONResponse({"ok": True, "token": token, "expiresAt": expires, "student": _student_public(row, True)})


@router.get("/students/me")
async def student_me(request: Request) -> Dict[str, Any]:
    row = _current_student(request)
    return {"ok": True, "student": _student_public(row, True)}


@router.get("/parents/reports")
async def parent_reports(request: Request, studentId: str = "", month: str = "") -> Dict[str, Any]:
    parent = _current_parent(request)
    studentId = _text(studentId, 64)
    month = _text(month, 16)
    where = ["parent_id=?"]
    params: list[Any] = [parent["id"]]
    if studentId:
        where.append("student_id=?")
        params.append(studentId)
    if month:
        if not MONTH_RE.fullmatch(month):
            raise HTTPException(status_code=400, detail="month must be YYYY-MM")
        where.append("month=?")
        params.append(month)
    sql = "SELECT * FROM monthly_reports WHERE " + " AND ".join(where) + " ORDER BY month DESC,updated_at DESC LIMIT 300"
    with DB_LOCK, _db() as conn:
        _claim_reports(conn, parent["id"])
        rows = conn.execute(sql, params).fetchall()
    return {"ok": True, "reports": [_report_dict(r, True) for r in rows], "count": len(rows)}


@router.get("/students/reports")
async def student_reports(request: Request, month: str = "") -> Dict[str, Any]:
    student = _current_student(request)
    params: list[Any] = [student["id"]]
    where = ["student_id=?"]
    if month:
        if not MONTH_RE.fullmatch(month):
            raise HTTPException(status_code=400, detail="month must be YYYY-MM")
        where.append("month=?")
        params.append(month)
    sql = "SELECT * FROM monthly_reports WHERE " + " AND ".join(where) + " ORDER BY month DESC,updated_at DESC LIMIT 200"
    with DB_LOCK, _db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"ok": True, "reports": [_report_dict(r, False) for r in rows], "count": len(rows)}


@router.post("/reports/publish")
async def publish_report(request: Request) -> Dict[str, Any]:
    teacher = current_teacher(request)
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid request")
    device_id = _text(data.get("targetDeviceId"), 180)
    if not DEVICE_RE.fullmatch(device_id or ""):
        raise HTTPException(status_code=400, detail="valid target device is required")
    code = re.sub(r"\D", "", _text(data.get("classroomCode"), 16))[:6]
    if len(code) != 6:
        raise HTTPException(status_code=400, detail="classroom code must be 6 digits")
    month = _text(data.get("month"), 16)
    if not MONTH_RE.fullmatch(month):
        raise HTTPException(status_code=400, detail="month must be YYYY-MM")
    student_name = _text(data.get("studentName"))
    if len(student_name) < 2:
        raise HTTPException(status_code=400, detail="student name is required")
    now = int(time.time())
    parent_id: Optional[str] = None
    student_id: Optional[str] = None
    with DB_LOCK, _db() as conn:
        device = conn.execute("SELECT parent_id FROM parent_devices WHERE device_id=?", (device_id,)).fetchone()
        if device is not None:
            parent_id = device["parent_id"]
            candidates = conn.execute("SELECT id,full_name FROM students WHERE parent_id=? AND active=1", (parent_id,)).fetchall()
            matching = [r["id"] for r in candidates if _normalize_name(r["full_name"]) == _normalize_name(student_name)]
            if len(matching) == 1:
                student_id = matching[0]
        existing = conn.execute(
            "SELECT id,created_at FROM monthly_reports WHERE teacher_id=? AND classroom_code=? AND target_device_id=? AND student_name=? AND month=?",
            (teacher["id"], code, device_id, student_name, month),
        ).fetchone()
        report_id = existing["id"] if existing else secrets.token_hex(12)
        created_at = existing["created_at"] if existing else now
        values = (
            report_id,
            teacher["id"],
            parent_id,
            student_id,
            device_id,
            code,
            _text(data.get("classroomName")),
            _text(data.get("subject")),
            student_name,
            _text(data.get("parentName")),
            month,
            max(0, int(data.get("present", 0) or 0)),
            max(0, int(data.get("absent", 0) or 0)),
            max(0, int(data.get("excused", 0) or 0)),
            max(0, int(data.get("late", 0) or 0)),
            max(0.0, float(data.get("due", 0) or 0)),
            max(0.0, float(data.get("paid", 0) or 0)),
            max(0.0, float(data.get("remaining", 0) or 0)),
            _text(data.get("paymentStatus"), 120),
            1 if bool(data.get("finalized", False)) else 0,
            created_at,
            now,
        )
        conn.execute(
            """INSERT INTO monthly_reports(
            id,teacher_id,parent_id,student_id,target_device_id,classroom_code,classroom_name,subject,
            student_name,parent_name,month,present_count,absent_count,excused_count,late_count,due,paid,
            remaining,payment_status,finalized,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(teacher_id,classroom_code,target_device_id,student_name,month) DO UPDATE SET
            parent_id=excluded.parent_id,student_id=excluded.student_id,classroom_name=excluded.classroom_name,
            subject=excluded.subject,parent_name=excluded.parent_name,present_count=excluded.present_count,
            absent_count=excluded.absent_count,excused_count=excluded.excused_count,late_count=excluded.late_count,
            due=excluded.due,paid=excluded.paid,remaining=excluded.remaining,payment_status=excluded.payment_status,
            finalized=MAX(monthly_reports.finalized,excluded.finalized),updated_at=excluded.updated_at""",
            values,
        )
    return {"ok": True, "deliveredToParentAccount": parent_id is not None, "linkedToStudent": student_id is not None, "reportId": report_id}
