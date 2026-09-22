"""Minimal Proxy Admin control-plane POC.

It is not an Internet-facing API: compose
binds it only to loopback and OpenResty receives snapshots on the internal
network with a separate snapshot-reader credential.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse


DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", "/var/lib/proxy-admin/proxy-admin.db"))


def read_secret(name: str) -> bytes:
    path = Path(os.environ[name])
    value = path.read_bytes().strip()
    if not value:
        raise RuntimeError(f"{name} is empty")
    return value


AUTH_PEPPER = read_secret("AUTH_PEPPER_FILE")
SNAPSHOT_SIGNING_KEY = read_secret("SNAPSHOT_SIGNING_KEY_FILE")
ADMIN_API_TOKEN = read_secret("ADMIN_API_TOKEN_FILE")
SNAPSHOT_ACCESS_TOKEN = read_secret("SNAPSHOT_ACCESS_TOKEN_FILE")

POLICIES = {
    "default": {
        "allowed_ports": [80, 443],
        "allowed_domains": [],
        "denied_cidrs": [],
        "max_connections": 100,
        "request_rate": 0,
    }
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def token_digest(token: str) -> str:
    return hmac.new(AUTH_PEPPER, token.encode("utf-8"), hashlib.sha256).hexdigest()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.connection:
            self.connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
                    expires_at TEXT,
                    policy_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    token_digest TEXT NOT NULL,
                    not_before TEXT,
                    expires_at TEXT,
                    revoked_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS control_state (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO control_state(name, value) VALUES ('snapshot_version', '0');
                """
            )

    def _snapshot_version(self) -> int:
        return int(self.connection.execute(
            "SELECT value FROM control_state WHERE name = 'snapshot_version'"
        ).fetchone()["value"])

    def _bump_snapshot(self) -> int:
        version = self._snapshot_version() + 1
        self.connection.execute(
            "UPDATE control_state SET value = ? WHERE name = 'snapshot_version'", (str(version),)
        )
        return version

    def _audit(self, actor: str, request_id: str, action: str, resource_type: str,
               resource_id: str, detail: dict) -> None:
        self.connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), utc_now(), actor, request_id, action, resource_type,
             resource_id, json.dumps(detail, sort_keys=True, separators=(",", ":"))),
        )

    @staticmethod
    def _user(row: sqlite3.Row) -> dict:
        return dict(row)

    def list_users(self) -> list[dict]:
        with self.lock:
            return [self._user(row) for row in self.connection.execute(
                "SELECT * FROM users ORDER BY username"
            )]

    def get_user(self, user_id: str) -> dict | None:
        with self.lock:
            row = self.connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                return None
            user = self._user(row)
            user["tokens"] = [dict(token) for token in self.connection.execute(
                "SELECT id, not_before, expires_at, revoked_at, created_by, created_at "
                "FROM credentials WHERE user_id = ? ORDER BY created_at", (user_id,)
            )]
            return user

    def create_user(self, body: dict, actor: str, request_id: str) -> dict:
        username = body.get("username")
        if not isinstance(username, str) or not username or ":" in username or len(username) > 128:
            raise ValueError("username must be a non-empty string without ':'")
        policy_id = body.get("policy_id", "default")
        if policy_id not in POLICIES:
            raise ValueError("unknown policy_id")
        expires_at = body.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("expires_at must be an RFC3339 UTC string or null")
        now, user_id = utc_now(), str(uuid.uuid4())
        with self.lock, self.connection:
            self.connection.execute(
                "INSERT INTO users VALUES (?, ?, 'active', ?, ?, ?, ?, NULL)",
                (user_id, username, expires_at, policy_id, now, now),
            )
            self._bump_snapshot()
            self._audit(actor, request_id, "user.created", "user", user_id, {"username": username})
        return self.get_user(user_id)  # type: ignore[return-value]

    def patch_user(self, user_id: str, body: dict, actor: str, request_id: str) -> dict | None:
        allowed = {"username", "expires_at", "policy_id"}
        if not set(body).issubset(allowed) or not body:
            raise ValueError("only username, expires_at and policy_id may be patched")
        if "username" in body and (not isinstance(body["username"], str) or not body["username"] or ":" in body["username"]):
            raise ValueError("username must be a non-empty string without ':'")
        if "policy_id" in body and body["policy_id"] not in POLICIES:
            raise ValueError("unknown policy_id")
        if "expires_at" in body and body["expires_at"] is not None and not isinstance(body["expires_at"], str):
            raise ValueError("expires_at must be an RFC3339 UTC string or null")
        assignments = ", ".join(f"{name} = ?" for name in body)
        values = [body[name] for name in body] + [utc_now(), user_id]
        with self.lock, self.connection:
            result = self.connection.execute(
                f"UPDATE users SET {assignments}, updated_at = ? WHERE id = ?", values
            )
            if not result.rowcount:
                return None
            self._bump_snapshot()
            self._audit(actor, request_id, "user.updated", "user", user_id, body)
        return self.get_user(user_id)

    def set_status(self, user_id: str, status: str, actor: str, request_id: str) -> dict | None:
        with self.lock, self.connection:
            result = self.connection.execute(
                "UPDATE users SET status = ?, updated_at = ? WHERE id = ?", (status, utc_now(), user_id)
            )
            if not result.rowcount:
                return None
            self._bump_snapshot()
            self._audit(actor, request_id, f"user.{status}", "user", user_id, {})
        return self.get_user(user_id)

    def create_token(self, user_id: str, body: dict, actor: str, request_id: str) -> dict | None:
        token = secrets.token_urlsafe(32)
        token_id, now = str(uuid.uuid4()), utc_now()
        expires_at = body.get("expires_at")
        not_before = body.get("not_before")
        if expires_at is not None and not isinstance(expires_at, str):
            raise ValueError("expires_at must be an RFC3339 UTC string or null")
        if not_before is not None and not isinstance(not_before, str):
            raise ValueError("not_before must be an RFC3339 UTC string or null")
        with self.lock, self.connection:
            if not self.connection.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
                return None
            self.connection.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                (token_id, user_id, token_digest(token), not_before, expires_at, actor, now),
            )
            self._bump_snapshot()
            self._audit(actor, request_id, "token.created", "credential", token_id, {"user_id": user_id})
        return {"id": token_id, "token": token, "not_before": not_before, "expires_at": expires_at}

    def revoke_token(self, user_id: str, token_id: str, actor: str, request_id: str) -> bool:
        with self.lock, self.connection:
            result = self.connection.execute(
                "UPDATE credentials SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
                (utc_now(), token_id, user_id),
            )
            if not result.rowcount:
                return False
            self._bump_snapshot()
            self._audit(actor, request_id, "token.revoked", "credential", token_id, {"user_id": user_id})
            return True

    def audit_events(self, limit: int) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.connection.execute(
                "SELECT * FROM audit_events ORDER BY occurred_at DESC LIMIT ?", (limit,)
            )]

    def signed_snapshot(self) -> dict:
        with self.lock:
            users = []
            for row in self.connection.execute("SELECT * FROM users ORDER BY username"):
                user = self._user(row)
                user["credentials"] = [dict(credential) for credential in self.connection.execute(
                    "SELECT id, token_digest, not_before, expires_at, revoked_at FROM credentials "
                    "WHERE user_id = ? ORDER BY created_at", (user["id"],)
                )]
                users.append(user)
            payload = json.dumps(
                {"version": self._snapshot_version(), "generated_at": utc_now(), "users": users,
                 "policies": POLICIES}, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        return {
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": hmac.new(SNAPSHOT_SIGNING_KEY, payload, hashlib.sha256).hexdigest(),
        }


STORE = Store(DATABASE_PATH)
app = FastAPI(title="Proxy Admin", docs_url=None, redoc_url=None)
STATIC_DIR = Path(__file__).with_name("static")


def admin_context(
    authorization: str | None = Header(default=None),
    x_actor: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
) -> tuple[str, str]:
    if not authorization or not hmac.compare_digest(authorization.encode(), b"Bearer " + ADMIN_API_TOKEN):
        raise HTTPException(status_code=401, detail="admin authentication required")
    return x_actor or "unknown", x_request_id or str(uuid.uuid4())


def bad_request(error: Exception) -> None:
    raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/v1/snapshot")
def snapshot(x_proxy_snapshot_token: str | None = Header(default=None)) -> dict:
    if not x_proxy_snapshot_token or not hmac.compare_digest(x_proxy_snapshot_token.encode(), SNAPSHOT_ACCESS_TOKEN):
        raise HTTPException(status_code=401, detail="snapshot authentication required")
    return STORE.signed_snapshot()


@app.get("/v1/users")
def list_users(_: tuple[str, str] = Depends(admin_context)) -> dict:
    return {"items": STORE.list_users()}


@app.post("/v1/users", status_code=201)
def create_user(body: dict, context: tuple[str, str] = Depends(admin_context)) -> dict:
    try:
        return STORE.create_user(body, *context)
    except (ValueError, sqlite3.IntegrityError) as error:
        bad_request(error)


@app.get("/v1/users/{user_id}")
def get_user(user_id: str, _: tuple[str, str] = Depends(admin_context)) -> dict:
    user = STORE.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@app.patch("/v1/users/{user_id}")
def patch_user(user_id: str, body: dict, context: tuple[str, str] = Depends(admin_context)) -> dict:
    try:
        user = STORE.patch_user(user_id, body, *context)
    except (ValueError, sqlite3.IntegrityError) as error:
        bad_request(error)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@app.post("/v1/users/{user_id}/tokens", status_code=201)
def create_token(user_id: str, body: dict, context: tuple[str, str] = Depends(admin_context)) -> dict:
    try:
        token = STORE.create_token(user_id, body, *context)
    except ValueError as error:
        bad_request(error)
    if not token:
        raise HTTPException(status_code=404, detail="user not found")
    return token


@app.post("/v1/users/{user_id}/{action}")
def set_status(user_id: str, action: str, context: tuple[str, str] = Depends(admin_context)) -> dict:
    if action not in {"disable", "enable"}:
        raise HTTPException(status_code=404, detail="not found")
    user = STORE.set_status(user_id, "disabled" if action == "disable" else "active", *context)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@app.delete("/v1/users/{user_id}/tokens/{token_id}", status_code=204)
def revoke_token(user_id: str, token_id: str, context: tuple[str, str] = Depends(admin_context)) -> Response:
    if not STORE.revoke_token(user_id, token_id, *context):
        raise HTTPException(status_code=404, detail="active token not found")
    return Response(status_code=204)


@app.get("/v1/audit-events")
def audit_events(limit: int = Query(default=100, ge=1, le=500), _: tuple[str, str] = Depends(admin_context)) -> dict:
    return {"items": STORE.audit_events(limit)}


@app.get("/")
def management_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
