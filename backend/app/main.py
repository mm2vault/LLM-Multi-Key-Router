from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import time
import uuid
import hashlib
import hmac
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

load_dotenv()
ROOT = Path(__file__).resolve().parents[2]
DB_PATH = os.getenv("DATABASE_PATH", str(ROOT / "data" / "router.db"))
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_DAYS = max(1, int(os.getenv("SESSION_DAYS", "14")))
DEFAULT_USER_REQUEST_LIMIT = max(0, int(os.getenv("DEFAULT_USER_REQUEST_LIMIT", "0")))
DEFAULT_USER_TOKEN_LIMIT = max(0, int(os.getenv("DEFAULT_USER_TOKEN_LIMIT", "0")))
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "90"))
MAX_ATTEMPTS = max(1, int(os.getenv("MAX_KEY_ATTEMPTS", "20")))
COOLDOWN = max(5, int(os.getenv("COOLDOWN_SECONDS", "60")))
PROVIDERS = {
    "openai": {"base": "https://api.openai.com/v1", "kind": "openai"},
    "deepseek": {"base": "https://api.deepseek.com/v1", "kind": "openai"},
    "openrouter": {"base": "https://openrouter.ai/api/v1", "kind": "openai"},
    "anthropic": {"base": "https://api.anthropic.com/v1", "kind": "anthropic"},
    "gemini": {"base": "https://generativelanguage.googleapis.com/v1beta", "kind": "gemini"},
}

def get_cipher() -> Fernet:
    raw = os.getenv("MASTER_ENCRYPTION_KEY", "")
    try:
        return Fernet(raw.encode())
    except Exception as exc:
        raise RuntimeError("MASTER_ENCRYPTION_KEY must be a valid Fernet key. Generate one with Fernet.generate_key().") from exc

def encrypt(value: str) -> str:
    return get_cipher().encrypt(value.encode()).decode()

def decrypt(value: str) -> str:
    try:
        return get_cipher().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Could not decrypt API key. Check MASTER_ENCRYPTION_KEY.") from exc

async def db() -> aiosqlite.Connection:
    connection = await aiosqlite.connect(DB_PATH)
    connection.row_factory = aiosqlite.Row
    return connection

async def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
          id TEXT PRIMARY KEY, provider TEXT NOT NULL, label TEXT NOT NULL,
          secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          cooldown_until REAL NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
          successes INTEGER NOT NULL DEFAULT 0, last_used REAL, created_at REAL NOT NULL,
          limit_info TEXT NOT NULL DEFAULT '{}'
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS usage (
          id TEXT PRIMARY KEY, provider TEXT NOT NULL, model TEXT NOT NULL,
          key_id TEXT, latency_ms INTEGER NOT NULL, success INTEGER NOT NULL,
          status_code INTEGER, created_at REAL NOT NULL,
          input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
          total_tokens INTEGER NOT NULL DEFAULT 0, user_id TEXT
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_providers (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
          base_url TEXT NOT NULL, created_at REAL NOT NULL
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
          quota_requests INTEGER NOT NULL DEFAULT 0, quota_tokens INTEGER NOT NULL DEFAULT 0,
          created_at REAL NOT NULL
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at REAL NOT NULL,
          created_at REAL NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL,
          created_at REAL NOT NULL, updated_at REAL NOT NULL
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL,
          content TEXT NOT NULL, created_at REAL NOT NULL,
          FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
        )""")
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
          id TEXT PRIMARY KEY, ip TEXT NOT NULL, action TEXT NOT NULL, created_at REAL NOT NULL
        )""")
        # Safe additive migrations for databases created by earlier versions.
        key_columns = {row[1] for row in await (await conn.execute("PRAGMA table_info(api_keys)")).fetchall()}
        if "limit_info" not in key_columns:
            await conn.execute("ALTER TABLE api_keys ADD COLUMN limit_info TEXT NOT NULL DEFAULT '{}'")
        columns = {row[1] for row in await (await conn.execute("PRAGMA table_info(usage)")).fetchall()}
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            if name not in columns:
                await conn.execute(f"ALTER TABLE usage ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0")
        if "user_id" not in columns:
            await conn.execute("ALTER TABLE usage ADD COLUMN user_id TEXT")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_user_id ON usage(user_id)")
        await conn.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    if (not ADMIN_USERNAME or ADMIN_USERNAME == "your-admin-username" or
        len(ADMIN_PASSWORD) < 12 or ADMIN_PASSWORD.startswith("replace-with-")):
        raise RuntimeError("Set a real ADMIN_USERNAME and a unique ADMIN_PASSWORD of at least 12 characters.")
    get_cipher()
    await init_db()
    if ADMIN_USERNAME and ADMIN_PASSWORD:
        async with aiosqlite.connect(DB_PATH) as conn:
            row = await (await conn.execute("SELECT id,password_hash FROM users WHERE username=?", (ADMIN_USERNAME,))).fetchone()
            if row:
                if not verify_password(ADMIN_PASSWORD, row[1]):
                    await conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                        (password_hash(ADMIN_PASSWORD), row[0]))
                    await conn.execute("DELETE FROM sessions WHERE user_id=?", (row[0],))
                await conn.execute("UPDATE users SET role='admin',status='active' WHERE id=?", (row[0],))
            else:
                await conn.execute("""INSERT INTO users
                    (id,username,password_hash,role,status,quota_requests,quota_tokens,created_at)
                    VALUES (?,?,?,'admin','active',0,0,?)""",
                    (str(uuid.uuid4()), ADMIN_USERNAME, password_hash(ADMIN_PASSWORD), time.time()))
            await conn.commit()
    yield

app = FastAPI(title="LLM Multi-Key Router", version="0.1.0", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "pbkdf2_sha256$310000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

async def issue_session(user_id: str) -> str:
    token = secrets.token_urlsafe(48)
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("INSERT INTO sessions (token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)",
            (token_digest(token), user_id, time.time() + SESSION_DAYS * 86400, time.time()))
        await conn.commit()
    return token

async def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    token = authorization[7:].strip()
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute("""SELECT u.id,u.username,u.role,u.status,u.quota_requests,u.quota_tokens,s.expires_at
            FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""", (token_digest(token),))).fetchone()
    if not row or row["expires_at"] < time.time():
        raise HTTPException(401, "Session expired. Sign in again.")
    if row["status"] != "active":
        raise HTTPException(403, "Account is disabled")
    return dict(row)

async def require_admin(
    x_admin_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None)
):
    if x_admin_key and ADMIN_API_KEY and hmac.compare_digest(x_admin_key, ADMIN_API_KEY):
        return {"role": "admin", "username": ADMIN_USERNAME or "legacy-admin"}
    if authorization and authorization.startswith("Bearer "):
        user = await current_user(authorization)
        if user["role"] == "admin":
            return user
    raise HTTPException(403, "Administrator access required")

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=256)

class LoginRequest(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    status: str | None = None
    role: str | None = None
    quota_requests: int | None = None
    quota_tokens: int | None = None

class ConversationCreate(BaseModel):
    title: str = Field(default="New conversation", min_length=1, max_length=120)

class MessageCreate(BaseModel):
    role: str
    content: str = Field(min_length=1, max_length=100000)

async def enforce_auth_rate_limit(ip: str, action: str):
    now = time.time()
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("DELETE FROM auth_events WHERE created_at<?", (now - 900,))
        count = (await (await conn.execute("SELECT COUNT(*) FROM auth_events WHERE ip=? AND created_at>=?", (ip, now - 900))).fetchone())[0]
        if count >= 10:
            raise HTTPException(429, "Too many authentication attempts. Try again in 15 minutes.")
        await conn.execute("INSERT INTO auth_events (id,ip,action,created_at) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), ip, action, now))
        await conn.commit()

@app.post("/auth/register")
async def register(body: RegisterRequest, request: Request):
    await enforce_auth_rate_limit(request.client.host if request.client else "unknown", "register")
    username = body.username.strip()
    if not username.replace("_", "").replace("-", "").isalnum() or len(username) < 3 or len(username) > 32:
        raise HTTPException(400, "Username must be 3-32 characters (letters, numbers, _ or -).")
    if len(body.password) < 12:
        raise HTTPException(400, "Password must contain at least 12 characters.")
    user_id = str(uuid.uuid4())
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            await conn.execute("""INSERT INTO users
                (id,username,password_hash,role,status,quota_requests,quota_tokens,created_at)
                VALUES (?,?,?,'user','active',?,?,?)""",
                (user_id, username, password_hash(body.password), DEFAULT_USER_REQUEST_LIMIT,
                 DEFAULT_USER_TOKEN_LIMIT, time.time()))
            await conn.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "Username already exists")
    token = await issue_session(user_id)
    return {"token": token, "user": {"id": user_id, "username": username, "role": "user"}}

@app.post("/auth/login")
async def login(body: LoginRequest, request: Request):
    await enforce_auth_rate_limit(request.client.host if request.client else "unknown", "login")
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute("SELECT * FROM users WHERE username=?", (body.username.strip(),))).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    if row["status"] != "active":
        raise HTTPException(403, "Account is disabled")
    token = await issue_session(row["id"])
    return {"token": token, "user": {"id": row["id"], "username": row["username"], "role": row["role"]}}

@app.get("/auth/me")
async def me(user: dict = Depends(current_user)):
    return {"user": {k: user[k] for k in ("id","username","role","status","quota_requests","quota_tokens")}}

@app.post("/auth/logout")
async def logout(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"logged_out": True}
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(authorization[7:].strip()),))
        await conn.commit()
    return {"logged_out": True}

@app.get("/admin/users", dependencies=[Depends(require_admin)])
async def admin_users():
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute("""SELECT u.id,u.username,u.role,u.status,u.quota_requests,u.quota_tokens,u.created_at,
            COUNT(DISTINCT v.id) requests,COALESCE(SUM(v.total_tokens),0) tokens
            FROM users u LEFT JOIN usage v ON v.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC""")).fetchall()
    return {"users": [dict(row) for row in rows]}

@app.patch("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def update_user(user_id: str, body: UserUpdate):
    updates, values = [], []
    for field in ("status","role","quota_requests","quota_tokens"):
        value = getattr(body, field)
        if value is not None:
            if field == "status" and value not in ("active","disabled"):
                raise HTTPException(400, "status must be active or disabled")
            if field == "role" and value not in ("user","admin"):
                raise HTTPException(400, "role must be user or admin")
            if field.startswith("quota_") and value < 0:
                raise HTTPException(400, "quota values cannot be negative")
            updates.append(field+"=?")
            values.append(value)
    if not updates:
        raise HTTPException(400, "No changes supplied")
    values.append(user_id)
    async with aiosqlite.connect(DB_PATH) as conn:
        current = await (await conn.execute("SELECT role,status FROM users WHERE id=?", (user_id,))).fetchone()
        if not current:
            raise HTTPException(404, "User not found")
        is_last_admin = current[0] == "admin" and current[1] == "active" and (
            (body.role is not None and body.role != "admin") or
            (body.status is not None and body.status != "active"))
        if is_last_admin:
            active_admins = (await (await conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'")).fetchone())[0]
            if active_admins <= 1:
                raise HTTPException(400, "Cannot disable or demote the last active administrator")
        cur = await conn.execute("UPDATE users SET "+", ".join(updates)+" WHERE id=?", values)
        await conn.commit()
    if not cur.rowcount:
        raise HTTPException(404, "User not found")
    return {"updated": True}

class AdminPasswordReset(BaseModel):
    password: str = Field(min_length=12, max_length=256)

@app.patch("/admin/users/{user_id}/password", dependencies=[Depends(require_admin)])
async def admin_reset_password(user_id: str, body: AdminPasswordReset):
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("UPDATE users SET password_hash=? WHERE id=?",
            (password_hash(body.password), user_id))
        if cur.rowcount:
            await conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        await conn.commit()
    if not cur.rowcount:
        raise HTTPException(404, "User not found")
    return {"password_reset": True, "sessions_revoked": True}

@app.delete("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def delete_user(user_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute("SELECT role,status FROM users WHERE id=?", (user_id,))).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row[0] == "admin" and row[1] == "active":
            count = (await (await conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'")).fetchone())[0]
            if count <= 1:
                raise HTTPException(400, "Cannot delete the last active administrator")
        await conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        await conn.execute("DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id=?)", (user_id,))
        await conn.execute("DELETE FROM conversations WHERE user_id=?", (user_id,))
        await conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        await conn.commit()
    return {"deleted": True}

@app.get("/admin/usage", dependencies=[Depends(require_admin)])
async def admin_usage():
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute("""SELECT v.id,v.provider,v.model,v.key_id,v.latency_ms,v.success,
            v.status_code,v.created_at,v.input_tokens,v.output_tokens,v.total_tokens,v.user_id,u.username
            FROM usage v LEFT JOIN users u ON u.id=v.user_id ORDER BY v.created_at DESC LIMIT 500""")).fetchall()
    return {"usage": [dict(row) for row in rows]}

@app.get("/admin/conversations", dependencies=[Depends(require_admin)])
async def admin_conversations():
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute("""SELECT c.id,c.user_id,u.username,c.title,c.created_at,c.updated_at,
            COUNT(m.id) message_count FROM conversations c JOIN users u ON u.id=c.user_id
            LEFT JOIN messages m ON m.conversation_id=c.id GROUP BY c.id ORDER BY c.updated_at DESC LIMIT 500""")).fetchall()
    return {"conversations": [dict(row) for row in rows]}

@app.get("/admin/conversations/{conversation_id}", dependencies=[Depends(require_admin)])
async def admin_conversation_detail(conversation_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute("""SELECT c.*,u.username FROM conversations c JOIN users u ON u.id=c.user_id WHERE c.id=?""",(conversation_id,))).fetchone()
        if not row:
            raise HTTPException(404, "Conversation not found")
        messages = await (await conn.execute("SELECT role,content,created_at FROM messages WHERE conversation_id=? ORDER BY created_at",(conversation_id,))).fetchall()
    return {"conversation": dict(row), "messages": [dict(m) for m in messages]}

@app.delete("/admin/conversations/{conversation_id}", dependencies=[Depends(require_admin)])
async def admin_delete_conversation(conversation_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute("SELECT id FROM conversations WHERE id=?", (conversation_id,))).fetchone()
        if not row:
            raise HTTPException(404, "Conversation not found")
        await conn.execute("DELETE FROM messages WHERE conversation_id=?", (conversation_id,))
        await conn.execute("DELETE FROM conversations WHERE id=?", (conversation_id,))
        await conn.commit()
    return {"deleted": True}

@app.get("/conversations")
async def my_conversations(user: dict = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute("SELECT id,title,created_at,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC",(user["id"],))).fetchall()
    return {"conversations": [dict(row) for row in rows]}

@app.post("/conversations")
async def create_conversation(body: ConversationCreate, user: dict = Depends(current_user)):
    conversation_id, now = str(uuid.uuid4()), time.time()
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("INSERT INTO conversations (id,user_id,title,created_at,updated_at) VALUES (?,?,?,?,?)",
            (conversation_id,user["id"],body.title,now,now))
        await conn.commit()
    return {"id": conversation_id, "title": body.title}

@app.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str, user: dict = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute("SELECT * FROM conversations WHERE id=? AND user_id=?",(conversation_id,user["id"]))).fetchone()
        if not row:
            raise HTTPException(404, "Conversation not found")
        messages = await (await conn.execute("SELECT role,content,created_at FROM messages WHERE conversation_id=? ORDER BY created_at",(conversation_id,))).fetchall()
    return {"conversation": dict(row), "messages": [dict(m) for m in messages]}

@app.post("/conversations/{conversation_id}/messages")
async def save_message(conversation_id: str, body: MessageCreate, user: dict = Depends(current_user)):
    if body.role not in ("user","assistant","system"):
        raise HTTPException(400, "Invalid message role")
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute("SELECT id FROM conversations WHERE id=? AND user_id=?",(conversation_id,user["id"]))).fetchone()
        if not row:
            raise HTTPException(404, "Conversation not found")
        await conn.execute("INSERT INTO messages (id,conversation_id,role,content,created_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()),conversation_id,body.role,body.content,time.time()))
        await conn.execute("UPDATE conversations SET updated_at=? WHERE id=?",(time.time(),conversation_id))
        await conn.commit()
    return {"saved": True}

class KeyCreate(BaseModel):
    provider: str
    label: str = "API key"
    api_key: str = Field(min_length=8)

class ChatRequest(BaseModel):
    model: str
    messages: list[dict[str, Any]]
    temperature: float | None = 0.7
    max_tokens: int | None = None
    stream: bool = False
    provider: str | None = None

def mask_secret(secret: str) -> str:
    return "••••••••" + secret[-4:]

async def log_usage(provider: str, model: str, key_id: str | None, latency: int, success: bool, status: int | None, usage: dict | None = None, user_id: str | None = None):
    usage = usage or {}
    input_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or usage.get("promptTokenCount") or 0)
    output_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or usage.get("candidatesTokenCount") or 0)
    total_tokens = int(usage.get("total_tokens") or usage.get("totalTokenCount") or (input_tokens + output_tokens))
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("""INSERT INTO usage
          (id,provider,model,key_id,latency_ms,success,status_code,created_at,input_tokens,output_tokens,total_tokens,user_id)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), provider, model, key_id, latency, int(success), status, time.time(),
             input_tokens, output_tokens, total_tokens, user_id))
        await conn.commit()

async def provider_config(provider: str) -> dict | None:
    if provider in PROVIDERS:
        return PROVIDERS[provider]
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        row = await (await conn.execute("SELECT slug,base_url FROM custom_providers WHERE slug=?", (provider,))).fetchone()
    return {"base": row["base_url"].rstrip("/"), "kind": "openai"} if row else None

async def all_provider_ids() -> list[str]:
    async with aiosqlite.connect(DB_PATH) as conn:
        rows = await (await conn.execute("SELECT slug FROM custom_providers ORDER BY name")).fetchall()
    return list(PROVIDERS) + [row[0] for row in rows]

async def get_candidates(provider: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT * FROM api_keys WHERE provider=? AND enabled=1 AND cooldown_until<=? ORDER BY last_used ASC, created_at ASC",
            (provider, time.time()))
        return [dict(row) for row in await cur.fetchall()]

async def mark_key(key_id: str, ok: bool, cooldown: int = 0, headers=None):
    headers = headers or {}
    names = ("x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests",
             "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens", "x-ratelimit-reset-tokens",
             "anthropic-ratelimit-requests-limit", "anthropic-ratelimit-requests-remaining",
             "anthropic-ratelimit-tokens-limit", "anthropic-ratelimit-tokens-remaining")
    limits = {name: headers.get(name) for name in names if headers.get(name) is not None}
    async with aiosqlite.connect(DB_PATH) as conn:
        if ok:
            await conn.execute("UPDATE api_keys SET successes=successes+1, failures=0, last_used=?, cooldown_until=0, limit_info=? WHERE id=?", (time.time(), json.dumps(limits), key_id))
        else:
            await conn.execute("UPDATE api_keys SET failures=failures+1, last_used=?, cooldown_until=?, limit_info=? WHERE id=?", (time.time(), time.time()+cooldown, json.dumps(limits), key_id))
        await conn.commit()

async def provider_order(requested: str | None):
    available = await all_provider_ids()
    if requested:
        if requested not in available:
            raise HTTPException(400, f"Unsupported provider: {requested}")
        return [requested] + [p for p in available if p != requested]
    return available

async def call_openai_compatible(provider: str, key: str, payload: dict):
    config = await provider_config(provider)
    if not config:
        raise HTTPException(400, f"Unknown provider: {provider}")
    base = config["base"]
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        response = await client.post(f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=payload)
    return response

async def call_anthropic(key: str, payload: dict):
    messages = payload["messages"]
    system = "\n".join(str(m.get("content", "")) for m in messages if m.get("role") == "system")
    body = {"model": payload["model"], "messages": [m for m in messages if m.get("role") != "system"],
            "max_tokens": payload.get("max_tokens") or 1024}
    if system:
        body["system"] = system
    if payload.get("temperature") is not None:
        body["temperature"] = payload["temperature"]
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        return await client.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}, json=body)

async def call_gemini(key: str, payload: dict):
    contents = []
    system = []
    for item in payload["messages"]:
        role = item.get("role", "user")
        content = item.get("content", "")
        if role == "system":
            system.append(str(content))
        else:
            contents.append({"role": "model" if role == "assistant" else "user", "parts": [{"text": str(content)}]})
    body = {"contents": contents}
    if system:
        body["systemInstruction"] = {"parts": [{"text": "\n".join(system)}]}
    generation = {}
    if payload.get("temperature") is not None:
        generation["temperature"] = payload["temperature"]
    if payload.get("max_tokens"):
        generation["maxOutputTokens"] = payload["max_tokens"]
    if generation:
        body["generationConfig"] = generation
    model = payload["model"].removeprefix("models/")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        return await client.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}",
            headers={"content-type": "application/json"}, json=body)

async def execute_provider(provider: str, key: str, payload: dict):
    config = await provider_config(provider)
    if not config:
        raise HTTPException(400, f"Unknown provider: {provider}")
    if config["kind"] == "anthropic":
        return await call_anthropic(key, payload)
    if config["kind"] == "gemini":
        return await call_gemini(key, payload)
    return await call_openai_compatible(provider, key, payload)

def normalize_response(provider: str, data: dict, requested_model: str):
    if provider == "anthropic":
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
        return {"id": data.get("id", "anthropic-response"), "object": "chat.completion",
                "model": data.get("model", requested_model),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": data.get("stop_reason")}],
                "usage": data.get("usage", {})}
    if provider == "gemini":
        candidates = data.get("candidates", [])
        text = "".join(p.get("text", "") for p in (candidates[0].get("content", {}).get("parts", []) if candidates else []))
        usage = data.get("usageMetadata", {})
        return {"id": "gemini-response", "object": "chat.completion", "model": requested_model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": candidates[0].get("finishReason") if candidates else None}],
                "usage": usage}
    return data

@app.get("/health")
async def health():
    return {"status": "ok", "service": "LLM Multi-Key Router", "providers": list(PROVIDERS)}

@app.get("/v1/providers")
async def public_providers():
    async with aiosqlite.connect(DB_PATH) as conn:
        rows = await (await conn.execute("SELECT DISTINCT provider FROM api_keys WHERE enabled=1 ORDER BY provider")).fetchall()
    return {"providers": [row[0] for row in rows]}

@app.get("/v1/models")
async def models():
    providers = await all_provider_ids()
    return {"object": "list", "data": [{"id": f"{p}:<model-name>", "object": "model", "owned_by": p} for p in providers]}

class CustomProviderCreate(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    base_url: str = Field(min_length=12, max_length=300)

@app.post("/admin/providers", dependencies=[Depends(require_admin)])
async def add_custom_provider(body: CustomProviderCreate):
    from urllib.parse import urlparse
    parsed = urlparse(body.base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(400, "Custom provider URL must be a valid HTTPS URL.")
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in body.name).strip("-")
    slug = "-".join(part for part in slug.split("-") if part)
    if not slug or slug in PROVIDERS:
        raise HTTPException(400, "Provider name conflicts with a built-in provider.")
    provider_id = str(uuid.uuid4())
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            await conn.execute("INSERT INTO custom_providers (id,name,slug,base_url,created_at) VALUES (?,?,?,?,?)",
                (provider_id, body.name, slug, body.base_url.rstrip("/"), time.time()))
            await conn.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "A provider with this name already exists.")
    return {"id": provider_id, "name": body.name, "provider": slug, "base_url": body.base_url}

@app.get("/admin/providers", dependencies=[Depends(require_admin)])
async def list_custom_providers():
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute("SELECT id,name,slug,base_url,created_at FROM custom_providers ORDER BY name")).fetchall()
    return {"providers": [dict(row) for row in rows]}

@app.delete("/admin/providers/{provider_id}", dependencies=[Depends(require_admin)])
async def delete_custom_provider(provider_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute("SELECT slug FROM custom_providers WHERE id=?", (provider_id,))).fetchone()
        if not row:
            raise HTTPException(404, "Provider not found")
        await conn.execute("DELETE FROM api_keys WHERE provider=?", (row[0],))
        await conn.execute("DELETE FROM custom_providers WHERE id=?", (provider_id,))
        await conn.commit()
    return {"deleted": True}

@app.post("/admin/keys", dependencies=[Depends(require_admin)])
async def add_key(body: KeyCreate):
    if not await provider_config(body.provider):
        raise HTTPException(400, "Unsupported provider. Add a custom OpenAI-compatible provider first if needed.")
    key_id = str(uuid.uuid4())
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("INSERT INTO api_keys (id,provider,label,secret,created_at) VALUES (?,?,?,?,?)",
            (key_id, body.provider, body.label, encrypt(body.api_key), time.time()))
        await conn.commit()
    return {"id": key_id, "provider": body.provider, "label": body.label, "masked_key": mask_secret(body.api_key), "enabled": True}

@app.get("/admin/keys", dependencies=[Depends(require_admin)])
async def list_keys():
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT id,provider,label,secret,enabled,cooldown_until,failures,successes,last_used,created_at,limit_info FROM api_keys ORDER BY created_at DESC")
        rows = [dict(r) for r in await cur.fetchall()]
    result = []
    for row in rows:
        secret = decrypt(row.pop("secret"))
        row["masked_key"] = mask_secret(secret)
        row["cooling_down"] = row["cooldown_until"] > time.time()
        try:
            row["limit_info"] = json.loads(row["limit_info"] or "{}")
        except json.JSONDecodeError:
            row["limit_info"] = {}
        result.append(row)
    return {"keys": result}

class KeyUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=100)
    api_key: str | None = Field(default=None, min_length=8)

@app.patch("/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def update_key(key_id: str, body: KeyUpdate):
    updates, values = [], []
    if body.label is not None:
        updates.append("label=?"); values.append(body.label)
    if body.api_key is not None:
        updates.append("secret=?"); values.append(encrypt(body.api_key))
    if not updates:
        raise HTTPException(400, "Provide a new label or API key")
    values.append(key_id)
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("UPDATE api_keys SET "+", ".join(updates)+" WHERE id=?", values)
        await conn.commit()
    if not cur.rowcount:
        raise HTTPException(404, "API key not found")
    return {"updated": True, "id": key_id}

class ProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=60)
    base_url: str | None = Field(default=None, min_length=12, max_length=300)

@app.patch("/admin/providers/{provider_id}", dependencies=[Depends(require_admin)])
async def update_provider(provider_id: str, body: ProviderUpdate):
    updates, values = [], []
    if body.name is not None:
        updates.append("name=?"); values.append(body.name)
    if body.base_url is not None:
        from urllib.parse import urlparse
        parsed = urlparse(body.base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise HTTPException(400, "Custom provider URL must be HTTPS")
        updates.append("base_url=?"); values.append(body.base_url.rstrip("/"))
    if not updates:
        raise HTTPException(400, "No changes supplied")
    values.append(provider_id)
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("UPDATE custom_providers SET "+", ".join(updates)+" WHERE id=?", values)
        await conn.commit()
    if not cur.rowcount:
        raise HTTPException(404, "Provider not found")
    return {"updated": True}

@app.get("/usage/me")
async def my_usage(user: dict = Depends(current_user)):
    async with aiosqlite.connect(DB_PATH) as conn:
        row = await (await conn.execute("""SELECT COUNT(*),COALESCE(SUM(input_tokens),0),
            COALESCE(SUM(output_tokens),0),COALESCE(SUM(total_tokens),0),
            SUM(CASE WHEN success=0 THEN 1 ELSE 0 END)
            FROM usage WHERE user_id=?""",(user["id"],))).fetchone()
    return {"requests": row[0] or 0, "input_tokens": row[1] or 0, "output_tokens": row[2] or 0,
            "total_tokens": row[3] or 0, "failed_requests": row[4] or 0,
            "quota_requests": user["quota_requests"], "quota_tokens": user["quota_tokens"]}

@app.delete("/admin/keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_key(key_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Key not found")
    return {"deleted": True, "id": key_id}

@app.patch("/admin/keys/{key_id}/toggle", dependencies=[Depends(require_admin)])
async def toggle_key(key_id: str):
    async with aiosqlite.connect(DB_PATH) as conn:
        cur = await conn.execute("UPDATE api_keys SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (key_id,))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Key not found")
        row = await (await conn.execute("SELECT enabled FROM api_keys WHERE id=?", (key_id,))).fetchone()
    return {"id": key_id, "enabled": bool(row[0])}

@app.get("/admin/stats", dependencies=[Depends(require_admin)])
async def stats():
    async with aiosqlite.connect(DB_PATH) as conn:
        total = (await (await conn.execute("SELECT COUNT(*) FROM api_keys")).fetchone())[0]
        enabled = (await (await conn.execute("SELECT COUNT(*) FROM api_keys WHERE enabled=1")).fetchone())[0]
        calls = (await (await conn.execute("SELECT COUNT(*) FROM usage")).fetchone())[0]
        failed = (await (await conn.execute("SELECT COUNT(*) FROM usage WHERE success=0")).fetchone())[0]
        by_provider = await (await conn.execute("SELECT provider,COUNT(*) FROM usage GROUP BY provider")).fetchall()
        token_row = await (await conn.execute("SELECT COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(total_tokens),0) FROM usage")).fetchone()
        by_key = await (await conn.execute("""SELECT a.id,a.label,a.provider,a.enabled,a.successes,a.failures,
            COALESCE(SUM(u.input_tokens),0),COALESCE(SUM(u.output_tokens),0),COALESCE(SUM(u.total_tokens),0),
            COUNT(u.id) FROM api_keys a LEFT JOIN usage u ON u.key_id=a.id GROUP BY a.id ORDER BY a.created_at DESC""")).fetchall()
    return {"total_keys": total, "enabled_keys": enabled, "requests": calls, "failed_requests": failed,
            "input_tokens": token_row[0], "output_tokens": token_row[1], "total_tokens": token_row[2],
            "providers": {r[0]: r[1] for r in by_provider},
            "keys_usage": [{"id":r[0],"label":r[1],"provider":r[2],"enabled":bool(r[3]),"successes":r[4],"failures":r[5],
                "input_tokens":r[6],"output_tokens":r[7],"total_tokens":r[8],"requests":r[9]} for r in by_key]}

@app.post("/v1/chat/completions")
async def chat(body: ChatRequest, user: dict = Depends(current_user)):
    if not body.messages:
        raise HTTPException(400, "messages cannot be empty")
    async with aiosqlite.connect(DB_PATH) as conn:
        request_count = (await (await conn.execute("SELECT COUNT(*) FROM usage WHERE user_id=?",(user["id"],))).fetchone())[0]
        token_count = (await (await conn.execute("SELECT COALESCE(SUM(total_tokens),0) FROM usage WHERE user_id=?",(user["id"],))).fetchone())[0]
    async with aiosqlite.connect(DB_PATH) as conn:
        recent_count = (await (await conn.execute(
            "SELECT COUNT(*) FROM usage WHERE user_id=? AND created_at>=?",
            (user["id"], time.time() - 60))).fetchone())[0]
    if recent_count >= 30:
        raise HTTPException(429, "Rate limit reached. Please wait a minute before trying again.")
    if user["quota_requests"] and request_count >= user["quota_requests"]:
        raise HTTPException(429, "Your request quota has been reached. Contact an administrator.")
    if user["quota_tokens"] and token_count >= user["quota_tokens"]:
        raise HTTPException(429, "Your token quota has been reached. Contact an administrator.")
    payload = body.model_dump(exclude_none=True)
    if user["quota_tokens"]:
        remaining = max(1, user["quota_tokens"] - token_count)
        requested_output = payload.get("max_tokens") or 1024
        payload["max_tokens"] = min(requested_output, remaining)
    errors = []
    attempts = 0
    for provider in await provider_order(body.provider):
        candidates = await get_candidates(provider)
        for row in candidates:
            if attempts >= MAX_ATTEMPTS:
                break
            attempts += 1
            started = time.perf_counter()
            try:
                secret = decrypt(row["secret"])
                upstream = await execute_provider(provider, secret, payload)
                latency = int((time.perf_counter()-started)*1000)
                if upstream.is_success:
                    data = normalize_response(provider, upstream.json(), body.model)
                    await mark_key(row["id"], True, headers=upstream.headers)
                    await log_usage(provider, body.model, row["id"], latency, True, upstream.status_code, data.get("usage", {}), user["id"])
                    data.setdefault("router", {"provider": provider, "key_id": row["id"], "latency_ms": latency})
                    return JSONResponse(data)
                status = upstream.status_code
                detail = upstream.text[:1000]
                cooldown = int(upstream.headers.get("retry-after", COOLDOWN)) if status == 429 else (COOLDOWN*5 if status in (401,403) else min(COOLDOWN, 20))
                await mark_key(row["id"], False, cooldown, upstream.headers)
                await log_usage(provider, body.model, row["id"], latency, False, status, user_id=user["id"])
                errors.append({"provider": provider, "status": status, "detail": detail})
                if status in (400, 404, 422):
                    raise HTTPException(status, detail)
            except HTTPException:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, RuntimeError, ValueError) as exc:
                latency = int((time.perf_counter()-started)*1000)
                await mark_key(row["id"], False, COOLDOWN)
                await log_usage(provider, body.model, row["id"], latency, False, None, user_id=user["id"])
                errors.append({"provider": provider, "error": str(exc)[:300]})
                continue
        if attempts >= MAX_ATTEMPTS:
            break
    raise HTTPException(503, {"message": "All configured API keys/providers failed or are cooling down.", "attempts": attempts, "errors": errors[-8:]})
