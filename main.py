import os
import json
import uuid
import io
import hashlib
import secrets
from typing import Dict, Optional
import asyncpg
from PIL import Image, ImageOps
from pydantic import BaseModel
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, status, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Digital Store & Chat Hub")

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
CONFIG_FILE = "config.json"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:UboDxTYnxICaHiRQHeciCWnDujvBQyxW@postgres.railway.internal:5432/railway"
)

DEFAULT_CONFIG = {
    "title": "Digital Store & Services",
    "subtitle": "Игровой донат, пополнение баланса, ключи и цифровые сервисы",
    "telegram": "https://t.me/your_handle",
    "instagram": "https://instagram.com/your_handle",
    "funpay": "https://funpay.com",
    "email": "support@yourdomain.com",
    "bg_image": ""
}

class SettingsPayload(BaseModel):
    title: str
    subtitle: str
    telegram: str
    instagram: str
    funpay: str
    email: str
    bg_image: str = ""

class AuthPayload(BaseModel):
    username: str
    password: str

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, hashed)

def load_file_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_file_config(data: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def get_db_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url and env_url.strip():
        return env_url.strip()
    return DATABASE_URL

async def get_raw_connection():
    db_url = get_db_url()
    try:
        pg_url = db_url.replace("postgres://", "postgresql://", 1)
        conn = await asyncpg.connect(pg_url, timeout=10)
        return conn, None
    except Exception as e:
        return None, str(e)

@app.on_event("startup")
async def startup_db():
    conn, err = await get_raw_connection()
    if conn:
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(32) UNIQUE NOT NULL,
                    password_hash VARCHAR(128) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    session_token VARCHAR(64) UNIQUE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    text TEXT,
                    image_url TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS site_settings (
                    id INT PRIMARY KEY,
                    title TEXT,
                    subtitle TEXT,
                    telegram TEXT,
                    instagram TEXT,
                    funpay TEXT,
                    email TEXT,
                    bg_image TEXT
                );
            """)
            await conn.close()
        except Exception as e:
            print(f"[DB INIT ERR] {e}")
            await conn.close()

@app.post("/api/chat/register")
async def chat_register(payload: AuthPayload):
    username = payload.username.strip()
    password = payload.password.strip()

    if len(username) < 3 or len(username) > 20:
        raise HTTPException(status_code=400, detail="Логин должен быть от 3 до 20 символов")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Пароль должен быть от 4 символов")
    if username.lower() in ["администратор", "admin", "system", "root"]:
        raise HTTPException(status_code=400, detail="Этот никнейм зарезервирован")

    conn, err = await get_raw_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Ошибка подключения к базе данных")

    try:
        existing = await conn.fetchval("SELECT id FROM chat_users WHERE LOWER(username) = LOWER($1)", username)
        if existing:
            await conn.close()
            raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")

        pwd_hash, salt = hash_password(password)
        token = secrets.token_hex(32)
        await conn.execute("""
            INSERT INTO chat_users (username, password_hash, salt, session_token)
            VALUES ($1, $2, $3, $4);
        """, username, pwd_hash, salt, token)
        await conn.close()
        return {"status": "ok", "token": token, "username": username}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            await conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat/login")
async def chat_login(payload: AuthPayload):
    username = payload.username.strip()
    password = payload.password.strip()

    conn, err = await get_raw_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Ошибка подключения к базе данных")

    try:
        row = await conn.fetchrow("SELECT username, password_hash, salt FROM chat_users WHERE LOWER(username) = LOWER($1)", username)
        if not row or not verify_password(password, row["password_hash"], row["salt"]):
            await conn.close()
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")

        new_token = secrets.token_hex(32)
        await conn.execute("UPDATE chat_users SET session_token = $1 WHERE username = $2", new_token, row["username"])
        await conn.close()
        return {"status": "ok", "token": new_token, "username": row["username"]}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            await conn.close()
        raise HTTPException(status_code=500, detail=str(e))

async def get_username_by_token(token: str) -> Optional[str]:
    if not token:
        return None
    conn, _ = await get_raw_connection()
    if conn:
        try:
            user = await conn.fetchval("SELECT username FROM chat_users WHERE session_token = $1", token)
            await conn.close()
            return user
        except Exception:
            await conn.close()
    return None

@app.get("/api/check-db")
async def check_db_status():
    conn, err = await get_raw_connection()
    if err:
        return {"database_connected": False, "error_detail": err}
    try:
        tables = await conn.fetch("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        table_names = [t["table_name"] for t in tables]
        settings_count = await conn.fetchval("SELECT COUNT(*) FROM site_settings;") if "site_settings" in table_names else 0
        messages_count = await conn.fetchval("SELECT COUNT(*) FROM chat_messages;") if "chat_messages" in table_names else 0
        users_count = await conn.fetchval("SELECT COUNT(*) FROM chat_users;") if "chat_users" in table_names else 0
        await conn.close()
        return {
            "database_connected": True,
            "tables_found": table_names,
            "rows_in_site_settings": settings_count,
            "rows_in_chat_messages": messages_count,
            "total_users": users_count
        }
    except Exception as e:
        if conn:
            await conn.close()
        return {"database_connected": False, "error_detail": str(e)}

async def get_site_config() -> dict:
    conn, _ = await get_raw_connection()
    if conn:
        try:
            row = await conn.fetchrow("SELECT title, subtitle, telegram, instagram, funpay, email, bg_image FROM site_settings WHERE id = 1")
            await conn.close()
            if row:
                return dict(row)
        except Exception as e:
            print(f"[DB ERR] get_site_config: {e}")
            await conn.close()
    return load_file_config()

async def update_site_config(data: dict):
    save_file_config(data)
    conn, err = await get_raw_connection()
    if not conn:
        raise HTTPException(status_code=500, detail=f"Ошибка подключения к БД: {err}")
    try:
        await conn.execute("""
            INSERT INTO site_settings (id, title, subtitle, telegram, instagram, funpay, email, bg_image)
            VALUES (1, $1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                subtitle = EXCLUDED.subtitle,
                telegram = EXCLUDED.telegram,
                instagram = EXCLUDED.instagram,
                funpay = EXCLUDED.funpay,
                email = EXCLUDED.email,
                bg_image = EXCLUDED.bg_image;
        """, data["title"], data["subtitle"], data["telegram"], data["instagram"], data["funpay"], data["email"], data["bg_image"])
        await conn.close()
    except Exception as e:
        await conn.close()
        raise HTTPException(status_code=500, detail=f"Ошибка SQL: {e}")

async def get_recent_chat_messages(limit: int = 50) -> list:
    conn, _ = await get_raw_connection()
    if conn:
        try:
            rows = await conn.fetch("""
                SELECT username, is_admin, text, image_url,
                       to_char(created_at, 'HH24:MI') as time_str
                FROM chat_messages
                ORDER BY id DESC
                LIMIT $1;
            """, limit)
            await conn.close()
            return [dict(r) for r in reversed(rows)]
        except Exception:
            await conn.close()
    return []

async def save_chat_message(msg: dict):
    conn, _ = await get_raw_connection()
    if not conn:
        return
    try:
        await conn.execute("""
            INSERT INTO chat_messages (username, is_admin, text, image_url)
            VALUES ($1, $2, $3, $4);
        """, msg.get("username", ""), msg.get("is_admin", False), msg.get("text", ""), msg.get("image_url", ""))
        await conn.close()
    except Exception as e:
        await conn.close()
        print(f"[DB ERR] save_chat_message: {e}")

class RoomManager:
    def __init__(self):
        self.active_connections: Dict[WebSocket, dict] = {}

    async def connect(self, websocket: WebSocket, username: str, is_admin: bool):
        self.active_connections[websocket] = {"username": username, "is_admin": is_admin}
        history = await get_recent_chat_messages()
        await websocket.send_text(json.dumps({
            "type": "history",
            "messages": history
        }))
        display_name = "👑 Администратор" if is_admin else username
        await self.broadcast({
            "type": "system",
            "text": f"{display_name} вошёл в чат",
            "online_count": len(self.active_connections)
        })

    def disconnect(self, websocket: WebSocket) -> dict:
        return self.active_connections.pop(websocket, {"username": "Пользователь", "is_admin": False})

    async def broadcast(self, message: dict):
        dead_connections = []
        payload = json.dumps(message)
        for connection in list(self.active_connections.keys()):
            try:
                await connection.send_text(payload)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.active_connections.pop(dead, None)

manager = RoomManager()

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    cfg = await get_site_config()
    return templates.TemplateResponse(request=request, name="index.html", context={"cfg": cfg})

@app.get("/chat-window", response_class=HTMLResponse)
async def get_chat_window(request: Request):
    return templates.TemplateResponse(request=request, name="chat_window.html", context={})

@app.get("/admin", response_class=HTMLResponse)
async def get_admin(request: Request):
    token = request.cookies.get("admin_session")
    is_authenticated = (token == ADMIN_PASSWORD)
    cfg = await get_site_config()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"authenticated": is_authenticated, "cfg": cfg, "admin_pwd": ADMIN_PASSWORD if is_authenticated else ""}
    )

@app.post("/admin/login")
async def admin_login(request: Request):
    form_data = await request.form()
    password = form_data.get("password", "")
    if password.strip() == ADMIN_PASSWORD:
        resp = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        resp.set_cookie(key="admin_session", value=ADMIN_PASSWORD, max_age=60*60*24*30, httponly=True)
        return resp
    return RedirectResponse(url="/admin?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/save")
async def save_admin_settings(request: Request, payload: SettingsPayload):
    token = request.cookies.get("admin_session")
    if token != ADMIN_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия администратора устарела.")
    new_data = {
        "title": payload.title.strip(),
        "subtitle": payload.subtitle.strip(),
        "telegram": payload.telegram.strip(),
        "instagram": payload.instagram.strip(),
        "funpay": payload.funpay.strip(),
        "email": payload.email.strip(),
        "bg_image": payload.bg_image.strip()
    }
    await update_site_config(new_data)
    return JSONResponse({"status": "ok", "message": "Настройки успешно сохранены!"})

@app.post("/upload")
async def upload_image(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Разрешены только изображения")
    contents = await file.read()
    try:
        image = Image.open(io.BytesIO(contents))
        image = ImageOps.exif_transpose(image)
        image = image.convert("RGBA" if image.mode in ("RGBA", "P") else "RGB")
        if max(image.size) > 1920:
            image.thumbnail((1920, 1920), Image.Resampling.LANCZOS)
        filename = f"{uuid.uuid4().hex}.webp"
        file_path = os.path.join(UPLOAD_DIR, filename)
        image.save(file_path, "WEBP", quality=80, optimize=True)
        return JSONResponse({"url": f"/static/uploads/{filename}"})
    except Exception:
        raise HTTPException(status_code=500, detail="Ошибка обработки файла")

@app.websocket("/ws/chat")
async def chat_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        init_data = await websocket.receive_text()
        init_payload = json.loads(init_data)
        admin_key = init_payload.get("admin_key", "").strip()
        user_token = init_payload.get("token", "").strip()

        is_admin = (admin_key == ADMIN_PASSWORD)
        username = None

        if is_admin:
            username = "Администратор"
        elif user_token:
            username = await get_username_by_token(user_token)

        if not username:
            await websocket.send_text(json.dumps({"type": "error", "message": "Необходима авторизация"}))
            await websocket.close()
            return

        await manager.connect(websocket, username, is_admin)

        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            text = payload.get("text", "").strip()
            image_url = payload.get("image_url", "").strip()

            if text or image_url:
                msg_entry = {
                    "username": "" if is_admin else username,
                    "is_admin": is_admin,
                    "text": text[:300],
                    "image_url": image_url
                }
                await save_chat_message(msg_entry)
                await manager.broadcast({
                    "type": "chat_message",
                    "username": msg_entry["username"],
                    "is_admin": msg_entry["is_admin"],
                    "text": msg_entry["text"],
                    "image_url": msg_entry["image_url"]
                })
    except WebSocketDisconnect:
        user_info = manager.disconnect(websocket)
        display_name = "👑 Администратор" if user_info['is_admin'] else user_info['username']
        await manager.broadcast({
            "type": "system",
            "text": f"{display_name} покинул чат",
            "online_count": len(manager.active_connections)
        })
    except Exception:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
