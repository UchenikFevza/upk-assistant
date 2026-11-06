import os
import io
import time
import hmac
import struct
import hashlib
import base64
import uuid
from collections import defaultdict
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from database import (
    init_db,
    get_connection,
    create_ticket,
    get_student_tickets,
    save_admin_reply,
    hash_password,
    create_specialist,
    delete_specialist_by_name,
    get_all_specialists,
    change_user_password,
    get_specialist_replied_tickets,
    set_user_2fa_secret,
    activate_user_2fa,
    disable_user_2fa,
    get_user_2fa_status,
    get_floor_map_data
)
from ai_service import analyze_user_request

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(
    title="УПК: Цифровой помощник колледжа",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
SERVER_SECRET = os.getenv("SERVER_SECRET", "upk-dgu-secure-hmac-key-2026-pro")

@app.on_event("startup")
def startup_event():
    init_db()

# --- ЗАЩИТА И ЛИМИТИРОВАНИЕ ЗАПРОСОВ ---

ip_general_requests = defaultdict(list)
ip_ai_requests = defaultdict(list)
ip_auth_requests = defaultdict(list)

MAX_PAYLOAD_SIZE = 6 * 1024 * 1024

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@app.middleware("http")
async def security_and_ddos_middleware(request: Request, call_next):
    path = request.url.path.lower()
    client_ip = get_client_ip(request)
    now = time.time()

    if path == "/static/admin.html" or path.endswith(".db") or path.endswith(".py") or path.endswith(".env"):
        return RedirectResponse(url="/")

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_PAYLOAD_SIZE:
        return JSONResponse(status_code=413, content={"detail": "Размер запроса превышает 6 МБ."})

    ip_general_requests[client_ip] = [t for t in ip_general_requests[client_ip] if now - t < 60]
    if len(ip_general_requests[client_ip]) >= 90:
        return JSONResponse(status_code=429, content={"detail": "Слишком много запросов. Подождите минуту."})
    ip_general_requests[client_ip].append(now)

    if path in ("/api/tickets/analyze", "/api/tickets") and request.method == "POST":
        ip_ai_requests[client_ip] = [t for t in ip_ai_requests[client_ip] if now - t < 60]
        if len(ip_ai_requests[client_ip]) >= 15:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Превышен лимит запросов.",
                    "ai_answer": "Пожалуйста, подождите минуту перед следующим сообщением.",
                    "type": "info_question",
                    "should_create_ticket": False,
                    "is_dangerous": False
                }
            )
        ip_ai_requests[client_ip].append(now)

    if path in ("/api/auth/login", "/api/auth/verify-2fa-login") and request.method == "POST":
        ip_auth_requests[client_ip] = [t for t in ip_auth_requests[client_ip] if now - t < 60]
        if len(ip_auth_requests[client_ip]) >= 10:
            return JSONResponse(status_code=429, content={"detail": "Слишком много попыток входа. Подождите минуту."})
        ip_auth_requests[client_ip].append(now)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# --- ТОКЕНЫ И АУТЕНТИФИКАЦИЯ ---

def create_session_token(login: str, role: str) -> str:
    payload = f"{login}:{role}"
    signature = hmac.new(SERVER_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")

def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization.replace("Bearer ", "").strip()
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        login, role, signature = decoded.split(":", 2)
        expected_sig = hmac.new(SERVER_SECRET.encode("utf-8"), f"{login}:{role}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError()
        return {"login": login, "role": role}
    except Exception:
        raise HTTPException(status_code=401, detail="Сессия недействительна")

def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode('utf-8').replace('=', '')

def verify_totp(secret: str, code: str, interval: int = 30, window: int = 1) -> bool:
    clean_code = str(code).strip()
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False
    clean_secret = secret.strip().upper().replace(" ", "")
    padding = len(clean_secret) % 8
    if padding:
        clean_secret += "=" * (8 - padding)
    try:
        key = base64.b32decode(clean_secret)
    except Exception:
        return False

    current_timestamp = int(time.time())
    current_step = current_timestamp // interval

    for dt in range(-window, window + 1):
        step = current_step + dt
        msg = struct.pack(">Q", step)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[19] & 15
        binary_val = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % 1000000
        if f"{binary_val:06d}" == clean_code:
            return True
    return False

# --- СХЕМЫ ЗАПРОСОВ ---

class AnalyzeRequest(BaseModel):
    text: str

class CreateTicketRequest(BaseModel):
    title: str
    description: str
    category: str
    location_id: int | None = None
    room_number: str | None = None
    is_dangerous: bool = False
    student_name: str | None = None
    student_card: str | None = None
    photo_base64: str | None = None

class AdminReplyRequest(BaseModel):
    reply: str
    status: str
    assignee_name: str = "Инженер УПК"

class LoginRequest(BaseModel):
    login: str
    password: str

class Verify2FaLoginRequest(BaseModel):
    login: str
    code: str

class Setup2FaConfirmRequest(BaseModel):
    login: str
    secret: str
    code: str

class Disable2FaRequest(BaseModel):
    login: str
    password: str

class CreateSpecialistRequest(BaseModel):
    surname: str
    name: str
    patronymic: str
    login: str
    password: str

class DeleteSpecialistRequest(BaseModel):
    fio: str

class ChangePasswordRequest(BaseModel):
    login: str
    old_password: str
    new_password: str

# --- ЭНДПОИНТЫ КАРТЫ ЭТАЖЕЙ И СЕТИ QR-КОДОВ ---

@app.get("/api/admin/floor-map")
def api_floor_map(_: dict = Depends(verify_token)):
    return get_floor_map_data()

@app.get("/api/qr/room/{room_number}")
def generate_room_qr(room_number: str, request: Request):
    import qrcode
    # Берём реальный адрес сайта из входящего запроса (https://upk-test.onrender.com)
    domain = str(request.base_url).rstrip("/")
    target_url = f"{domain}/?room={room_number.strip()}"
    img = qrcode.make(target_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

# --- АВТОРИЗАЦИЯ И 2FA ---

@app.post("/api/auth/login")
def login(data: LoginRequest):
    conn = get_connection()
    user = conn.execute(
        "SELECT id, name, role, login, is_2fa_enabled FROM users WHERE login = ? AND password_hash = ?",
        (data.login.strip(), hash_password(data.password.strip()))
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")

    if user["is_2fa_enabled"]:
        return {"status": "require_2fa", "login": user["login"]}

    token = create_session_token(user["login"], user["role"])
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
            "login": user["login"]
        }
    }

@app.post("/api/auth/verify-2fa-login")
def verify_2fa_login(data: Verify2FaLoginRequest):
    conn = get_connection()
    user = conn.execute(
        "SELECT id, name, role, login, totp_secret, is_2fa_enabled FROM users WHERE login = ?",
        (data.login.strip(),)
    ).fetchone()
    conn.close()

    if not user or not user["is_2fa_enabled"] or not user["totp_secret"]:
        raise HTTPException(status_code=400, detail="2FA не настроена")

    if not verify_totp(user["totp_secret"], data.code):
        raise HTTPException(status_code=400, detail="Неверный 6-значный код")

    token = create_session_token(user["login"], user["role"])
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
            "login": user["login"]
        }
    }

@app.get("/api/auth/2fa/status")
def api_2fa_status(login: str, _: dict = Depends(verify_token)):
    return get_user_2fa_status(login)

@app.post("/api/auth/2fa/setup")
def api_2fa_setup(data: dict, _: dict = Depends(verify_token)):
    import qrcode
    login = data.get("login", "").strip()
    if not login:
        raise HTTPException(status_code=400, detail="Логин не указан")

    secret = generate_totp_secret()
    set_user_2fa_secret(login, secret)

    issuer = "UPK-College"
    otpauth_url = f"otpauth://totp/{issuer}:{login}?secret={secret}&issuer={issuer}"

    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1e1b4b", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_image_data": f"data:image/png;base64,{qr_base64}"
    }

@app.post("/api/auth/2fa/confirm")
def api_2fa_confirm(data: Setup2FaConfirmRequest, _: dict = Depends(verify_token)):
    if not verify_totp(data.secret, data.code):
        raise HTTPException(status_code=400, detail="Введён неверный код из приложения")
    activate_user_2fa(data.login.strip(), data.secret.strip())
    return {"status": "success", "message": "2FA успешно активирована!"}

@app.post("/api/auth/2fa/disable")
def api_2fa_disable(data: Disable2FaRequest, _: dict = Depends(verify_token)):
    success, msg = disable_user_2fa(data.login.strip(), data.password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@app.post("/api/auth/change-password")
def api_change_password(data: ChangePasswordRequest, _: dict = Depends(verify_token)):
    if len(data.new_password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Пароль должен быть от 4 символов")
    success, msg = change_user_password(data.login.strip(), data.old_password.strip(), data.new_password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

# --- УПРАВЛЕНИЕ СПЕЦИАЛИСТАМИ ---

@app.get("/api/admin/specialists")
def api_list_specialists(session: dict = Depends(verify_token)):
    if session.get("role") != "superadmin" and session.get("login") != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещён")
    return get_all_specialists()

@app.post("/api/admin/specialists")
def api_create_specialist(data: CreateSpecialistRequest, session: dict = Depends(verify_token)):
    if session.get("role") != "superadmin" and session.get("login") != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещён")
    fio = f"{data.surname.strip()} {data.name.strip()} {data.patronymic.strip()}"
    success, message = create_specialist(fio, data.login.strip(), data.password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "message": message}

@app.post("/api/admin/specialists/delete")
def api_delete_specialist(data: DeleteSpecialistRequest, session: dict = Depends(verify_token)):
    if session.get("role") != "superadmin" and session.get("login") != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещён")
    success, message = delete_specialist_by_name(data.fio.strip())
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "message": message}

# --- ОБРАЩЕНИЯ И ФИЛЬТРАЦИЯ ПО КАБИНЕТАМ ---

@app.post("/api/tickets/analyze")
def analyze_ticket_text(data: AnalyzeRequest):
    return analyze_user_request(data.text[:1500])

@app.post("/api/tickets")
def submit_ticket(data: CreateTicketRequest):
    photo_url = None
    if data.photo_base64:
        try:
            header, encoded = data.photo_base64.split(",", 1) if "," in data.photo_base64 else ("", data.photo_base64)
            file_ext = "png" if "png" in header else "jpg"
            filename = f"img_{uuid.uuid4().hex[:10]}.{file_ext}"
            file_path = UPLOAD_DIR / filename
            with open(file_path, "wb") as fh:
                fh.write(base64.b64decode(encoded))
            photo_url = f"/static/uploads/{filename}"
        except Exception:
            pass

    return create_ticket(
        title=data.title[:200],
        description=data.description[:2000],
        category=data.category,
        location_id=data.location_id,
        room_number=data.room_number.strip() if data.room_number else None,
        is_dangerous=data.is_dangerous,
        student_name=data.student_name,
        student_card=data.student_card,
        photo_url=photo_url
    )

@app.get("/api/student/tickets")
def fetch_student_tickets(student_card: str):
    return get_student_tickets(student_card.strip())

@app.get("/api/tickets/track/{query}")
def track_ticket(query: str):
    clean_query = query.strip()
    formatted_number = clean_query if clean_query.startswith("ТИК-") else f"ТИК-{clean_query}"

    conn = get_connection()
    ticket = conn.execute("""
        SELECT * FROM tickets 
        WHERE tracking_token = ? OR public_number = ? OR public_number = ?
    """, (clean_query, clean_query, formatted_number)).fetchone()

    if not ticket:
        conn.close()
        raise HTTPException(status_code=404, detail="Заявка не найдена")

    history = conn.execute("""
        SELECT old_status, new_status, actor_name, note, created_at
        FROM ticket_history
        WHERE ticket_id = ?
        ORDER BY id ASC
    """, (ticket["id"],)).fetchall()
    conn.close()

    return {"ticket": dict(ticket), "history": [dict(h) for h in history]}

@app.get("/api/admin/tickets")
def admin_tickets(
    status: str | None = None,
    category: str | None = None,
    room: str | None = None,
    query: str | None = None,
    _: dict = Depends(verify_token)
):
    conn = get_connection()
    sql = "SELECT * FROM tickets WHERE 1=1"
    params = []
    if status and status != "Все":
        sql += " AND status = ?"
        params.append(status)
    if category and category != "Все":
        sql += " AND category = ?"
        params.append(category)
    if room and room != "Все":
        sql += " AND room_number = ?"
        params.append(room)
    if query:
        sql += " AND (title LIKE ? OR description LIKE ? OR public_number LIKE ? OR student_name LIKE ? OR room_number LIKE ?)"
        term = f"%{query}%"
        params.extend([term, term, term, term, term])

    sql += " ORDER BY id DESC"
    tickets = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(t) for t in tickets]

@app.get("/api/admin/my-tickets")
def api_my_tickets(assignee_name: str, _: dict = Depends(verify_token)):
    return get_specialist_replied_tickets(assignee_name)

@app.post("/api/admin/tickets/{ticket_id}/reply")
def reply_ticket(ticket_id: int, data: AdminReplyRequest, _: dict = Depends(verify_token)):
    success = save_admin_reply(
        ticket_id=ticket_id,
        reply_text=data.reply,
        new_status=data.status,
        actor_name=data.assignee_name
    )
    if not success:
        raise HTTPException(status_code=404, detail="Заявка не найдена")
    return {"status": "success", "message": "Ответ сохранен"}

@app.get("/api/admin/stats")
def admin_stats(_: dict = Depends(verify_token)):
    conn = get_connection()
    total = conn.execute("SELECT count(*) FROM tickets").fetchone()[0]
    resolved = conn.execute("SELECT count(*) FROM tickets WHERE status = 'Решена'").fetchone()[0]
    in_progress = conn.execute("SELECT count(*) FROM tickets WHERE status IN ('В работе', 'На рассмотрении', 'Назначен исполнитель')").fetchone()[0]
    new_count = conn.execute("SELECT count(*) FROM tickets WHERE status = 'Новая'").fetchone()[0]
    conn.close()
    return {
        "total": total,
        "resolved": resolved,
        "in_progress": in_progress,
        "new": new_count
    }

@app.get("/api/qr")
def generate_qr():
    import qrcode
    img = qrcode.make(f"{BASE_URL}/")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/admin")
def serve_admin():
    return FileResponse(STATIC_DIR / "admin.html")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
