import os
import io
import time
import hmac
import struct
import hashlib
import base64
import uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
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
    get_user_2fa_status
)
from ai_service import analyze_user_request

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(title="УПК: Цифровой помощник колледжа")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")

@app.on_event("startup")
def startup_event():
    init_db()

# --- КРИПТОГРАФИЧЕСКИЙ ДВИЖОК TOTP (RFC 6238 ДЛЯ GOOGLE AUTHENTICATOR) ---

def generate_totp_secret() -> str:
    # 20 байт случайных данных в Base32
    raw = os.urandom(20)
    return base64.b32encode(raw).decode('utf-8').replace('=', '')

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

    # Проверка текущего шага и соседних (устранение рассинхронизации часов до 30 сек)
    for dt in range(-window, window + 1):
        step = current_step + dt
        msg = struct.pack(">Q", step)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[19] & 15
        binary_val = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % 1000000
        expected_code = f"{binary_val:06d}"
        if expected_code == clean_code:
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

DEMO_AUTH_TOKEN = "upk-admin-session-token-2026"

def verify_token(authorization: str = Header(None)):
    if not authorization or authorization.replace("Bearer ", "") != DEMO_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return True

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

    # Если включена двухфакторная аутентификация — запрашиваем код
    if user["is_2fa_enabled"]:
        return {
            "status": "require_2fa",
            "login": user["login"]
        }

    return {
        "status": "success",
        "token": DEMO_AUTH_TOKEN,
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
        raise HTTPException(status_code=400, detail="Для пользователя не настроена 2FA")

    if not verify_totp(user["totp_secret"], data.code):
        raise HTTPException(status_code=400, detail="Неверный или устаревший 6-значный код из приложения")

    return {
        "status": "success",
        "token": DEMO_AUTH_TOKEN,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
            "login": user["login"]
        }
    }

@app.get("/api/auth/2fa/status")
def api_2fa_status(login: str, _: bool = Depends(verify_token)):
    return get_user_2fa_status(login)

@app.post("/api/auth/2fa/setup")
def api_2fa_setup(data: dict, _: bool = Depends(verify_token)):
    import qrcode
    login = data.get("login", "").strip()
    if not login:
        raise HTTPException(status_code=400, detail="Логин не указан")

    secret = generate_totp_secret()
    set_user_2fa_secret(login, secret)

    # Стандартный URI для добавления в Google Authenticator
    issuer = "UPK-College"
    otpauth_url = f"otpauth://totp/{issuer}:{login}?secret={secret}&issuer={issuer}"

    # Создание QR-кода на сервере в base64
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
def api_2fa_confirm(data: Setup2FaConfirmRequest, _: bool = Depends(verify_token)):
    if not verify_totp(data.secret, data.code):
        raise HTTPException(status_code=400, detail="Введён неверный код из приложения. Попробуйте снова.")

    activate_user_2fa(data.login.strip(), data.secret.strip())
    return {"status": "success", "message": "Двухфакторная аутентификация успешно активирована!"}

@app.post("/api/auth/2fa/disable")
def api_2fa_disable(data: Disable2FaRequest, _: bool = Depends(verify_token)):
    success, msg = disable_user_2fa(data.login.strip(), data.password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

@app.post("/api/auth/change-password")
def api_change_password(data: ChangePasswordRequest, _: bool = Depends(verify_token)):
    if len(data.new_password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Новый пароль должен содержать не менее 4 символов")
    
    success, msg = change_user_password(data.login.strip(), data.old_password.strip(), data.new_password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg}

# --- УПРАВЛЕНИЕ СПЕЦИАЛИСТАМИ ---

@app.get("/api/admin/specialists")
def api_list_specialists(_: bool = Depends(verify_token)):
    return get_all_specialists()

@app.post("/api/admin/specialists")
def api_create_specialist(data: CreateSpecialistRequest, _: bool = Depends(verify_token)):
    fio = f"{data.surname.strip()} {data.name.strip()} {data.patronymic.strip()}"
    if not data.surname.strip() or not data.name.strip():
        raise HTTPException(status_code=400, detail="Фамилия и имя обязательны к заполнению")
    if len(data.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Пароль должен содержать минимум 4 символа")

    success, message = create_specialist(fio, data.login.strip(), data.password.strip())
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "message": message}

@app.post("/api/admin/specialists/delete")
def api_delete_specialist(data: DeleteSpecialistRequest, _: bool = Depends(verify_token)):
    if not data.fio.strip():
        raise HTTPException(status_code=400, detail="Введите ФИО специалиста")

    success, message = delete_specialist_by_name(data.fio.strip())
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "message": message}

# --- ОБРАЩЕНИЯ И МОИ ОТВЕТЫ ---

@app.post("/api/tickets/analyze")
def analyze_ticket_text(data: AnalyzeRequest):
    return analyze_user_request(data.text)

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
        except Exception as e:
            print("Ошибка сохранения фото:", e)

    return create_ticket(
        title=data.title,
        description=data.description,
        category=data.category,
        location_id=data.location_id,
        is_dangerous=data.is_dangerous,
        student_name=data.student_name,
        student_card=data.student_card,
        photo_url=photo_url
    )

@app.get("/api/student/tickets")
def fetch_student_tickets(student_card: str):
    return get_student_tickets(student_card)

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
        raise HTTPException(status_code=404, detail="Заявка с таким номером не найдена")

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
    query: str | None = None,
    _: bool = Depends(verify_token)
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
    if query:
        sql += " AND (title LIKE ? OR description LIKE ? OR public_number LIKE ? OR student_name LIKE ?)"
        term = f"%{query}%"
        params.extend([term, term, term, term])

    sql += " ORDER BY id DESC"
    tickets = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(t) for t in tickets]

@app.get("/api/admin/my-tickets")
def api_my_tickets(assignee_name: str, _: bool = Depends(verify_token)):
    return get_specialist_replied_tickets(assignee_name)

@app.post("/api/admin/tickets/{ticket_id}/reply")
def reply_ticket(
    ticket_id: int,
    data: AdminReplyRequest,
    _: bool = Depends(verify_token)
):
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
def admin_stats(_: bool = Depends(verify_token)):
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