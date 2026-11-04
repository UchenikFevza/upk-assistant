import os
import io
import uuid
import base64
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
    hash_password
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

DEMO_AUTH_TOKEN = "upk-admin-session-token-2026"

def verify_token(authorization: str = Header(None)):
    if not authorization or authorization.replace("Bearer ", "") != DEMO_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return True

@app.post("/api/auth/login")
def login(data: LoginRequest):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE login = ? AND password_hash = ?",
        (data.login, hash_password(data.password))
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")

    return {
        "token": DEMO_AUTH_TOKEN,
        "user": {"name": user["name"], "role": user["role"], "login": user["login"]}
    }

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
            print("Ошибка фото:", e)

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

# Поиск заявки: по токену, полному номеру (ТИК-1001) или только цифрам (1001)
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

# Ответ тех. специалиста
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