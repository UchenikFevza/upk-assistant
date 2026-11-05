import sqlite3
import hashlib
import uuid
from datetime import datetime

DB_FILE = "college.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Таблица пользователей
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        login TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'specialist',
        password_hash TEXT NOT NULL,
        totp_secret TEXT,
        is_2fa_enabled INTEGER DEFAULT 0
    );
    """)

    # Миграция колонок users
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in cursor.fetchall()]
    if "role" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'specialist'")
    if "totp_secret" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "is_2fa_enabled" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN is_2fa_enabled INTEGER DEFAULT 0")

    # 2. Таблица локаций
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        building TEXT NOT NULL,
        floor INTEGER NOT NULL,
        room TEXT NOT NULL,
        zone_name TEXT,
        qr_key TEXT UNIQUE NOT NULL
    );
    """)

    # 3. Таблица обращений
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        location_id INTEGER,
        status TEXT NOT NULL DEFAULT 'Новая',
        assignee_name TEXT,
        tracking_token TEXT UNIQUE NOT NULL,
        is_dangerous INTEGER DEFAULT 0,
        student_name TEXT,
        student_card TEXT,
        photo_url TEXT,
        admin_reply TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (location_id) REFERENCES locations (id)
    );
    """)

    # Миграция tickets
    cursor.execute("PRAGMA table_info(tickets)")
    ticket_cols = [col[1] for col in cursor.fetchall()]
    if "student_name" not in ticket_cols:
        cursor.execute("ALTER TABLE tickets ADD COLUMN student_name TEXT")
    if "student_card" not in ticket_cols:
        cursor.execute("ALTER TABLE tickets ADD COLUMN student_card TEXT")
    if "photo_url" not in ticket_cols:
        cursor.execute("ALTER TABLE tickets ADD COLUMN photo_url TEXT")
    if "admin_reply" not in ticket_cols:
        cursor.execute("ALTER TABLE tickets ADD COLUMN admin_reply TEXT")
    if "assignee_name" not in ticket_cols:
        cursor.execute("ALTER TABLE tickets ADD COLUMN assignee_name TEXT")

    # 4. Таблица истории тикетов
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT NOT NULL,
        actor_name TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (ticket_id) REFERENCES tickets (id)
    );
    """)

    # 5. Инициализация Главного Специалиста
    cursor.execute("SELECT id FROM users WHERE login = 'admin'")
    admin_user = cursor.fetchone()
    if not admin_user:
        cursor.execute("""
        INSERT INTO users (name, login, role, password_hash)
        VALUES (?, ?, 'superadmin', ?)
        """, ("Главный специалист УПК", "admin", hash_password("admin123")))
    else:
        cursor.execute("""
        UPDATE users 
        SET role = 'superadmin', password_hash = ? 
        WHERE login = 'admin'
        """, (hash_password("admin123"),))

    conn.commit()
    conn.close()

# --- УПРАВЛЕНИЕ СПЕЦИАЛИСТАМИ ---

def create_specialist(name: str, login: str, password: str) -> tuple[bool, str]:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE login = ?", (login.strip(),))
        if cursor.fetchone():
            conn.close()
            return False, "Специалист с таким логином уже существует в системе."

        cursor.execute("""
            INSERT INTO users (name, login, role, password_hash)
            VALUES (?, ?, 'specialist', ?)
        """, (name.strip(), login.strip(), hash_password(password.strip())))
        conn.commit()
        conn.close()
        return True, f"Специалист «{name.strip()}» успешно назначен."
    except Exception as e:
        conn.close()
        return False, str(e)

def delete_specialist_by_name(name: str) -> tuple[bool, str]:
    clean_name = name.strip()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, role, login FROM users WHERE name = ? COLLATE NOCASE", (clean_name,))
    users = cursor.fetchall()
    if not users:
        conn.close()
        return False, f"Специалист с ФИО «{clean_name}» не найден в базе данных."

    if any(u["role"] == "superadmin" or u["login"] == "admin" for u in users):
        conn.close()
        return False, "Запрещено удалять Главного Специалиста (суперадмина)."

    cursor.execute("DELETE FROM users WHERE name = ? COLLATE NOCASE AND role != 'superadmin'", (clean_name,))
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return True, f"Специалист «{clean_name}» успешно снят с должности (удалено записей: {deleted_count})."

def get_all_specialists() -> list[dict]:
    conn = get_connection()
    specs = conn.execute("""
        SELECT id, name, login, role, is_2fa_enabled FROM users WHERE role != 'superadmin' ORDER BY id DESC
    """).fetchall()
    conn.close()
    return [dict(s) for s in specs]

def change_user_password(login: str, old_pass: str, new_pass: str) -> tuple[bool, str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE login = ?", (login,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, "Пользователь не найден."

    if user["password_hash"] != hash_password(old_pass):
        conn.close()
        return False, "Неверный текущий пароль."

    cursor.execute("UPDATE users SET password_hash = ? WHERE login = ?", (hash_password(new_pass), login))
    conn.commit()
    conn.close()
    return True, "Пароль успешно обновлен."

# --- ФУНКЦИИ 2FA ---

def set_user_2fa_secret(login: str, secret: str):
    conn = get_connection()
    conn.execute("UPDATE users SET totp_secret = ? WHERE login = ?", (secret, login))
    conn.commit()
    conn.close()

def activate_user_2fa(login: str, secret: str) -> bool:
    conn = get_connection()
    conn.execute("UPDATE users SET totp_secret = ?, is_2fa_enabled = 1 WHERE login = ?", (secret, login))
    conn.commit()
    conn.close()
    return True

def disable_user_2fa(login: str, password: str) -> tuple[bool, str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE login = ?", (login,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, "Пользователь не найден."

    if user["password_hash"] != hash_password(password):
        conn.close()
        return False, "Неверный пароль учётной записи."

    cursor.execute("UPDATE users SET totp_secret = NULL, is_2fa_enabled = 0 WHERE login = ?", (login,))
    conn.commit()
    conn.close()
    return True, "Двухфакторная защита отключена."

def get_user_2fa_status(login: str) -> dict:
    conn = get_connection()
    user = conn.execute("SELECT is_2fa_enabled, totp_secret FROM users WHERE login = ?", (login,)).fetchone()
    conn.close()
    if not user:
        return {"is_2fa_enabled": False, "has_secret": False}
    return {
        "is_2fa_enabled": bool(user["is_2fa_enabled"]),
        "has_secret": bool(user["totp_secret"])
    }

# --- ТИКЕТЫ И ОТВЕТЫ ---

def create_ticket(title: str, description: str, category: str, location_id: int | None = None, 
                  is_dangerous: bool = False, student_name: str | None = None, 
                  student_card: str | None = None, photo_url: str | None = None) -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT count(id) FROM tickets")
    count = cursor.fetchone()[0]
    public_number = f"ТИК-{1001 + count}"
    tracking_token = str(uuid.uuid4())[:8]

    cursor.execute("""
    INSERT INTO tickets (public_number, title, description, category, location_id, status, tracking_token, 
                         is_dangerous, student_name, student_card, photo_url, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'Новая', ?, ?, ?, ?, ?, ?, ?)
    """, (public_number, title, description, category, location_id, tracking_token, 
          1 if is_dangerous else 0, student_name, student_card, photo_url, now, now))
    
    ticket_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO ticket_history (ticket_id, old_status, new_status, actor_name, note, created_at)
    VALUES (?, NULL, 'Новая', 'Система', 'Заявка зарегистрирована', ?)
    """, (ticket_id, now))

    conn.commit()
    conn.close()

    return {
        "id": ticket_id,
        "public_number": public_number,
        "tracking_token": tracking_token,
        "status": "Новая"
    }

def get_student_tickets(student_card: str) -> list[dict]:
    conn = get_connection()
    tickets = conn.execute("""
        SELECT * FROM tickets WHERE student_card = ? ORDER BY id DESC
    """, (student_card,)).fetchall()
    conn.close()
    return [dict(t) for t in tickets]

def save_admin_reply(ticket_id: int, reply_text: str, new_status: str, actor_name: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        conn.close()
        return False

    old_status = ticket["status"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE tickets 
        SET admin_reply = ?, status = ?, assignee_name = ?, updated_at = ?
        WHERE id = ?
    """, (reply_text, new_status, actor_name, now, ticket_id))

    cursor.execute("""
        INSERT INTO ticket_history (ticket_id, old_status, new_status, actor_name, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ticket_id, old_status, new_status, actor_name, f"Ответ специалиста: {reply_text[:50]}...", now))

    conn.commit()
    conn.close()
    return True

def get_specialist_replied_tickets(assignee_name: str) -> list[dict]:
    conn = get_connection()
    tickets = conn.execute("""
        SELECT * FROM tickets 
        WHERE assignee_name = ? AND admin_reply IS NOT NULL
        ORDER BY updated_at DESC
    """, (assignee_name,)).fetchall()
    conn.close()
    return [dict(t) for t in tickets]